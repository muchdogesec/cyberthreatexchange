from collections import defaultdict
from datetime import datetime, UTC
import hashlib
import json
import logging
import sys
import typing
import uuid
from django.conf import settings
from django.db import models
from django.utils import timezone

from django.dispatch import receiver
from dogesec_commons.objects.helpers import ArangoDBHelper
from django.db.models.signals import post_save, post_delete, pre_delete
from django.contrib.postgres.fields import ArrayField
from django.db.models.functions import Substr
import django.contrib.postgres.indexes as postgres_indexes
import stix2
from stix2arango.stix2arango import Stix2Arango
from dogesec_commons.identity.models import Identity
from cryptography.fernet import Fernet
import base64
from django.core.exceptions import ImproperlyConfigured
from cyberthreatexchange.server.values import filters as value_filters

from cyberthreatexchange.worker.populate_dbs import setup_arangodb, setup_semantic_search_view

if typing.TYPE_CHECKING:
    from .. import settings

class Category(models.TextChoices):
    OTHER = "other"
    APT_GROUP = "apt_group"
    VULNERABILITY = "vulnerability"
    DATA_LEAK = "data_leak"
    MALWARE = "malware"
    RANSOMWARE = "ransomware"
    INFOSTEALER = "infostealer"
    THREAT_ACTOR = "threat_actor"
    CAMPAIGN = "campaign"
    EXPLOIT = "exploit"
    CYBER_CRIME = "cyber_crime"
    INDICATOR_OF_COMPROMISE = "indicator_of_compromise"
    TTP = "ttp"

NULL_DT = datetime(1970, 1, 1, tzinfo=UTC)


class Feed(models.Model):
    id = models.UUIDField(primary_key=True, default=None, unique=True)
    collection_name = models.CharField(max_length=200, unique=True)
    name = models.CharField(max_length=200)
    description = models.TextField(null=True, blank=True)
    short_description = models.CharField(max_length=512)
    tags = ArrayField(models.CharField(max_length=100), default=list, blank=True)
    last_run = models.DateTimeField(null=True)
    identity = models.ForeignKey(
        Identity, on_delete=models.CASCADE, null=True, editable=False
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    categories = ArrayField(
        models.CharField(max_length=128, choices=Category.choices),
        default=list,
        blank=True,
    )

    def calculate_id(self):
        genid = self.id
        if not self.id:
            print(f"{self.name}+{self.identity.id}")
            genid = uuid.uuid5(settings.FEED_NAMESPACE, f"{self.name}+{self.identity.id}")
            self.id = genid
        return genid

    def save(self, *args, **kwargs) -> None:
        self.calculate_id()
        self.collection_name = self.generate_collection_name()
        return super().save(*args, **kwargs)

    def generate_collection_name(self):
        return self.collection_name or "ctx_" + str(self.id).replace("-", "")

    @property
    def edge_collection(self):
        return self.collection_name + "_edge_collection"

    @property
    def vertex_collection(self):
        return self.collection_name + "_vertex_collection"


@receiver(post_save, sender=Feed)
def auto_create_collection(sender, instance: Feed, created, **kwargs):
    if created:
        create_collection(instance)

@receiver(post_save, sender=Identity)
def auto_update_identities(sender, instance: Identity, created, **kwargs):
    if not created:
        for feed in Feed.objects.filter(identity=instance):
            update_identities(feed)


def create_collection(feed: Feed):
    s2a = Stix2Arango(
        database=settings.ARANGODB_DATABASE,
        collection=feed.collection_name,
        file="",
        host_url=settings.ARANGODB_HOST_URL,
        create_collection=True,
        versioning_mode='versionless',
    )
    s2a.run(
        data=dict(
            type="bundle",
            id="bundle--" + str(feed.id),
            objects=[feed.identity.dict],
        )
    )
    setup_arangodb()

def update_identities(feed: Feed):
    identity = feed.identity.dict
    identity["_record_modified"] = timezone.now().isoformat().replace("+00:00", "Z")
    identity['_product_identity'] = True
    query = """
    FOR doc IN @@vertex_collection
    FILTER doc.id == @identity.id
    UPDATE doc WITH @identity IN @@vertex_collection
    RETURN doc._key
    """
    binds = {
        "@vertex_collection": feed.vertex_collection,
        "identity": identity,
    }

    from django.http.request import HttpRequest
    from rest_framework.request import Request

    helper = ArangoDBHelper(settings.VIEW_NAME, Request(HttpRequest()))
    try:
        updated_keys = helper.execute_query(query, bind_vars=binds, paginate=False)
        logging.info(f"updated {len(updated_keys)} identities for {feed.id}")
    except Exception as e:
        logging.exception("could not update identities")


@receiver(post_delete, sender=Feed)
def delete_collections(sender, instance: Feed, **kwargs):
    db = ArangoDBHelper(instance.collection_name, None).db
    try:
        graph = db.graph(db.name.split('_database')[0]+'_graph')
        graph.delete_edge_definition(instance.collection_name+'_edge_collection', purge=True)
        graph.delete_vertex_collection(instance.collection_name+'_vertex_collection', purge=True)
    except BaseException as e:
        logging.error(f"cannot delete collection `{instance.collection_name}`: {e}")

class NewObjectValue(models.Model):
    """
    New version of ObjectValue with JSONB field for values and optimized indexing.
    Stores all values for a STIX object in a single record for easier updates and queries.
    Unique constraint: (feed, stix_id, modified)
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    feed = models.ForeignKey(Feed, on_delete=models.CASCADE)
    stix_id = models.CharField(max_length=128, db_index=True)
    type = models.CharField(max_length=64, db_index=True)
    modified = models.DateTimeField(default=NULL_DT)
    created = models.DateTimeField(default=NULL_DT)
    values = models.JSONField()  # Store all values in a JSON field
    is_dupe = models.BooleanField(default=True)
    knowledgebase = models.CharField(max_length=64, null=True, blank=True)
    arango_pk = models.CharField(max_length=255, null=True)
    values_concat = models.GeneratedField(
        expression=models.Func(models.F("values"), function="jsonb_values_concat"),
        output_field=models.TextField(),
        db_persist=True,
        null=True,
        blank=True,
    )
    values_sort = models.GeneratedField(
        expression=models.Func(
            models.F("values"),
            models.functions.Cast(models.F('id'), models.TextField()),
            function="jsonb_sort_value"
        ),
        output_field=models.CharField(max_length=69),
        db_persist=True,
        null=True,
        blank=True,
    )
    hashed_values_list = models.GeneratedField(
        expression=models.Func(models.F("values"), function="jsonb_hash_values_list"),
        output_field=ArrayField(base_field=models.UUIDField()),
        db_persist=True,
        null=True,
        blank=True,
    )
    added_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)


    class Meta:
        unique_together = [['feed', 'stix_id']]
        indexes = [
            models.Index(fields=['is_dupe'], name='ctx_nov_empty_query_idx'),
            models.Index(fields=['stix_id', 'modified']),
            models.Index(fields=['feed', 'stix_id'], condition=models.Q(is_dupe=False), name='ctx_deduplicator_idx'),
            models.Index(fields=['feed', 'stix_id'], name='ctx_nov_feed_stix_idx'),
            models.Index(fields=['type', 'stix_id'], name='ctx_nov_type_stix_idx', condition=models.Q(is_dupe=False)),
            models.Index(fields=['created', 'id', 'type', 'feed_id'], name='ctx_nov_created_type_idx', condition=models.Q(is_dupe=False)),
            models.Index(fields=['modified', 'id', 'type', 'feed_id'], name='ctx_nov_modified_type_idx', condition=models.Q(is_dupe=False)),
            models.Index(fields=['values_sort', 'type', 'feed_id'], name='ctx_nov_values_sort_type_idx', condition=models.Q(is_dupe=False)),
            models.Index(fields=['created', 'id', 'knowledgebase', 'feed_id'], name='ctx_nov_created_kb_idx', condition=models.Q(is_dupe=False)),
            models.Index(fields=['modified', 'id', 'knowledgebase', 'feed_id'], name='ctx_nov_modified_kb_idx', condition=models.Q(is_dupe=False)),
            models.Index(fields=['values_sort', 'knowledgebase', 'feed_id'], name='ctx_nov_values_sort_kb_idx', condition=models.Q(is_dupe=False)),
        ]

    def __str__(self):
        return f"ObjectValue(stix_id={self.stix_id}, type={self.type}, modified={self.modified}, feed={self.feed.id}, values={len(self.values)})"

    @staticmethod
    def real_date_value(d: datetime):
        if d == NULL_DT:
            return None
        return d

def _refresh_stix_dedupe_state(stix_ids: str | list[str] | set[str] | tuple[str, ...]) -> int:
    'returns number of updated rows'
    if isinstance(stix_ids, str):
        stix_ids = [stix_ids]
    stix_ids = list(set(stix_ids))
    if not stix_ids:
        return 0

    scoped = NewObjectValue.objects.filter(stix_id__in=stix_ids, is_dupe=False)\
            .only('id', 'stix_id', 'modified', 'is_dupe')
    return _scoped_refresh_dedupe_state(scoped)


def _scoped_refresh_dedupe_state(scoped: list[NewObjectValue]) -> int:
    # Keep one canonical row per STIX ID and mark all others as duplicates.
    objs = defaultdict(list)
    objs2 = []
    seen = set()
    
    for obj in sorted(scoped, key=lambda obj: (obj.stix_id, obj.modified), reverse=True):
        orig_is_dupe = obj.is_dupe
        if obj.stix_id in seen:
            obj.is_dupe = True
        else:
            obj.is_dupe = False
        seen.add(obj.stix_id)
        if orig_is_dupe != obj.is_dupe:
            objs[obj.is_dupe].append(obj.id)
            objs2.append(obj)
    count = 0
    batch_size = 500
    for k, v in objs.items():
        for chunk_start in range(0, len(v), batch_size):
            count += NewObjectValue.objects.filter(id__in=v[chunk_start:chunk_start+batch_size]).update(is_dupe=k)
    return count

def refresh_dupes_on_feed_batched(feed_id: str, chunk_size: int = 10_000):
    from django.db.models import OuterRef, Exists, Subquery

    feed_ids = list(Feed.objects.exclude(id=feed_id).values_list('id', flat=True))

    scope = NewObjectValue.objects.filter(
        feed_id__in=feed_ids,
        stix_id__in=Subquery(
            NewObjectValue.objects.filter(feed_id=feed_id, is_dupe=False).values(
                "stix_id"
            )
        ),
    ).only("stix_id", "modified", "id", "is_dupe")
    updated = _scoped_refresh_dedupe_state(scope)
    return updated


@receiver(pre_delete, sender=Feed)
def rebalance_newobjectvalue_dupes(sender, instance: Feed, **kwargs):
    refresh_dupes_on_feed_batched(instance.id)

class JobTypes(models.TextChoices):
    BUNDLE_UPLOAD  = "bundle-upload"
    CONNECTOR_POLL = "connector-poll"
    SINGLE_UPLOAD  = "single-upload"
    SINGLE_DELETE  = "single-delete"


class JobStates(models.TextChoices):
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"

class Job(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4)
    feed = models.ForeignKey(Feed, on_delete=models.CASCADE, null=True)
    type = models.CharField(choices=JobTypes.choices)
    state = models.CharField(choices=JobStates.choices)
    payload = models.JSONField(null=True, default=None)
    extra = models.JSONField(null=True, default=None)
    errors = ArrayField(models.JSONField(), default=list, blank=True)
    warnings = ArrayField(models.JSONField(), default=list, blank=True)
    start_time = models.DateTimeField(auto_now_add=True)
    completion_time = models.DateTimeField(null=True, default=None)


class ConnectorType(models.TextChoices):
    TAXII = "taxii"


def get_encryption_key():
    """Get or generate encryption key from Django SECRET_KEY."""
    secret = settings.SECRET_KEY.encode()
    # Use the first 32 bytes of SECRET_KEY hash for Fernet key
    from hashlib import sha256
    key = base64.urlsafe_b64encode(sha256(secret).digest())
    return key


def encrypt_field(value: str) -> str:
    if not value:
        return value
    f = Fernet(get_encryption_key())
    return f.encrypt(value.encode()).decode()


def decrypt_field(value: str) -> str:
    if not value:
        return value
    f = Fernet(get_encryption_key())
    return f.decrypt(value.encode()).decode()


class Connector(models.Model):
    """
    Connector for pulling data from remote sources into feeds.
    Currently supports TAXII 2.1 collections.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4)
    feed = models.ForeignKey(Feed, on_delete=models.CASCADE, related_name='connectors')
    name = models.CharField(max_length=200)
    description = models.TextField(null=True, blank=True)
    type = models.CharField(
        max_length=50,
        choices=ConnectorType.choices,
        default=ConnectorType.TAXII,
        editable=False
    )
    url = models.URLField(max_length=500)
    enc_user = models.TextField(null=True, blank=True)
    enc_pass = models.TextField(null=True, blank=True)
    last_completion_time = models.DateTimeField(null=True, blank=True)
    next_run_added_after = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.name} ({self.feed.name})"

    @property
    def username(self):
        """Decrypt and return username."""
        if self.enc_user:
            return decrypt_field(self.enc_user)
        return None

    @username.setter
    def username(self, value):
        if value is not None:
            self.enc_user = encrypt_field(value)
        else:
            self.enc_user = None

    @property
    def password(self):
        if self.enc_pass:
            return decrypt_field(self.enc_pass)
        return None

    @password.setter
    def password(self, value):
        if value is not None:
            self.enc_pass = encrypt_field(value)
        else:
            self.enc_pass = None

    def session(self):
        import requests
        session = requests.Session()
        if self.username and self.password:
            from requests.auth import HTTPBasicAuth
            session.auth = HTTPBasicAuth(self.username, self.password)
        return session
    
    @property
    def remote_info(self):
        response = None
        try:
            resp = self.session().get(self.url)
            data = dict(status_code=resp.status_code)
            if resp.status_code == 200:
                response = data['response'] = resp.json()
            else:
                data['error'] = resp.json()
        except Exception as e:
            data = dict(error=f'Connection error: {e}')
        if response and not set(['title', 'can_read', 'can_write']).issubset(response):
            data['error'] = 'Invalid TAXII collection response'
        if 'error' not in data and not response['can_read']:
            data['error'] = 'This collection does not support read (required)'
        if data.get('can_write'):
            data['warning'] = 'write permission is active for this user'
        return data


class UnprocessedRelationship(models.Model):
    """
    Store relationships that could not be processed due to missing referenced objects.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4)
    job = models.ForeignKey(Job, on_delete=models.CASCADE)
    stix_id = models.CharField(max_length=255)
    target_ref = models.CharField(max_length=255)
    source_ref = models.CharField(max_length=255)
    stix_data = models.JSONField()
