import json
import logging
import typing
import uuid
from django.conf import settings
from django.db import models
from django.utils import timezone

from django.dispatch import receiver
from dogesec_commons.objects.helpers import ArangoDBHelper
from django.db.models.signals import post_save, post_delete
from django.contrib.postgres.fields import ArrayField
import stix2
from stix2arango.stix2arango import Stix2Arango
from dogesec_commons.identity.models import Identity
from cryptography.fernet import Fernet
import base64
from django.core.exceptions import ImproperlyConfigured

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



class Feed(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, unique=True)
    collection_name = models.CharField(max_length=200, unique=True)
    name = models.CharField(max_length=200)
    description = models.TextField(null=True, max_length=140)
    short_description = models.CharField(max_length=512, null=True, blank=True)
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

from django.contrib.postgres.search import SearchVectorField

class ObjectValue(models.Model):
    """
    Stores searchable values from STIX objects including their references.
    Enables searching by value and finding objects where referenced objects match.
    Unique constraint: (feed, stix_id, modified, value, value_type, is_ref, ref_stix_id)
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4)
    feed = models.ForeignKey(Feed, on_delete=models.CASCADE)
    stix_id = models.CharField(max_length=255)
    stix_type = models.CharField(max_length=100)
    modified = models.DateTimeField()
    value = models.TextField(db_index=True)
    value_type = models.CharField(max_length=100)
    is_ref = models.BooleanField(default=False)
    ref_stix_id = models.CharField(max_length=255, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = [['feed', 'stix_id', 'modified', 'value', 'value_type', 'is_ref', 'ref_stix_id']]
        indexes = [
            models.Index(fields=['feed', 'value']),
            models.Index(fields=['feed', 'stix_id', 'modified']),
            models.Index(fields=['feed', 'ref_stix_id']),
            models.Index(fields=['feed', 'is_ref']),
        ]

    def __str__(self):
        return f"{self.stix_id} ({self.value_type}): {self.value}"


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
    taxii_collection_url = models.URLField(max_length=500)
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
