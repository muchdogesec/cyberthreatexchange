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

from cyberthreatexchange.worker.populate_dbs import setup_semantic_search_view

if typing.TYPE_CHECKING:
    from .. import settings


class IdentityIDField(models.CharField):
    def pre_save(self, model_instance, add):
        if add:
            value = "identity--" + str(uuid.uuid4())
            setattr(model_instance, self.attname, value)
            return value
        return super().pre_save(model_instance, add)


class Identity(models.Model):
    id = IdentityIDField(primary_key=True, max_length=64)
    type = models.CharField(max_length=10, default="identity")
    spec_version = models.CharField(max_length=3, default="2.1")

    labels = ArrayField(
        models.CharField(max_length=64), default=list, blank=True, null=True
    )
    created = models.DateTimeField(auto_now_add=True)
    modified = models.DateTimeField(auto_now=True)

    revoked = models.BooleanField(default=False)
    confidence = models.IntegerField(null=True, blank=True)
    lang = models.CharField(max_length=32, blank=True, null=True)

    roles = models.JSONField(default=list, blank=True)
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True, null=True)
    identity_class = models.CharField(max_length=64)
    sectors = ArrayField(models.CharField(max_length=64), default=list, blank=True)
    contact_information = models.TextField(blank=True, null=True)

    @property
    def dict(self):
        from .serializers import IdentitySerializer

        return json.loads(stix2.parse(IdentitySerializer(self).data).serialize())


class Feed(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, unique=True)
    collection_name = models.CharField(max_length=200, unique=True)
    name = models.CharField(max_length=200)
    description = models.TextField(null=True)
    tags = ArrayField(models.CharField(max_length=100), default=list, blank=True)
    last_run = models.DateTimeField(null=True)
    identity = models.ForeignKey(
        Identity, on_delete=models.CASCADE, null=True, editable=False
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def save(self, *args, **kwargs) -> None:
        self.collection_name = self.generate_collection_name()
        return super().save(*args, **kwargs)

    def generate_collection_name(self):
        return "ctx_" + str(self.id).replace("-", "")

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
    setup_semantic_search_view()
    
def update_identities(feed: Feed):
    identity = feed.identity.dict
    identity["_record_modified"] = timezone.now().isoformat().replace("+00:00", "Z")
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


class JobTypes(models.TextChoices):
    BUNDLE_UPLOAD = "bundle-upload"
    SINGLE_UPLOAD = "single-upload"
    SINGLE_DELETE = "single-delete"


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
    errors = ArrayField(models.JSONField(), default=list, blank=True)
    warnings = ArrayField(models.JSONField(), default=list, blank=True)
    start_time = models.DateTimeField(auto_now_add=True)
    completion_time = models.DateTimeField(null=True, default=None)
