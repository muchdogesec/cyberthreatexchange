import logging
from pathlib import Path
import shutil
from urllib.parse import urljoin
import uuid

import requests

from cyberthreatexchange.server.arango_helpers import ArangoDBHelper
from cyberthreatexchange.server.models import Job
from cyberthreatexchange.server import models
from datetime import datetime
from celery import Task
import tempfile
import typing
from django.utils import timezone
from django.conf import settings
from dateutil.parser import parse as parse_datetime
from cyberthreatexchange.server.values.values import save_object_values

from cyberthreatexchange.worker.populate_dbs import setup_arangodb
from cyberthreatexchange.worker.utils import md5_hash
from .celery import app
from stix2arango.stix2arango import Stix2Arango
import logging
from celery import signals

if typing.TYPE_CHECKING:
    from .. import settings


class CustomTask(Task):
    def on_failure(self, exc, task_id, args, kwargs, einfo):
        job = Job.objects.get(pk=kwargs["job_id"])
        job.state = models.JobStates.FAILED
        job.errors.append(f"celery task {self.name} failed with: {exc}")
        job.completion_time = timezone.now()
        job.save(update_fields=["state", "errors", "completion_time"])
        return super().on_failure(exc, task_id, args, kwargs, einfo)

    def before_start(self, task_id, args, kwargs):
        if not kwargs.get("job_id"):
            raise Exception("rejected: `job_id` not in kwargs")
        job = Job.objects.get(pk=kwargs["job_id"])
        job.state = models.JobStates.PROCESSING
        job.save(update_fields=["state"])
        return super().before_start(task_id, args, kwargs)


@app.task(base=CustomTask)
def upload_bundle_task(job_id=None, warnings=None):
    job = Job.objects.get(pk=job_id)
    make_uploads(job_id, job.payload.get("objects", []), warnings=warnings)

    job.state = models.JobStates.COMPLETED
    job.completion_time = timezone.now()
    job.save(update_fields=["state", "completion_time"])
    job.feed.last_run = timezone.now()
    job.feed.save(update_fields=["last_run"])




def get_existing_object_pks(feed, object_ids):
    helper = ArangoDBHelper("", None)
    query = """
    FOR obj IN @@collection
    FILTER obj.id IN @object_ids
    RETURN KEEP(obj, "id", "_id", "_key", "_record_md5_hash")
    """
    bind_vars = {
        "@collection": feed.vertex_collection,
        "object_ids": object_ids,
    }
    result = helper.execute_query(query, bind_vars=bind_vars, paginate=False)
    return result

@app.task
def link_collections():
    setup_arangodb(sync=False)


def make_uploads(job_id, objects, warnings=None, arango_extra=None):
    job = Job.objects.get(pk=job_id)
    feed = job.feed
    s2a = Stix2Arango(
        file=None,
        database=settings.ARANGODB_DATABASE,
        collection=feed.collection_name,
        host_url=settings.ARANGODB_HOST_URL,
        username=settings.ARANGODB_USERNAME,
        password=settings.ARANGODB_PASSWORD,
        create_db=False,
        create_collection=False,
        versioning_mode='versionless',
    )
    bundle_id = job.payload.get('id', 'bundle--'+str(uuid.uuid4()))
    objects_to_process = []
    warnings = warnings or {}
    relationship_refs = set()
    arango_extra = arango_extra or {}
    for i, obj_it in enumerate(objects):
        obj = obj_it.copy()
        warning = warnings.get(i)
        if warning is None or warning.get("resolution") == "rewrite":
            if warning and "created" in warning:
                obj["created"] = warning["created"]
            objects_to_process.append(obj)
            obj["_record_md5_hash"] = md5_hash(obj)
            obj.update(arango_extra)
        if obj.get("type") == "relationship":
            relationship_refs.add(obj.get("source_ref"))
            relationship_refs.add(obj.get("target_ref"))
    # Ensure all referenced objects in relationships are included
    existing_objects = get_existing_object_pks(feed, list(relationship_refs))
    s2a.update_object_key_mapping(feed.vertex_collection, existing_objects)

    # Upload bundle to ArangoDB
    s2a.run(
        data=dict(
            type="bundle",
            id=bundle_id,
            objects=objects_to_process,
        )
    )
    # Extract and save all object values to ObjectValue model
    created_count = save_object_values(objects_to_process, str(feed.id))
    logging.info(f"Saved object values for bundle: created={created_count}")


@app.task(base=CustomTask)
def poll_taxii_connector_task(job_id=None, connector_id=None, added_after=None):
    job = Job.objects.get(pk=job_id)
    connector = models.Connector.objects.get(pk=connector_id)
    feed = connector.feed
    total_objects_imported = 0
    try:
        session = connector.session()

        # Prepare filters for get_objects
        filters = {}
        if added_after:
            if isinstance(added_after, datetime):
                added_after = added_after.isoformat()
            filters["added_after"] = added_after

        logging.info(f"Polling TAXII collection for connector {connector_id}")
        more = True
        extra_hidden_properties = {"_ctx_connector_id": str(connector_id)}

        while more:
            resp = session.get(urljoin(connector.url + "/", "objects/"), params=filters)
            if resp.status_code != 200:
                raise Exception(
                    f"Failed to retrieve TAXII collection: {resp.status_code} {resp.text}"
                )

            resp_data: dict = resp.json()
            objects = resp_data["objects"]
            more = resp_data.get("more")

            if not objects:
                logging.info(f"No object in TAXII envelope. filters: {filters}")
                continue
            filters = {"next": resp_data.get("next")}

            objects = remove_problematic_relationships(job, objects)

            logging.info(f"Retrieved {len(objects)} objects from TAXII collection page")
            make_uploads(job_id, objects, {}, arango_extra=extra_hidden_properties)
            total_objects_imported += len(objects)
            connector.next_run_added_after = parse_datetime(
                resp.headers["X-TAXII-Date-Added-Last"]
            )
        relationships, warnings = rerun_relationship_uploads(job)
        make_uploads(
            job_id, relationships, warnings, arango_extra=extra_hidden_properties
        )
        connector.last_completion_time = timezone.now()
        connector.save()
        job.warnings = list(warnings.values())
        job.state = models.JobStates.COMPLETED
        logging.info(
            f"Successfully polled connector {connector_id}, imported {total_objects_imported} objects"
        )

    except Exception as e:
        job.state = models.JobStates.FAILED
        job.errors.append(f"TAXII poll failed: {str(e)}")
        logging.error(
            f"TAXII poll failed for connector {connector_id}: {e}", exc_info=True
        )
    finally:
        job.completion_time = timezone.now()
        if total_objects_imported:
            job.extra = job.extra or {}
            job.extra["objects_imported"] = total_objects_imported
        job.save()
        feed.last_run = timezone.now()
        feed.save(update_fields=["last_run"])


def _known_ids(context: dict):
    """ids resolvable either from within this upload or from the feed already"""
    return set(context.get("obj_ids", [])) | set(context.get("existing_objects", {}))


def remove_problematic_relationships(job: models.Job, objects):
    helper = ArangoDBHelper("", None)
    context = {}
    helper.build_context(context, objects, job.feed)
    known_ids = _known_ids(context)
    retval: list = objects.copy()
    for obj in objects:
        if obj.get("type") != "relationship":
            continue
        refs = {obj.get("source_ref"), obj.get("target_ref")}
        if not known_ids.issuperset(refs):
            models.UnprocessedRelationship.objects.create(
                job=job,
                stix_id=obj["id"],
                stix_data=obj,
            )
            retval.remove(obj)
    return retval


def rerun_relationship_uploads(job: models.Job):
    relationships = list(models.UnprocessedRelationship.objects.filter(job=job))
    objects = [rel.stix_data for rel in relationships]
    helper = ArangoDBHelper("", None)
    context = {}
    helper.build_context(context, objects, job.feed)
    known_ids = _known_ids(context)
    warnings = {}
    unresolved_ids = set()
    for i, obj in enumerate(objects):
        source_ref = obj.get("source_ref")
        target_ref = obj.get("target_ref")
        if source_ref not in known_ids:
            unresolved_ids.add(obj["id"])
            warnings[i] = {
                "type": "missing_source",
                "message": f"could not resolve obj.source_ref ({source_ref}) for relationship in feed or upload",
                "id": obj["id"],
                "resolution": "skipped",
                "index": i,
            }
            continue
        if target_ref not in known_ids:
            unresolved_ids.add(obj["id"])
            warnings[i] = {
                "type": "missing_target",
                "message": f"could not resolve obj.target_ref ({target_ref}) for relationship in feed or upload",
                "id": obj["id"],
                "resolution": "skipped",
                "index": i,
            }
            continue
    for r in relationships:
        if r.stix_id not in unresolved_ids:
            r.delete()
    return objects, warnings


@signals.worker_ready.connect
def mark_old_jobs_as_failed(**kwargs):
    models.Job.objects.exclude(
        state__in=[
            models.JobStates.COMPLETED,
            models.JobStates.FAILED,
        ]
    ).update(
        state=models.JobStates.FAILED,
        errors=[{"message": "Marked as failed on startup"}],
        completion_time=timezone.now(),
    )
