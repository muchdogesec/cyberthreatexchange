import logging
from pathlib import Path
import shutil
from urllib.parse import urljoin

import requests

from cyberthreatexchange.server.models import Job
from cyberthreatexchange.server import models
from datetime import datetime
from celery import Task
import tempfile
import typing
from django.utils import timezone
from django.conf import settings
from dateutil.parser import parse as parse_datetime

from cyberthreatexchange.worker.utils import md5_hash
from .celery import app
from stix2arango.stix2arango import Stix2Arango
import logging

if typing.TYPE_CHECKING:
    from ..import settings

def get_job_temp_dir(job):
    return str(Path(tempfile.gettempdir())/f"cyberthreatexchange/{job.type}--{str(job.id)}")

class CustomTask(Task):
    def on_failure(self, exc, task_id, args, kwargs, einfo):
        job = Job.objects.get(pk=kwargs['job_id'])
        job.state = models.JobStates.FAILED
        job.errors.append(f"celery task {self.name} failed with: {exc}")
        job.save()
        try:
            logging.info('removing directory')
            path = get_job_temp_dir(job)
            shutil.rmtree(path)
            logging.info(f'directory `{path}` removed')
        except Exception as e:
            logging.error(f'delete dir failed: {e}')
        return super().on_failure(exc, task_id, args, kwargs, einfo)
    
    def before_start(self, task_id, args, kwargs):
        if not kwargs.get('job_id'):
            raise Exception("rejected: `job_id` not in kwargs")
        return super().before_start(task_id, args, kwargs)


@app.task(base=CustomTask)
def upload_bundle_task(job_id=None, warnings=None):
    job = Job.objects.get(pk=job_id)
    make_uploads(job_id, job.payload.get('objects', []), warnings=warnings)
    
    job.state = models.JobStates.COMPLETED
    job.completion_time = timezone.now()
    job.save()
    job.feed.last_run = timezone.now()
    job.feed.save(update_fields=['last_run'])


from celery import signals
@signals.worker_ready.connect
def mark_old_jobs_as_failed(**kwargs):
    Job.objects.filter(state=models.JobStates.PENDING).update(state = models.JobStates.FAILED, errors=["marked as failed on startup"])


def make_uploads(job_id, objects, warnings=None):
    from cyberthreatexchange.server.values import save_object_values
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
    )
    bundle = job.payload.copy()
    objects_to_process = []
    warnings = warnings or {}
    for i, obj_it in enumerate(objects):
        obj = obj_it.copy()
        if i not in warnings:
            objects_to_process.append(obj)
            obj['_record_md5_hash'] = md5_hash(obj)
    
    # Upload bundle to ArangoDB
    s2a.run(data=dict(
        type="bundle",
        id=bundle.get('id', f"bundle--{job.id}"),
        objects=objects_to_process
    ))
    # Extract and save all object values to ObjectValue model
    try:
        created_count, deleted_count = save_object_values(objects_to_process, feed, str(feed.id))
        logging.info(f"Saved object values for bundle: created={created_count}, deleted={deleted_count}")
    except Exception as e:
        logging.error(f"Failed to save object values: {e}")

@app.task(base=CustomTask)
def poll_taxii_connector_task(job_id=None, connector_id=None, added_after=None):
    
    job = Job.objects.get(pk=job_id)
    connector = models.Connector.objects.get(pk=connector_id)
    feed = connector.feed
    total_objects_imported = 0
    
    try:
        session = requests.Session()
        if connector.username and connector.password:
            from requests.auth import HTTPBasicAuth
            session.auth = HTTPBasicAuth(connector.username, connector.password)

        # Prepare filters for get_objects
        filters = {}
        if added_after:
            if isinstance(added_after, datetime):
                added_after = added_after.isoformat()
            filters['added_after'] = added_after

        logging.info(f"Polling TAXII collection for connector {connector_id}")
        more = True

        while more:
            resp = session.get(urljoin(connector.taxii_collection_url+'/', 'objects/'), params=filters)
            if resp.status_code != 200:
                raise Exception(f"Failed to retrieve TAXII collection: {resp.status_code} {resp.text}")
            
            resp_data: dict = resp.json()
            objects = resp_data['objects']
            more = resp_data.get('more')
            filters = {'next': resp_data.get('next')}

            if not objects:
                logging.info("No object in TAXII envelope")
                continue

            logging.info(f"Retrieved {len(objects)} objects from TAXII collection page")
            make_uploads(job_id, objects, {})
            total_objects_imported += len(objects)
            connector.next_run_added_after = parse_datetime(resp.headers['X-TAXII-Date-Added-Last'])
        connector.last_completion_time = timezone.now()
        connector.save()

        job.state = models.JobStates.COMPLETED
        logging.info(f"Successfully polled connector {connector_id}, imported {total_objects_imported} objects")
        
    except Exception as e:
        job.state = models.JobStates.FAILED
        job.errors.append(f"TAXII poll failed: {str(e)}")
        logging.error(f"TAXII poll failed for connector {connector_id}: {e}", exc_info=True)
    finally:
        job.completion_time = timezone.now()
        if total_objects_imported:
            job.extra = job.extra or {}
            job.extra['objects_imported'] = total_objects_imported
        job.save()
        feed.last_run = timezone.now()
        feed.save(update_fields=['last_run'])

