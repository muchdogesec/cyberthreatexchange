import logging
from pathlib import Path
import shutil

from cyberthreatexchange.server.models import Job
from cyberthreatexchange.server import models
from celery import Task
import tempfile
import typing
from django.utils import timezone
from django.conf import settings

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
    for i, obj_it in enumerate(bundle.get('objects', [])):
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
    
    job.state = models.JobStates.COMPLETED
    job.completion_time = timezone.now()
    job.save()
    job.feed.last_run = timezone.now()
    job.feed.save(update_fields=['last_run'])


from celery import signals
@signals.worker_ready.connect
def mark_old_jobs_as_failed(**kwargs):
    Job.objects.filter(state=models.JobStates.PENDING).update(state = models.JobStates.FAILED, errors=["marked as failed on startup"])
