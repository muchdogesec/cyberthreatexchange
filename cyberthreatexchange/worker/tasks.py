import logging
from pathlib import Path
import shutil
from urllib.parse import urljoin

import requests
from cyberthreatexchange.server.models import Job
from cyberthreatexchange.server import models
from celery import Task
import tempfile
from datetime import datetime, date, timedelta
import typing
from django.utils import timezone
from django.conf import settings
from .celery import app
from stix2arango.stix2arango import Stix2Arango

from arango_cti_processor.managers import TechniqueTactic
from arango_cti_processor.__main__ import run_all as run_task_with_acp
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
    if warnings:
        bundle['objects'] = [obj.copy() for i, obj in enumerate(bundle['objects']) if i not in warnings]
    s2a.run(data=bundle)
    job.state = models.JobStates.COMPLETED
    job.completion_time = timezone.now()
    job.save()
    job.feed.last_run = timezone.now()
    job.feed.save()


from celery import signals
@signals.worker_ready.connect
def mark_old_jobs_as_failed(**kwargs):
    Job.objects.filter(state=models.JobStates.PENDING).update(state = models.JobStates.FAILED, errors=["marked as failed on startup"])
