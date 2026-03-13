"""
Scheduled jobs for the Cyber Threat Exchange server.

Uses django-apscheduler to run periodic maintenance tasks.
"""

import logging
import os

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
from django_apscheduler.jobstores import DjangoJobStore
from django_apscheduler import util
from django.utils import timezone
from datetime import timedelta
logger = logging.getLogger(__name__)

_scheduler = None

@util.close_old_connections
def purge_old_job_data():
    """
    Clear `payload` and `warnings` from Jobs whose completion_time is more
    than 24 hours in the past.  Runs automatically on a schedule.
    """

    from cyberthreatexchange.server.models import Job
    logger.info("purge_old_job_data: looking for completed jobs with completion_time > 24 h ago")

    cutoff = timezone.now() - timedelta(hours=24)
    updated = (
        Job.objects.filter(
            completion_time__lt=cutoff,
        )
        .exclude(payload=None, warnings=[])
        .update(payload=None, warnings=[])
    )
    if updated:
        logger.info("purge_old_job_data: cleared payload/warnings on %d job(s)", updated)


def start():
    """Initialise and start the background scheduler (idempotent).

    Skips startup when Django tables aren't ready yet (e.g. during
    ``manage.py migrate``) to avoid ``ProgrammingError`` on missing tables.
    """
    global _scheduler

    if _scheduler is not None and _scheduler.running:
        return

    # Verify the apscheduler tables actually exist before starting.
    from django.db import connection
    existing = connection.introspection.table_names()
    if "django_apscheduler_djangojob" not in existing:
        logger.warning(
            "APScheduler tables not found — run 'manage.py migrate'. Skipping scheduler start."
        )
        return

    _scheduler = BackgroundScheduler()
    _scheduler.add_jobstore(DjangoJobStore(), "default")

    _scheduler.add_job(
        purge_old_job_data,
        trigger=IntervalTrigger(hours=1),
        id="purge_old_job_data",
        name="Purge payload/warnings from completed jobs older than 24 h",
        replace_existing=True,
        max_instances=1,
        misfire_grace_time=300,
        coalesce=True,
        next_run_time=timezone.now() + timedelta(seconds=30),
    )

    _scheduler.start()
    logger.info("APScheduler started — purge_old_job_data runs every hour")
