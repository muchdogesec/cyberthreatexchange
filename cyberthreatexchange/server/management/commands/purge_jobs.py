from datetime import timedelta
import itertools
from django.core.management.base import BaseCommand
from django.utils import timezone
from django.db import transaction
from cyberthreatexchange.server import models
from django.db.models import Q


class Command(BaseCommand):
    help = "Atomically purge all old jobs older than --days (defaults to 30)."

    def add_arguments(self, parser):
        parser.add_argument(
            "--days",
            type=int,
            default=30,
            help="Purge jobs older than this number of days. Defaults to 30.",
        )

    def handle(self, *args, **options):
        days = options["days"]
        cutoff = timezone.now() - timedelta(days=days)

        # Identify ctx jobs that completed before the cutoff or started before the cutoff minus 3 days (to account for long-running jobs)
        obs_jobs_qs = models.Job.objects.filter(Q(completion_time__lt=cutoff) | Q(start_time__lt=cutoff - timedelta(days=3)))
        count = obs_jobs_qs.count()

        if count == 0:
            self.stdout.write(
                self.style.SUCCESS(
                    f"No jobs older than {days} days found (cutoff: {cutoff})."
                )
            )
            return

        self.stdout.write(
            self.style.WARNING(
                f"Found {count} jobs older than {days} days. Starting purge..."
            )
        )

        with transaction.atomic():
            _, counts = obs_jobs_qs.delete()

            total_removed = 0
            for key in sorted(counts.keys()):
                deleted_count = counts.get(key, 0)
                self.stdout.write(
                    f"  - {key}: " + self.style.SUCCESS(str(deleted_count))
                )
                total_removed += deleted_count
                
        self.stdout.write(
            self.style.SUCCESS("Successfully purged ")
            + self.style.WARNING(total_removed)
            + self.style.SUCCESS(" total records across all related models.")
        )

