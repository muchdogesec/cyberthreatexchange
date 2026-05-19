"""
Management command to index existing STIX objects from ArangoDB into ObjectValue table.

This command retrieves objects from each feed's ArangoDB vertex collection
in bounded batches and indexes them into the ObjectValue table.

Usage:
    python manage.py index_object_values
    python manage.py index_object_values --feeds <uuid>
    python manage.py index_object_values --batch-size 2000
    python manage.py index_object_values --dry-run
"""

import logging
from django.core.management.base import BaseCommand
from django.conf import settings
from arango import ArangoClient

from cyberthreatexchange.server.models import Feed, NewObjectValue, refresh_dupes_on_feed_batched
from cyberthreatexchange.server.values.values import save_object_values


logger = logging.getLogger(__name__)


def validate_feed_id(value):
    Feed.objects.get(pk=value)  # Will raise DoesNotExist if invalid
    return value


class Command(BaseCommand):
    help = "Index existing STIX objects from ArangoDB into ObjectValue table"

    def add_arguments(self, parser):
        parser.add_argument(
            "--feeds",
            type=validate_feed_id,
            nargs="+",
            help="Process only a specific feed by UUID",
        )
        parser.add_argument(
            "--batch-size",
            type=int,
            default=2000,
            help="Number of objects to process per indexing batch",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Show what would be processed without actually indexing",
        )
        parser.add_argument(
            "--refresh-dupes",
            action="store_true",
            help="Refresh deduplication flags for all STIX IDs and exit. WARNING: This can be slow for large datasets.",
        )

    def handle(self, *args, **options):
        feed_ids = options.get("feeds")
        batch_size = options.get("batch_size")
        dry_run = options.get("dry_run")
        refresh_dupes = options.get("refresh_dupes")
        if batch_size <= 0:
            raise ValueError("--batch-size must be greater than 0")

        # Get feeds to process
        feed_queryset = Feed.objects.all()
        if feed_ids:
            feed_queryset = feed_queryset.filter(pk__in=feed_ids)

        total_feeds = feed_queryset.count()
        self.stdout.write(self.style.SUCCESS(f"Processing {total_feeds} feed(s)"))
        self.stdout.write(f"Indexing batch size: {batch_size}")

        if dry_run:
            self.stdout.write(
                self.style.WARNING("DRY RUN MODE - No changes will be made")
            )

        # Connect to ArangoDB
        client = ArangoClient(hosts=settings.ARANGODB_HOST_URL)
        db_name = settings.ARANGODB_DATABASE + "_database"
        db = client.db(
            db_name,
            username=settings.ARANGODB_USERNAME,
            password=settings.ARANGODB_PASSWORD,
            verify=True,
        )
        self.stdout.write(self.style.SUCCESS(f"Connected to ArangoDB: {db.db_name}"))

        total_objects_indexed = 0
        failed_feeds = []
        total_feeds = feed_queryset.count()

        for i, feed in enumerate(feed_queryset):
            self.stdout.write(f"\nProcessing feed {feed.id} ({feed.name}) [{i+1}/{total_feeds}]")
            self.stdout.write(f"Collection: {feed.vertex_collection}")

            try:
                # Check if collection exists
                if not db.has_collection(feed.vertex_collection):
                    self.stdout.write(
                        self.style.WARNING(
                            f"Collection {feed.vertex_collection} does not exist, skipping"
                        )
                    )
                    continue

                if not (dry_run or refresh_dupes):
                    NewObjectValue.objects.filter(feed=feed).delete()

                if refresh_dupes:
                    self.stdout.write(
                        self.style.WARNING(
                            "Refreshing deduplication flags for all STIX IDs after indexing (can be slow)"
                        )
                    )
                    total_ov, updated_count = refresh_dupes_on_feed_batched(feed_id=str(feed.id))
                    self.stdout.write(self.style.SUCCESS("Deduplication refresh complete [{}/{} updated]".format(updated_count, total_ov)))
                    continue



                feed_objects_indexed = 0
                indexed_batches = 0
                object_batch = []

                collection_query = """
                    FOR doc IN @@collection
                        FILTER HAS(doc, \"id\")
                        FILTER HAS(doc, \"type\")
                        RETURN doc
                """

                cursor = db.aql.execute(
                    collection_query,
                    bind_vars={"@collection": feed.vertex_collection},
                    batch_size=batch_size,
                )

                for stix_object in cursor:
                    object_batch.append(stix_object)
                    if len(object_batch) < batch_size:
                        continue

                    if not dry_run:
                        save_object_values(stix_objects=object_batch, feed_id=str(feed.id))

                    feed_objects_indexed += len(object_batch)
                    indexed_batches += 1
                    self.stdout.write(
                        f"    Indexed batch {indexed_batches} ({feed_objects_indexed} objects total)"
                    )
                    object_batch = []

                if object_batch:
                    if not dry_run:
                        save_object_values(stix_objects=object_batch, feed_id=str(feed.id))
                    feed_objects_indexed += len(object_batch)
                    indexed_batches += 1

                if feed_objects_indexed == 0:
                    self.stdout.write(self.style.WARNING("    No objects found in collection"))
                    continue

                self.stdout.write(
                    self.style.SUCCESS(
                        f"Feed {feed.id} complete: {feed_objects_indexed} objects in {indexed_batches} batch(es)"
                    )
                )

                total_objects_indexed += feed_objects_indexed

            except Exception as e:
                self.stderr.write(
                    self.style.ERROR(f"Error processing feed {feed.id}: {str(e)}")
                )
                logger.exception(f"Error processing feed {feed.id}")
                failed_feeds.append(
                    {
                        "feed_id": str(feed.id),
                        "feed_name": feed.name,
                        "error": str(e),
                    }
                )
                continue

        # Summary
        self.stdout.write("\n" + "=" * 50)
        self.stdout.write(self.style.SUCCESS("SUMMARY"))
        self.stdout.write(f"Total feeds processed: {total_feeds}")
        self.stdout.write(f"Total objects indexed: {total_objects_indexed}")
        self.stdout.write(f"Failed feeds: {len(failed_feeds)}")

        if failed_feeds:
            self.stdout.write("\n" + self.style.ERROR("FAILED FEEDS:"))
            for failed in failed_feeds:
                self.stdout.write(
                    f"  - Feed: {failed['feed_id']} ({failed['feed_name']}), "
                    f"Error: {failed['error']}"
                )

        self.stdout.write("=" * 50)

        if dry_run:
            self.stdout.write(
                self.style.WARNING(
                    "\nDRY RUN COMPLETE - No changes were made to the database"
                )
            )
