"""
Management command to remove all ObjectValues and truncate ArangoDB collections for specified feeds.

This command deletes database records and ArangoDB collections for one or more feeds.
WARNING: This is a destructive operation and cannot be undone.

Usage:
    python manage.py remove_feed_data --feeds <uuid1> <uuid2> ...
    python manage.py remove_feed_data --feeds <uuid> --dry-run
"""

import logging
from django.core.management.base import BaseCommand

from cyberthreatexchange.server.arango_helpers import ArangoDBHelper
from cyberthreatexchange.server.models import Feed, NewObjectValue


logger = logging.getLogger(__name__)


def validate_feed_id(value):
    """Validate that feed ID exists."""
    if value == 'all':
        return value
    Feed.objects.get(pk=value)  # Will raise DoesNotExist if invalid
    return value

def all_feeds():
    return [f.id for f in Feed.objects.all()]


class Command(BaseCommand):
    help = "Remove all ObjectValues and truncate ArangoDB collections for specified feeds"

    def add_arguments(self, parser):
        mxe = parser.add_mutually_exclusive_group(required=True)
        mxe.add_argument(
            "--feeds",
            type=validate_feed_id,
            nargs="+",
            help="Feed UUIDs to remove data from (space-separated)",
        )
        mxe.add_argument(
            "--all",
            dest='feeds',
            action='store',
            const=all_feeds(),
            nargs='?',
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Show what would be removed without actually deleting data",
        )

    def _get_collection_count(self, helper, collection_name):
        """Get count of documents in collection, return 0 if collection doesn't exist."""
        if not helper.db.has_collection(collection_name):
            return 0
        return helper.db.collection(collection_name).count()

    def _delete_django_records(self, feed, dry_run):
        """Delete ObjectValues for a feed."""
        ov_count = NewObjectValue.objects.filter(feed=feed).count()
        
        self.stdout.write(f"  ObjectValues to delete: {ov_count}")
        
        if dry_run:
            self.stdout.write(
                self.style.WARNING(f"  [DRY RUN] Would delete {ov_count} ObjectValues")
            )
            return 0, 0
        
        deleted_ov = NewObjectValue.objects.filter(feed=feed).delete()[0]
        self.stdout.write(
            self.style.SUCCESS(f"  Deleted {deleted_ov} ObjectValues")
        )
        return deleted_ov

    def _truncate_collection(self, helper, collection_name, doc_count, dry_run):
        """Truncate a single ArangoDB collection."""
        exists = helper.db.has_collection(collection_name)
        self.stdout.write(f"  {collection_name}: (exists: {exists}, documents: {doc_count})")
        
        if not exists:
            self.stdout.write(self.style.WARNING(f"    Collection does not exist, skipping"))
            return 0, 0
        
        if dry_run:
            self.stdout.write(
                self.style.WARNING(f"    [DRY RUN] Would truncate ({doc_count} documents)")
            )
            return 0, 0
        
        helper.db.collection(collection_name).truncate()
        self.stdout.write(self.style.SUCCESS(f"    Truncated ({doc_count} documents)"))
        return 1, doc_count

    def handle(self, *args, **options):
        feed_ids = options.get("feeds")
        dry_run = options.get("dry_run")

        if not feed_ids:
            self.stderr.write(self.style.ERROR("Error: --feeds argument is required"))
            return

        # Get feeds to process
        feeds = Feed.objects.filter(pk__in=feed_ids)
        total_feeds = feeds.count()

        if total_feeds == 0:
            self.stderr.write(self.style.ERROR("No valid feeds found"))
            return

        if total_feeds != len(feed_ids):
            self.stdout.write(
                self.style.WARNING(
                    f"Warning: {len(feed_ids)} feed IDs provided, but only {total_feeds} valid feeds found"
                )
            )

        self.stdout.write(self.style.WARNING(f"Processing {total_feeds} feed(s)"))

        if dry_run:
            self.stdout.write(
                self.style.WARNING("DRY RUN MODE - No changes will be made")
            )

        # Connect to ArangoDB
        helper = ArangoDBHelper(None, None)
        self.stdout.write(self.style.SUCCESS(f"Connected to ArangoDB: {helper.db.db_name}"))

        total_objectvalues_deleted = 0
        total_objectversions_deleted = 0
        total_collections_truncated = 0
        total_arango_documents_removed = 0
        failed_feeds = []

        for i, feed in enumerate(feeds):
            self.stdout.write(
                f"\n{'='*60}\nProcessing feed {i+1}/{total_feeds}: {feed.id} ({feed.name})"
            )

            try:
                # Count ArangoDB documents before deletion
                vertex_count = self._get_collection_count(helper, feed.vertex_collection)
                edge_count = self._get_collection_count(helper, feed.edge_collection)
                self.stdout.write(f"  Vertex objects in ArangoDB: {vertex_count}")
                self.stdout.write(f"  Edge objects in ArangoDB: {edge_count}")

                # Delete Django records
                deleted_ov = self._delete_django_records(feed, dry_run)
                total_objectvalues_deleted += deleted_ov

                # Truncate ArangoDB collections
                vertex_truncated, vertex_docs = self._truncate_collection(
                    helper, feed.vertex_collection, vertex_count, dry_run
                )
                edge_truncated, edge_docs = self._truncate_collection(
                    helper, feed.edge_collection, edge_count, dry_run
                )
                
                collections_truncated = vertex_truncated + edge_truncated
                arango_docs_removed = vertex_docs + edge_docs
                
                total_collections_truncated += collections_truncated
                total_arango_documents_removed += arango_docs_removed

                if not dry_run:
                    self.stdout.write(
                        self.style.SUCCESS(
                            f"✓ Feed {feed.id} complete - {collections_truncated} collection(s) truncated, {arango_docs_removed} documents removed"
                        )
                    )

            except Exception as e:
                self.stderr.write(
                    self.style.ERROR(f"✗ Error processing feed {feed.id}: {str(e)}")
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
        self.stdout.write("\n" + "=" * 60)
        self.stdout.write(self.style.SUCCESS("SUMMARY"))
        self.stdout.write("=" * 60)
        self.stdout.write(f"Total feeds processed: {total_feeds}")
        
        summary_style = self.style.WARNING if dry_run else self.style.SUCCESS
        prefix = "[DRY RUN] Would have deleted" if dry_run else "Deleted"
        
        self.stdout.write(f"Truncated: {total_collections_truncated} ArangoDB collections, {total_arango_documents_removed} documents")
        self.stdout.write(f"Failed feeds: {len(failed_feeds)}")

        if failed_feeds:
            self.stdout.write("\n" + self.style.ERROR("FAILED FEEDS:"))
            for failed in failed_feeds:
                self.stdout.write(f"  - {failed['feed_id']} ({failed['feed_name']}): {failed['error']}")

        if not dry_run and not failed_feeds:
            self.stdout.write("\n" + self.style.SUCCESS("All feed data removed successfully!"))

