from cyberthreatexchange.server import models


def test_create_feed_uses_name_based_uuid(identity):
    feed = models.Feed.objects.create(
        name="Test Feed",
        description="A test feed for unit tests",
        identity=identity,
        tags=["test", "sample"],
    )
    # "Test Feed+identity--73faab8f-9a95-4417-a2db-c1a8b73c7029"
    assert str(feed.id) == "71fc296d-25d2-55aa-90b3-3d61de0b29ba"

    feed2 = models.Feed.objects.create(
        name="Test Feed 2",
        description="A test feed for unit tests",
        identity_id=identity.id,
        tags=["test", "sample"],
    )
    # "Test Feed 2+identity--73faab8f-9a95-4417-a2db-c1a8b73c7029"
    assert str(feed2.id) == "bed845fd-1a46-509a-8440-cbb98a87e044"

    identity2 = models.Identity.objects.create(
        id="identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
        stix={"name": "Identity for Feed Tests", "identity_class": "organization", "type": "identity"},
    )
    feed3 = models.Feed.objects.create(
        name="My basic feed",
        description="A test feed for unit tests",
        identity=identity2,
        tags=["test", "sample"],
    )
    # "My basic feed+identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5"
    assert str(feed3.id) == "2902eb6f-aa38-5e50-b56d-c85ebfb1e377"


import pytest
import uuid
import random
from datetime import UTC, timedelta, datetime
from django.utils import timezone



def random_values():
    return {
        "field": random.randint(1, 1000),
        "nested": {"name": str(uuid.uuid4())}
    }


@pytest.fixture
def feeds_with_object_values(db, identity):
    """
    Creates:
    - 3 feeds
    - 5 shared stix_ids across feeds
    - Each feed has one record per stix_id
    - Modified timestamps staggered so "latest" is deterministic

    Returns:
        {
            "feeds": [feed1, feed2, feed3],
            "delete_feed": feed1,
            "stix_ids": [...]
        }
    """

    now = timezone.now()

    # Create feeds
    feed2 = models.Feed.objects.create(name="feed2", identity_id=identity.id)
    feed1 = models.Feed.objects.create(name="feed1", identity_id=identity.id)
    feed3 = models.Feed.objects.create(name="feed3", identity_id=identity.id)

    feeds = [feed1, feed2, feed3]

    # Shared STIX IDs across all feeds
    stix_ids = [f"indicator--{uuid.uuid4()}" for _ in range(5)]

    objects = []

    for i, stix_id in enumerate(stix_ids):
        # Create 3 versions (one per feed) with different modified times
        # Ensure feed1 is NOT always the latest (so deletion matters)
        base_time = datetime(2021, 1, 1, tzinfo=UTC)

        objs = [
            models.NewObjectValue(
                feed=feed1,
                stix_id=stix_id,
                type='file',
                modified=base_time,
                created=base_time,
                values=random_values(),
                is_dupe=False,
            ),
            models.NewObjectValue(
                feed=feed2,
                stix_id=stix_id,
                type='file',
                modified=base_time + timedelta(hours=1),
                created=base_time,
                values=random_values(),
                is_dupe=False,
            ),
            models.NewObjectValue(
                feed=feed3,
                stix_id=stix_id,
                type='file',
                modified=base_time + timedelta(hours=2),
                created=base_time,
                values=random_values(),
                is_dupe=False,
            ),
        ]

        objects.extend(objs)

    models.NewObjectValue.objects.bulk_create(objects)

    models._refresh_stix_dedupe_state([x.stix_id for x in objects])

    return {
        "feeds": [feed for feed in models.Feed.objects.all()],
        "stix_ids": stix_ids,
    }

def test_ov__values(feeds_with_object_values, monkeypatch):
    assert models.NewObjectValue.objects.count() == 15
    feed_to_remove = feeds_with_object_values["feeds"][2]
    feed_to_remove.refresh_from_db()

    assert models.NewObjectValue.objects.filter(is_dupe=False).count() == len(set(feeds_with_object_values["stix_ids"]))
    assert models.NewObjectValue.objects.filter(is_dupe=True, feed_id=feed_to_remove.id).count() == 0
    monkeypatch.setenv('DEBUG_SQL', '2')
    feed_to_remove.delete()
    assert models.NewObjectValue.objects.count() == 10
    assert models.NewObjectValue.objects.filter(is_dupe=False).count() == 5
    assert models.NewObjectValue.objects.filter(is_dupe=True).count() == 5