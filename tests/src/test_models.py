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
