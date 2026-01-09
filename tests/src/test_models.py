from cyberthreatexchange.server import models


def test_create_feed_uses_name_based_uuid(identity):
    feed = models.Feed.objects.create(
        name="Test Feed",
        description="A test feed for unit tests",
        identity=identity,
        tags=["test", "sample"],
    )
    assert str(feed.id) == "71fc296d-25d2-55aa-90b3-3d61de0b29ba"

    feed2 = models.Feed.objects.create(
        name="Test Feed 2",
        description="A test feed for unit tests",
        identity_id=identity.id,
        tags=["test", "sample"],
    )
    assert str(feed2.id) == "bed845fd-1a46-509a-8440-cbb98a87e044"
