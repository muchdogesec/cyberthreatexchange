"""
Pytest fixtures for testing.
"""

import pytest
from cyberthreatexchange.server import models
from tests.src.data import non_relationship_objects, all_objects
import time
import pytest
from unittest.mock import Mock, patch
from cyberthreatexchange.server.arango_helpers import ArangoDBHelper
from cyberthreatexchange.server import models
from cyberthreatexchange.worker.tasks import upload_bundle_task

@pytest.fixture
def identity():
    """Create a test identity (feed owner)."""
    identity = models.Identity.objects.create(
        id="identity--test-identity-123",
        name="Test Identity",
        identity_class="organization",
        sectors=["technology"],
    )

    yield identity


@pytest.fixture
def feed(identity):
    """Create a test feed."""
    feed = models.Feed.objects.create(
        name="Test Feed",
        description="A test feed for unit tests",
        identity=identity,
        tags=["test", "sample"],
        id="ec8fec0c-10d8-476f-8a51-0c71d94bbda7",
    )

    yield feed


@pytest.fixture
def job(feed):
    """Create a test job associated with a feed."""
    job = models.Job.objects.create(
        feed=feed,
        type=models.JobTypes.BUNDLE_UPLOAD,
        state=models.JobStates.PENDING,
        payload={"type": "bundle", "objects": []},
        id="16cc28a9-da88-40de-8749-7e7ac9436366",
    )

    yield job


@pytest.fixture(autouse=True)
def enable_db_access_for_all_tests(db):
    """Enable database access for all tests automatically."""
    pass


@pytest.fixture(scope="module")
def arango_helper():
    """Create an ArangoDBHelper instance with mocked database."""
    feed = Mock(spec=models.Feed)
    feed.vertex_collection = "test_vertex_collection"
    feed.edge_collection = "test_edge_collection"
    feed.collection_name = "test"
    job = Mock()
    helper = ArangoDBHelper(feed.vertex_collection, None)
    helper.feed = feed
    job.feed = feed
    feed.identity.dict = {
        "type": "identity",
        "id": "identity--f3a5f413-0ccd-4821-9778-f4b70ecbb47f",
        "name": "Test Identity",
    }
    job.payload = {"type": "bundle", "objects": all_objects}
    models.create_collection(feed)
    with patch("cyberthreatexchange.server.models.Job.objects.get", return_value=job):
        upload_bundle_task.run(job_id=job.id)
    time.sleep(3)  # Wait for the data to be committed
    yield helper

@pytest.fixture
def disconnect_signals():
    """Fixture to disconnect and reconnect model signals around a test."""
    from django.db.models.signals import post_save, post_delete
    from cyberthreatexchange.server.models import (
        auto_create_collection,
        delete_collections,
    )

    # Disconnect signals
    post_save.disconnect(auto_create_collection, sender=models.Feed)
    post_delete.disconnect(delete_collections, sender=models.Feed)

    yield

    # Reconnect signals
    post_save.connect(auto_create_collection, sender=models.Feed)
    post_delete.connect(delete_collections, sender=models.Feed)
