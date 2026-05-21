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
    with (patch("cyberthreatexchange.worker.tasks.Job.objects.get", return_value=job), patch("cyberthreatexchange.worker.tasks.save_object_values")):
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


@pytest.fixture(scope="session")
def api_schema():
    import schemathesis
    from cyberthreatexchange.asgi import application

    yield schemathesis.openapi.from_asgi("/api/schema/?format=json", application)

@pytest.fixture
def celery_always_eager():
    from cyberthreatexchange.worker.celery import app

    app.conf.task_always_eager = True
    app.conf.broker_url = None
    yield
    app.conf.task_always_eager = False
