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
