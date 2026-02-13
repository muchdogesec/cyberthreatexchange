"""
Pytest fixtures for testing.
"""

import pytest
from cyberthreatexchange.server import models, serializers
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
    from dogesec_commons.identity.serializers import IdentitySerializer
    identity_s = IdentitySerializer(
        data=dict(
            id="identity--73faab8f-9a95-4417-a2db-c1a8b73c7029",
            name="Test Identity",
            identity_class="organization",
            sectors=["technology"],
            created="2020-01-01T00:00:00.000Z",
            modified="2020-01-01T00:00:00.000Z",
        )
    )
    identity_s.is_valid(raise_exception=True)
    identity: models.Identity = identity_s.save()
    identity.refresh_from_db()
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

@pytest.fixture
def with_hidden_properties():
    """Fixture to patch ArangoDBHelper to include hidden properties in results."""
    genric_query_fn = ArangoDBHelper.generic_query
    with patch.object(ArangoDBHelper, "generic_query", autospec=True) as mock_generic_query:
        def side_effect(self, *args, **kwargs):
            # Call the original method to get the actual objects
            kwargs['return_verb'] = 'doc'
            original_objects = genric_query_fn(self, *args, **kwargs)
            return original_objects
        
        mock_generic_query.side_effect = side_effect
        yield