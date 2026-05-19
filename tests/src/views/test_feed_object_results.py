import random
import pytest
from rest_framework import status
from cyberthreatexchange.server import models
from tests.src.data import (
    all_objects,
    non_relationship_objects,
    relationships,
    apt29_malware,
    apt29_threat_actor,
    malicious_ip,
    mac_address,
    target_location,
    network_traffic_observation,
)
from dogesec_commons.objects.helpers import SDO_TYPES, SCO_TYPES, SMO_TYPES
from unittest.mock import patch

from tests.utils import Transport, create_identity

@pytest.fixture()
def test_feed(arango_helper, disconnect_signals):
    """Create a feed that uses the same collections as arango_helper.

    Since Feed.save() always overwrites collection_name and the post_save signal
    creates collections, we need to disable the signal and manually set collection_name.
    """

    identity = create_identity(
        id="identity--f3a5f413-0ccd-4821-9778-f4b70ecbb47f",
        name="Test Identity",
        identity_class="organization",
    )
    feed = models.Feed.objects.create(
        name="Test Feed for Objects",
        description="Feed for testing object queries",
        identity=identity,
        collection_name=arango_helper.feed.collection_name,
    )
    yield feed


class TestFeedObjectsViewList:
    """Test FeedObjectsView.list method returns all objects."""

    def test_list_returns_all_objects(self, client, test_feed, api_schema):
        """Test that list endpoint returns all objects in the feed."""
        response = client.get(f"/api/v1/feeds/{test_feed.id}/objects/")

        assert response.status_code == status.HTTP_200_OK
        assert "objects" in response.data
        assert len(response.data["objects"]) > 0
        api_schema["/api/v1/feeds/{feed_id}/objects/"]["GET"].validate_response(
            Transport.get_st_response(response)
        )

    def test_list_returns_expected_object_count(self, client, test_feed, api_schema):
        """Test that list returns the expected number of objects."""
        response = client.get(f"/api/v1/feeds/{test_feed.id}/objects/")

        assert response.status_code == status.HTTP_200_OK
        # The arango_helper fixture loads all_objects which contains 25 objects
        # (14 non-relationship objects + 11 relationships)
        assert len(response.data["objects"]) >= len(all_objects)
        api_schema["/api/v1/feeds/{feed_id}/objects/"]["GET"].validate_response(
            Transport.get_st_response(response)
        )


class TestFeedObjectsViewRetrieve:
    """Test FeedObjectsView.retrieve method."""

    def test_retrieve_returns_object_by_id(self, client, test_feed, api_schema):
        """Test that retrieve endpoint returns a single object by its STIX ID."""
        # Use the malware object from test data
        object_id = "malware--d1c612bc-146f-4b65-b7b0-9a54a14150a4"
        
        response = client.get(f"/api/v1/feeds/{test_feed.id}/objects/{object_id}/")
        
        assert response.status_code == status.HTTP_200_OK
        assert response.data["id"] == object_id
        assert response.data["type"] == "malware"
        assert response.data["name"] == "Cobalt Strike"
        api_schema["/api/v1/feeds/{feed_id}/objects/{object_id}/"]["GET"].validate_response(
            Transport.get_st_response(response)
        )

    def test_retrieve_returns_object_by_external_id(self, client, test_feed, api_schema):
        """Test that retrieve endpoint returns object using external_id."""
        # The attack pattern has external_id "T1566.001"
        external_id = "T1566.001"
        
        response = client.get(f"/api/v1/feeds/{test_feed.id}/objects/{external_id}/")
        
        assert response.status_code == status.HTTP_200_OK
        assert response.data["id"] == "attack-pattern--2e34237d-8574-43f6-aace-ae2915de8597"
        assert response.data["type"] == "attack-pattern"
        api_schema["/api/v1/feeds/{feed_id}/objects/{object_id}/"]["GET"].validate_response(
            Transport.get_st_response(response)
        )

    def test_retrieve_nonexistent_object_returns_empty(self, client, test_feed):
        """Test that retrieving a non-existent object returns empty result."""
        object_id = "malware--00000000-0000-0000-0000-000000000000"
        
        response = client.get(f"/api/v1/feeds/{test_feed.id}/objects/{object_id}/")
        
        assert response.status_code == status.HTTP_404_NOT_FOUND


    def test_retrieve_with_version_parameter(self, client, test_feed, api_schema):
        """Test that retrieve endpoint accepts version parameter."""
        object_id = "malware--d1c612bc-146f-4b65-b7b0-9a54a14150a4"
        version = "2020-01-15T10:00:00.000Z"
        
        response = client.get(
            f"/api/v1/feeds/{test_feed.id}/objects/{object_id}/?version={version}"
        )
        
        assert response.status_code == status.HTTP_200_OK
        assert response.data["id"] == object_id
        assert response.data["modified"] == version
        api_schema["/api/v1/feeds/{feed_id}/objects/{object_id}/"]["GET"].validate_response(
            Transport.get_st_response(response)
        )
