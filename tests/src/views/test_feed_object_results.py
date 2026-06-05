import random
import pytest
from rest_framework import status
from unittest.mock import Mock, patch
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

    def remove_auto_objects(self, objects):
        DEFAULT_OBJECT_IDS = [
            "marking-definition--72e906ce-ca1b-5d73-adcd-9ea9eb66a1b4",
            "identity--72e906ce-ca1b-5d73-adcd-9ea9eb66a1b4",
            "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
            "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
            "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
            "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
            "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed",
            "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
            "marking-definition--bab4a63c-aed9-4cf5-a766-dfca5abac2bb",
            "marking-definition--55d920b0-5e8b-4f79-9ee9-91f868d9b421",
            "marking-definition--939a9414-2ddd-4d32-a0cd-375ea402b003",
            "marking-definition--e828b379-4e03-4974-9ac4-e53a884c97c1",
        ] # objects where _stix2arango_note == "automatically imported on collection creation"
        return [
            obj
            for obj in objects
            if obj['id'] not in DEFAULT_OBJECT_IDS
        ]

    def test_list_returns_expected_object_count(self, client, test_feed, api_schema):
        """Test that list returns the expected number of objects."""
        response = client.get(f"/api/v1/feeds/{test_feed.id}/objects/")

        assert response.status_code == status.HTTP_200_OK
        objects = self.remove_auto_objects(response.data["objects"])
        # The arango_helper fixture loads all_objects which contains 25 objects
        # (14 non-relationship objects + 11 relationships)
        # subtract 1 feed_identity object
        assert {(obj['relationship_type']) for obj in objects if obj['type'] == 'relationship'}.isdisjoint(['belongs-to', 'resolves-to', 'created-by']), "must not return embedded refs"
        assert len(objects) == len(all_objects) + 1
        api_schema["/api/v1/feeds/{feed_id}/objects/"]["GET"].validate_response(
            Transport.get_st_response(response)
        )

    def test_list_returns_expected_object_count__with_refs(
        self, client, test_feed, api_schema
    ):
        """Test that list returns the expected number of objects."""
        response = client.get(
            f"/api/v1/feeds/{test_feed.id}/objects/?show_embedded_refs=true"
        )

        assert response.status_code == status.HTTP_200_OK
        objects = self.remove_auto_objects(response.data["objects"])
        # The arango_helper fixture loads all_objects which contains 25 objects
        # (14 non-relationship objects + 11 relationships) 
        # subtract 1 feed_identity object
        assert {(obj['relationship_type']) for obj in objects if obj['type'] == 'relationship'}.issuperset(['belongs-to', 'resolves-to', 'created-by']), "must return embedded refs"
        assert len(objects) > len(all_objects) + 1
        api_schema["/api/v1/feeds/{feed_id}/objects/"]["GET"].validate_response(
            Transport.get_st_response(response)
        )

    @patch("cyberthreatexchange.server.arango_helpers.ArangoDBHelper.execute_query")
    def test_list_forwards_feed_query_params(
        self, mock_execute_query, client, test_feed, api_schema
    ):
        """Test that the list endpoint forwards query params into the Arango query."""
        mock_execute_query.return_value = [
            {
                "id": "malware--1",
                "type": "malware",
                "_record_modified": "2024-01-01T10:00:00.000Z",
            },
            {
                "id": "malware--2",
                "type": "malware",
                "_record_modified": "2024-01-01T11:00:00.000Z",
            },
        ]

        response = client.get(
            f"/api/v1/feeds/{test_feed.id}/objects/"
            "?limit=2&added_after=2024-01-01T00:00:00.000Z&types=malware&show_embedded_refs=false"
        )

        assert response.status_code == status.HTTP_200_OK
        assert response.data == {
            "objects": [
                {"id": "malware--1", "type": "malware"},
                {"id": "malware--2", "type": "malware"},
            ],
            "next": "2024-01-01T11:00:00.000Z",
            "count": 2,
        }

        called_args, called_kwargs = mock_execute_query.call_args
        assert called_kwargs["bind_vars"] == {
            "@edge_collection": "test_edge_collection",
            "@vertex_collection": "test_vertex_collection",
            "types": ["malware"],
            "added_after": "2024-01-01T00:00:00.000Z",
            "is_ref_matcher": [False],
            "limit": 2,
        }
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
        api_schema["/api/v1/feeds/{feed_id}/objects/{object_id}/"][
            "GET"
        ].validate_response(Transport.get_st_response(response))

    def test_retrieve_returns_object_by_external_id(
        self, client, test_feed, api_schema
    ):
        """Test that retrieve endpoint returns object using external_id."""
        # The attack pattern has external_id "T1566.001"
        external_id = "T1566.001"

        response = client.get(f"/api/v1/feeds/{test_feed.id}/objects/{external_id}/")

        assert response.status_code == status.HTTP_200_OK
        assert (
            response.data["id"]
            == "attack-pattern--2e34237d-8574-43f6-aace-ae2915de8597"
        )
        assert response.data["type"] == "attack-pattern"
        api_schema["/api/v1/feeds/{feed_id}/objects/{object_id}/"][
            "GET"
        ].validate_response(Transport.get_st_response(response))

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
        api_schema["/api/v1/feeds/{feed_id}/objects/{object_id}/"][
            "GET"
        ].validate_response(Transport.get_st_response(response))
