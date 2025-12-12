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

@pytest.fixture()
def test_feed(arango_helper, disconnect_signals):
    """Create a feed that uses the same collections as arango_helper.

    Since Feed.save() always overwrites collection_name and the post_save signal
    creates collections, we need to disable the signal and manually set collection_name.
    """

    identity = models.Identity.objects.create(
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

    def test_list_returns_all_objects(self, client, test_feed):
        """Test that list endpoint returns all objects in the feed."""
        response = client.get(f"/api/v1/feeds/{test_feed.id}/objects/")

        assert response.status_code == status.HTTP_200_OK
        assert "objects" in response.data
        assert len(response.data["objects"]) > 0

    def test_list_returns_expected_object_count(self, client, test_feed):
        """Test that list returns the expected number of objects."""
        response = client.get(f"/api/v1/feeds/{test_feed.id}/objects/")

        assert response.status_code == status.HTTP_200_OK
        # The arango_helper fixture loads all_objects which contains 25 objects
        # (14 non-relationship objects + 11 relationships)
        assert len(response.data["objects"]) >= len(all_objects)


class TestFeedObjectsViewSDOs:
    """Test FeedObjectsView.sdos method returns only SDOs."""

    def test_sdos_includes_expected_types(self, client, test_feed):
        """Test that sdos endpoint includes expected SDO types from test data."""
        response = client.get(f"/api/v1/feeds/{test_feed.id}/objects/sdos/")

        assert response.status_code == status.HTTP_200_OK

        returned_types = {obj["type"] for obj in response.data["objects"]}

        # Test data includes these SDO types
        expected_sdo_types = {
            "malware",
            "threat-actor",
            "attack-pattern",
            "identity",
            "indicator",
            "campaign",
            "infrastructure",
            "tool",
            "vulnerability",
        }

        # Verify expected types are present
        assert expected_sdo_types.issubset(
            returned_types
        ), f"Missing SDO types: {expected_sdo_types - returned_types}"


    def test_sdos_objects_match_expected_data(self, client, test_feed):
        """Test that specific SDO objects match expected test data."""
        response = client.get(f"/api/v1/feeds/{test_feed.id}/objects/sdos/")

        assert response.status_code == status.HTTP_200_OK

        # Create lookup by ID
        objects_by_id = {obj["id"]: obj for obj in response.data["objects"]}

        # Verify specific test objects are present with correct data
        assert apt29_malware["id"] in objects_by_id
        malware_obj = objects_by_id[apt29_malware["id"]]
        assert malware_obj["name"] == "Cobalt Strike"
        assert malware_obj["type"] == "malware"

        assert apt29_threat_actor["id"] in objects_by_id
        threat_actor_obj = objects_by_id[apt29_threat_actor["id"]]
        assert threat_actor_obj["name"] == "APT29"
        assert threat_actor_obj["type"] == "threat-actor"


class TestFeedObjectsViewSCOs:

    def test_scos_includes_expected_types(self, client, test_feed):
        """Test that scos endpoint includes expected SCO types from test data."""
        response = client.get(f"/api/v1/feeds/{test_feed.id}/objects/scos/")

        assert response.status_code == status.HTTP_200_OK

        returned_types = {obj["type"] for obj in response.data["objects"]}

        # Test data includes these SCO types
        expected_sco_types = {
            "ipv4-addr",
            "mac-addr",
            "autonomous-system",
        }

        # Verify expected types are present
        assert expected_sco_types.issubset(
            returned_types
        ), f"Missing SCO types: {expected_sco_types - returned_types}"


    def test_scos_objects_match_expected_data(self, client, test_feed):
        response = client.get(f"/api/v1/feeds/{test_feed.id}/objects/scos/")

        assert response.status_code == status.HTTP_200_OK

        # Create lookup by ID
        objects_by_id = {obj["id"]: obj for obj in response.data["objects"]}

        # Verify specific test objects are present with correct data
        assert malicious_ip["id"] in objects_by_id
        ip_obj = objects_by_id[malicious_ip["id"]]
        assert ip_obj["value"] == "198.51.100.42"
        assert ip_obj["type"] == "ipv4-addr"

        assert mac_address["id"] in objects_by_id
        mac_obj = objects_by_id[mac_address["id"]]
        assert mac_obj["value"] == "00:1a:2b:3c:4d:5e"
        assert mac_obj["type"] == "mac-addr"


class TestFeedObjectsViewSMOs:
    """Test FeedObjectsView.smos method returns only SMOs."""

    def test_smos_returns_only_smo_types(self, client, test_feed):
        """Test that smos endpoint returns only STIX Meta Objects."""
        response = client.get(f"/api/v1/feeds/{test_feed.id}/objects/smos/")

        assert response.status_code == status.HTTP_200_OK
        assert "objects" in response.data
        assert len(response.data["objects"]) > 0

        # Verify all returned objects are SMOs
        for obj in response.data["objects"]:
            assert (
                obj["type"] in SMO_TYPES
            ), f"Object type {obj['type']} is not in SMO_TYPES"


class TestFeedObjectsViewSROs:

    def test_sros_excludes_non_sro_types(self, client, test_feed):
        """Test that sros endpoint excludes SDOs, SCOs, and SMOs."""
        response = client.get(f"/api/v1/feeds/{test_feed.id}/objects/sros/")

        assert response.status_code == status.HTTP_200_OK

        returned_types = {obj["type"] for obj in response.data["objects"]}

        # Should only contain relationship (and potentially sighting)
        assert returned_types.issubset({"relationship", "sighting"})

    def test_sros_count_matches_test_data(self, client, test_feed):
        """Test that the number of relationships matches test data."""
        response = client.get(f"/api/v1/feeds/{test_feed.id}/objects/sros/")

        assert response.status_code == status.HTTP_200_OK
        embedded = []
        real_rels = []
        for obj in response.data["objects"]:
            is_embedded = any(
                [
                    x.get("description") == "embedded-relationship"
                    for x in obj.get("external_references", [])
                ]
            )

            if is_embedded:
                embedded.append(obj)
            else:
                real_rels.append(obj)

        # Test data has 11 relationship objects
        assert len(response.data["objects"]) == 11 + len(embedded)


class TestFeedObjectsViewTypeFiltering:
    """Test that type filtering works correctly across all endpoints."""

    def test_no_overlap_between_sdo_and_sco(self, client, test_feed):
        """Test that SDOs and SCOs don't overlap."""
        sdo_response = client.get(f"/api/v1/feeds/{test_feed.id}/objects/sdos/")
        sco_response = client.get(f"/api/v1/feeds/{test_feed.id}/objects/scos/")

        assert sdo_response.status_code == status.HTTP_200_OK
        assert sco_response.status_code == status.HTTP_200_OK

        sdo_ids = {obj["id"] for obj in sdo_response.data["objects"]}
        sco_ids = {obj["id"] for obj in sco_response.data["objects"]}

        # No overlap between SDOs and SCOs
        assert len(sdo_ids & sco_ids) == 0

    def test_no_overlap_between_sdo_and_sro(self, client, test_feed):
        """Test that SDOs and SROs don't overlap."""
        sdo_response = client.get(f"/api/v1/feeds/{test_feed.id}/objects/sdos/")
        sro_response = client.get(f"/api/v1/feeds/{test_feed.id}/objects/sros/")

        assert sdo_response.status_code == status.HTTP_200_OK
        assert sro_response.status_code == status.HTTP_200_OK

        sdo_ids = {obj["id"] for obj in sdo_response.data["objects"]}
        sro_ids = {obj["id"] for obj in sro_response.data["objects"]}

        # No overlap between SDOs and SROs
        assert len(sdo_ids & sro_ids) == 0

    def test_all_endpoints_return_valid_objects(self, client, test_feed):
        """Test that all endpoints return valid STIX objects."""
        endpoints = [
            f"/api/v1/feeds/{test_feed.id}/objects/",
            f"/api/v1/feeds/{test_feed.id}/objects/sdos/",
            f"/api/v1/feeds/{test_feed.id}/objects/scos/",
            f"/api/v1/feeds/{test_feed.id}/objects/smos/",
            f"/api/v1/feeds/{test_feed.id}/objects/sros/",
        ]

        for endpoint in endpoints:
            response = client.get(endpoint)
            assert response.status_code == status.HTTP_200_OK
            assert "objects" in response.data
            assert len(response.data["objects"]) > 0
