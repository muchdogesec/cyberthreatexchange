"""
Tests for ArangoDBHelper methods.
"""

import time
import pytest
from unittest.mock import Mock, MagicMock, patch
from types import SimpleNamespace
from django.http import HttpRequest
from rest_framework.request import Request
from cyberthreatexchange.server.arango_helpers import ArangoDBHelper
from cyberthreatexchange.server import models
from cyberthreatexchange.worker.tasks import upload_bundle_task
from tests.src.data import (
    apt29_malware,
    apt29_threat_actor,
    spearphishing_attack,
    victim_organization,
    network_indicator,
    apt29_campaign,
    non_relationship_objects,
    all_objects,
)


def make_mock_request(**queries):
    """Create a mock request object with query parameters."""
    r = Request(HttpRequest())
    r.query_params.update(queries)
    return r


@pytest.fixture
def mock_db():
    """Create a mock ArangoDB database."""
    db = Mock()
    db.aql = Mock()
    return db


class TestArangoDBHelperInit:
    """Test ArangoDBHelper initialization."""

    def test_init_with_collection_and_request(self):
        """Test basic initialization."""
        helper = ArangoDBHelper("test_collection", make_mock_request())
        assert helper.collection == "test_collection"
        assert helper.container == "objects"

    def test_init_with_custom_container(self):
        """Test initialization with custom container."""
        helper = ArangoDBHelper(
            "test_collection", make_mock_request(), container="custom"
        )
        assert helper.container == "custom"


class TestGetObjectByExternalId:
    """Test get_object_by_external_id method."""

    def test_get_object_by_external_id_basic(self, arango_helper):
        """Test retrieving object by external ID."""
        arango_helper.query = {}
        arango_helper.page = 3
        arango_helper.page_size = 3

        response = arango_helper.get_object_by_external_id("T1566.001")

        assert response.status_code == 200
        assert {d["id"] for d in response.data["objects"]} == {
            "attack-pattern--2e34237d-8574-43f6-aace-ae2915de8597"
        }

    @pytest.mark.parametrize(
        "version,has_result",
        [
            (None, True),
            ("2020-01-15T10:00:00.000Z", True),
            ("1999-12-31T23:59:59.000Z", False),
        ],
    )
    def test_get_object_by_external_id_with_version(
        self, arango_helper, version, has_result
    ):
        """Test retrieving specific version by external ID."""
        arango_helper.query = {"version": version} if version else {}
        arango_helper.page = 1
        arango_helper.page_size = 10

        response = arango_helper.get_object_by_external_id("T1566.001")
        assert response.status_code == 200
        if has_result:
            assert len(response.data["objects"]) == 1
            assert (
                response.data["objects"][0]["id"]
                == "attack-pattern--2e34237d-8574-43f6-aace-ae2915de8597"
            )
        else:
            assert len(response.data["objects"]) == 0


class TestGetVersions:
    """Test get_versions method."""

    def test_get_versions_returns_list(self, arango_helper):

        response = arango_helper.get_versions(
            "malware--d1c612bc-146f-4b65-b7b0-9a54a14150a4"
        )

        assert response.status_code == 200
        assert response.data == ["2020-01-15T10:00:00.000Z"]


class TestGetExistingObjects:
    """Test get_existing_objects method."""

    def test_get_existing_objects(self, arango_helper):
        """Test retrieving existing objects from database."""
        object_ids = [
            "attack-pattern--2e34237d-8574-43f6-aace-ae2915de8597",
            "threat-actor--899ce53f-13a0-479b-a0e4-67d46e241542",
        ]

        result = arango_helper.get_existing_objects(arango_helper.feed, object_ids)
        assert result == {
            "attack-pattern--2e34237d-8574-43f6-aace-ae2915de8597": {
                "_record_md5_hash": "0e7b5d67ff6bd15fda4051db175b004c",
                "created": "2020-01-15T10:00:00.000Z",
                "id": "attack-pattern--2e34237d-8574-43f6-aace-ae2915de8597",
                "modified": "2020-01-15T10:00:00.000Z",
            },
            "threat-actor--899ce53f-13a0-479b-a0e4-67d46e241542": {
                "_record_md5_hash": "dcf7e241bc3a6aa7e4344be1e83c05c7",
                "created": "2020-01-15T10:00:00.000Z",
                "id": "threat-actor--899ce53f-13a0-479b-a0e4-67d46e241542",
                "modified": "2020-01-15T10:00:00.000Z",
            },
        }


# Integration-style tests that upload real data
class TestArangoDBHelperWithRealData:

    def test_get_object_by_external_id(self, arango_helper):
        """Test retrieving object by external ID after upload."""
        feed = arango_helper.feed

        helper = ArangoDBHelper(feed.vertex_collection, None)
        response = helper.get_object_by_external_id("T1566.001")
        assert response.status_code == 200
        assert (
            response.data["objects"][0]["id"]
            == "attack-pattern--2e34237d-8574-43f6-aace-ae2915de8597"
        )

    def test_get_bundle(self, arango_helper):
        """Test bundle generation with uploaded data."""
        feed = arango_helper.feed

        helper = ArangoDBHelper(feed.vertex_collection, None)

        # Get bundle for the malware object
        bundle = helper.get_object_by_external_id(
            "malware--d1c612bc-146f-4b65-b7b0-9a54a14150a4", bundle=True
        ).data
        assert {k["id"] for k in bundle["objects"]}.issuperset(
            [
                "campaign--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
                "indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
                "infrastructure--3f9b5f3c-5c3a-4f5d-9e5e-3c3c3c3c3c3c",
                "malware--d1c612bc-146f-4b65-b7b0-9a54a14150a4",
                "relationship--a1b2c3d4-e5f6-4a5b-8c9d-0e1f2a3b4c5d",
                "relationship--a7b8c9d0-e1f2-4a1b-8c5d-6e7f8a9b0c1d",
                "relationship--b8c9d0e1-f2a3-4b2c-9d6e-7f8a9b0c1d2e",
                "relationship--f6a7b8c9-d0e1-4f0a-bb4c-5d6e7f8a9b0c",
                "threat-actor--899ce53f-13a0-479b-a0e4-67d46e241542",
            ]
        )

    @pytest.mark.parametrize(
        "params,expected_ids",
        [
            (
                {},
                {
                    "autonomous-system--f91b6a7a-2e9c-4e5e-8e5e-5e5e5e5e5e5e",
                    "ipv4-addr--ff26c055-6336-4bc6-b60e-6d2c7e6d5e5e",
                    "mac-addr--a8b2c3d4-e5f6-4a5b-8c7d-9e8f7a6b5c4d",
                    "relationship--d0e1f2a3-b4c5-4d4e-bf8a-9b0c1d2e3f4a",
                    "relationship--c3d4e5f6-a7b8-4c7d-8e1f-2a3b4c5d6e7f",
                    "location--a6e9345f-5a54-4825-8b7e-9f4e5e5e5e5e",
                    "attack-pattern--2e34237d-8574-43f6-aace-ae2915de8597",
                    "campaign--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
                    "marking-definition--55d920b0-5e8b-4f79-9ee9-91f868d9b421",
                    "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
                    "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
                    "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
                    "identity--72e906ce-ca1b-5d73-adcd-9ea9eb66a1b4",
                    "relationship--a7b8c9d0-e1f2-4a1b-8c5d-6e7f8a9b0c1d",
                    "relationship--e5f6a7b8-c9d0-4e9f-aa3b-4c5d6e7f8a9b",
                    "marking-definition--72e906ce-ca1b-5d73-adcd-9ea9eb66a1b4",
                    "relationship--a1b2c3d4-e5f6-4a5b-8c9d-0e1f2a3b4c5d",
                    "marking-definition--939a9414-2ddd-4d32-a0cd-375ea402b003",
                    "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
                    "tool--242f3da3-4425-4d11-8f5c-b842886da966",
                    "identity--f3a5f413-0ccd-4821-9778-f4b70ecbb47f",
                    "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
                    "relationship--f6a7b8c9-d0e1-4f0a-bb4c-5d6e7f8a9b0c",
                    "relationship--bbc10a4e-90a0-5a52-b6d1-8d8276394572",
                    "marking-definition--bab4a63c-aed9-4cf5-a766-dfca5abac2bb",
                    "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
                    "malware--d1c612bc-146f-4b65-b7b0-9a54a14150a4",
                    "relationship--e1f2a3b4-c5d6-4e5f-8a9b-0c1d2e3f4a5b",
                    "relationship--b2c3d4e5-f6a7-4b6c-9d0e-1f2a3b4c5d6e",
                    "marking-definition--e828b379-4e03-4974-9ac4-e53a884c97c1",
                    "relationship--67c37025-76ec-52ad-8098-48d8f3fbdd9b",
                    "relationship--b8c9d0e1-f2a3-4b2c-9d6e-7f8a9b0c1d2e",
                    "relationship--d4e5f6a7-b8c9-4d8e-9f2a-3b4c5d6e7f8a",
                    "indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
                    "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed",
                    "relationship--c9d0e1f2-a3b4-4c3d-ae7f-8a9b0c1d2e3f",
                },
            ),
            ({"types": "campaign"}, ["campaign--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f"]),
            (
                {"types": "indicator"},
                ["indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f"],
            ),
            (
                {"text": "APT29"},
                [
                    "malware--d1c612bc-146f-4b65-b7b0-9a54a14150a4",
                    "campaign--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
                    "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
                ],
            ),
            (
                {"name": "Cobalt Strike"},
                [
                    "malware--d1c612bc-146f-4b65-b7b0-9a54a14150a4",
                    "indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
                ],
            ),
            (
                {
                    "stix_ids": "relationship--a1b2c3d4-e5f6-4a5b-8c9d-0e1f2a3b4c5d,malware--d1c612bc-146f-4b65-b7b0-9a54a14150a4,indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f"
                },
                [
                    "malware--d1c612bc-146f-4b65-b7b0-9a54a14150a4",
                    "indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
                    "relationship--a1b2c3d4-e5f6-4a5b-8c9d-0e1f2a3b4c5d",
                ],
            ),
        ],
    )
    def test_semantic_search_params(self, arango_helper, params, expected_ids):
        """Test semantic search on uploaded data."""
        request = make_mock_request(**(params or {}))
        feed = arango_helper.feed

        helper = ArangoDBHelper(feed.vertex_collection, request)
        response = helper.semantic_search(collections=[feed.collection_name])
        objects = response.data.get("objects", [])
        print({obj["id"] for obj in objects})
        assert {obj["id"] for obj in objects} == set(expected_ids)
