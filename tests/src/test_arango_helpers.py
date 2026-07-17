"""
Tests for ArangoDBHelper methods.
"""

import time
import pytest
from unittest.mock import Mock, MagicMock, patch
from types import SimpleNamespace
from django.http import HttpRequest
from rest_framework.request import Request
from cyberthreatexchange.server.arango_helpers import (
    ArangoDBHelper,
    decode_bundle_cursor,
    encode_bundle_cursor,
    make_bundle_query,
    make_objects_query,
)
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
        assert response.data["id"] == "attack-pattern--2e34237d-8574-43f6-aace-ae2915de8597"

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
        try:
            response = arango_helper.get_object_by_external_id("T1566.001")
            assert response.status_code == 200
            assert response.data["id"] == "attack-pattern--2e34237d-8574-43f6-aace-ae2915de8597"
        except Exception as exc:
            assert "not_found" in str(exc), f"Expected no result for version {version} but got a different error: {exc}"
            assert not has_result, f"Expected no result for version {version} but got an error instead."


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


class TestGetObjects:
    """Test feed object listing queries."""

    def test_make_objects_query_uses_feed_collections(self):
        feed = SimpleNamespace(
            vertex_collection="ctx_test_vertex_collection",
            edge_collection="ctx_test_edge_collection",
        )

        query, binds = make_objects_query(
            feed,
            types=["malware"],
            added_after="2024-01-01T00:00:00.000Z",
            limit=25,
            show_embedded_refs=False,
        )

        assert "@@vertex_collection" in query
        assert "@@edge_collection" in query
        assert "edge._record_modified > @added_after" in query
        assert "vertex._record_modified > @added_after" in query
        assert binds == {
            "@edge_collection": "ctx_test_edge_collection",
            "@vertex_collection": "ctx_test_vertex_collection",
            "types": ["malware"],
            "added_after": "2024-01-01T00:00:00.000Z",
            "is_ref_matcher": [False],
            "limit": 25,
        }

    def test_get_objects_returns_next_cursor_and_strips_record_modified(self, arango_helper):
        feed = arango_helper.feed
        arango_helper.query = {
            "limit": "2",
            "added_after": "2024-01-01T00:00:00.000Z",
        }
        arango_helper.query_as_array = Mock(return_value=["malware"])
        arango_helper.query_as_bool = Mock(return_value=False)
        arango_helper.execute_query = Mock(
            return_value=[
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
        )

        response = arango_helper.get_objects(feed)

        assert response.status_code == 200
        assert response.data == {
            "objects": [
                {"id": "malware--1", "type": "malware"},
                {"id": "malware--2", "type": "malware"},
            ],
            "next": "2024-01-01T11:00:00.000Z",
            "size": 2,
        }
        assert arango_helper.execute_query.call_count == 1
        called_query, called_kwargs = arango_helper.execute_query.call_args
        assert "@@vertex_collection" in called_query[0]
        assert "@@edge_collection" in called_query[0]
        assert called_kwargs["paginate"] is False
        assert called_kwargs["bind_vars"]["limit"] == 2
        assert called_kwargs["bind_vars"]["types"] == ["malware"]


# Integration-style tests that upload real data
class TestArangoDBHelperWithRealData:

    def test_get_object_by_external_id(self, arango_helper):
        """Test retrieving object by external ID after upload."""
        feed = arango_helper.feed

        helper = ArangoDBHelper(feed.vertex_collection, None)
        response = helper.get_object_by_external_id("T1566.001")
        assert response.status_code == 200
        assert (
            response.data["id"]
            == "attack-pattern--2e34237d-8574-43f6-aace-ae2915de8597"
        )

    def test_get_bundle(self, arango_helper):
        """Test bundle generation with uploaded data."""
        feed = arango_helper.feed

        helper = ArangoDBHelper(feed.vertex_collection, None)

        # Get bundle for the malware object
        bundle = helper.get_bundle(
            "malware--d1c612bc-146f-4b65-b7b0-9a54a14150a4", feed
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

    def test_bundle_cursor_round_trip(self):
        """Test the packed bundle cursor can be encoded and decoded."""
        cursor = encode_bundle_cursor(
            {
                "k1": "2024-01-01T00:00:00.000Z",
                "kid": "edge--1",
                "k2": "2024-01-02T00:00:00.000Z",
                "index": 7,
            }
        )
        assert isinstance(cursor, str)
        assert decode_bundle_cursor(cursor) == {
            "k1": "2024-01-01T00:00:00.000Z",
            "kid": "edge--1",
            "k2": "2024-01-02T00:00:00.000Z",
            "index": 7,
        }

    def test_make_bundle_query_uses_feed_edge_collection(self):
        """Test bundle query binds the feed edge collection dynamically."""
        query, binds = make_bundle_query(
            "object--1",
            edge_collection="ctx_test_edge_collection",
        )
        assert binds["@edgeCollection"] == "ctx_test_edge_collection"

    def test_get_bundle2_uses_encoded_cursor_and_parameters(self, arango_helper):
        """Test bundle2 returns an encoded cursor and forwards query parameters."""
        feed = arango_helper.feed
        helper = ArangoDBHelper(
            feed.vertex_collection,
            make_mock_request(
                limit="2",
                cursor=encode_bundle_cursor({"k1": "2024-01-01T00:00:00.000Z", "kid": "edge--x", "k2": None}),
                secondary_relations="true",
                types="campaign",
                secondary_types="indicator",
            ),
        )
        helper.query_as_bool = Mock(
            side_effect=lambda key, default=False: {"secondary_relations": True}.get(
                key, default
            )
        )
        helper.query_as_array = Mock(
            side_effect=lambda key: {
                "types": ["campaign"],
                "secondary_types": ["indicator"],
            }.get(key)
        )
        helper.execute_query = Mock(
            return_value=[
                {
                    "level1Edges": [
                        ["2024-01-01T00:00:00.000Z", "edge-1", "vertex-a"],
                        ["2024-01-02T00:00:00.000Z", "edge-2", "vertex-b"],
                    ],
                    "level2Edges": [],
                    "objects": [
                        ("edge-1", {"id": "edge-2"}),
                        ("vertex-a", {"id": "vertex-a"}),
                        ("edge-N", {"id": "not there"}),
                        ("edge-2", {"id": "edge-2"}),
                        ("vertex-b", {"id": "vertex-b"}),
                    ]
                }
            ]
        )

        response = helper.get_bundle("vertex-a", feed)
        assert response.status_code == 200
        assert response.data["objects"] == [{'id': 'vertex-a'}, {'id': 'edge-2'}, {'id': 'vertex-b'}, {'id': 'edge-2'}]
        assert response.data["size"] == 4
        
