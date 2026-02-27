"""
Tests for views.
"""

import pytest
from unittest.mock import Mock, patch
from rest_framework import status
from rest_framework.response import Response
from cyberthreatexchange.server import views, serializers
from dogesec_commons.objects.helpers import SDO_TYPES, SCO_TYPES, SMO_TYPES


class TestJobViewGetSerializerClass:
    """Test JobView.get_serializer_class method."""

    def test_returns_job_detail_serializer_for_retrieve_action(self):
        """Test that retrieve action returns JobDetailSerializer."""
        view = views.JobView()
        view.action = "retrieve"

        serializer_class = view.get_serializer_class()

        assert serializer_class == serializers.JobDetailSerializer

    def test_returns_default_serializer_for_list_action(self):
        """Test that list action returns default JobSerializer."""
        view = views.JobView()
        view.action = "list"

        serializer_class = view.get_serializer_class()

        assert serializer_class == serializers.JobSerializer

    def test_returns_default_serializer_for_other_actions(self):
        """Test that other actions return default JobSerializer."""
        view = views.JobView()
        view.action = "create"  # Not a real action, but testing default behavior

        serializer_class = view.get_serializer_class()

        assert serializer_class == serializers.JobSerializer


class TestSearchViewList:
    """Test SearchView.list method."""

    def test_calls_arango_helper_semantic_search(self, client):
        """Test that list calls ArangoDBHelper.semantic_search."""
        with patch(
            "cyberthreatexchange.server.views.ArangoDBHelper.semantic_search"
        ) as mock_semantic_search:
            mock_semantic_search.return_value = Response({"objects": []}, status=200)

            # Execute
            response = client.get("/api/v1/search/")

            # Verify
            mock_semantic_search.assert_called_once_with()

    def test_passes_request_to_arango_helper(self, client):
        """Test that request is passed to ArangoDBHelper."""
        with patch(
            "cyberthreatexchange.server.views.ArangoDBHelper.semantic_search"
        ) as mock_semantic_search:
            mock_semantic_search.return_value = Response({"objects": []}, status=200)

            # Execute
            client.get("/api/v1/search/", {"text": "malware"})

            # Verify the semantic_search was called
            mock_semantic_search.assert_called_once_with()


class TestFeedObjectsView:
    """Test FeedObjectsView methods."""

    def test_list_calls_semantic_search(self, client, feed):
        """Test that list method calls semantic_search with feed collection."""
        with patch(
            "cyberthreatexchange.server.views.ArangoDBHelper.semantic_search"
        ) as mock_semantic_search:
            mock_semantic_search.return_value = Response({"objects": []}, status=200)

            # Execute
            response = client.get(f"/api/v1/feeds/{feed.id}/objects/")

            # Verify
            mock_semantic_search.assert_called_once_with([feed.collection_name])

    def test_sdos_filters_by_sdo_types(self, client, feed):
        """Test that sdos method filters by SDO types."""
        with patch(
            "cyberthreatexchange.server.views.ArangoDBHelper.semantic_search"
        ) as mock_semantic_search:
            mock_semantic_search.return_value = Response({"objects": []}, status=200)

            # Execute
            response = client.get(f"/api/v1/feeds/{feed.id}/objects/sdos/")

            # Verify
            mock_semantic_search.assert_called_once_with(
                [feed.collection_name], valid_types=SDO_TYPES
            )

    def test_scos_filters_by_sco_types(self, client, feed):
        """Test that scos method filters by SCO types."""
        with patch(
            "cyberthreatexchange.server.views.ArangoDBHelper.semantic_search"
        ) as mock_semantic_search:
            mock_semantic_search.return_value = Response({"objects": []}, status=200)

            # Execute
            response = client.get(f"/api/v1/feeds/{feed.id}/objects/scos/")

            # Verify
            mock_semantic_search.assert_called_once_with(
                [feed.collection_name], valid_types=SCO_TYPES
            )

    def test_smos_filters_by_smo_types(self, client, feed):
        """Test that smos method filters by SMO types."""
        with patch(
            "cyberthreatexchange.server.views.ArangoDBHelper.semantic_search"
        ) as mock_semantic_search:
            mock_semantic_search.return_value = Response({"objects": []}, status=200)

            # Execute
            response = client.get(f"/api/v1/feeds/{feed.id}/objects/smos/")

            # Verify
            mock_semantic_search.assert_called_once_with(
                [feed.collection_name], valid_types=SMO_TYPES
            )

    def test_sros_filters_by_relationship_type(self, client, feed):
        """Test that sros method filters by relationship type."""
        with patch(
            "cyberthreatexchange.server.views.ArangoDBHelper.semantic_search"
        ) as mock_semantic_search:
            mock_semantic_search.return_value = Response({"objects": []}, status=200)

            # Execute
            response = client.get(f"/api/v1/feeds/{feed.id}/objects/sros/")

            # Verify
            mock_semantic_search.assert_called_once_with(
                [feed.collection_name], valid_types=["relationship"]
            )

    def test_retrieve_gets_object_by_external_id(self, client, feed):
        """Test that retrieve method gets object by external ID."""
        with patch(
            "cyberthreatexchange.server.views.ArangoDBHelper.get_object_by_external_id"
        ) as mock_get_object:
            mock_get_object.return_value = Response(
                {"type": "malware", "id": "malware--123"}, status=200
            )

            # Execute
            response = client.get(f"/api/v1/feeds/{feed.id}/objects/malware--123/")

            # Verify
            mock_get_object.assert_called_once_with("malware--123")

    def test_destroy_returns_204_no_content(self, client, feed):
        """Test that destroy method returns 204 NO CONTENT."""
        # Execute
        response = client.delete(f"/api/v1/feeds/{feed.id}/objects/malware--123/")

        # Verify
        assert response.status_code == status.HTTP_204_NO_CONTENT

    def test_versions_gets_object_versions(self, client, feed):
        """Test that versions method gets object versions."""
        with patch(
            "cyberthreatexchange.server.views.ArangoDBHelper.get_versions"
        ) as mock_get_versions:
            mock_get_versions.return_value = Response({"versions": ["2020-01-15T10:00:00.000Z"]}, status=200)

            # Execute
            response = client.get(
                f"/api/v1/feeds/{feed.id}/objects/malware--123/versions/"
            )

            # Verify
            mock_get_versions.assert_called_once_with("malware--123")
            assert response.data == dict(versions=["2020-01-15T10:00:00.000Z"])
    def test_bundle_gets_object_with_bundle_flag(self, client, feed):
        """Test that bundle method gets object with bundle=True."""
        with patch(
            "cyberthreatexchange.server.views.ArangoDBHelper.get_object_by_external_id"
        ) as mock_get_object:
            mock_get_object.return_value = Response(
                {"type": "bundle", "objects": []}, status=200
            )

            # Execute
            response = client.get(
                f"/api/v1/feeds/{feed.id}/objects/malware--123/bundle/"
            )

            # Verify
            mock_get_object.assert_called_once_with("malware--123", bundle=True)

    def test_list_raises_404_when_feed_not_found(self, client):
        """Test that list raises 404 when feed is not found."""
        # Execute
        response = client.get(
            "/api/v1/feeds/00000000-0000-0000-0000-000000000000/objects/"
        )

        # Verify
        assert response.status_code == status.HTTP_404_NOT_FOUND

    def test_retrieve_raises_404_when_feed_not_found(self, client):
        """Test that retrieve raises 404 when feed is not found."""
        # Execute
        response = client.get(
            "/api/v1/feeds/00000000-0000-0000-0000-000000000000/objects/malware--123/"
        )

        # Verify
        assert response.status_code == status.HTTP_404_NOT_FOUND
