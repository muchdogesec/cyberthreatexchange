"""
Tests for ObjectFeedsView endpoint (/api/v1/search/<object_id>/feeds/)
"""

import pytest
from rest_framework import status
from cyberthreatexchange.server.models import Feed, NewObjectValue
from cyberthreatexchange.server.views import SearchView
from tests.utils import Transport
from django.utils import timezone


@pytest.fixture
def feed1(db, identity):
    """Create first test feed."""
    return Feed.objects.create(
        name="Test Feed 1",
        identity=identity,
    )


@pytest.fixture
def feed2(db, identity):
    """Create second test feed."""
    return Feed.objects.create(
        name="Test Feed 2",
        identity=identity,
    )


@pytest.fixture
def feed3(db, identity):
    """Create third test feed."""
    return Feed.objects.create(
        name="Test Feed 3",
        identity=identity,
    )


@pytest.fixture
def object_in_multiple_feeds(db, feed1, feed2):
    """Create an object that exists in multiple feeds."""
    stix_id = "indicator--12345678-1234-1234-1234-123456789abc"
    modified_time = timezone.now()

    # Create NewObjectValue entries for the same object in two different feeds
    NewObjectValue.objects.create(
        feed=feed1,
        stix_id=stix_id,
        type="indicator",
        modified=modified_time,
        values={"pattern": "test-value"},
    )

    NewObjectValue.objects.create(
        feed=feed2,
        stix_id=stix_id,
        type="indicator",
        modified=modified_time,
        values={"pattern": "test-value"},
    )

    return stix_id


@pytest.fixture
def object_in_single_feed(db, feed1):
    """Create an object that exists in only one feed."""
    stix_id = "malware--87654321-4321-4321-4321-cba987654321"
    modified_time = timezone.now()

    NewObjectValue.objects.create(
        feed=feed1,
        stix_id=stix_id,
        type="malware",
        modified=modified_time,
        values={"name": "malware-name"},
    )

    return stix_id


@pytest.mark.django_db
class TestObjectFeedsView:
    """Test suite for ObjectFeedsView endpoint."""

    def test_get_feeds_for_object_in_multiple_feeds(
        self, client, object_in_multiple_feeds, feed1, feed2, api_schema
    ):
        """Test retrieving feeds for an object that exists in multiple feeds."""
        response = client.get(f"/api/v1/search/{object_in_multiple_feeds}/feeds/")

        assert response.status_code == status.HTTP_200_OK
        assert response.data["id"] == object_in_multiple_feeds
        assert "feeds" in response.data
        assert len(response.data["feeds"]) == 2

        assert response.data == {
            "id": "indicator--12345678-1234-1234-1234-123456789abc",
            "feeds": [
                {"id": "07bae936-7b37-57d1-9c3a-d7b91e07353b", "name": "Test Feed 1"},
                {"id": "bed845fd-1a46-509a-8440-cbb98a87e044", "name": "Test Feed 2"},
            ],
        }
        # Validate against API schema
        api_schema["/api/v1/search/{object_id}/feeds/"]["GET"].validate_response(
            Transport.get_st_response(response)
        )


@pytest.mark.django_db
class TestSearchKnowledgebaseFilter:
    def test_filterset_filters_by_single_knowledgebase(self, feed1, feed2):
        shared_modified = timezone.now()

        NewObjectValue.objects.create(
            feed=feed1,
            stix_id="attack-pattern--aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            type="attack-pattern",
            modified=shared_modified,
            knowledgebase="enterprise-attack",
            values={"name": "Phishing", "kb_id": "T1566"},
            is_dupe=False,
        )
        NewObjectValue.objects.create(
            feed=feed2,
            stix_id="weakness--bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            type="weakness",
            modified=shared_modified,
            knowledgebase="cwe",
            values={"name": "Improper Input Validation", "kb_id": "CWE-20"},
            is_dupe=False,
        )

        qs = SearchView.filterset_class(
            data={"knowledgebases": "cwe"},
            queryset=NewObjectValue.objects.all(),
        ).qs

        assert qs.count() == 1
        assert qs.first().knowledgebase == "cwe"

    def test_filterset_filters_by_multiple_knowledgebases(self, feed1, feed2):
        shared_modified = timezone.now()

        NewObjectValue.objects.create(
            feed=feed1,
            stix_id="attack-pattern--cccccccc-cccc-4ccc-8ccc-cccccccccccc",
            type="attack-pattern",
            modified=shared_modified,
            knowledgebase="enterprise-attack",
            values={"name": "Discovery", "kb_id": "T1087"},
            is_dupe=False,
        )
        NewObjectValue.objects.create(
            feed=feed2,
            stix_id="weakness--dddddddd-dddd-4ddd-8ddd-dddddddddddd",
            type="weakness",
            modified=shared_modified,
            knowledgebase="cwe",
            values={"name": "Memory Corruption", "kb_id": "CWE-119"},
            is_dupe=False,
        )

        qs = SearchView.filterset_class(
            data={"knowledgebases": "enterprise-attack,cwe"},
            queryset=NewObjectValue.objects.all(),
        ).qs

        assert qs.count() == 2

    def test_get_feeds_for_object_in_single_feed(
        self, client, object_in_single_feed, feed1, api_schema
    ):
        """Test retrieving feeds for an object that exists in only one feed."""
        response = client.get(f"/api/v1/search/{object_in_single_feed}/feeds/")

        assert response.status_code == status.HTTP_200_OK
        assert response.data["id"] == object_in_single_feed
        assert "feeds" in response.data
        assert len(response.data["feeds"]) == 1

        # Check that the correct feed is returned
        assert response.data["feeds"][0]["id"] == str(feed1.id)
        assert response.data["feeds"][0]["name"] == "Test Feed 1"

        # Validate against API schema
        api_schema["/api/v1/search/{object_id}/feeds/"]["GET"].validate_response(
            Transport.get_st_response(response)
        )

    def test_get_feeds_for_nonexistent_object(self, client, api_schema):
        """Test retrieving feeds for an object that doesn't exist."""
        nonexistent_id = "indicator--00000000-0000-0000-0000-000000000000"
        response = client.get(f"/api/v1/search/{nonexistent_id}/feeds/")

        assert response.status_code == status.HTTP_404_NOT_FOUND
        # Validate 404 response against schema
        api_schema["/api/v1/search/{object_id}/feeds/"]["GET"].validate_response(
            Transport.get_st_response(response)
        )

    def test_get_feeds_with_invalid_object_id_format(self, client, api_schema):
        """Test retrieving feeds with an invalid object ID format."""
        invalid_id = "not-a-valid-stix-id"
        response = client.get(f"/api/v1/search/{invalid_id}/feeds/")

        # Should return 404 since object doesn't exist
        assert response.status_code == status.HTTP_404_NOT_FOUND
        # Validate 404 response against schema
        api_schema["/api/v1/search/{object_id}/feeds/"]["GET"].validate_response(
            Transport.get_st_response(response)
        )



    def test_feeds_response_structure(
        self, client, object_in_single_feed, feed1, api_schema
    ):
        """Test that the response structure matches the expected schema."""
        response = client.get(f"/api/v1/search/{object_in_single_feed}/feeds/")

        assert response.status_code == status.HTTP_200_OK

        # Check top-level structure
        assert "id" in response.data
        assert "feeds" in response.data
        assert isinstance(response.data["feeds"], list)

        # Check feed object structure
        if response.data["feeds"]:
            feed = response.data["feeds"][0]
            assert "id" in feed
            assert "name" in feed
            # Should only have id and name (MicroFeedSerializer)
            assert set(feed.keys()) == {"id", "name"}

        # Validate against API schema
        api_schema["/api/v1/search/{object_id}/feeds/"]["GET"].validate_response(
            Transport.get_st_response(response)
        )

    def test_object_exists_in_three_feeds(
        self, client, feed1, feed2, feed3, api_schema
    ):
        """Test retrieving feeds when an object exists in three different feeds."""
        stix_id = "threat-actor--99999999-9999-9999-9999-999999999999"
        modified_time = timezone.now()

        # Create the same object in three feeds
        for feed in [feed1, feed2, feed3]:
            NewObjectValue.objects.create(
                feed=feed,
                stix_id=stix_id,
                type="threat-actor",
                modified=modified_time,
                values={"name": "APT Group"},
            )

        response = client.get(f"/api/v1/search/{stix_id}/feeds/")

        assert response.status_code == status.HTTP_200_OK
        assert len(response.data["feeds"]) == 3

        feed_ids = {feed["id"] for feed in response.data["feeds"]}
        assert feed_ids == {
            str(feed1.id),
            str(feed2.id),
            str(feed3.id),
        }

        # Validate against API schema
        api_schema["/api/v1/search/{object_id}/feeds/"]["GET"].validate_response(
            Transport.get_st_response(response)
        )
