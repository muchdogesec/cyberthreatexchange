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
        response.data["feeds"] = sorted(response.data["feeds"], key=lambda x: x["id"])

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


@pytest.fixture
def search_objects_feed1(db, feed1):
    """Create multiple test objects in feed1."""
    shared_modified = timezone.now()
    
    objects = {
        "indicator": NewObjectValue.objects.create(
            feed=feed1,
            stix_id="indicator--11111111-1111-1111-1111-111111111111",
            type="indicator",
            modified=shared_modified,
            values={"pattern": "[ipv4-addr:value = '192.168.1.1']"},
            is_dupe=False,
        ),
        "malware": NewObjectValue.objects.create(
            feed=feed1,
            stix_id="malware--22222222-2222-2222-2222-222222222222",
            type="malware",
            modified=shared_modified,
            values={"name": "TrickBot"},
            is_dupe=False,
        ),
        "attack_pattern": NewObjectValue.objects.create(
            feed=feed1,
            stix_id="attack-pattern--33333333-3333-3333-3333-333333333333",
            type="attack-pattern",
            modified=shared_modified,
            values={"name": "Phishing"},
            is_dupe=False,
        ),
        "threat_actor": NewObjectValue.objects.create(
            feed=feed1,
            stix_id="threat-actor--44444444-4444-4444-4444-444444444444",
            type="threat-actor",
            modified=shared_modified,
            values={"name": "APT28"},
            is_dupe=False,
        ),
        "vulnerability": NewObjectValue.objects.create(
            feed=feed1,
            stix_id="vulnerability--55555555-5555-5555-5555-555555555555",
            type="vulnerability",
            modified=shared_modified,
            values={"name": "CVE-2021-44228"},
            is_dupe=False,
        ),
    }
    return objects


@pytest.fixture
def search_object_with_duplicate(db, feed1):
    """Create objects to test is_dupe filtering."""
    shared_modified = timezone.now()
    
    # Create a non-duplicate object (should be included)
    obj = NewObjectValue.objects.create(
        feed=feed1,
        stix_id="indicator--77777777-7777-7777-7777-777777777777",
        type="indicator",
        modified=shared_modified,
        values={"pattern": "[file:hashes.MD5 = 'abc123']"},
        is_dupe=False,
    )
    
    # Create a separate duplicate object (should be excluded)
    NewObjectValue.objects.create(
        feed=feed1,
        stix_id="indicator--77777788-7777-7777-7777-777777777777",
        type="indicator",
        modified=shared_modified,
        values={"pattern": "[file:hashes.MD5 = 'def456']"},
        is_dupe=True,
    )
    
    return obj


@pytest.fixture
def search_object_multiple_feeds(db, feed1, feed2):
    """Create the same object in multiple feeds."""
    shared_modified = timezone.now()
    stix_id = "malware--88888888-8888-8888-8888-888888888888"
    
    obj1 = NewObjectValue.objects.create(
        feed=feed1,
        stix_id=stix_id,
        type="malware",
        modified=shared_modified,
        values={"name": "Emotet"},
        is_dupe=False,
    )
    obj2 = NewObjectValue.objects.create(
        feed=feed2,
        stix_id=stix_id,
        type="malware",
        modified=shared_modified,
        values={"name": "Emotet"},
        is_dupe=False,
    )
    return {"feed1": obj1, "feed2": obj2, "stix_id": stix_id}


@pytest.fixture
def search_tools_multiple_feeds(db, feed1, feed2):
    """Create different tool objects in different feeds."""
    shared_modified = timezone.now()
    
    obj1 = NewObjectValue.objects.create(
        feed=feed1,
        stix_id="tool--99999999-9999-9999-9999-999999999999",
        type="tool",
        modified=shared_modified,
        values={"name": "Mimikatz"},
        is_dupe=False,
    )
    obj2 = NewObjectValue.objects.create(
        feed=feed2,
        stix_id="tool--aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        type="tool",
        modified=shared_modified,
        values={"name": "Cobalt Strike"},
        is_dupe=False,
    )
    return {"feed1": obj1, "feed2": obj2}


@pytest.fixture
def search_campaigns(db, feed1):
    """Create campaign objects for filterset testing."""
    shared_modified = timezone.now()
    
    target = NewObjectValue.objects.create(
        feed=feed1,
        stix_id="campaign--bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
        type="campaign",
        modified=shared_modified,
        values={"name": "Operation Aurora"},
        is_dupe=False,
    )
    other = NewObjectValue.objects.create(
        feed=feed1,
        stix_id="campaign--cccccccc-cccc-cccc-cccc-cccccccccccc",
        type="campaign",
        modified=shared_modified,
        values={"name": "SolarWinds"},
        is_dupe=False,
    )
    return {"target": target, "other": other}


@pytest.mark.django_db
class TestSearchStixIdFilter:
    """Test suite for stix_id filter on SearchView list endpoint."""

    @pytest.fixture(autouse=True)
    def mock_arango_context(self, monkeypatch):
        """Mock ArangoDBHelper.get_context_for_objects to return simple dict."""
        def mock_get_context(self, stix_ids):
            retval = {}
            for stix_id in stix_ids:
                _type, _ = stix_id.split("--", 1)
                retval[stix_id] = {"id": stix_id, "type": _type}
            return retval
        
        from cyberthreatexchange.server.arango_helpers import ArangoDBHelper
        monkeypatch.setattr(ArangoDBHelper, "get_context_for_objects", mock_get_context)

    def test_filter_by_single_stix_id(self, client, search_objects_feed1, api_schema):
        """Test filtering search results by a single STIX ID."""
        stix_id_1 = search_objects_feed1["indicator"].stix_id
        
        # Filter by single stix_id
        response = client.get(f"/api/v1/search/?stix_id={stix_id_1}")
        
        assert response.status_code == status.HTTP_200_OK
        assert "objects" in response.data
        assert len(response.data["objects"]) == 1
        assert response.data["objects"][0]["id"] == stix_id_1
        
        # Validate against API schema
        api_schema["/api/v1/search/"]["GET"].validate_response(
            Transport.get_st_response(response)
        )

    def test_filter_by_multiple_stix_ids(self, client, search_objects_feed1, api_schema):
        """Test filtering search results by multiple STIX IDs."""
        stix_id_1 = search_objects_feed1["attack_pattern"].stix_id
        stix_id_2 = search_objects_feed1["threat_actor"].stix_id
        
        # Filter by multiple stix_ids using CSV format
        response = client.get(f"/api/v1/search/?stix_id={stix_id_1},{stix_id_2}")
        
        assert response.status_code == status.HTTP_200_OK
        assert "objects" in response.data
        assert len(response.data["objects"]) == 2
        
        returned_ids = {obj["id"] for obj in response.data["objects"]}
        assert returned_ids == {stix_id_1, stix_id_2}
        
        # Validate against API schema
        api_schema["/api/v1/search/"]["GET"].validate_response(
            Transport.get_st_response(response)
        )

    def test_filter_by_nonexistent_stix_id(self, client, api_schema):
        """Test filtering by a STIX ID that doesn't exist."""
        # Filter by non-existent stix_id
        nonexistent_id = "indicator--00000000-0000-0000-0000-000000000000"
        response = client.get(f"/api/v1/search/?stix_id={nonexistent_id}")
        
        assert response.status_code == status.HTTP_200_OK
        assert "objects" in response.data
        assert len(response.data["objects"]) == 0
        
        # Validate against API schema
        api_schema["/api/v1/search/"]["GET"].validate_response(
            Transport.get_st_response(response)
        )

    def test_stix_id_filter_excludes_duplicates(self, client, search_object_with_duplicate, api_schema):
        """Test that stix_id filter excludes objects marked as duplicates."""
        stix_id = search_object_with_duplicate.stix_id
        
        response = client.get(f"/api/v1/search/?stix_id={stix_id}")
        
        assert response.status_code == status.HTTP_200_OK
        assert "objects" in response.data
        # Should only return the non-duplicate
        assert len(response.data["objects"]) == 1
        
        # Validate against API schema
        api_schema["/api/v1/search/"]["GET"].validate_response(
            Transport.get_st_response(response)
        )

    def test_stix_id_filter_with_multiple_feeds(self, client, search_object_multiple_feeds, api_schema):
        """Test that stix_id filter returns objects from multiple feeds."""
        stix_id = search_object_multiple_feeds["stix_id"]
        
        response = client.get(f"/api/v1/search/?stix_id={stix_id}")
        
        assert response.status_code == status.HTTP_200_OK
        assert "objects" in response.data
        # Should return both instances (one from each feed)
        assert len(response.data["objects"]) == 2
        
        # Validate against API schema
        api_schema["/api/v1/search/"]["GET"].validate_response(
            Transport.get_st_response(response)
        )

    def test_stix_id_filter_combined_with_other_filters(self, client, search_tools_multiple_feeds, feed1, api_schema):
        """Test stix_id filter combined with feed_ids filter."""
        stix_id_1 = search_tools_multiple_feeds["feed1"].stix_id
        stix_id_2 = search_tools_multiple_feeds["feed2"].stix_id
        
        # Filter by both stix_ids but only feed1
        response = client.get(
            f"/api/v1/search/?stix_id={stix_id_1},{stix_id_2}&feed_ids={feed1.id}"
        )
        
        assert response.status_code == status.HTTP_200_OK
        assert "objects" in response.data
        # Should only return the object from feed1
        assert len(response.data["objects"]) == 1
        assert response.data["objects"][0]["id"] == stix_id_1
        
        # Validate against API schema
        api_schema["/api/v1/search/"]["GET"].validate_response(
            Transport.get_st_response(response)
        )

    def test_stix_id_filterset_directly(self, search_campaigns):
        """Test the stix_id filter directly using the filterset class."""
        stix_id_target = search_campaigns["target"].stix_id
        
        # Test filterset directly
        qs = SearchView.filterset_class(
            data={"stix_id": stix_id_target},
            queryset=NewObjectValue.objects.all(),
        ).qs
        
        assert qs.count() == 1
        assert qs.first().stix_id == stix_id_target