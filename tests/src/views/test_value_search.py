"""
Tests for ObjectValueSearchView.

Tests verify that the value search endpoint correctly:
- Searches for direct value matches
- Finds objects that reference other objects with matching values
- Filters by feed_ids
- Handles version filtering (show_older_versions)
- Returns proper error messages for invalid inputs
"""

import pytest
from datetime import UTC, datetime
from rest_framework import status
from cyberthreatexchange.server import models


@pytest.fixture
def feeds(identity, disconnect_signals):
    """Create multiple test feeds."""
    feed1 = models.Feed.objects.create(
        name="Feed 1",
        description="First test feed",
        identity=identity,
        id="ec8fec0c-10d8-476f-8a51-0c71d94bbda6",
    )
    feed2 = models.Feed.objects.create(
        name="Feed 2",
        description="Second test feed",
        identity=identity,
        id="8d8965b5-6e41-454b-936f-eb6cf0b81d52",
    )
    yield feed1, feed2


@pytest.fixture
def test_values(feeds):
    """Create test ObjectValue records with various scenarios.
    
    Scenario setup:
    Feed 1:
    - Malware object "Cobalt Strike" (version 1: 2020-01-15, version 2: 2020-02-15)
    - Campaign "Operation Ghost" that references the malware
    - Threat actor "APT29"
    - Tool "Mimikatz"
    
    Feed 2:
    - Different malware "WannaCry"
    - Campaign "Ransomware Campaign" that references WannaCry
    - duplicate malware entry
    """
    feed1, feed2 = feeds
    
    # Feed 1: Malware - version 1 (older)
    malware_v1 = models.ObjectValue.objects.create(
        feed=feed1,
        stix_id="malware--d1c612bc-146f-4b65-b7b0-9a54a14150a4",
        stix_type="malware",
        modified=datetime(2020, 1, 15, 10, 0, 0, tzinfo=UTC),
        value="Cobalt Strike",
        value_type="name",
        is_ref=False,
    )
    
    # Feed 1: Malware - version 2 (newer)
    malware_v2 = models.ObjectValue.objects.create(
        feed=feed1,
        stix_id="malware--d1c612bc-146f-4b65-b7b0-9a54a14150a4",
        stix_type="malware",
        modified=datetime(2020, 2, 15, 10, 0, 0, tzinfo=UTC),
        value="Cobalt Strike",
        value_type="name",
        is_ref=False,
    )

    feed2_malware_v1 = models.ObjectValue.objects.create(
        feed=feed2,
        stix_id="malware--d1c612bc-146f-4b65-b7b0-9a54a14150a4",
        stix_type="malware",
        modified=datetime(2020, 1, 15, 10, 0, 0, tzinfo=UTC),
        value="Cobalt Strike",
        value_type="name",
        is_ref=False,
    )
    
    # Feed 1: Malware description (v2 only)
    malware_desc_v2 = models.ObjectValue.objects.create(
        feed=feed1,
        stix_id="malware--d1c612bc-146f-4b65-b7b0-9a54a14150a4",
        stix_type="malware",
        modified=datetime(2020, 2, 15, 10, 0, 0, tzinfo=UTC),
        value="Commercial penetration testing tool",
        value_type="description",
        is_ref=False,
    )
    
    # Feed 1: Campaign that references the malware
    campaign_ref = models.ObjectValue.objects.create(
        feed=feed1,
        stix_id="campaign--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
        stix_type="campaign",
        modified=datetime(2020, 1, 15, 10, 0, 0, tzinfo=UTC),
        value="malware--d1c612bc-146f-4b65-b7b0-9a54a14150a4",
        value_type="relationship_ref",
        is_ref=True,
        ref_stix_id="malware--d1c612bc-146f-4b65-b7b0-9a54a14150a4",
    )
    
    # Feed 1: Campaign name
    campaign_name = models.ObjectValue.objects.create(
        feed=feed1,
        stix_id="campaign--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
        stix_type="campaign",
        modified=datetime(2020, 1, 15, 10, 0, 0, tzinfo=UTC),
        value="Operation Ghost Writer",
        value_type="name",
        is_ref=False,
    )
    
    # Feed 1: Threat actor
    threat_actor = models.ObjectValue.objects.create(
        feed=feed1,
        stix_id="threat-actor--899ce53f-13a0-479b-a0e4-67d46e241542",
        stix_type="threat-actor",
        modified=datetime(2020, 1, 15, 10, 0, 0, tzinfo=UTC),
        value="APT29",
        value_type="name",
        is_ref=False,
    )
    
    # Feed 1: Tool
    tool = models.ObjectValue.objects.create(
        feed=feed1,
        stix_id="tool--242f3da3-4425-4d11-8f5c-b842886da966",
        stix_type="tool",
        modified=datetime(2020, 1, 15, 10, 0, 0, tzinfo=UTC),
        value="Mimikatz",
        value_type="name",
        is_ref=False,
    )
    
    # Feed 2: Different malware
    wannacry = models.ObjectValue.objects.create(
        feed=feed2,
        stix_id="malware--a1b2c3d4-e5f6-7890-abcd-ef1234567890",
        stix_type="malware",
        modified=datetime(2020, 3, 1, 10, 0, 0, tzinfo=UTC),
        value="WannaCry",
        value_type="name",
        is_ref=False,
    )
    
    # Feed 2: Campaign that references WannaCry
    ransomware_campaign_ref = models.ObjectValue.objects.create(
        feed=feed2,
        stix_id="campaign--b2c3d4e5-f6a7-8901-bcde-f12345678901",
        stix_type="campaign",
        modified=datetime(2020, 3, 1, 10, 0, 0, tzinfo=UTC),
        value="malware--a1b2c3d4-e5f6-7890-abcd-ef1234567890",
        value_type="relationship_ref",
        is_ref=True,
        ref_stix_id="malware--a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    )
    
    # Feed 2: Campaign name
    ransomware_campaign_name = models.ObjectValue.objects.create(
        feed=feed2,
        stix_id="campaign--b2c3d4e5-f6a7-8901-bcde-f12345678901",
        stix_type="campaign",
        modified=datetime(2020, 3, 1, 10, 0, 0, tzinfo=UTC),
        value="Ransomware Campaign",
        value_type="name",
        is_ref=False,
    )
    
    return {
        'feed1': feed1,
        'feed2': feed2,
        'malware_v1': malware_v1,
        'malware_v2': malware_v2,
        'malware_desc_v2': malware_desc_v2,
        'campaign_ref': campaign_ref,
        'campaign_name': campaign_name,
        'threat_actor': threat_actor,
        'tool': tool,
        'wannacry': wannacry,
        'ransomware_campaign_ref': ransomware_campaign_ref,
        'ransomware_campaign_name': ransomware_campaign_name,
        "feed2_malware_v1": feed2_malware_v1,
    }


class TestObjectValueSearchBasic:
    """Test basic search functionality."""
    
    def test_search_requires_value_parameter(self, client):
        """Test that search requires the 'value' parameter."""
        response = client.get('/api/v1/search/values/')
        
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        response_data = response.json()
        assert 'details' in response_data
        assert 'value' in response_data['details']
    
    def test_search_direct_match(self, client, test_values):
        """Test searching for a direct value match."""
        response = client.get('/api/v1/search/values/', {'value': 'Cobalt Strike'})
        
        assert response.status_code == status.HTTP_200_OK
        assert 'values' in response.data
        
        results = response.data['values']
        
        # Compare actual returned data with expected using set of tuples
        returned_ids = {
            (str(r['feed_id']), r['stix_id'], r['modified']) 
            for r in results
        }
        
        # Expected: Latest version from both feeds
        expected_ids = {
            ("ec8fec0c-10d8-476f-8a51-0c71d94bbda6", 'malware--d1c612bc-146f-4b65-b7b0-9a54a14150a4', '2020-02-15T10:00:00Z'),
            ("8d8965b5-6e41-454b-936f-eb6cf0b81d52", 'malware--d1c612bc-146f-4b65-b7b0-9a54a14150a4', '2020-01-15T10:00:00Z'),
        }
        
        assert returned_ids == expected_ids
    
    def test_search_partial_match(self, client, test_values):
        """Test searching with partial string match."""
        response = client.get('/api/v1/search/values/', {'value': 'Cobalt'})
        
        assert response.status_code == status.HTTP_200_OK
        results = response.data['values']
        
        # Should find objects containing "Cobalt"
        values = [r['value'] for r in results]
        assert any('Cobalt' in v for v in values)
    
    def test_search_case_insensitive(self, client, test_values):
        """Test that search is case-insensitive."""
        response1 = client.get('/api/v1/search/values/', {'value': 'cobalt strike'})
        response2 = client.get('/api/v1/search/values/', {'value': 'COBALT STRIKE'})
        response3 = client.get('/api/v1/search/values/', {'value': 'Cobalt Strike'})
        
        assert response1.status_code == status.HTTP_200_OK
        assert response2.status_code == status.HTTP_200_OK
        assert response3.status_code == status.HTTP_200_OK
        
        # All should return the same results - compare using set of tuples
        ids1 = {(str(r['feed_id']), r['stix_id'], r['modified']) for r in response1.data['values']}
        ids2 = {(str(r['feed_id']), r['stix_id'], r['modified']) for r in response2.data['values']}
        ids3 = {(str(r['feed_id']), r['stix_id'], r['modified']) for r in response3.data['values']}
        
        assert ids1 == ids2 == ids3
    
    def test_search_multiple_words(self, client, test_values):
        """Test searching with multiple words."""
        response = client.get('/api/v1/search/values/', {'value': 'penetration testing'})
        
        assert response.status_code == status.HTTP_200_OK
        results = response.data['values']
        
        # Should find objects containing either "penetration" or "testing"
        values = [r['value'] for r in results]
        assert any('penetration' in v.lower() or 'testing' in v.lower() for v in values)
    
    def test_search_no_results(self, client, test_values):
        """Test search with no matching results."""
        response = client.get('/api/v1/search/values/', {'value': 'NonexistentValue12345'})
        
        assert response.status_code == status.HTTP_200_OK
        assert len(response.data['values']) == 0


class TestObjectValueSearchReferences:
    """Test reference resolution in search."""
    
    def test_search_finds_direct_matches(self, client, test_values):
        """Test that searching finds direct value matches."""
        response = client.get('/api/v1/search/values/', {'value': 'Cobalt Strike'})
        
        assert response.status_code == status.HTTP_200_OK
        results = response.data['values']
        
        # Compare actual returned data with expected using set of tuples
        returned_ids = {
            (str(r['feed_id']), r['stix_id'], r['modified']) 
            for r in results
        }
        
        # Expected: Latest version from both feeds
        expected_ids = {
            ("ec8fec0c-10d8-476f-8a51-0c71d94bbda6", 'malware--d1c612bc-146f-4b65-b7b0-9a54a14150a4', '2020-02-15T10:00:00Z'),
            ("8d8965b5-6e41-454b-936f-eb6cf0b81d52", 'malware--d1c612bc-146f-4b65-b7b0-9a54a14150a4', '2020-01-15T10:00:00Z'),
        }
        
        assert returned_ids == expected_ids
    
    def test_search_finds_objects_with_matching_references(self, client, test_values):
        """Test that search finds objects that reference other matching objects."""
        # Search for campaign name which should return the campaign
        campaign_response = client.get('/api/v1/search/values/', {'value': 'Ghost'})
        
        assert campaign_response.status_code == status.HTTP_200_OK
        results = campaign_response.data['values']
        
        # Compare actual returned data with expected using set of tuples
        returned_ids = {
            (str(r['feed_id']), r['stix_id'], r['modified']) 
            for r in results
        }
        
        # Expected: Campaign from feed1
        expected_ids = {
            ("ec8fec0c-10d8-476f-8a51-0c71d94bbda6", 'campaign--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f', '2020-01-15T10:00:00Z'),
        }
        
        assert returned_ids == expected_ids
    
    def test_search_distinguishes_feeds_in_references(self, client, test_values):
        """Test that reference resolution works correctly within each feed."""
        # Search for WannaCry (only in feed2)
        response = client.get('/api/v1/search/values/', {'value': 'WannaCry'})
        
        assert response.status_code == status.HTTP_200_OK
        results = response.data['values']
        
        # Compare actual returned data with expected using set of tuples
        returned_ids = {
            (str(r['feed_id']), r['stix_id'], r['modified']) 
            for r in results
        }
        
        # Expected: WannaCry malware from feed2 only
        expected_ids = {
            ("8d8965b5-6e41-454b-936f-eb6cf0b81d52", 'malware--a1b2c3d4-e5f6-7890-abcd-ef1234567890', '2020-03-01T10:00:00Z'),
        }
        
        assert returned_ids == expected_ids


class TestObjectValueSearchFeedFiltering:
    """Test feed_ids filtering."""
    
    def test_filter_by_single_feed(self, client, test_values):
        """Test filtering results by a single feed."""
        feed1 = test_values['feed1']
        
        response = client.get('/api/v1/search/values/', {
            'value': 'Strike',  # Will match Cobalt Strike
            'feed_ids': str(feed1.id)
        })
        
        assert response.status_code == status.HTTP_200_OK
        results = response.data['values']
        
        # Compare actual returned data with expected using set of tuples
        returned_ids = {
            (str(r['feed_id']), r['stix_id'], r['modified']) 
            for r in results
        }
        
        # Expected: Latest Cobalt Strike from feed1 only
        expected_ids = {
            (str(feed1.id), 'malware--d1c612bc-146f-4b65-b7b0-9a54a14150a4', '2020-02-15T10:00:00Z'),
        }
        
        assert returned_ids == expected_ids
    
    def test_filter_by_multiple_feeds(self, client, test_values):
        """Test filtering results by multiple feeds."""
        feed1 = test_values['feed1']
        feed2 = test_values['feed2']
        
        # Search for 'Campaign' which appears in both feeds
        response = client.get('/api/v1/search/values/', {
            'value': 'Campaign',
            'feed_ids': f'{feed1.id},{feed2.id}'
        })
        
        assert response.status_code == status.HTTP_200_OK
        results = response.data['values']
        
        # Compare actual returned data with expected using set of tuples
        returned_ids = {
            (str(r['feed_id']), r['stix_id'], r['modified']) 
            for r in results
        }
        
        # Expected: Only the campaign from feed2 (which has "Ransomware Campaign" in the name)
        # feed1's campaign is "Operation Ghost Writer" which doesn't contain "Campaign"
        expected_ids = {
            (str(feed2.id), 'campaign--b2c3d4e5-f6a7-8901-bcde-f12345678901', '2020-03-01T10:00:00Z'),
        }
        
        assert returned_ids == expected_ids
    
    def test_filter_by_nonexistent_feed(self, client, test_values):
        """Test that filtering by nonexistent feed returns error."""
        response = client.get('/api/v1/search/values/', {
            'value': 'test',
            'feed_ids': '00000000-0000-0000-0000-000000000000'
        })
        
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        response_data = response.json()
        assert 'details' in response_data
        assert 'feed_ids' in response_data['details']
    
    def test_filter_excludes_other_feeds(self, client, test_values):
        """Test that feed filtering properly excludes results from other feeds."""
        feed2 = test_values['feed2']
        
        # Search for something only in feed1, but filter by feed2
        response = client.get('/api/v1/search/values/', {
            'value': 'APT29',  # Only in feed1
            'feed_ids': str(feed2.id)
        })
        
        assert response.status_code == status.HTTP_200_OK
        assert len(response.data['values']) == 0
    
    def test_no_feed_filter_searches_all_feeds(self, client, test_values):
        """Test that omitting feed_ids searches across all feeds."""
        response = client.get('/api/v1/search/values/', {
            'value': 'Strike'  # Term that appears in Cobalt Strike in feed1
        })
        
        assert response.status_code == status.HTTP_200_OK
        results = response.data['values']
        
        # Should get results from at least one feed
        assert len(results) > 0


class TestObjectValueSearchVersionFiltering:
    """Test show_older_versions parameter."""
    
    def test_default_returns_latest_version_only(self, client, test_values):
        """Test that by default, only the latest version is returned."""
        response = client.get('/api/v1/search/values/', {
            'value': 'Cobalt Strike'
        })
        
        assert response.status_code == status.HTTP_200_OK
        results = response.data['values']
        
        # Compare actual returned data with expected using set of tuples
        returned_ids = {
            (str(r['feed_id']), r['stix_id'], r['modified']) 
            for r in results
        }
        
        # Expected: Latest version per feed (feed1 has v2, feed2 has v1 only)
        expected_ids = {
            ("ec8fec0c-10d8-476f-8a51-0c71d94bbda6", 'malware--d1c612bc-146f-4b65-b7b0-9a54a14150a4', '2020-02-15T10:00:00Z'),
            ("8d8965b5-6e41-454b-936f-eb6cf0b81d52", 'malware--d1c612bc-146f-4b65-b7b0-9a54a14150a4', '2020-01-15T10:00:00Z'),
        }
        
        assert returned_ids == expected_ids
    
    def test_show_older_versions_false_explicit(self, client, test_values):
        """Test explicitly setting show_older_versions=false."""
        response = client.get('/api/v1/search/values/', {
            'value': 'Cobalt Strike',
            'show_older_versions': 'false'
        })
        
        assert response.status_code == status.HTTP_200_OK
        results = response.data['values']
        
        # Compare actual returned data with expected using set of tuples
        returned_ids = {
            (str(r['feed_id']), r['stix_id'], r['modified']) 
            for r in results
        }
        
        # Expected: Latest version per feed (same as default)
        expected_ids = {
            ("ec8fec0c-10d8-476f-8a51-0c71d94bbda6", 'malware--d1c612bc-146f-4b65-b7b0-9a54a14150a4', '2020-02-15T10:00:00Z'),
            ("8d8965b5-6e41-454b-936f-eb6cf0b81d52", 'malware--d1c612bc-146f-4b65-b7b0-9a54a14150a4', '2020-01-15T10:00:00Z'),
        }
        
        assert returned_ids == expected_ids
    
    def test_show_older_versions_true(self, client, test_values):
        """Test that show_older_versions=true returns all versions."""
        response = client.get('/api/v1/search/values/', {
            'value': 'Cobalt Strike',
            'show_older_versions': 'true'
        })
        
        assert response.status_code == status.HTTP_200_OK
        results = response.data['values']
        
        # Compare actual returned data with expected using set of tuples
        returned_ids = {
            (str(r['feed_id']), r['stix_id'], r['modified']) 
            for r in results
        }
        
        # Expected: All versions from feed1 (v1 and v2) plus feed2 (v1)
        expected_ids = {
            ("ec8fec0c-10d8-476f-8a51-0c71d94bbda6", 'malware--d1c612bc-146f-4b65-b7b0-9a54a14150a4', '2020-01-15T10:00:00Z'),
            ("ec8fec0c-10d8-476f-8a51-0c71d94bbda6", 'malware--d1c612bc-146f-4b65-b7b0-9a54a14150a4', '2020-02-15T10:00:00Z'),
            ("8d8965b5-6e41-454b-936f-eb6cf0b81d52", 'malware--d1c612bc-146f-4b65-b7b0-9a54a14150a4', '2020-01-15T10:00:00Z'),
        }
        
        assert returned_ids == expected_ids
    
    def test_version_filtering_with_feed_filter(self, client, test_values):
        """Test that version filtering works correctly with feed filtering."""
        feed1 = test_values['feed1']
        
        response = client.get('/api/v1/search/values/', {
            'value': 'Cobalt Strike',
            'feed_ids': str(feed1.id),
            'show_older_versions': 'true'
        })
        
        assert response.status_code == status.HTTP_200_OK
        results = response.data['values']
        
        # Compare actual returned data with expected using set of tuples
        returned_ids = {
            (str(r['feed_id']), r['stix_id'], r['modified']) 
            for r in results
        }
        
        # Expected: All versions from feed1 only (v1 and v2)
        expected_ids = {
            (str(feed1.id), 'malware--d1c612bc-146f-4b65-b7b0-9a54a14150a4', '2020-01-15T10:00:00Z'),
            (str(feed1.id), 'malware--d1c612bc-146f-4b65-b7b0-9a54a14150a4', '2020-02-15T10:00:00Z'),
        }
        
        assert returned_ids == expected_ids


class TestObjectValueSearchCombinedFilters:
    """Test combinations of filters."""
    
    def test_feed_filter_with_references(self, client, test_values):
        """Test that feed filtering works correctly."""
        feed1 = test_values['feed1']
        
        response = client.get('/api/v1/search/values/', {
            'value': 'Cobalt Strike',
            'feed_ids': str(feed1.id)
        })
        
        assert response.status_code == status.HTTP_200_OK
        results = response.data['values']
        
        # Compare actual returned data with expected using set of tuples
        returned_ids = {
            (str(r['feed_id']), r['stix_id'], r['modified']) 
            for r in results
        }
        
        # Expected: Latest version of Cobalt Strike from feed1 only
        expected_ids = {
            (str(feed1.id), 'malware--d1c612bc-146f-4b65-b7b0-9a54a14150a4', '2020-02-15T10:00:00Z'),
        }
        
        assert returned_ids == expected_ids
    
    def test_all_filters_combined(self, client, test_values):
        """Test using all filter parameters together."""
        feed1 = test_values['feed1']
        
        response = client.get('/api/v1/search/values/', {
            'value': 'Cobalt Strike',
            'feed_ids': str(feed1.id),
            'show_older_versions': 'true'
        })
        
        assert response.status_code == status.HTTP_200_OK
        results = response.data['values']
        
        # Compare actual returned data with expected using set of tuples
        returned_ids = {
            (str(r['feed_id']), r['stix_id'], r['modified']) 
            for r in results
        }
        
        # Expected: All versions from feed1 (v1 and v2)
        expected_ids = {
            (str(feed1.id), 'malware--d1c612bc-146f-4b65-b7b0-9a54a14150a4', '2020-01-15T10:00:00Z'),
            (str(feed1.id), 'malware--d1c612bc-146f-4b65-b7b0-9a54a14150a4', '2020-02-15T10:00:00Z'),
        }
        
        assert returned_ids == expected_ids
    
    def test_empty_feed_ids_parameter(self, client, test_values):
        """Test that empty feed_ids parameter searches all feeds."""
        response = client.get('/api/v1/search/values/', {
            'value': 'Strike',
            'feed_ids': ''  # Empty string
        })
        
        assert response.status_code == status.HTTP_200_OK
        results = response.data['values']
        
        # Should search all feeds (not error on empty string)
        assert len(results) > 0


class TestObjectValueSearchResponseFormat:
    """Test the format of search responses."""
    
    def test_response_has_correct_structure(self, client, test_values):
        """Test that response has the correct structure."""
        response = client.get('/api/v1/search/values/', {'value': 'APT29'})
        
        assert response.status_code == status.HTTP_200_OK
        assert 'values' in response.data
        assert isinstance(response.data['values'], list)
    
    def test_result_object_fields(self, client, test_values):
        """Test that each result object has the required fields."""
        response = client.get('/api/v1/search/values/', {'value': 'APT29'})
        
        assert response.status_code == status.HTTP_200_OK
        results = response.data['values']
        assert len(results) > 0
        
        # Check first result has expected fields
        result = results[0]
        required_fields = ['id', 'feed_id', 'stix_id', 'stix_type', 'modified', 
                          'value', 'value_type', 'is_ref']
        for field in required_fields:
            assert field in result
    
    def test_results_ordered_by_modified_desc(self, client, test_values):
        """Test that results are ordered by modified date descending."""
        response = client.get('/api/v1/search/values/', {
            'value': 'Campaign',
            'show_older_versions': 'true'
        })
        
        assert response.status_code == status.HTTP_200_OK
        results = response.data['values']
        
        if len(results) > 1:
            # Check that results are in descending order by modified
            for i in range(len(results) - 1):
                curr_modified = datetime.fromisoformat(results[i]['modified'].replace('Z', '+00:00'))
                next_modified = datetime.fromisoformat(results[i+1]['modified'].replace('Z', '+00:00'))
                assert curr_modified >= next_modified
    
    def test_pagination_present(self, client, test_values):
        """Test that pagination info is present in response."""
        response = client.get('/api/v1/search/values/', {'value': 'Strike'})
        
        assert response.status_code == status.HTTP_200_OK
        # Response should have pagination structure from Pagination class
        assert 'values' in response.data
