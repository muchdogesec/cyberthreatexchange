"""
Tests for connector-related Celery tasks.
"""

import pytest
from unittest.mock import Mock, patch, call
from datetime import datetime, timedelta, timezone

from cyberthreatexchange.server import models
from cyberthreatexchange.worker.tasks import poll_taxii_connector_task


@pytest.fixture
def connector(feed):
    """Create a test TAXII connector."""
    connector = models.Connector.objects.create(
        feed=feed,
        name="Test TAXII Connector",
        type=models.ConnectorType.TAXII,
        taxii_collection_url="https://example.com/taxii2/collections/123",
        username="testuser",
        password="testpass",
    )
    yield connector


@pytest.fixture
def connector_job(feed, connector):
    """Create a job for connector polling."""
    job = models.Job.objects.create(
        feed=feed,
        type=models.JobTypes.CONNECTOR_POLL,
        state=models.JobStates.PENDING,
        payload={
            "connector_id": str(connector.id),
            "added_after": None,
        },
    )
    yield job


class TestPollTaxiiConnectorTask:
    """Test poll_taxii_connector_task function."""
    
    @patch('cyberthreatexchange.worker.tasks.rerun_relationship_uploads', return_value=([], {}))
    @patch('cyberthreatexchange.worker.tasks.make_uploads')
    @patch('requests.Session')
    def test_poll_single_page_success(self, mock_session_class, mock_make_uploads, mock_rerun, connector_job, connector):
        """Test polling a TAXII collection with a single page of results."""
        # Setup mock session
        mock_session = Mock()
        mock_session_class.return_value = mock_session
        
        # Mock response for single page
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'objects': [
                {'type': 'indicator', 'id': 'indicator--1'},
                {'type': 'malware', 'id': 'malware--1'},
            ],
            'more': False,
        }
        mock_response.headers = {'X-TAXII-Date-Added-Last': '2024-01-15T10:00:00.000Z'}
        mock_session.get.return_value = mock_response
        
        # Run the task
        poll_taxii_connector_task(
            job_id=connector_job.id,
            connector_id=connector.id,
            added_after=None,
        )
        
        # Verify session was configured with auth
        from requests.auth import HTTPBasicAuth
        assert isinstance(mock_session.auth, HTTPBasicAuth)
        
        # Verify TAXII request was made
        mock_session.get.assert_called_once()
        call_args = mock_session.get.call_args
        assert 'objects/' in call_args[0][0]
        
        # Verify objects were uploaded (called twice: once for objects, once for relationships)
        assert mock_make_uploads.call_count == 2
        # Check first call (objects)
        first_call = mock_make_uploads.call_args_list[0]
        assert first_call[0][0] == connector_job.id  # job_id
        assert len(first_call[0][1]) == 2  # 2 objects
        assert first_call[1]['arango_extra'] == {'_ctx_connector_id': str(connector.id)}
        
        # Verify job completed successfully
        connector_job.refresh_from_db()
        assert connector_job.state == models.JobStates.COMPLETED
        assert connector_job.completion_time is not None
        assert connector_job.extra['objects_imported'] == 2
        
        # Verify connector was updated
        connector.refresh_from_db()
        assert connector.next_run_added_after is not None
        assert connector.last_completion_time is not None
    
    @patch('cyberthreatexchange.worker.tasks.rerun_relationship_uploads', return_value=([], {}))
    @patch('cyberthreatexchange.worker.tasks.make_uploads')
    @patch('requests.Session')
    def test_poll_multiple_pages(self, mock_session_class, mock_make_uploads, mock_rerun, connector_job, connector):
        """Test polling with pagination (multiple pages)."""
        mock_session = Mock()
        mock_session_class.return_value = mock_session
        
        # Mock responses for multiple pages
        page1_response = Mock()
        page1_response.status_code = 200
        page1_response.json.return_value = {
            'objects': [{'type': 'indicator', 'id': 'indicator--1'}],
            'more': True,
            'next': 'page2-token',
        }
        page1_response.headers = {'X-TAXII-Date-Added-Last': '2024-01-15T10:00:00.000Z'}
        
        page2_response = Mock()
        page2_response.status_code = 200
        page2_response.json.return_value = {
            'objects': [{'type': 'malware', 'id': 'malware--1'}],
            'more': True,
            'next': 'page3-token',
        }
        page2_response.headers = {'X-TAXII-Date-Added-Last': '2024-01-15T11:00:00.000Z'}
        
        page3_response = Mock()
        page3_response.status_code = 200
        page3_response.json.return_value = {
            'objects': [{'type': 'attack-pattern', 'id': 'attack-pattern--1'}],
            'more': False,
        }
        page3_response.headers = {'X-TAXII-Date-Added-Last': '2024-01-15T12:00:00.000Z'}
        
        mock_session.get.side_effect = [page1_response, page2_response, page3_response]
        
        # Run the task
        poll_taxii_connector_task(
            job_id=connector_job.id,
            connector_id=connector.id,
            added_after=None,
        )
        
        # Verify multiple requests were made
        assert mock_session.get.call_count == 3
        
        # Verify pagination parameters
        calls = mock_session.get.call_args_list
        assert calls[0][1]['params'] == {}  # First call has no filters
        assert calls[1][1]['params'] == {'next': 'page2-token'}
        assert calls[2][1]['params'] == {'next': 'page3-token'}
        
        # Verify make_uploads was called 4 times (3 pages + 1 relationship)
        assert mock_make_uploads.call_count == 4
        
        # Verify total objects imported
        connector_job.refresh_from_db()
        assert connector_job.state == models.JobStates.COMPLETED
        assert connector_job.extra['objects_imported'] == 3
        
        # Verify next_run_added_after is set to last page's header
        connector.refresh_from_db()
        assert connector.next_run_added_after.isoformat() == '2024-01-15T12:00:00+00:00'
    
    @patch('cyberthreatexchange.worker.tasks.make_uploads')
    @patch('cyberthreatexchange.worker.tasks.rerun_relationship_uploads', return_value=([], {}))
    @patch('requests.Session')
    def test_poll_with_added_after_filter(self, mock_session_class, mock_make_uploads, mock_rerun, connector_job, connector):
        """Test polling with added_after filter."""
        mock_session = Mock()
        mock_session_class.return_value = mock_session
        
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'objects': [{'type': 'indicator', 'id': 'indicator--1'}],
            'more': False,
        }
        mock_response.headers = {'X-TAXII-Date-Added-Last': '2024-01-15T10:00:00.000Z'}
        mock_session.get.return_value = mock_response
        
        # Set added_after
        added_after = datetime(2024, 1, 10, 0, 0, 0, tzinfo=timezone.utc)
        
        # Run the task
        poll_taxii_connector_task(
            job_id=connector_job.id,
            connector_id=connector.id,
            added_after=added_after,
        )
        
        # Verify added_after filter was sent
        call_args = mock_session.get.call_args
        assert call_args[1]['params'] == {'added_after': added_after.isoformat()}
        
        # Verify job completed
        connector_job.refresh_from_db()
        assert connector_job.state == models.JobStates.COMPLETED
    
    @patch('cyberthreatexchange.worker.tasks.make_uploads')
    @patch('cyberthreatexchange.worker.tasks.rerun_relationship_uploads', return_value=([], {}))
    @patch('requests.Session')
    def test_poll_with_authentication(self, mock_session_class, mock_make_uploads, mock_rerun, connector_job, connector):
        """Test that authentication credentials are used."""
        mock_session = Mock()
        mock_session_class.return_value = mock_session
        
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'objects': [],
            'more': False,
        }
        mock_response.headers = {'X-TAXII-Date-Added-Last': '2024-01-15T10:00:00.000Z'}
        mock_session.get.return_value = mock_response
        
        # Run the task
        poll_taxii_connector_task(
            job_id=connector_job.id,
            connector_id=connector.id,
            added_after=None,
        )
        
        # Verify authentication was configured
        from requests.auth import HTTPBasicAuth
        assert isinstance(mock_session.auth, HTTPBasicAuth)
        assert mock_session.auth.username == "testuser"
        assert mock_session.auth.password == "testpass"
    
    @patch('cyberthreatexchange.worker.tasks.rerun_relationship_uploads', return_value=([], {}))
    @patch('cyberthreatexchange.worker.tasks.make_uploads')
    @patch('requests.Session')
    def test_poll_without_authentication(self, mock_session_class, mock_make_uploads, mock_rerun, connector_job, feed):
        """Test polling without authentication credentials."""
        # Create connector without credentials
        connector = models.Connector.objects.create(
            feed=feed,
            name="Public TAXII Connector",
            type=models.ConnectorType.TAXII,
            taxii_collection_url="https://example.com/taxii2/collections/public",
        )
        
        mock_session = Mock()
        mock_session_class.return_value = mock_session
        mock_session.auth = None  # Explicitly set auth to None
        
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'objects': [],
            'more': False,
        }
        mock_response.headers = {'X-TAXII-Date-Added-Last': '2024-01-15T10:00:00.000Z'}
        mock_session.get.return_value = mock_response
        
        # Run the task
        poll_taxii_connector_task(
            job_id=connector_job.id,
            connector_id=connector.id,
            added_after=None,
        )
        
        # Verify no auth was set
        assert mock_session.auth is None
    
    @patch('cyberthreatexchange.worker.tasks.rerun_relationship_uploads', return_value=([], {}))
    @patch('cyberthreatexchange.worker.tasks.make_uploads')
    @patch('requests.Session')
    def test_poll_empty_response(self, mock_session_class, mock_make_uploads, mock_rerun, connector_job, connector):
        """Test handling of empty TAXII response."""
        mock_session = Mock()
        mock_session_class.return_value = mock_session
        
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'objects': [],
            'more': False,
        }
        mock_response.headers = {'X-TAXII-Date-Added-Last': '2024-01-15T10:00:00.000Z'}
        mock_session.get.return_value = mock_response
        
        # Run the task
        poll_taxii_connector_task(
            job_id=connector_job.id,
            connector_id=connector.id,
            added_after=None,
        )
        
        # Verify make_uploads was called only once for relationships (no objects to upload)
        assert mock_make_uploads.call_count == 1
        # Check it was called with empty relationships
        call_args = mock_make_uploads.call_args
        assert len(call_args[0][1]) == 0  # Empty relationships list
        
        # Verify job still completed successfully
        connector_job.refresh_from_db()
        assert connector_job.state == models.JobStates.COMPLETED
        # Check that extra dict exists before checking key
        if connector_job.extra is not None:
            assert 'objects_imported' not in connector_job.extra
    
    @patch('cyberthreatexchange.worker.tasks.rerun_relationship_uploads', return_value=([], {}))
    @patch('requests.Session')
    def test_poll_http_error(self, mock_session_class, mock_rerun, connector_job, connector):
        """Test handling of HTTP errors from TAXII server."""
        mock_session = Mock()
        mock_session_class.return_value = mock_session
        
        mock_response = Mock()
        mock_response.status_code = 404
        mock_response.text = "Collection not found"
        mock_session.get.return_value = mock_response
        
        # Run the task
        poll_taxii_connector_task(
            job_id=connector_job.id,
            connector_id=connector.id,
            added_after=None,
        )
        
        # Verify job failed
        connector_job.refresh_from_db()
        assert connector_job.state == models.JobStates.FAILED
        assert len(connector_job.errors) > 0
        assert "404" in connector_job.errors[0]
        assert connector_job.completion_time is not None
    
    @patch('cyberthreatexchange.worker.tasks.make_uploads')
    @patch('cyberthreatexchange.worker.tasks.rerun_relationship_uploads', return_value=([], {}))
    @patch('requests.Session')
    def test_poll_network_error(self, mock_session_class, mock_make_uploads, mock_rerun, connector_job, connector):
        """Test handling of network errors."""
        mock_session = Mock()
        mock_session_class.return_value = mock_session
        
        import requests
        mock_session.get.side_effect = requests.ConnectionError("Network unreachable")
        
        # Run the task
        poll_taxii_connector_task(
            job_id=connector_job.id,
            connector_id=connector.id,
            added_after=None,
        )
        
        # Verify job failed
        connector_job.refresh_from_db()
        assert connector_job.state == models.JobStates.FAILED
        assert len(connector_job.errors) > 0
        assert "Network unreachable" in connector_job.errors[0]
    
    @patch('cyberthreatexchange.worker.tasks.make_uploads')
    @patch('cyberthreatexchange.worker.tasks.rerun_relationship_uploads', return_value=([], {}))
    @patch('requests.Session')
    def test_poll_updates_feed_last_run(self, mock_session_class, mock_make_uploads, mock_rerun, connector_job, connector, feed):
        """Test that feed.last_run is updated after polling."""
        mock_session = Mock()
        mock_session_class.return_value = mock_session
        
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'objects': [{'type': 'indicator', 'id': 'indicator--1'}],
            'more': False,
        }
        mock_response.headers = {'X-TAXII-Date-Added-Last': '2024-01-15T10:00:00.000Z'}
        mock_session.get.return_value = mock_response
        
        # Record feed's last_run before task
        initial_last_run = feed.last_run
        
        # Run the task
        poll_taxii_connector_task(
            job_id=connector_job.id,
            connector_id=connector.id,
            added_after=None,
        )
        
        # Verify feed.last_run was updated
        feed.refresh_from_db()
        assert feed.last_run is not None
        if initial_last_run:
            assert feed.last_run > initial_last_run
    
    @patch('cyberthreatexchange.worker.tasks.make_uploads')
    @patch('cyberthreatexchange.worker.tasks.rerun_relationship_uploads', return_value=([], {}))
    @patch('requests.Session')
    def test_poll_arango_extra_includes_connector_id(self, mock_session_class, mock_rerun, mock_make_uploads, connector_job, connector):
        """Test that connector ID is passed to make_uploads in arango_extra."""
        mock_session = Mock()
        mock_session_class.return_value = mock_session
        
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'objects': [{'type': 'indicator', 'id': 'indicator--1'}],
            'more': False,
        }
        mock_response.headers = {'X-TAXII-Date-Added-Last': '2024-01-15T10:00:00.000Z'}
        mock_session.get.return_value = mock_response
        
        # Run the task
        poll_taxii_connector_task(
            job_id=connector_job.id,
            connector_id=connector.id,
            added_after=None,
        )
        
        # Verify arango_extra contains connector ID (check first call for objects)
        assert mock_make_uploads.call_count == 2
        first_call = mock_make_uploads.call_args_list[0]
        call_kwargs = first_call[1]
        assert call_kwargs['arango_extra'] == {'_ctx_connector_id': str(connector.id)}
    
    @patch('cyberthreatexchange.worker.tasks.make_uploads')
    @patch('cyberthreatexchange.worker.tasks.rerun_relationship_uploads', return_value=([], {}))
    @patch('requests.Session')
    def test_poll_with_iso_string_added_after(self, mock_session_class, mock_make_uploads, mock_rerun, connector_job, connector):
        """Test that added_after as ISO string is handled correctly."""
        mock_session = Mock()
        mock_session_class.return_value = mock_session
        
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'objects': [],
            'more': False,
        }
        mock_response.headers = {'X-TAXII-Date-Added-Last': '2024-01-15T10:00:00.000Z'}
        mock_session.get.return_value = mock_response
        
        # Pass added_after as ISO string
        added_after_str = "2024-01-10T00:00:00.000Z"
        
        # Run the task
        poll_taxii_connector_task(
            job_id=connector_job.id,
            connector_id=connector.id,
            added_after=added_after_str,
        )
        
        # Verify filter was sent correctly
        call_args = mock_session.get.call_args
        assert call_args[1]['params'] == {'added_after': added_after_str}
        
        # Verify job completed
        connector_job.refresh_from_db()
        assert connector_job.state == models.JobStates.COMPLETED
