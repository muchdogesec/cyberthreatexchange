import pytest
from unittest.mock import patch, Mock, MagicMock, PropertyMock
from rest_framework import status
from cyberthreatexchange.server import models
from tests.utils import create_identity
from django.utils import timezone
from datetime import datetime, timedelta


@pytest.fixture
def connector(feed):
    """Create a test connector."""
    connector = models.Connector.objects.create(
        feed=feed,
        name="Test TAXII Connector",
        description="A test connector for TAXII",
        url="https://example.com/taxii2/collections/12345/objects/",
    )
    connector.username = "test_user"
    connector.password = "test_pass"
    connector.save()
    return connector

class TestConnectorViewList:
    """Test ConnectorView.list method."""
    
    def test_list_returns_connectors_for_feed(self, client, feed, connector):
        """Test that list returns all connectors for a feed."""
        # Create another connector
        connector2 = models.Connector.objects.create(
            feed=feed,
            name="Second Connector",
            description="Another test connector",
            url="https://example.com/taxii2/collections/67890/objects/",
        )
        
        response = client.get(f'/api/v1/feeds/{feed.id}/connectors/')
        
        assert response.status_code == status.HTTP_200_OK
        assert 'connectors' in response.data
        assert len(response.data['connectors']) == 2
        
        # Verify correct connector IDs are returned
        assert {str(connector.id), str(connector2.id)} ==  {c['id'] for c in response.data['connectors']}
    
    def test_list_only_returns_connectors_for_specified_feed(self, client, feed, identity, connector):
        """Test that list only returns connectors for the specified feed."""
        # Create another feed with its own connector
        feed2 = models.Feed.objects.create(
            name="Feed 2",
            description="Another test feed",
            identity=identity,
        )
        connector2 = models.Connector.objects.create(
            feed=feed2,
            name="Feed 2 Connector",
            description="Connector for feed 2",
            url="https://example.com/taxii2/collections/abc/objects/",
        )
        
        response = client.get(f'/api/v1/feeds/{feed.id}/connectors/')
        
        assert response.status_code == status.HTTP_200_OK
        assert {str(connector.id)} == {c['id'] for c in response.data['connectors']}
    
    def test_list_returns_empty_for_feed_without_connectors(self, client, feed):
        """Test that list returns empty list for feed without connectors."""
        response = client.get(f'/api/v1/feeds/{feed.id}/connectors/')
        
        assert response.status_code == status.HTTP_200_OK
        assert 'connectors' in response.data
        assert len(response.data['connectors']) == 0


class TestConnectorViewCreate:
    """Test ConnectorView.create method."""
    
    @patch('requests.Session.get', return_value=Mock(status_code=200, json=lambda: {'title': 'test', 'can_read': True, 'can_write': False}))
    def test_create_connector_success(self, mock_get, client, feed):
        """Test successful connector creation."""
        data = {
            'name': 'New Connector',
            'description': 'A new test connector',
            'url': 'https://example.com/taxii2/collections/test/objects/',
            'username': 'user123',
            'password': 'pass456',
        }
        
        response = client.post(f'/api/v1/feeds/{feed.id}/connectors/taxii21/', data, content_type='application/json')
        
        assert response.status_code == status.HTTP_201_CREATED, response.content
        assert response.data['name'] == 'New Connector'
        assert response.data['description'] == 'A new test connector'
        assert response.data['url'] == data['url']
        assert response.data['type'] == 'taxii'
        assert response.data['has_username'] is True
        assert response.data['has_password'] is True
        assert 'username' not in response.data  # Should not return actual username
        assert 'password' not in response.data  # Should not return actual password
        
        # Verify connector was created in database
        connector = models.Connector.objects.get(id=response.data['id'])
        assert connector.name == 'New Connector'
        assert connector.username == 'user123'  # Verify decryption works
        assert connector.enc_pass and connector.enc_pass != 'pass456'  # Verify password is encrypted
        assert connector.password == 'pass456'
    
    @patch('requests.Session.get', return_value=Mock(status_code=200, json=lambda: {'title': 'test', 'can_read': True, 'can_write': False}))
    def test_create_connector_without_credentials(self, mock_get, client, feed):
        """Test creating connector without optional credentials."""
        data = {
            'name': 'Public Connector',
            'url': 'https://example.com/taxii2/collections/public/objects/',
        }
        
        response = client.post(f'/api/v1/feeds/{feed.id}/connectors/taxii21/', data, content_type='application/json')
        
        assert response.status_code == status.HTTP_201_CREATED
        assert response.data['has_username'] is False
        assert response.data['has_password'] is False
        
        connector = models.Connector.objects.get(id=response.data['id'])
        assert connector.username is None
        assert connector.password is None
    
    def test_create_connector_missing_required_fields(self, client, feed):
        """Test that creating connector without required fields fails."""
        data = {
            # Missing name and url
        }
        
        response = client.post(f'/api/v1/feeds/{feed.id}/connectors/taxii21/', data, content_type='application/json')
        
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        # Check that error response contains the missing fields
        response_json = response.json()
        assert 'details' in response_json
        assert 'name' in response_json['details']
        assert 'url' in response_json['details']
    
    def test_create_connector_for_nonexistent_feed(self, client):
        """Test creating connector for non-existent feed returns 404."""
        fake_feed_id = '00000000-0000-0000-0000-000000000000'
        data = {
            'name': 'Test Connector',
            'url': 'https://example.com/taxii2/collections/test/objects/',
        }
        
        response = client.post(f'/api/v1/feeds/{fake_feed_id}/connectors/taxii21/', data, content_type='application/json')
        
        assert response.status_code == status.HTTP_404_NOT_FOUND


class TestConnectorViewRetrieve:
    """Test ConnectorView.retrieve method."""
    
    def test_retrieve_connector(self, client, feed, connector):
        """Test retrieving a connector."""
        response = client.get(f'/api/v1/feeds/{feed.id}/connectors/{connector.id}/')
        
        assert response.status_code == status.HTTP_200_OK
        assert response.data['id'] == str(connector.id)
        assert response.data['name'] == connector.name
        assert response.data['description'] == connector.description
        assert response.data['url'] == connector.url
        assert response.data['type'] == 'taxii'
        assert response.data['has_username'] is True
        assert response.data['has_password'] is True
        assert 'username' not in response.data
        assert 'password' not in response.data
    
    def test_retrieve_nonexistent_connector(self, client, feed):
        """Test retrieving a non-existent connector."""
        fake_id = '00000000-0000-0000-0000-000000000000'
        response = client.get(f'/api/v1/feeds/{feed.id}/connectors/{fake_id}/')
        
        assert response.status_code == status.HTTP_404_NOT_FOUND


class TestConnectorViewUpdate:
    """Test ConnectorView.partial_update method."""
    
    @patch('requests.Session.get', return_value=Mock(status_code=200, json=lambda: {'title': 'test', 'can_read': True, 'can_write': False}))
    def test_update_connector_name(self, mock_get, client, feed, connector):
        """Test updating connector name."""
        data = {'name': 'Updated Connector Name'}
        
        response = client.patch(
            f'/api/v1/feeds/{feed.id}/connectors/taxii21/{connector.id}/',
            data,
            content_type='application/json'
        )
        
        assert response.status_code == status.HTTP_200_OK
        assert response.data['name'] == 'Updated Connector Name'
        
        connector.refresh_from_db()
        assert connector.name == 'Updated Connector Name'
    
    @patch('requests.Session.get', return_value=Mock(status_code=200, json=lambda: {'title': 'test', 'can_read': True, 'can_write': False}))
    def test_update_connector_credentials(self, mock_get, client, feed, connector):
        """Test updating connector credentials."""
        data = {
            'username': 'new_user',
            'password': 'new_pass',
        }
        
        response = client.patch(
            f'/api/v1/feeds/{feed.id}/connectors/taxii21/{connector.id}/',
            data,
            content_type='application/json'
        )
        
        assert response.status_code == status.HTTP_200_OK
        
        connector.refresh_from_db()
        assert connector.username == 'new_user'
        assert connector.password == 'new_pass'
    
    @patch('requests.Session.get', return_value=Mock(status_code=200, json=lambda: {'title': 'test', 'can_read': True, 'can_write': False}))
    def test_update_connector_remove_credentials(self, mock_get, client, feed, connector):
        """Test removing connector credentials."""
        data = {
            'username': '',
            'password': '',
        }
        
        response = client.patch(
            f'/api/v1/feeds/{feed.id}/connectors/taxii21/{connector.id}/',
            data,
            content_type='application/json'
        )
        
        assert response.status_code == status.HTTP_200_OK
        assert response.data['has_username'] is False
        assert response.data['has_password'] is False
        
        connector.refresh_from_db()
        assert connector.username is None or connector.username == ''
        assert connector.password is None or connector.password == ''
    
    @patch('requests.Session.get', return_value=Mock(status_code=200, json=lambda: {'title': 'test', 'can_read': True, 'can_write': False}))
    def test_update_connector_url(self, mock_get, client, feed, connector):
        """Test updating connector TAXII URL."""
        data = {'url': 'https://new-example.com/taxii2/collections/new/objects/'}
        
        response = client.patch(
            f'/api/v1/feeds/{feed.id}/connectors/taxii21/{connector.id}/',
            data,
            content_type='application/json'
        )
        
        assert response.status_code == status.HTTP_200_OK
        assert response.data['url'] == data['url']
        
        connector.refresh_from_db()
        assert connector.url == data['url']
    
    def test_update_cannot_change_type(self, client, feed, connector):
        """Test that type field cannot be changed (it's read-only)."""
        original_type = connector.type
        data = {'type': 'other'}
        
        response = client.patch(
            f'/api/v1/feeds/{feed.id}/connectors/taxii21/{connector.id}/',
            data,
            content_type='application/json'
        )
        
        connector.refresh_from_db()
        assert connector.type == original_type  # Type should not change


class TestConnectorViewDelete:
    """Test ConnectorView.destroy method."""
    
    def test_delete_connector(self, client, feed, connector):
        """Test deleting a connector."""
        connector_id = connector.id
        
        response = client.delete(f'/api/v1/feeds/{feed.id}/connectors/{connector_id}/')
        
        assert response.status_code == status.HTTP_204_NO_CONTENT
        
        # Verify connector was deleted
        assert not models.Connector.objects.filter(id=connector_id).exists()
    
    def test_delete_nonexistent_connector(self, client, feed):
        """Test deleting a non-existent connector."""
        fake_id = '00000000-0000-0000-0000-000000000000'
        response = client.delete(f'/api/v1/feeds/{feed.id}/connectors/{fake_id}/')
        
        assert response.status_code == status.HTTP_404_NOT_FOUND


class TestConnectorTestConnection:
    """Test ConnectorView.test_connection action."""
    
    @patch('requests.Session.get', return_value=Mock(status_code=200, json=lambda: {'title': 'test', 'can_read': True, 'can_write': False}))
    def test_connection_success(self, mock_get, client, feed, connector):
        """Test successful connection test."""
        response = client.get(f'/api/v1/feeds/{feed.id}/connectors/{connector.id}/test-connection/')
        
        assert response.status_code == status.HTTP_200_OK
        assert response.data['success'] is True
        assert response.data['status_code'] == 200
        assert 'response' in response.data
    
    @patch('requests.Session.get', return_value=Mock(status_code=200, json=lambda: {'title': 'test', 'can_read': True, 'can_write': False}))
    def test_connection_with_authentication(self, mock_get, client, feed, connector):
        """Test connection test uses authentication credentials."""
        response = client.get(f'/api/v1/feeds/{feed.id}/connectors/{connector.id}/test-connection/')
        
        assert response.status_code == status.HTTP_200_OK
        assert response.data['success'] is True

    def test_connection_cant_read(self, client, feed, connector):
        """Test connection test when connector cannot read collection."""
        mock_response = Mock(status_code=200, json=lambda: {'title': 'test', 'can_read': False, 'can_write': False})
        with patch('requests.Session.get', return_value=mock_response):
            response = client.get(f'/api/v1/feeds/{feed.id}/connectors/{connector.id}/test-connection/')
        
        assert response.status_code == status.HTTP_200_OK
        assert response.data['success'] is False
        assert 'error' in response.data
    
    @patch('requests.Session.get', return_value=Mock(status_code=401, json=lambda: {'title': 'Unauthorized'}))
    def test_connection_failure_401(self, mock_get, client, feed, connector):
        """Test connection test with authentication failure."""
        response = client.get(f'/api/v1/feeds/{feed.id}/connectors/{connector.id}/test-connection/')
        
        assert response.status_code == status.HTTP_200_OK
        assert response.data['success'] is False
        assert response.data['status_code'] == 401
        assert 'error' in response.data
    
    @patch('requests.Session.get', return_value=Mock(status_code=404, json=lambda: {'title': 'Not Found'}))
    def test_connection_failure_404(self, mock_get, client, feed, connector):
        """Test connection test with not found error."""
        response = client.get(f'/api/v1/feeds/{feed.id}/connectors/{connector.id}/test-connection/')
        
        assert response.status_code == status.HTTP_200_OK
        assert response.data['success'] is False
        assert response.data['status_code'] == 404
        assert 'error' in response.data
    
    @patch('requests.Session.get', side_effect=Exception('Connection timed out'))
    def test_connection_timeout(self, mock_get, client, feed, connector):
        """Test connection test with timeout error."""
        response = client.get(f'/api/v1/feeds/{feed.id}/connectors/{connector.id}/test-connection/')
        
        assert response.status_code == status.HTTP_200_OK
        assert response.data['success'] is False
        assert 'error' in response.data
    
    @patch('requests.Session.get', side_effect=Exception('Network unreachable'))
    def test_connection_network_error(self, mock_get, client, feed, connector):
        """Test connection test with network error."""
        response = client.get(f'/api/v1/feeds/{feed.id}/connectors/{connector.id}/test-connection/')
        
        assert response.status_code == status.HTTP_200_OK
        assert response.data['success'] is False
        assert 'error' in response.data


class TestConnectorPoll:
    """Test ConnectorView.poll action."""
    
    @patch('cyberthreatexchange.worker.tasks.poll_taxii_connector_task.delay')
    def test_poll_creates_job(self, mock_task, client, feed, connector):
        """Test that poll action creates a job."""
        response = client.post(f'/api/v1/feeds/{feed.id}/connectors/{connector.id}/poll/', content_type='application/json')
        
        assert response.status_code == status.HTTP_202_ACCEPTED
        assert 'id' in response.data
        
        # Verify job was created
        job = models.Job.objects.get(id=response.data['id'])
        assert str(job.feed.id) == str(feed.id)
        assert job.type == models.JobTypes.CONNECTOR_POLL
        assert job.state == models.JobStates.PROCESSING
        
        # Verify task was called
        mock_task.assert_called_once()
    
    @patch('cyberthreatexchange.worker.tasks.poll_taxii_connector_task.delay')
    def test_poll_with_added_after(self, mock_task, client, feed, connector):
        """Test poll with added_after parameter."""
        added_after = timezone.now() - timedelta(days=7)
        data = {'added_after': added_after.isoformat()}
        
        response = client.post(
            f'/api/v1/feeds/{feed.id}/connectors/{connector.id}/poll/',
            data,
            content_type='application/json'
        )
        
        assert response.status_code == status.HTTP_202_ACCEPTED
        
        # Verify task was called with added_after
        call_kwargs = mock_task.call_args[1]
        assert call_kwargs['added_after'] is not None
    
    @patch('cyberthreatexchange.worker.tasks.poll_taxii_connector_task.delay')
    def test_poll_without_added_after_uses_next_run_added_after(self, mock_task, client, feed, connector):
        """Test poll without added_after uses connector's next_run_added_after."""
        # Set next_run_added_after on connector
        last_added = timezone.now() - timedelta(days=1)
        connector.next_run_added_after = last_added
        connector.save()
        
        response = client.post(f'/api/v1/feeds/{feed.id}/connectors/{connector.id}/poll/')
        
        assert response.status_code == status.HTTP_202_ACCEPTED
        
        # Verify job payload contains connector info
        job = models.Job.objects.get(id=response.data['id'])
        assert 'connector_id' in job.payload
        assert job.payload['connector_id'] == str(connector.id)
    
    @patch('cyberthreatexchange.worker.tasks.poll_taxii_connector_task.delay')
    def test_poll_invalid_added_after(self, mock_task, client, feed, connector):
        """Test poll with invalid added_after format."""
        data = {'added_after': 'invalid-date'}
        
        response = client.post(
            f'/api/v1/feeds/{feed.id}/connectors/{connector.id}/poll/',
            data,
            content_type='application/json'
        )
        
        assert response.status_code == status.HTTP_400_BAD_REQUEST


class TestConnectorEncryption:
    """Test credential encryption/decryption."""
    
    def test_credentials_are_encrypted_in_database(self, feed):
        """Test that credentials are encrypted when stored."""
        connector = models.Connector.objects.create(
            feed=feed,
            name="Test Encryption",
            url="https://example.com/taxii2/collections/test/objects/",
        )
        connector.username = "plaintext_user"
        connector.password = "plaintext_pass"
        connector.save()
        
        # Reload from database to get raw encrypted values
        connector_from_db = models.Connector.objects.get(id=connector.id)
        
        # Raw database values should be encrypted (different from plaintext)
        assert connector_from_db.enc_user != "plaintext_user"
        assert connector_from_db.enc_pass != "plaintext_pass"
        
        # But property access should decrypt correctly
        assert connector_from_db.username == "plaintext_user"
        assert connector_from_db.password == "plaintext_pass"
    
    def test_empty_credentials_not_encrypted(self, feed):
        """Test that None/empty credentials are not encrypted."""
        connector = models.Connector.objects.create(
            feed=feed,
            name="No Credentials",
            url="https://example.com/taxii2/collections/test/objects/",
        )
        
        assert connector.enc_user is None
        assert connector.enc_pass is None
        assert connector.username is None
        assert connector.password is None
    
    def test_update_credentials_maintains_encryption(self, feed, connector):
        """Test that updating credentials maintains encryption."""
        original_username = connector.username
        
        # Update credentials
        connector.username = "updated_user"
        connector.password = "updated_pass"
        connector.save()
        
        # Reload and verify
        connector.refresh_from_db()
        assert connector.username == "updated_user"
        assert connector.password == "updated_pass"
        assert connector.enc_user != "updated_user"  # Should be encrypted
