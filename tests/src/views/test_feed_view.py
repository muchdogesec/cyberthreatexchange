import pytest
from unittest.mock import patch, Mock
from rest_framework import status
from rest_framework.response import Response
from cyberthreatexchange.server import models, serializers
from cyberthreatexchange.server.arango_helpers import ArangoDBHelper
from tests.src.data import all_objects
from tests.utils import create_identity



class TestFeedViewList:
    """Test FeedView.list method."""
    
    def test_list_returns_all_feeds(self, client, feed, identity):
        """Test that list returns all feeds."""
        # Create another feed
        feed2 = models.Feed.objects.create(
            name="Test Feed 2",
            description="Another test feed",
            identity=identity,
            tags=["test2"],
        )
        
        response = client.get('/api/v1/feeds/')
        
        assert response.status_code == status.HTTP_200_OK
        assert 'feeds' in response.data
        assert len(response.data['feeds']) >= 2
        
        # Verify correct feed IDs are returned
        returned_ids = {f['id'] for f in response.data['feeds']}
        assert str(feed.id) in returned_ids
        assert str(feed2.id) in returned_ids
    
    def test_list_filters_by_name(self, client, feed, identity):
        """Test that list can filter by name."""
        # Create feeds with different names
        feed2 = models.Feed.objects.create(
            name="Different Name",
            description="Another test feed",
            identity=identity,
        )
        
        response = client.get('/api/v1/feeds/', {'name': 'Test Feed'})
        
        assert response.status_code == status.HTTP_200_OK
        assert 'feeds' in response.data
        # Should only return the feed with "Test Feed" in the name
        feed_names = [f['name'] for f in response.data['feeds']]
        assert all('Test Feed' in name for name in feed_names)
        
        # Verify correct feed ID is returned and feed2 is not included
        returned_ids = [f['id'] for f in response.data['feeds']]
        assert str(feed.id) in returned_ids
        assert str(feed2.id) not in returned_ids
    
    def test_list_filters_by_tags(self, client, feed, identity):
        """Test that list can filter by tags."""
        # Create feed with different tags
        feed2 = models.Feed.objects.create(
            name="Feed 2",
            description="Another test feed",
            identity=identity,
            tags=["production", "critical"],
        )
        
        response = client.get('/api/v1/feeds/', {'tags': 'test'})
        
        assert response.status_code == status.HTTP_200_OK
        assert 'feeds' in response.data
        
        # Verify only feeds with 'test' tag are returned
        returned_ids = [f['id'] for f in response.data['feeds']]
        assert str(feed.id) in returned_ids
        assert str(feed2.id) not in returned_ids
    
    def test_list_filters_by_identity(self, client, feed, identity):
        """Test that list can filter by identity."""
        # Create another identity and feed
        identity2 = create_identity(
            id="identity--b468283c-1ec0-4f6a-a904-898a56a6df38",
            name="Other Identity",
            identity_class="individual",
        )
        feed2 = models.Feed.objects.create(
            name="Feed 2",
            description="Feed with different identity",
            identity=identity2,
        )
        
        response = client.get('/api/v1/feeds/', {'identity_id': str(identity.id)})
        
        assert response.status_code == status.HTTP_200_OK
        assert 'feeds' in response.data
        
        assert {f['identity_id'] for f in response.data['feeds']} == {str(identity.id)}

        returned_ids = [f['id'] for f in response.data['feeds']]
        assert str(feed.id) in returned_ids
        assert str(feed2.id) not in returned_ids


class TestFeedViewRetrieve:
    """Test FeedView.retrieve method."""
    
    def test_retrieve_returns_feed(self, client, feed):
        """Test that retrieve returns a single feed by ID."""
        response = client.get(f'/api/v1/feeds/{feed.id}/')
        
        assert response.status_code == status.HTTP_200_OK
        assert response.data['id'] == str(feed.id)
        assert response.data['name'] == feed.name
        assert response.data['description'] == feed.description
    
    def test_retrieve_nonexistent_feed_returns_404(self, client):
        """Test that retrieving a non-existent feed returns 404."""
        response = client.get('/api/v1/feeds/00000000-0000-0000-0000-000000000000/')
        
        assert response.status_code == status.HTTP_404_NOT_FOUND


class TestFeedViewCreate:
    """Test FeedView.create method."""
    
    def test_create_feed(self, client, identity):
        """Test that create creates a new feed."""
        feed_data = {
            'name': 'New Feed',
            'short_description': 'A newly created feed',
            'identity_id': str(identity.id),
            'tags': ['new', 'test'],
        }
        
        response = client.post('/api/v1/feeds/', feed_data, content_type='application/json')
        
        assert response.status_code == status.HTTP_201_CREATED
        assert response.data['name'] == 'New Feed'
        assert response.data['short_description'] == 'A newly created feed'
        assert response.data['tags'] == ['new', 'test']
        
        # Verify feed was created in database with correct ID
        feed = models.Feed.objects.get(id=response.data['id'])
        assert feed.name == 'New Feed'
        assert str(feed.id) == response.data['id']
    
    def test_create_feed_without_name_fails(self, client, identity):
        """Test that creating a feed without a name fails."""
        feed_data = {
            'description': 'Missing name',
            'identity': str(identity.id),
        }
        
        response = client.post('/api/v1/feeds/', feed_data, content_type='application/json')
        
        assert response.status_code == status.HTTP_400_BAD_REQUEST
    
    def test_create_feed_without_identity_fails(self, client):
        """Test that creating a feed without an identity fails."""
        feed_data = {
            'name': 'No Identity Feed',
            'description': 'Missing identity_id',
        }
        
        response = client.post('/api/v1/feeds/', feed_data, content_type='application/json')
        
        assert response.status_code == status.HTTP_400_BAD_REQUEST


    def test_create_feed_creates_arango_collections(self, client, identity):
        """Test that creating a feed also creates ArangoDB collections."""
        feed_data = {
            'name': 'Arango Feed',
            'short_description': 'Feed to test ArangoDB collections',
            'identity_id': str(identity.id),
        }
        
        response = client.post('/api/v1/feeds/', feed_data, content_type='application/json')
        
        assert response.status_code == status.HTTP_201_CREATED
        
        # Verify ArangoDB collections were created
        feed = models.Feed.objects.get(id=response.data['id'])
        helper = ArangoDBHelper(feed.vertex_collection, None)
        assert helper.db.has_collection(feed.vertex_collection)
        assert helper.db.has_collection(feed.edge_collection)


class TestFeedViewUpdate:
    """Test FeedView.partial_update method."""
    
    def test_update_feed_name(self, client, feed):
        """Test that partial_update can update feed name."""
        update_data = {'name': 'Updated Feed Name'}
        
        response = client.patch(f'/api/v1/feeds/{feed.id}/', update_data, content_type='application/json')
        
        assert response.status_code == status.HTTP_200_OK
        assert response.data['id'] == str(feed.id)
        assert response.data['name'] == 'Updated Feed Name'
        
        # Verify in database
        feed.refresh_from_db()
        assert feed.name == 'Updated Feed Name'
    
    def test_update_feed_description(self, client, feed):
        """Test that partial_update can update feed description."""
        update_data = {'description': 'Updated description'}
        
        response = client.patch(f'/api/v1/feeds/{feed.id}/', update_data, content_type='application/json')
        
        assert response.status_code == status.HTTP_200_OK
        assert response.data['id'] == str(feed.id)
        assert response.data['description'] == 'Updated description'
        
        # Verify in database
        feed.refresh_from_db()
        assert feed.description == 'Updated description'
    
    def test_update_feed_tags(self, client, feed):
        """Test that partial_update can update feed tags."""
        update_data = {'tags': ['updated', 'tags']}
        
        response = client.patch(f'/api/v1/feeds/{feed.id}/', update_data, content_type='application/json')
        
        assert response.status_code == status.HTTP_200_OK
        assert response.data['id'] == str(feed.id)
        assert response.data['tags'] == ['updated', 'tags']
        
        # Verify in database
        feed.refresh_from_db()
        assert feed.tags == ['updated', 'tags']
    
    def test_update_nonexistent_feed_returns_404(self, client):
        """Test that updating a non-existent feed returns 404."""
        update_data = {'name': 'Updated'}
        
        response = client.patch('/api/v1/feeds/00000000-0000-0000-0000-000000000000/', update_data, content_type='application/json')
        
        assert response.status_code == status.HTTP_404_NOT_FOUND


class TestFeedViewDestroy:
    """Test FeedView.destroy method."""
    
    def test_destroy_feed(self, client, identity):
        """Test that destroy deletes a feed."""
        # Create a feed to delete
        feed = models.Feed.objects.create(
            name="Feed to Delete",
            description="This feed will be deleted",
            identity=identity,
        )
        feed_id = feed.id
        
        response = client.delete(f'/api/v1/feeds/{feed_id}/')
        
        assert response.status_code == status.HTTP_204_NO_CONTENT
        
        # Verify feed was deleted from database
        assert not models.Feed.objects.filter(id=feed_id).exists()
        helper = ArangoDBHelper('', None)
        assert not helper.db.has_collection(feed.vertex_collection)
        assert not helper.db.has_collection(feed.edge_collection)
    
    def test_destroy_nonexistent_feed_returns_404(self, client):
        """Test that deleting a non-existent feed returns 404."""
        response = client.delete('/api/v1/feeds/00000000-0000-0000-0000-000000000000/')
        
        assert response.status_code == status.HTTP_404_NOT_FOUND


class TestFeedViewBundle:
    """Test FeedView.bundle custom action."""
    
    def test_bundle_creates_job(self, client, feed):
        """Test that posting a bundle creates a job."""
        bundle_data = {
            'type': 'bundle',
            'id': 'bundle--d1c612bc-146f-4b65-b7b0-9a54a14150a4',
            'objects': all_objects[:5],  # Use first 5 objects from test data
        }
        
        response = client.post(f'/api/v1/feeds/{feed.id}/bundle/', bundle_data, content_type='application/json')
        
        assert response.status_code == status.HTTP_202_ACCEPTED, response.content
        assert 'id' in response.data
        assert response.data['type'] == models.JobTypes.BUNDLE_UPLOAD
        
        # Verify job was created in processing state
        job = models.Job.objects.get(id=response.data['id'])
        assert str(job.feed.id) == str(feed.id)
        assert job.type == models.JobTypes.BUNDLE_UPLOAD
        assert job.state == models.JobStates.PROCESSING
    
    def test_bundle_with_valid_data_starts_processing(self, client, feed):  
        """Test that a valid bundle doesn't fail validation."""
        bundle_data = {
            'type': 'bundle',
            'id': 'bundle--a1b2c3d4-e5f6-4a5b-8c9d-0e1f2a3b4c5d',
            'objects': all_objects[:3],
        }
        
        # Mock both context building and serializer validation
        with patch('cyberthreatexchange.server.arango_helpers.ArangoDBHelper.build_context') as mock_build_context:
            with patch('cyberthreatexchange.server.views.serializers.BundleSerializer.is_valid') as mock_is_valid:
                mock_build_context.return_value = {'warnings': {}}
                mock_is_valid.return_value = True
                with patch('cyberthreatexchange.worker.tasks.upload_bundle_task.delay') as mock_task:
                    response = client.post(f'/api/v1/feeds/{feed.id}/bundle/', bundle_data, content_type='application/json')
        
        assert response.status_code == status.HTTP_202_ACCEPTED
        
        # Verify job was created and is in processing state
        job = models.Job.objects.get(id=response.data['id'])
        assert job.state == models.JobStates.PROCESSING
        assert len(job.errors) == 0
        
        # Verify task was called
        mock_task.assert_called_once()
    
    def test_bundle_with_invalid_data_fails(self, client, feed):
        """Test that an invalid bundle returns 400 without creating a job."""
        bundle_data = {
            'type': 'bundle',
            'id': 'invalid-bundle-id',  # Invalid STIX ID format
            'objects': [],
        }
        job_count_before = models.Job.objects.count()
        
        response = client.post(f'/api/v1/feeds/{feed.id}/bundle/', bundle_data, content_type='application/json')
        
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        # No job should have been created
        assert models.Job.objects.count() == job_count_before
    
    def test_bundle_without_objects_fails(self, client, feed):
        """Test that a bundle without objects returns 400 without creating a job."""
        bundle_data = {
            'type': 'bundle',
            'id': 'bundle--d1c612bc-146f-4b65-b7b0-9a54a14150a4',
        }
        job_count_before = models.Job.objects.count()
        
        response = client.post(f'/api/v1/feeds/{feed.id}/bundle/', bundle_data, content_type='application/json')
        
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        # No job should have been created
        assert models.Job.objects.count() == job_count_before
    
    def test_bundle_validation_context_includes_feed(self, client, feed):
        """Test that bundle validation context includes feed information."""
        bundle_data = {
            'type': 'bundle',
            'id': 'bundle--f1e2d3c4-b5a6-4978-8c9d-0e1f2a3b4c5d',
            'objects': all_objects[:2],
        }
        
        with patch('cyberthreatexchange.server.arango_helpers.ArangoDBHelper.build_context') as mock_build_context:
            mock_build_context.return_value = {}
            
            response = client.post(f'/api/v1/feeds/{feed.id}/bundle/', bundle_data, content_type='application/json')
            
            # Verify build_context was called with correct parameters
            mock_build_context.assert_called_once()
            call_args = mock_build_context.call_args
            # Check that feed was passed
            assert str(call_args[0][2].id) == str(feed.id)


class TestFeedViewGetValidationContext:
    """Test FeedView.get_validation_context method."""
    
    def test_get_validation_context_calls_arango_helper(self, client, feed):
        """Test that get_validation_context calls ArangoDBHelper.build_context."""
        bundle_data = {
            'type': 'bundle',
            'id': 'bundle--a1b2c3d4-e5f6-4a5b-8c9d-0e1f2a3b4c5d',
            'objects': all_objects[:1],
        }
        
        with patch('cyberthreatexchange.server.arango_helpers.ArangoDBHelper.build_context') as mock_build_context:
            mock_build_context.return_value = {'warnings': {}}
            
            response = client.post(f'/api/v1/feeds/{feed.id}/bundle/', bundle_data, content_type='application/json')
            
            # Verify build_context was called
            mock_build_context.assert_called_once()
