"""
Tests for serializers.
"""

import pytest
from unittest.mock import MagicMock, Mock, patch
from rest_framework.exceptions import ValidationError
from cyberthreatexchange.server import serializers, models
from tests.src.data import (
    apt29_malware,
    apt29_threat_actor,
    spearphishing_attack,
    victim_organization,
    network_indicator,
    apt29_campaign,
    non_relationship_objects,
)


class TestStixObjectsPlaceholderSerializer:
    """Test StixObjectsPlaceholderSerializer."""

    def test_serializer_accepts_valid_data(self):
        """Test that serializer accepts valid STIX object structure."""
        data = {
            "type": "malware",
            "id": "malware--a1b2c3d4-e5f6-4a5b-8c9d-0e1f2a3b4c5d",
        }
        serializer = serializers.StixObjectsPlaceholderSerializer(data=data)
        assert serializer.is_valid()
        assert serializer.validated_data["type"] == "malware"
        assert (
            serializer.validated_data["id"]
            == "malware--a1b2c3d4-e5f6-4a5b-8c9d-0e1f2a3b4c5d"
        )


class TestWarningSerializer:
    def test_serializer_with_warning_data(self):
        data = {
            "type": "duplicate_object",
            "message": "Duplicate object removed before upload",
            "stix_id": "malware--a1b2c3d4-e5f6-4a5b-8c9d-0e1f2a3b4c5d",
            "resolution": "skipped",
            "index": 0,
        }
        serializer = serializers.WarningSerializer(data=data)
        serializer.is_valid(raise_exception=True)
        assert serializer.validated_data["type"] == "duplicate_object"
        assert serializer.validated_data["resolution"] == "skipped"


class TestJobSerializer:
    def test_serializer_excludes_sensitive_fields(self, feed):
        job = models.Job.objects.create(
            feed=feed,
            type=models.JobTypes.BUNDLE_UPLOAD,
            state=models.JobStates.COMPLETED,
            payload={"type": "bundle", "objects": []},
            warnings=[{"message": "test"}],
        )

        serializer = serializers.JobSerializer(job)
        assert serializer.data['start_time']
        assert serializer.data == {
            "id": str(job.id),
            "feed_id": "ec8fec0c-10d8-476f-8a51-0c71d94bbda7",
            "type": "bundle-upload",
            "state": "completed",
            "errors": [],
            "start_time": serializer.data["start_time"],
            "completion_time": None,
        }

    def test_serializer_includes_job_metadata(self, feed):
        job = models.Job.objects.create(
            feed=feed,
            type=models.JobTypes.BUNDLE_UPLOAD,
            state=models.JobStates.PROCESSING,
        )

        serializer = serializers.JobSerializer(job)
        assert serializer.data["type"] == models.JobTypes.BUNDLE_UPLOAD
        assert serializer.data["state"] == models.JobStates.PROCESSING
        assert "id" in serializer.data


class TestJobDetailSerializer:
    def test_serializer_includes_warnings(self, feed):
        """Test that warnings are included in detail serializer."""
        warnings = [
            {
                "type": "duplicate_object",
                "message": "Duplicate removed",
                "id": "malware--c3d4e5f6-a7b8-6c7d-0e1f-2a3b4c5d6e7f",
                "resolution": "skipped",
                "index": 0,
            }
        ]
        job = models.Job.objects.create(
            feed=feed,
            type=models.JobTypes.BUNDLE_UPLOAD,
            state=models.JobStates.COMPLETED,
            payload={"type": "bundle", "objects": []},
            warnings=warnings,
        )

        serializer = serializers.JobDetailSerializer(job)
        assert "warnings" in serializer.data
        assert len(serializer.data["warnings"]) == 1
        assert serializer.data["warnings"][0]["type"] == "duplicate_object"

    def test_serializer_includes_payload(self, feed):
        """Test that payload is included in detail serializer."""
        payload = {
            "type": "bundle",
            "id": "bundle--d4e5f6a7-b8c9-7d8e-1f2a-3b4c5d6e7f8a",
            "objects": [],
        }
        job = models.Job.objects.create(
            feed=feed,
            type=models.JobTypes.BUNDLE_UPLOAD,
            state=models.JobStates.COMPLETED,
            payload=payload.copy(),
        )

        serializer = serializers.JobDetailSerializer(job)
        assert "payload" in serializer.data
        assert serializer.data["payload"] == payload


class TestIdentitySerializer:
    def test_serializer_with_identity(self, identity):
        serializer = serializers.IdentitySerializer(identity)
        assert serializer.data["name"] == "Test Identity"
        assert serializer.data["identity_class"] == "organization"
        # Match the fixture ID from conftest.py
        assert "identity--" in serializer.data["id"]

    def test_serializer_create_identity(self):
        data = {
            "id": "identity--f6a7b8c9-d0e1-9f0a-3b4c-5d6e7f8a9b0c",
            "name": "New Identity",
            "identity_class": "individual",
        }
        serializer = serializers.IdentitySerializer(data=data)
        assert serializer.is_valid()
        identity = serializer.save()
        assert identity.name == "New Identity"
        assert identity.identity_class == "individual"


class TestFeedSerializer:
    def test_serializer_with_feed(self, feed):
        """Test serialization of Feed instance."""
        serializer = serializers.FeedSerializer(feed)
        assert serializer.data["name"] == "Test Feed"
        assert "identity" in serializer.data
        assert serializer.data["identity"]["name"] == "Test Identity"
        assert "collection_name" not in serializer.data

    def test_serializer_create_feed(self, identity):
        """Test creating feed with serializer."""
        data = {
            "name": "New Feed",
            "description": "A new feed",
            "identity_id": identity.id,
            "tags": ["test"],
        }
        serializer = serializers.FeedSerializer(data=data)
        assert serializer.is_valid()
        feed = serializer.save()
        assert feed.name == "New Feed"
        assert feed.identity == identity

    def test_serializer_update_feed_name(self, feed):
        """Test updating feed with serializer."""
        data = {"name": "Updated Feed Name"}
        serializer = serializers.FeedSerializer(feed, data=data, partial=True)
        assert serializer.is_valid()
        updated_feed = serializer.save()
        assert updated_feed.name == "Updated Feed Name"

    def test_identity_id_required_for_create(self):
        """Test that identity_id is required when creating."""
        data = {"name": "Feed Without Identity", "description": "Missing identity"}
        serializer = serializers.FeedSerializer(data=data)
        assert not serializer.is_valid()
        assert "identity_id" in serializer.errors

    def test_identity_id_optional_for_update(self, feed):
        """Test that identity_id is optional when updating."""
        data = {"description": "Updated description"}
        serializer = serializers.FeedSerializer(feed, data=data, partial=True)
        assert serializer.is_valid()
        # identity_id should not be required
        assert serializer.fields["identity_id"].required is False


class TestSTIXObjectSerializer:
    def serializer_with_context(self, context=None):
        s = serializers.STIXObjectSerializer()
        s.parent = MagicMock()
        s.parent._context = context
        s.parent.parent = None
        return s

    @pytest.fixture(autouse=True)
    def set_monkeypatch(self, monkeypatch):
        self.monkeypatch = monkeypatch
                                

    def test_serializer_accepts_valid_stix_object(self):
        """Test that valid STIX object passes validation."""
        serializer = serializers.STIXObjectSerializer()
        result = serializer.to_internal_value(apt29_malware)
        assert result == apt29_malware

    def test_serializer_rejects_non_dict(self):
        """Test that non-dict data is rejected."""
        serializer = serializers.STIXObjectSerializer()
        with pytest.raises(ValidationError) as exc_info:
            serializer.to_internal_value("not a dict")
        assert "must be a JSON object" in str(exc_info.value)

    def test_serializer_rejects_invalid_stix(self):
        """Test that invalid STIX object is rejected."""
        invalid_stix = {
            "type": "malware",
            # Missing required fields like id, created, modified
        }
        serializer = serializers.STIXObjectSerializer()
        with pytest.raises(ValidationError) as exc_info:
            serializer.to_internal_value(invalid_stix)
        assert "Invalid STIX object" in str(exc_info.value)

    def test_versioning_validation_created_mismatch(self):
        existing = {
            "id": "malware--b86c76a7-7f4b-4517-9c9c-972f19a1aecf",
            "created": "2020-01-01T00:00:00.000Z",
            "modified": "2020-01-01T00:00:00.000Z",
        }
        new_obj = apt29_malware.copy()
        new_obj["id"] = "malware--b86c76a7-7f4b-4517-9c9c-972f19a1aecf"
        new_obj["created"] = "2020-02-01T00:00:00.000Z"  # Different
        new_obj["modified"] = "2020-02-01T00:00:00.000Z"

        context = {
            "existing_objects": {
                "malware--b86c76a7-7f4b-4517-9c9c-972f19a1aecf": existing
            }
        }
        serializer = self.serializer_with_context(context=context)

        with pytest.raises(ValidationError) as exc_info:
            serializer.to_internal_value(new_obj)
        assert "created" in exc_info.value.detail

    def test_versioning_validation_modified_not_greater(self):
        existing = {
            "id": "malware--57e7f500-7282-46c0-bb1a-aff96f554d01",
            "created": "2020-01-01T00:00:00.000Z",
            "modified": "2020-02-01T00:00:00.000Z",
        }
        new_obj = apt29_malware.copy()
        new_obj["id"] = "malware--57e7f500-7282-46c0-bb1a-aff96f554d01"
        new_obj["created"] = "2020-01-01T00:00:00.000Z"
        new_obj["modified"] = "2020-01-15T00:00:00.000Z"  # Not greater

        context = {
            "existing_objects": {
                "malware--57e7f500-7282-46c0-bb1a-aff96f554d01": existing
            }
        }
        serializer = self.serializer_with_context(context=context)

        with pytest.raises(ValidationError) as exc_info:
            serializer.to_internal_value(new_obj)
        assert "modified" in exc_info.value.detail

    def test_versioning_validation_created_by_ref_mismatch(self):
        existing = {
            "id": "malware--57e7f500-7282-46c0-bb1a-aff96f554d01",
            "created": "2020-01-01T00:00:00.000Z",
            "modified": "2020-01-01T00:00:00.000Z",
            "created_by_ref": "identity--a1b2c3d4-e5f6-4a5b-8c9d-0e1f2a3b4c5d",
        }
        new_obj = apt29_malware.copy()
        new_obj["id"] = "malware--57e7f500-7282-46c0-bb1a-aff96f554d01"
        new_obj["created"] = "2020-01-01T00:00:00.000Z"
        new_obj["modified"] = "2020-02-01T00:00:00.000Z"
        new_obj["created_by_ref"] = (
            "identity--b2c3d4e5-f6a7-5b6c-9d0e-1f2a3b4c5d6e"  # Different
        )

        context = {
            "existing_objects": {
                "malware--57e7f500-7282-46c0-bb1a-aff96f554d01": existing
            }
        }
        serializer = self.serializer_with_context(context=context)

        with pytest.raises(ValidationError) as exc_info:
            serializer.to_internal_value(new_obj)
        assert "created_by_ref" in exc_info.value.detail


class TestBundleSerializer:

    def test_serializer_accepts_valid_bundle(self):
        bundle_data = {
            "type": "bundle",
            "id": "bundle--d0e1f2a3-b4c5-3d4e-7f8a-9b0c1d2e3f4a",
            "objects": [apt29_malware, apt29_threat_actor],
        }
        serializer = serializers.BundleSerializer(data=bundle_data)
        assert serializer.is_valid()
        assert len(serializer.validated_data["objects"]) == 2

    def test_serializer_rejects_non_bundle_type(self):
        data = {
            "type": "not-bundle",
            "id": "bundle--e1f2a3b4-c5d6-4e5f-8a9b-0c1d2e3f4a5b",
            "objects": [apt29_campaign],
        }
        serializer = serializers.BundleSerializer(data=data)
        assert not serializer.is_valid()
        assert "type" in serializer.errors or "non_field_errors" in serializer.errors

    def test_serializer_rejects_empty_objects(self):
        data = {
            "type": "bundle",
            "id": "bundle--f2a3b4c5-d6e7-5f6a-9b0c-1d2e3f4a5b6c",
            "objects": [],
        }
        serializer = serializers.BundleSerializer(data=data)
        assert not serializer.is_valid()
        assert "objects" in serializer.errors

    def test_serializer_validates_each_object(self):
        invalid_obj = {
            "type": "malware",
            # Missing required fields
        }
        data = {
            "type": "bundle",
            "id": "bundle--a3b4c5d6-e7f8-6a7b-0c1d-2e3f4a5b6c7d",
            "objects": [apt29_malware, invalid_obj],
        }
        serializer = serializers.BundleSerializer(data=data)
        assert not serializer.is_valid()
        assert "objects" in serializer.errors


class TestWarningAwareListField:
    def get_serializer(self, context=None):
        field = serializers.WarningAwareListField(
            child=serializers.STIXObjectSerializer()
        )
        field.parent = Mock()
        field.parent._context = context
        field.parent.parent = None
        return field
    
    def test_field_skips_warned_objects(self):
        """Test that objects with warnings are skipped."""
        warnings = {1: {"message": "Skip this", "resolution": "skipped"}}
        context = {"warnings": warnings}

        field = self.get_serializer(context=context)


        data = [apt29_malware, apt29_threat_actor, spearphishing_attack]
        result = field.run_child_validation(data)

        # Should skip index 1 (apt29_threat_actor)
        assert len(result) == 2

    def test_field_includes_non_warned_objects(self):
        """Test that objects without warnings are included."""
        context = {"warnings": {}}

        field = self.get_serializer(context=context)
        data = [apt29_malware, apt29_threat_actor]
        result = field.run_child_validation(data)

        assert len(result) == 2

    def test_field_collects_validation_errors(self):
        """Test that validation errors are collected by index."""
        context = {"warnings": {}}

        field = self.get_serializer(context=context)


        invalid_obj = {"type": "malware"}  # Missing required fields
        data = [apt29_malware, invalid_obj]

        with pytest.raises(ValidationError) as exc_info:
            field.run_child_validation(data)

        # Should have error at index 1
        assert 1 in exc_info.value.detail


class TestStixVersionsSerializer:
    """Test StixVersionsSerializer."""

    def test_serializer_with_versions_data(self):
        """Test serialization of versions data."""
        data = {
            "latest": "2020-03-15T10:00:00.000Z",
            "versions": [
                "2020-01-15T10:00:00.000Z",
                "2020-02-15T10:00:00.000Z",
                "2020-03-15T10:00:00.000Z",
            ],
        }
        serializer = serializers.StixVersionsSerializer(data=data)
        assert serializer.is_valid()
        assert len(serializer.validated_data["versions"]) == 3

    def test_serializer_allows_null_latest(self):
        """Test that latest can be null."""
        data = {"latest": None, "versions": []}
        serializer = serializers.StixVersionsSerializer(data=data)
        assert serializer.is_valid()
        assert serializer.validated_data["latest"] is None
