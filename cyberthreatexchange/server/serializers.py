import json
import stix2
import stix2.exceptions

from cyberthreatexchange.server.arango_helpers import ArangoDBHelper
from .models import Feed, Identity, Job, Connector
from rest_framework import serializers, validators
from dogesec_commons.utils.serializers import JSONSchemaSerializer

from rest_framework import serializers, validators
from django.core.exceptions import ValidationError as DjangoValidationError
from rest_framework.fields import get_error_detail
from drf_spectacular.utils import extend_schema_serializer
from cyberthreatexchange.worker.utils import md5_hash

class StixObjectsPlaceholderSerializer(serializers.Serializer):
    type = serializers.CharField()
    id = serializers.CharField()

class PlaceholderStixObjectSerializer(StixObjectsPlaceholderSerializer):
    pass

@extend_schema_serializer(many=False)
class BundleObjects(serializers.Serializer):
    next = serializers.CharField(required=False, allow_null=True)
    size = serializers.IntegerField(required=False, default=0)
    objects = StixObjectsPlaceholderSerializer(many=True)


class WarningSerializer(serializers.Serializer):
    type = serializers.CharField()
    message = serializers.CharField()
    stix_id = serializers.CharField(source="id")
    resolution = serializers.CharField()
    index = serializers.IntegerField()


class JobSerializer(serializers.ModelSerializer):
    feed_id = serializers.UUIDField(source="feed.id", read_only=True)

    class Meta:
        model = Job
        exclude = ["payload", "warnings", "feed", "errors"]


class JobDetailSerializer(serializers.ModelSerializer):
    feed_id = serializers.UUIDField(source="feed.id", read_only=True)
    warnings = WarningSerializer(many=True, read_only=True)

    class Meta:
        model = Job
        exclude = ["feed"]

class MicroFeedSerializer(serializers.ModelSerializer):
    """ Serializer for listing feeds that contain a specific STIX object. """

    class Meta:
        model = Feed
        fields = ["id", "name"]
        read_only_fields = fields

class ObjectFeedsDetailSerializer(serializers.Serializer):
    id = serializers.CharField(read_only=True, source="stix_id")
    feeds = MicroFeedSerializer(many=True, read_only=True)
    


class StixVersionsSerializer(serializers.Serializer):
    versions = serializers.ListField(child=serializers.DateTimeField())


class FeedSerializer(serializers.ModelSerializer):
    # identity = IdentitySerializer(read_only=True)
    identity_id = serializers.PrimaryKeyRelatedField(
        queryset=Identity.objects.all(),
        source="identity",
        help_text="The UUID of the Identity object to associate with this feed.",
        required=True,
    )
    short_description = serializers.CharField(max_length=256, required=True)
    description = serializers.CharField(required=False, allow_blank=True, allow_null=True, max_length=2000)

    class Meta:
        model = Feed
        exclude = ["collection_name", "identity"]
        read_only_fields = ["id", "created_at", "updated_at", "last_run"]

    def validate(self, attrs):
        # Check for unique together constraint on name and identity_id
        # The field is sourced as 'identity' because of source='identity' in the field definition
        identity = attrs.get("identity")
        name = attrs.get("name")
        
        # During partial updates, get values from instance if not provided
        if self.instance:
            if not name:
                name = self.instance.name
            if not identity:
                identity = self.instance.identity
        
        if identity and name:
            queryset = Feed.objects.filter(name=name, identity=identity)
            if self.instance:
                queryset = queryset.exclude(pk=self.instance.pk)
            
            if queryset.exists():
                raise serializers.ValidationError({
                    "name": "Feed with this name and identity already exists."
                })
        
        return attrs


class FeedPatchSerializer(FeedSerializer):
    identity_id = None


from rest_framework import serializers
import stix2
from stix2.exceptions import STIXError


def validate_stix(data):
    try:
        stix2.parse(data, allow_custom=True)
    except STIXError as exc:
        raise serializers.ValidationError(f"Invalid STIX object: {exc}")
    except Exception as exc:
        raise


class STIXObjectSerializer(serializers.DictField):
    """
    Validates a single STIX object within a bundle upload and, in the same pass,
    works out any warning that applies to it: duplicate ids within the upload
    (`context['seen_ids']`), no-op re-uploads of an unchanged object, or a
    `created_mismatch` update whose `created` no longer matches the existing
    object's (rewritten rather than rejected). `modified` regressions and
    `created_by_ref` mismatches remain hard validation errors that reject the
    whole bundle.
    """

    def to_internal_value(self, data):
        if not isinstance(data, dict):
            raise serializers.ValidationError(
                "STIX object must be a JSON object (dict)."
            )
        validate_stix(data)

        obj_id = data["id"]
        idx = self.context.get("current_index")
        warnings = self.context.setdefault("warnings", {})
        seen_ids = self.context.setdefault("seen_ids", set())

        if obj_id in seen_ids:
            warnings[idx] = {
                "type": "duplicate_object",
                "message": "Duplicate object removed before upload",
                "id": obj_id,
                "resolution": "skipped",
                "index": idx,
            }
            return data
        seen_ids.add(obj_id)

        existing_objects = self.context.get("existing_objects", {})
        existing = existing_objects.get(obj_id)
        if existing:
            warning = self._validate_versioning(existing, data, idx)
            if warning:
                warnings[idx] = warning
                if warning["resolution"] == "rewrite":
                    data["created"] = warning["created"]
        return data

    def _validate_versioning(self, existing, raw_new, idx):
        new_created = raw_new.get("created")
        existing_created = existing.get("created")
        existing_hash = existing.get("_record_md5_hash")

        # An object whose only differences from the existing version are its
        # timestamps is a no-op re-upload: skip it before enforcing the
        # modified/created_by_ref checks below, which don't apply to no-ops.
        created_differs = bool(
            existing_created and new_created and new_created != existing_created
        )
        normalized = raw_new
        if created_differs:
            normalized = raw_new.copy()
            normalized["created"] = existing_created

        if existing_hash and md5_hash(normalized) == existing_hash:
            return {
                "type": "existing_object",
                "message": "stix object already exists in backend",
                "id": raw_new["id"],
                "resolution": "skipped",
                "index": idx,
            }

        errors = {}

        new_modified = raw_new.get("modified")
        existing_modified = existing.get("modified")

        if existing_modified and new_modified and new_modified < existing_modified:
            errors["modified"] = (
                f"'modified' timestamp must be strictly greater than existing version ({existing_modified})."
            )

        existing_cbr = existing.get("created_by_ref")
        new_cbr = raw_new.get("created_by_ref")

        if existing_cbr and new_cbr and existing_cbr != new_cbr:
            errors["created_by_ref"] = (
                f"created_by_ref must match the original created_by_ref ({existing_cbr})."
            )

        if errors:
            raise serializers.ValidationError(errors)

        if created_differs:
            return {
                "type": "created_mismatch",
                "message": (
                    f"'created' timestamp rewritten to match existing version ({existing_created})"
                ),
                "id": raw_new["id"],
                "resolution": "rewrite",
                "index": idx,
                "created": existing_created,
            }
        return None

    def to_representation(self, value):
        return value


class WarningAwareListField(serializers.ListField):
    def run_child_validation(self, data):
        result = []
        errors = {}
        warnings = self.context.setdefault("warnings", {})
        for idx, item in enumerate(data):
            if warnings.get(idx, {}).get("resolution") == "skipped":
                continue
            self.context["current_index"] = idx
            try:
                value = self.child.run_validation(item)
            except validators.ValidationError as e:
                errors[idx] = e.detail
                continue
            except DjangoValidationError as e:
                errors[idx] = get_error_detail(e)
                continue
            if warnings.get(idx, {}).get("resolution") == "skipped":
                continue
            result.append(value)
        if not errors:
            return result
        raise validators.ValidationError(errors)

    @staticmethod
    def run_validation_with_warnings(objects, warnings):
        context = {"warnings": warnings}
        field = WarningAwareListField(child=STIXObjectSerializer(), context=context)
        return field.run_validation(objects)


class BundleSerializer(serializers.Serializer):
    type = serializers.CharField()
    id = serializers.CharField()
    # spec_version = serializers.CharField()
    objects = WarningAwareListField(child=STIXObjectSerializer(), allow_empty=False)

    def validate(self, attrs):
        if attrs.get("type") != "bundle":
            raise serializers.ValidationError(
                "type must be 'bundle' for a STIX Bundle."
            )
        # validate_stix(attrs)
        return attrs
