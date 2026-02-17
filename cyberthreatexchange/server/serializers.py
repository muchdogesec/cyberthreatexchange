import json
import stix2
import stix2.exceptions

from cyberthreatexchange.server.arango_helpers import ArangoDBHelper
from .models import Feed, Identity, Job, ObjectValue, Connector
from rest_framework import serializers, validators
from dogesec_commons.utils.serializers import JSONSchemaSerializer

from .models import Feed, Identity, Job, ObjectValue, Connector
from rest_framework import serializers, validators
from django.core.exceptions import ValidationError as DjangoValidationError
from rest_framework.fields import get_error_detail


class StixObjectsPlaceholderSerializer(serializers.Serializer):
    type = serializers.CharField()
    id = serializers.CharField()


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
        exclude = ["payload", "warnings", "feed"]


class JobDetailSerializer(serializers.ModelSerializer):
    feed_id = serializers.UUIDField(source="feed.id", read_only=True)
    warnings = WarningSerializer(many=True, read_only=True)

    class Meta:
        model = Job
        exclude = ["feed"]


class ObjectValueSerializer(serializers.ModelSerializer):
    """Serializer for ObjectValue search results."""

    feed_id = serializers.UUIDField(source="feed.id", read_only=True)

    class Meta:
        model = ObjectValue
        fields = [
            "id",
            "feed_id",
            "stix_id",
            "stix_type",
            "modified",
            "value",
            "value_type",
            "is_ref",
            "ref_stix_id",
            "created_at",
        ]
        read_only_fields = fields


class StixVersionsSerializer(serializers.Serializer):
    latest = serializers.DateTimeField(allow_null=True)
    versions = serializers.ListField(child=serializers.DateTimeField())


class FeedSerializer(serializers.ModelSerializer):
    # identity = IdentitySerializer(read_only=True)
    identity_id = serializers.PrimaryKeyRelatedField(
        queryset=Identity.objects.all(),
        source="identity",
        help_text="The UUID of the Identity object to associate with this feed.",
        required=True,
    )

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
    def to_internal_value(self, data):
        if not isinstance(data, dict):
            raise serializers.ValidationError(
                "STIX object must be a JSON object (dict)."
            )
        validate_stix(data)
        existing_objects = self.context.get("existing_objects", {})

        obj_id = data["id"]
        if obj_id and obj_id in existing_objects:
            self._validate_versioning(existing_objects[obj_id], data)
        return data

    def _validate_versioning(self, existing, raw_new):
        errors = {}

        new_created = raw_new.get("created")
        new_modified = raw_new.get("modified")

        existing_created = existing.get("created")
        existing_modified = existing.get("modified")

        if existing_created and new_created and new_created != existing_created:
            errors["created"] = (
                f"'created' timestamp must match existing version ({existing_created})."
            )

        if existing_modified and new_modified and new_modified <= existing_modified:
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

    def to_representation(self, value):
        return value


class WarningAwareListField(serializers.ListField):
    def run_child_validation(self, data):
        result = []
        errors = {}
        for idx, item in enumerate(data):
            if (
                idx in self.context.get("warnings", {})
                and self.context["warnings"][idx]["resolution"] == "skipped"
            ):
                continue
            try:
                result.append(self.child.run_validation(item))
            except validators.ValidationError as e:
                errors[idx] = e.detail
            except DjangoValidationError as e:
                errors[idx] = get_error_detail(e)
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
