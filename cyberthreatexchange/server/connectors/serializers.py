
from ..models import Connector
from rest_framework import serializers
from drf_spectacular.utils import extend_schema_field

from ..models import Connector
from rest_framework import serializers

class ConnectorSerializer(serializers.ModelSerializer):
    # Write-only fields for credentials
    username = serializers.CharField(
        required=False,
        allow_blank=True,
        allow_null=True,
        write_only=True,
        help_text="Username for TAXII authentication (optional, stored encrypted)"
    )
    password = serializers.CharField(
        required=False,
        allow_blank=True,
        allow_null=True,
        write_only=True,
        style={'input_type': 'password'},
        help_text="Password for TAXII authentication (optional, stored encrypted)"
    )
    
    # Indicate if credentials are set (for GET requests)
    has_username = serializers.SerializerMethodField(help_text="Indicates if a username is set for this connector")
    has_password = serializers.SerializerMethodField(help_text="Indicates if a password is set for this connector")

    class Meta:
        model = Connector
        exclude = ["enc_user", "enc_pass", "feed"]
        read_only_fields = [
            'id',
            'type',
            'last_completion_time',
            'next_run_added_after',
            'created_at',
            'updated_at',
            'has_username',
            'has_password',
        ]

    @extend_schema_field(serializers.BooleanField())
    def get_has_username(self, obj):
        return bool(obj.enc_user)

    @extend_schema_field(serializers.BooleanField())
    def get_has_password(self, obj):
        return bool(obj.enc_pass)
    

    def create(self, validated_data):
        """Handle creation with encrypted credentials."""
        username = validated_data.pop('username', None)
        password = validated_data.pop('password', None)
        
        connector = Connector(**validated_data)
        
        if username:
            connector.username = username
        if password:
            connector.password = password
        
        if connector.remote_info.get('error'):
            raise serializers.ValidationError({'error': 'update failed', 'response': connector.remote_info})
            
        connector.save()
        return connector

    def update(self, instance: Connector, validated_data):
        for attr, value in validated_data.items():
            setattr(instance, attr, value)

        if instance.remote_info.get('error'):
            raise serializers.ValidationError({'error': 'update failed', 'response': instance.remote_info})
            
        instance.save()
        return instance


class ConnectorTestSerializer(serializers.Serializer):
    """Serializer for test-connection response."""
    success = serializers.BooleanField()
    response = serializers.DictField()
    status_code = serializers.IntegerField(required=False)
    error = serializers.CharField(required=False)


class ConnectorPollSerializer(serializers.Serializer):
    """Serializer for poll action request."""
    added_after = serializers.DateTimeField(
        required=False,
        allow_null=True,
        help_text="Only retrieve objects added after this time. If not provided, uses next_run_added_after."
    )
