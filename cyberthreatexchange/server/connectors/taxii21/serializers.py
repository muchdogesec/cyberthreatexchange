"""
Serializers for TAXII 2.1 connector.
"""
from rest_framework import serializers
from cyberthreatexchange.server.models import Connector, ConnectorType
from ..serializers import ConnectorSerializer


class Taxii21ConnectorSerializer(ConnectorSerializer):
    pass