"""
Tests for views.
"""

import pytest
from unittest.mock import Mock, patch
from rest_framework import status
from rest_framework.response import Response
from cyberthreatexchange.server import views, serializers
from dogesec_commons.objects.helpers import SDO_TYPES, SCO_TYPES, SMO_TYPES


class TestJobViewGetSerializerClass:
    """Test JobView.get_serializer_class method."""

    def test_returns_job_detail_serializer_for_retrieve_action(self):
        """Test that retrieve action returns JobDetailSerializer."""
        view = views.JobView()
        view.action = "retrieve"

        serializer_class = view.get_serializer_class()

        assert serializer_class == serializers.JobDetailSerializer

    def test_returns_default_serializer_for_list_action(self):
        """Test that list action returns default JobSerializer."""
        view = views.JobView()
        view.action = "list"

        serializer_class = view.get_serializer_class()

        assert serializer_class == serializers.JobSerializer

    def test_returns_default_serializer_for_other_actions(self):
        """Test that other actions return default JobSerializer."""
        view = views.JobView()
        view.action = "create"  # Not a real action, but testing default behavior

        serializer_class = view.get_serializer_class()

        assert serializer_class == serializers.JobSerializer

