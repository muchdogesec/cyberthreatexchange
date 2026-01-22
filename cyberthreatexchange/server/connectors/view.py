"""
Views for the Cyber Threat Exchange server.
"""

import textwrap


SEMANTIC_SEARCH_SORT_FIELDS = [
    "modified_descending",
    "modified_ascending",
    "created_ascending",
    "created_descending",
    "name_ascending",
    "name_descending",
    "type_ascending",
    "type_descending",
]

from django_filters.rest_framework import (
    DjangoFilterBackend,
    DjangoFilterBackend,
)
from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import extend_schema, extend_schema_view, OpenApiParameter
from rest_framework import decorators, status, viewsets, mixins
from rest_framework.response import Response
from django.shortcuts import get_object_or_404

from cyberthreatexchange.server import models
from cyberthreatexchange.server.connectors import serializers
from cyberthreatexchange.server.serializers import JobSerializer

from cyberthreatexchange.server.utils import Ordering, Pagination
from dogesec_commons.utils.schemas import DEFAULT_400_RESPONSE


class ConnectorBaseView(viewsets.GenericViewSet):
    """
    A base viewset for managing Connectors within feeds.
    """
    openapi_tags = ["Connectors"]
    serializer_class = serializers.ConnectorSerializer
    pagination_class = Pagination("connectors")

    def get_queryset(self):
        return models.Connector.objects.filter(feed_id=self.kwargs.get("feed_id"))

@extend_schema_view(
    create_taxii_connector=extend_schema(
        summary="Create a TAXII 2.1 Connector for a Feed",
        description=textwrap.dedent(
            """
            Create a new connector to pull data from a remote TAXII 2.1 collection into a feed.

            If you use a remote source (e.g. a Threat Intel Platform) to manage your intel, you can connect a Cyber Threat Exchange Feed to it so that it can poll the remote source for data.

            The connector will be associated with the specified feed and can be used to periodically poll the TAXII collection for new objects using the POST Connector Poll endpoint.

            The following key / values are accepted in the body of this request:

            * `username` (optional): not required if no authentication needed to access the feed (e.g. feed is public, do not include). Stored encrypted in the database.
            * `password` (optional): not required if no authentication needed to access the feed (e.g. feed is public, do not include). Stored encrypted in the database.
            * `name` (required): name of the Connector.
            * `description` (optional): more info about the Connector to help you identify it.
            * `url` (required): pass the full collection URL (e.g. `https://taxii.obstracts.com/v2_1/obstracts_database/collections/the_cloudflare_blog_aee1ee27a4ba526d97e3c955ffc172d9/objects/`) Connectors do not have any TAXII discovery capabilties so you must pass the collection.

            The `name` provided will be used to generate the UUID of the feed using the following logic; Namespace: `9779a2db-f98c-5f4b-8d08-8ee04e02dbb5`, Value: `<name>+<identity_id>` (e.g. `My basic feed+identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5` = `2902eb6f-aa38-5e50-b56d-c85ebfb1e377`)

            Important: the TAXII 2.1 server will be polled to test the connection. If anything other than a 200 response is returned using the configoration provided, the Connector will not be created and you will receive an error. This uses the same as the test connector endpoint.
            """
        ),
        responses={201: serializers.ConnectorSerializer, 400: DEFAULT_400_RESPONSE},
    ),
    list=extend_schema(
        summary="List Connectors for a Feed",
        description=textwrap.dedent(
            """
            List all connectors configured for the specified Feed. A Feed can have one or more Connectors. A Connector is unique to a Feed.

            Important: Credentials (username/password) are not returned in the response for security reasons. The response includes `has_username` and `has_password` boolean fields to indicate if credentials are set.
            """
        ),
    ),
    retrieve=extend_schema(
        summary="Retrieve a Connector",
        description=textwrap.dedent(
            """
            Get details of a specific connector configured for this feed.
            
            Important: Credentials (username/password) are not returned in the response for security reasons. The response includes `has_username` and `has_password` boolean fields to indicate if credentials are set.
            """
        ),
    ),
    partial_update=extend_schema(
        summary="Update a Connector",
        description=textwrap.dedent(
            """
            Update a connectors configuration.

            The following key / values are accepted in the body of this request:

            * `username` (optional): to remove, pass an empty value. Stored encrypted in the database.
            * `password` (optional): to remove, pass an empty value. Stored encrypted in the database.
            * `name` (required): name of the Connector. Note, changing this value will not change the UUID of the feed.
            * `description` (optional): more info about the Connector to help you identify it.
            
            You cannot change the `url` of a Connector. You must create a new Connector to change this value.
            """
        ),
    ),
    destroy=extend_schema(
        summary="Delete a Connector",
        description=textwrap.dedent(
            """
            Delete a connector. This does not delete any data that was previously pulled from the connector.
            """
        ),
    ),
    test_connection=extend_schema(
        summary="Test source connection",
        description=textwrap.dedent(
            """
            Test the connection to the remote source.

            This will attempt to connect to the remote source and verify that:
            
            * The server is reachable
            * Authentication credentials are valid (if provided)
            * The response to get objects returns a successful response

            Returns a success status and HTTP status code from the remote source to help you debug.
            """
        ),
    ),
    poll=extend_schema(
        summary="Poll source for new objects",
        description=textwrap.dedent(
            """
            This will get the connector to poll the remote source and import new objects into the feed.

            This is an asynchronous operation. A job will be created to track the progress of the poll and import.

            The following key / values are accepted in the body of this request:
            
            * `added_after` (optional): Only retrieve objects added after this timestamp. If not provided, uses the connector's `next_run_added_after` from the previous successful poll.

            The connector's `next_run_added_after` and `last_completion_time` will be updated upon successful completion.
            """
        ),
    ),
)
class ConnectorView(mixins.ListModelMixin, mixins.RetrieveModelMixin, mixins.DestroyModelMixin, ConnectorBaseView):
    """
    A viewset for managing Connectors within feeds.
    """
    lookup_field = "id"
    lookup_url_kwarg = "connector_id"
    filter_backends = [DjangoFilterBackend, Ordering]
    ordering_fields = ["name", "created_at", "updated_at"]
    ordering = "created_at_descending"
    http_method_names = ["get", "post", "patch", "delete", "head", "options"]

    openapi_path_params = [
        OpenApiParameter(
            "feed_id",
            type=OpenApiTypes.UUID,
            location=OpenApiParameter.PATH,
            description="The ID of the Feed",
        ),
        OpenApiParameter(
            "connector_id",
            type=OpenApiTypes.UUID,
            location=OpenApiParameter.PATH,
            description="The ID of the Connector",
        ),
    ]

    @extend_schema(
        request=None,
        responses={200: serializers.ConnectorTestSerializer, 400: DEFAULT_400_RESPONSE},
    )
    @decorators.action(detail=True, methods=["GET"], url_path="test-connection")
    def test_connection(self, request, feed_id=None, connector_id=None):
        connector = self.get_object()
        remote_info: dict = connector.remote_info
        remote_info['success'] = 'error' not in remote_info
        return Response(remote_info, status=status.HTTP_200_OK)

    @extend_schema(
        request=serializers.ConnectorPollSerializer,
        responses={202: JobSerializer, 400: DEFAULT_400_RESPONSE},
    )
    @decorators.action(detail=True, methods=["POST"], url_path="poll")
    def poll(self, request, feed_id=None, connector_id=None):
        connector = self.get_object()

        serializer = serializers.ConnectorPollSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        added_after = serializer.validated_data.get("added_after")
        if not added_after:
            added_after = connector.next_run_added_after

        # Create a job to track the polling operation
        job = models.Job.objects.create(
            feed=connector.feed,
            type=models.JobTypes.CONNECTOR_POLL,
            state=models.JobStates.PENDING,
            payload={
                "connector_id": str(connector.id),
                "added_after": added_after.isoformat() if added_after else None,
            },
        )

        # Import and start the polling task
        from cyberthreatexchange.worker.tasks import poll_taxii_connector_task

        poll_taxii_connector_task.delay(
            job_id=str(job.id),
            connector_id=str(connector.id),
            added_after=added_after.isoformat() if added_after else None,
        )

        job.state = models.JobStates.PROCESSING
        job.save()

        job_serializer = JobSerializer(job)
        return Response(job_serializer.data, status=status.HTTP_202_ACCEPTED)

