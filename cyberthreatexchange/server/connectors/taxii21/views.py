"""
Views for TAXII 2.1 connector.
"""
import textwrap
from django_filters.rest_framework import DjangoFilterBackend
from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import extend_schema, extend_schema_view, OpenApiParameter
from rest_framework import decorators, status, viewsets, mixins
from rest_framework.response import Response
from django.shortcuts import get_object_or_404

from cyberthreatexchange.server import models
from cyberthreatexchange.server.connectors.view import ConnectorBaseView
from cyberthreatexchange.server.utils import Ordering, Pagination
from cyberthreatexchange.server.connectors.taxii21.serializers import (
    Taxii21ConnectorSerializer,
)
from cyberthreatexchange.server.serializers import JobSerializer
from dogesec_commons.utils.schemas import DEFAULT_400_RESPONSE


@extend_schema_view(
    create=extend_schema(
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
        responses={201: Taxii21ConnectorSerializer, 400: DEFAULT_400_RESPONSE},
    ),
)
class Taxii21ConnectorView(mixins.CreateModelMixin, mixins.UpdateModelMixin, ConnectorBaseView):
    """
    A viewset for creating TAXII 2.1 Connectors.
    List, retrieve, update, and delete operations are handled by the main ConnectorView.
    """

    serializer_class = Taxii21ConnectorSerializer
    http_method_names = ["post", "patch"]

    openapi_path_params = [
        OpenApiParameter(
            "feed_id",
            type=OpenApiTypes.UUID,
            location=OpenApiParameter.PATH,
            description="The ID of the Feed",
        ),
    ]

    def get_queryset(self):
        return super().get_queryset().filter(type=models.ConnectorType.TAXII)
    
    def get_serializer_context(self):
        feed_id = self.kwargs.get("feed_id")
        return {'feed': get_object_or_404(models.Feed, id=feed_id)}

    def perform_create(self, serializer):
        feed_id = self.kwargs.get("feed_id")
        feed = get_object_or_404(models.Feed, id=feed_id)
        serializer.save(feed=feed)
