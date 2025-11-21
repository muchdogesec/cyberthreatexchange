"""
Views for the Cyber Threat Exchange server.
"""

import itertools
import logging
import textwrap
from django.utils import timezone

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
    BaseCSVFilter,
    CharFilter,
    DjangoFilterBackend,
    FilterSet,
    Filter,
    FilterSet,
    Filter,
    DjangoFilterBackend,
    ChoiceFilter,
    BaseCSVFilter,
    CharFilter,
    BooleanFilter,
)
from django_filters.fields import ChoiceField
from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import extend_schema, extend_schema_view, OpenApiParameter
from rest_framework import decorators, exceptions, status, viewsets, mixins
from rest_framework.response import Response
from django.shortcuts import get_object_or_404

from cyberthreatexchange.server import models, serializers
from cyberthreatexchange.server.arango_helpers import ALL_SEARCH_TYPES, ArangoDBHelper
from cyberthreatexchange.server.utils import Ordering, Pagination
from drf_spectacular.views import SpectacularAPIView
from cyberthreatexchange.worker.tasks import upload_bundle_task
from dogesec_commons.utils.schemas import DEFAULT_400_RESPONSE, DEFAULT_404_RESPONSE


class ChoiceCSVFilter(BaseCSVFilter):
    field_class = ChoiceField


@extend_schema_view(
    list=extend_schema(
        summary="List Identities",
        description="List all STIX Identity objects that can be used to create feeds.",
    ),
    retrieve=extend_schema(
        summary="Retrieve an Identity",
        description="Retrieve a STIX Identity object by its ID.",
    ),
    create=extend_schema(
        summary="Create an Identity",
        description="Create a new STIX Identity object.",
    ),
    partial_update=extend_schema(
        summary="Update an Identity",
        description="Update an existing STIX Identity object.",
    ),
    destroy=extend_schema(
        summary="Delete an Identity",
        description="Delete a STIX Identity object.",
    ),
)
class IdentityView(viewsets.ModelViewSet):  # Changed from ReadOnlyModelViewSet
    """
    A viewset for viewing Identities.
    Identities are the owners of feeds.
    """

    http_method_names = [
        "get",
        "post",
        "patch",
        "delete",
        "head",
        "options",
    ]  # Added for consistency with FeedView
    openapi_tags = ["Identities"]
    queryset = models.Identity.objects.all()
    serializer_class = serializers.IdentitySerializer
    pagination_class = Pagination("identities")
    lookup_field = "id"
    lookup_url_kwarg = "identity_id"
    filter_backends = [DjangoFilterBackend, Ordering]
    ordering_fields = ["created", "modified"]
    ordering = "modified_descending"
    openapi_path_params = [
        OpenApiParameter(
            "identity_id",
            type=OpenApiTypes.UUID,
            location=OpenApiParameter.PATH,
            description="The ID of the Identity object.",
        )
    ]

    class filterset_class(FilterSet):
        name = CharFilter(
            field_name="json_data__name",
            lookup_expr="icontains",
            help_text="Filter by identity name (case-insensitive, partial match).",
        )

        class Meta:
            model = models.Identity
            fields = ["name"]


@extend_schema_view(
    create=extend_schema(
        summary="Create a Feed",
        description="Create a new threat intelligence feed. A feed is a collection of STIX objects.",
    ),
    list=extend_schema(
        summary="List Feeds",
        description="List all available threat intelligence feeds.",
    ),
    retrieve=extend_schema(
        summary="Retrieve a Feed",
        description="Retrieve a specific threat intelligence feed by its ID.",
    ),
    partial_update=extend_schema(
        summary="Update a Feed",
        description="Update a specific threat intelligence feed's metadata (name, description, tags). Corresponds to `PATCH /feed/{id}`.",
    ),
    destroy=extend_schema(
        summary="Delete a Feed",
        description="Delete a specific threat intelligence feed and all its associated objects.",
    ),
)
class FeedView(viewsets.ModelViewSet):
    """
    A viewset for managing Feeds.
    """

    http_method_names = ["get", "post", "patch", "delete", "head", "options"]
    openapi_tags = ["Feeds"]
    queryset = models.Feed.objects.all()
    serializer_class = serializers.FeedSerializer
    pagination_class = Pagination("feeds")
    lookup_field = "id"
    lookup_url_kwarg = "feed_id"
    filter_backends = [DjangoFilterBackend, Ordering]
    ordering_fields = ["name", "created_at", "updated_at"]
    ordering = "updated_at_descending"
    openapi_path_params = [
        OpenApiParameter(
            "feed_id",
            type=OpenApiTypes.UUID,
            location=OpenApiParameter.PATH,
            description="The ID of the Feed.",
        )
    ]

    class filterset_class(FilterSet):
        name = CharFilter(lookup_expr="icontains")
        tags = BaseCSVFilter(field_name="tags", lookup_expr="icontains")

        class Meta:
            model = models.Feed
            fields = ["name", "tags", "identity"]

    @extend_schema(
        summary="Add a STIX bundle to a feed",
        description=textwrap.dedent(
            """
            Allows a user to post a STIX bundle of objects to their feed.
            This is an asynchronous operation. A job will be created to track the progress of the import.
            """
        ),
        request=serializers.BundleSerializer,
        responses={202: serializers.JobSerializer},
    )
    @decorators.action(detail=True, methods=["POST"], url_path="bundle")
    def bundle(self, request, feed_id=None):
        """
        This will be considered as one job. If one or more objects in the upload fail,
        the job will continue. All successes and errors will be reported in the
        job individually.
        """
        feed = self.get_object()
        job = models.Job.objects.create(
            feed=feed,
            type=models.JobTypes.BUNDLE_UPLOAD,
            state=models.JobStates.PENDING,
            payload=request.data,
        )
        context = self.get_validation_context()
        s = serializers.BundleSerializer(data=request.data, context=context)
        try:
            s.is_valid(raise_exception=True)
            upload_bundle_task.delay(job_id=job.id, warnings=context.get("warnings"))
            job.state = models.JobStates.PROCESSING
        except exceptions.ValidationError as e:
            job.errors.append(e.detail)
            job.state = models.JobStates.FAILED
            job.completion_time = timezone.now()
        if context.get("warnings"):
            job.warnings = list(context["warnings"].values())
        job.save()

        job_serializer = serializers.JobSerializer(job)
        return Response(job_serializer.data, status=status.HTTP_202_ACCEPTED)

    def get_validation_context(self):
        from stix2arango.utils import generate_md5

        request = self.request
        feed_id = self.kwargs["feed_id"]
        context = self.get_serializer_context()
        helper = ArangoDBHelper("", None)
        obj_ids = []
        rel_ids = {}
        warnings = {}
        objects: list = request.data.get("objects", [])
        try:
            for obj in objects:
                obj_id = obj["id"]
                if obj["type"] == "relationship":
                    rel_ids[obj_id] = [obj.get("source_ref"), obj.get("target_ref")]
                obj_ids.append(obj.get("id"))
        except:
            return context

        context.update(
            obj_ids=obj_ids,
            rel_ids=rel_ids,
            existing_objects=helper.get_existing_objects(
                feed_id, list(itertools.chain(obj_ids, *rel_ids.values()))
            ),
            warnings=warnings,
        )
        for i, obj in enumerate(objects):
            if obj_ids.count(obj["id"]) > 1:
                warnings[i] = {
                    "type": "duplicate_object",
                    "message": f"Duplicate object removed before upload",
                    "id": obj["id"],
                    "resolution": "skipped",
                    "index": i,
                }
                objects.remove(obj)
            obj["id"] in context["existing_objects"] and print(
                "yyy", context["existing_objects"][obj["id"]]
            )
            if obj["id"] in context["existing_objects"] and generate_md5(
                {**obj, "_stix2arango_note": ""}
            ) == context["existing_objects"][obj["id"]].get("_record_md5_hash"):
                warnings[i] = {
                    "type": "existing_object",
                    "message": f"stix object already exists in backend",
                    "id": obj["id"],
                    "resolution": "skipped",
                    "index": i,
                }
            if obj["type"] == "relationship":
                source_ref = obj.get("source_ref")
                target_ref = obj.get("target_ref")
                if (
                    source_ref not in obj_ids
                    and source_ref not in context["existing_objects"]
                ):
                    warnings[i] = {
                        "type": "missing_source",
                        "message": f"could not resolve obj.source_ref ({source_ref}) for relationship in feed or upload",
                        "id": obj["id"],
                        "resolution": "skipped",
                        "index": i,
                    }
                    continue
                if (
                    target_ref not in obj_ids
                    and target_ref not in context["existing_objects"]
                ):
                    warnings[i] = {
                        "type": "missing_target",
                        "message": f"could not resolve obj.target_ref ({target_ref}) for relationship in feed or upload",
                        "id": obj["id"],
                        "resolution": "skipped",
                        "index": i,
                    }
                    continue
        return context


@extend_schema_view(
    list=extend_schema(
        summary="List objects in a feed",
        description="Allows a user to filter on all objects in a feed.",
        parameters=[
            OpenApiParameter(
                "types",
                description="Only show objects of selected types",
                enum=ALL_SEARCH_TYPES,
                explode=False,
                style="form",
                many=True,
            ),
            OpenApiParameter(
                "text",
                description="Filter the results by the `name` and `description` property of the object.",
                type=OpenApiTypes.STR,
            ),
        ],
        responses=serializers.StixObjectsPlaceholderSerializer(many=True),
    ),
    retrieve=extend_schema(
        summary="Retrieve an object from a feed",
        description="Retrieve a single STIX object from a feed by its ID.",
        responses=serializers.StixObjectsPlaceholderSerializer,
    ),
    destroy=extend_schema(
        summary="Delete an object from a feed",
        description="Allows a user to delete an object and its relationships from a feed. This is an asynchronous operation.",
        responses={202: serializers.JobSerializer},
    ),
    versions=extend_schema(
        summary="Get object versions from a feed",
        description="Returns a list of all versions of the object in the database.",
        responses=serializers.StixVersionsSerializer(),
    ),
    bundle=extend_schema(
        summary="Get bundle of related objects from a feed",
        description="Get all objects directly related to the specified object within the feed.",
        responses=serializers.StixObjectsPlaceholderSerializer(many=True),
    ),
)
class FeedObjectsView(viewsets.GenericViewSet):
    """
    A small viewset mounted under `/feed/{feed_id}/objects` to handle
    feed object operations separately from `FeedView`.
    """

    http_method_names = ["get", "post", "delete", "head", "options"]
    openapi_tags = ["Feeds"]
    lookup_url_kwarg = "object_id"
    openapi_path_params = [
        OpenApiParameter(
            "object_id",
            type=OpenApiTypes.STR,
            location=OpenApiParameter.PATH,
            description="The ID of the Object.",
        ),
        OpenApiParameter(
            "feed_id",
            type=OpenApiTypes.UUID,
            location=OpenApiParameter.PATH,
            description="The ID of the Feed.",
        ),
    ]
    pagination_class = Pagination("objects")

    def list(self, request, feed_id=None):
        feed = get_object_or_404(models.Feed, id=feed_id)
        helper = ArangoDBHelper(feed.vertex_collection, request)
        return helper.semantic_search([feed.collection_name])

    def retrieve(self, request, object_id, feed_id=None):
        feed = get_object_or_404(models.Feed, id=feed_id)
        helper = ArangoDBHelper(feed.vertex_collection, request)
        return helper.get_object_by_external_id(object_id)

    def destroy(self, request, object_id, feed_id=None):
        feed = get_object_or_404(models.Feed, id=feed_id)
        logging.warning(
            "Job creation is not implemented for object deletion in feed %s.", feed.id
        )
        return Response(
            status=status.HTTP_204_NO_CONTENT,
        )

    @decorators.action(detail=True, methods=["GET"])
    def versions(self, request, object_id, feed_id=None):
        feed = get_object_or_404(models.Feed, id=feed_id)
        helper = ArangoDBHelper(feed.vertex_collection, request)
        return helper.get_versions(object_id)

    @decorators.action(detail=True, methods=["GET"])
    def bundle(self, request, object_id, feed_id=None):
        feed = get_object_or_404(models.Feed, id=feed_id)
        helper = ArangoDBHelper(feed.vertex_collection, request)
        return helper.get_object_by_external_id(object_id, bundle=True)


@extend_schema_view(
    list=extend_schema(
        responses={
            200: serializers.StixObjectsPlaceholderSerializer(many=True),
            400: DEFAULT_400_RESPONSE,
        },
        summary="Search for objects",
        description=textwrap.dedent(
            """
            Use the endpoint to search for objects across all endpoints.

            This endpoint is particularly useful when you don't know the objects you want, or if the concept you're interested in is covered by a framework.
            """
        ),
    )
)
class SearchView(viewsets.ViewSet):
    serializer_class = serializers.StixObjectsPlaceholderSerializer(many=True)
    pagination_class = Pagination("objects")
    openapi_tags = ["Search"]
    filter_backends = [DjangoFilterBackend]

    class filterset_class(FilterSet):
        text = CharFilter(help_text="The search query. e.g `denial of service`")
        types = ChoiceCSVFilter(
            choices=[(f, f) for f in ALL_SEARCH_TYPES],
            help_text="Filter the results by STIX Object type.",
        )
        feed_ids = BaseCSVFilter(
            help_text="Filter results by containing feed_ids you want to search.",
        )
        author_ids = BaseCSVFilter(
            help_text="Filter results by containing the identity_id of the feed's author.",
        )
        show_feed_id = BooleanFilter(
            help_text="If `true`, will add `x_ctx_feed_id` property to each returend object. Note, setting to `true` will break the objects in the response from being pure STIX 2.1. Default is `false`"
        )
        sort = ChoiceFilter(
            choices=[(f, f) for f in SEMANTIC_SEARCH_SORT_FIELDS],
            help_text="attribute to sort by",
        )

    def list(self, request, *args, **kwargs):
        return ArangoDBHelper("semantic_search_view", request).semantic_search()


@extend_schema_view(
    list=extend_schema(
        summary="Search and retrieve a list of Jobs",
        description=textwrap.dedent(
            """
            Jobs track the status of File upload, conversion of the File into markdown and the extraction of the data from the text. For every new File added a job will be created. The `id` of a Job is printed in the POST responses, but you can use this endpoint to search for the `id` again, if required.
            """
        ),
        responses={200: serializers.JobSerializer, 400: DEFAULT_400_RESPONSE},
    ),
    retrieve=extend_schema(
        summary="Get a job by ID",
        description=textwrap.dedent(
            """
            Using a Job ID you can retrieve information about its state via this endpoint. This is useful to see if a Job is still processing, if an error has occurred (and at what stage), or if it has completed.
            """
        ),
        parameters=[
            OpenApiParameter(
                "job_id",
                location=OpenApiParameter.PATH,
                type=OpenApiTypes.UUID,
                description="The `id` of the Job.",
            ),
        ],
        responses={200: serializers.JobSerializer, 404: DEFAULT_404_RESPONSE},
    ),
)
class JobView(
    mixins.ListModelMixin,
    mixins.RetrieveModelMixin,
    viewsets.GenericViewSet,
):
    openapi_tags = ["Jobs"]
    pagination_class = Pagination("jobs")
    serializer_class = serializers.JobSerializer
    lookup_url_kwarg = "job_id"

    ordering_fields = ["state", "completion_time", "start_time"]
    ordering = "start_time_descending"
    filter_backends = [DjangoFilterBackend, Ordering]

    def get_queryset(self):
        return models.Job.objects.all()

    class filterset_class(FilterSet):
        feed_id = Filter("feed_id", label="Filter Jobs by Feed `id`")

    def get_serializer_class(self):
        if self.action == "retrieve":
            return serializers.JobDetailSerializer
        return super().get_serializer_class()


class SchemaViewCached(SpectacularAPIView):
    _schema = None

    def _get_schema_response(self, request):
        version = (
            self.api_version or request.version or self._get_version_parameter(request)
        )
        if not self.__class__._schema:
            generator = self.generator_class(
                urlconf=self.urlconf, api_version=version, patterns=self.patterns
            )
            self.__class__._schema = generator.get_schema(
                request=request, public=self.serve_public
            )
        return Response(
            data=self._schema,
            headers={
                "Content-Disposition": f'inline; filename="{self._get_filename(request, version)}"'
            },
        )
