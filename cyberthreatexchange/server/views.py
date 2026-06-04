"""
Views for the Cyber Threat Exchange server.
"""

import hashlib
import itertools
import logging
import textwrap
import uuid

import cyberthreatexchange.server.values.serializers as values_serializers
from cyberthreatexchange.server.values.values import ALL_KNOWLEDGEBASES, type_value_map
from cyberthreatexchange.worker.utils import md5_hash


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
    DateTimeFilter,
)
from django_filters.fields import ChoiceField
from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import extend_schema, extend_schema_view, OpenApiParameter
from rest_framework import decorators, exceptions, status, viewsets, mixins
from rest_framework.response import Response
from django.shortcuts import get_object_or_404, get_list_or_404

from cyberthreatexchange.server import models, serializers
from cyberthreatexchange.server.arango_helpers import ALL_SEARCH_TYPES, ArangoDBHelper
from cyberthreatexchange.server.utils import Ordering, Pagination
from dogesec_commons.utils.pagination import CompositeCursorPagination
from drf_spectacular.views import SpectacularAPIView
from cyberthreatexchange.worker.tasks import upload_bundle_task
from dogesec_commons.utils.schemas import DEFAULT_400_RESPONSE, DEFAULT_404_RESPONSE
from dogesec_commons.objects.helpers import SMO_TYPES
from dogesec_commons.objects.helpers import SCO_TYPES
from dogesec_commons.objects.helpers import SDO_TYPES

from dogesec_commons.identity import (
    views as identity_view,
    serializers as identity_serializers,
)


class ChoiceCSVFilter(BaseCSVFilter):
    field_class = ChoiceField


@extend_schema_view(
    list=extend_schema(
        summary="List Identities",
        description=textwrap.dedent(
            """
            List all STIX Identity objects that can be used to create feeds.

            You can create an Identity using the POST Identities endpoint.

            This request will not return Identity objects that have been uploaded to Feeds.
            """
        ),
    ),
    retrieve=extend_schema(
        summary="Retrieve an Identity",
        description=textwrap.dedent(
            """
            Retrieve a STIX Identity object by its ID.

            This request will not return Identity objects that have been uploaded to Feeds.
            """
        ),
    ),
    create=extend_schema(
        summary="Create an Identity",
        description=textwrap.dedent(
            """
            Upload a valid STIX Identity object.

            The Identity object will be validated against the STIX specification.

            Some notes about Identity creation to be aware of

            * The Identity object you submit will be unmodified in this request
            * All properties will be validated against the STIX specification to ensure compliance. If validation fails, the object will not be updated.
            * You can use custom properties. These will not be validated against any schema.
            """
        ),
    ),
    update=extend_schema(
        summary="Update an Identity",
        description=textwrap.dedent(
            """
            Update a STIX Identity object.

            When an Identity object is updated, all references to this identity will point to the latest version you upload.
            
            IMPORTANT behaviour to be aware of:

            * You cannot edit the following properties in this request: `spec_version`, `modified`, `created`, `type`. You should pass the full identity object, but they will be ignored in processing.
            * The `id` passed in the body must match the `id` passed in URL of the request.
            * On update, the `modified` time of the object will be updated to match the current time. The `created` date will remain the same
            * All changes will be validated against the STIX specification to ensure compliance. If validation fails, the object will not be updated.
            * You cannot modify an Identity uploaded to a Feed using this endpoint. You must update it using the Feed objects endpoints.
            """
        ),
    ),
    destroy=extend_schema(
        summary="Delete an Identity and all its Feeds",
        description=textwrap.dedent(
            """
            Delete an Identity object and ALL Feeds related to it.

            IMPORTANT: make sure this is the request you want to run. It will delete all data related to the Identity ID, including the Identity object, all Feeds belonging to the Identity object, and all objects within those feeds.

            You cannot delete an Identity uploaded to a Feed using this endpoint. You must update it using the Feed objects endpoints.
            """
        ),
    ),
)
class IdentityView(identity_view.IdentityView):
    pass


@extend_schema_view(
    create=extend_schema(
        summary="Create a Feed",
        description=textwrap.dedent(
            """
            Use this endpoint to create a new Feed.

            The payload body accepts the following values:

            * `identity_id` (required): a full STIX Identity ID (e.g. `identity--643fea2b-5da6-47a9-9433-f8e97669f75b`). This Identity must already exist in the database. You can add Identities using the POST Identity endpoint.
            * `name` (required): the name of the feed
            * `description` (optional): a longer description of the feed
            * `short_description` (optional): a shorter description of the feed. This exist mainly for CTX web
            * `tags` (optional, list): tags for Feed. Can use alphanumeric characters and `-` only
            * `categories` (optional, enum): default is `uncategorized`. Can select one or more of the following options: `other`,`apt_group`,`vulnerability`,`data_leak`,`malware`,`ransomware`,`infostealer`,`threat_actor`,`campaign`,`exploit`,`cyber_crime`,`indicator_of_compromise`,`ttp`
            
            Feed IDs are generated using UUIDv5s, using the Namespace `9779a2db-f98c-5f4b-8d08-8ee04e02dbb5` and values `<NAME>+<IDENTITY_ID` (e.g. `My Feed+identity--7d144535-be7d-4b40-a90b-eb7b0489d0c8` = `1d167752-481d-564e-9b05-e947614dbfa1`)
            """
        ),
        responses={201: serializers.FeedSerializer, 400: DEFAULT_400_RESPONSE},
    ),
    list=extend_schema(
        summary="List Feeds",
        description=textwrap.dedent(
            """
            List all available Feeds.
            """
        ),
    ),
    retrieve=extend_schema(
        summary="Retrieve a Feed",
        description=textwrap.dedent(
            """
            Get the metadata of the Feed.
            """
        ),
    ),
    partial_update=extend_schema(
        request=serializers.FeedPatchSerializer,
        responses={201: serializers.FeedSerializer, 400: DEFAULT_400_RESPONSE},
        summary="Update a Feed",
        description=textwrap.dedent(
            """
            Update the metadata of the Feed.

            The payload body accepts the following values:

            * `name` (required): the name of the feed
            * `description` (optional): a longer description of the feed
            * `short_description` (optional): a shorter description of the feed. This exist mainly for CTX web
            * `tags` (optional, list): tags for Feed. Can use alphanumeric characters and `-` only
            * `categories` (optional, enum): default is `uncategorized`. Can select one or more of the following options: `other`,`apt_group`,`vulnerability`,`data_leak`,`malware`,`ransomware`,`infostealer`,`threat_actor`,`campaign`,`exploit`,`cyber_crime`,`indicator_of_compromise`,`ttp`
            
            You cannot change the `identity_id` assigned to a feed once it is created.
            """
        ),
    ),
    destroy=extend_schema(
        summary="Delete a Feed",
        description=textwrap.dedent(
            """
            Delete the feed and all STIX objects that are inside it.

            This request will not delete the Identity object listed as the creator of this feed. If you wish to delete all Feeds belonging to an Identity, use the DELETE Identity endpoint.
            """
        ),
    ),
)
class FeedView(viewsets.ModelViewSet):
    """
    A viewset for managing Feeds.
    """

    http_method_names = ["get", "post", "patch", "delete"]

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
            description="The ID of the Feed (e.g. `32912db5-d79f-442e-b609-baac0e5ad9f3`)",
        )
    ]

    class filterset_class(FilterSet):
        name = CharFilter(lookup_expr="icontains")
        tags = BaseCSVFilter(field_name="tags", lookup_expr="contains")
        identity_id = BaseCSVFilter(lookup_expr="in")

    @extend_schema(
        summary="Add a STIX bundle to a feed",
        description=textwrap.dedent(
            """
            Post a STIX bundle of objects to the feed.

            This is an asynchronous operation. A job will be created to track the progress of the import. The response will contain the ID of the job.

            IMPORTANT behaviour to be aware of:

            * Bundles must contain valid STIX objects. If one object in the bundle is not valid, the whole import will fail. In such instances, no objects will be inserted into the feed.
            * You can update objects in the feed using Bundle uploads. Ensure if they are SDOs or SROs that the `modified` times are higher than the old object already indexed or it won't be updated.
            * On updates, you should also ensure the `created_by_ref`, `created`, `spec_version`, and `type` properties match the original exactly, otherwise this will cause issues. This won't cause the update to fail (nor will it be reported in the job as an issue), but will likely lead to downstream issues for consumers of your feed.
            * If your bundle contains an SRO you must ensure that both the `source_ref` or `target_ref` either 1) exists in the bundle, OR 2) already exist in the feed. If either object is not present, the job will not fail, but the SRO will not be imported. Any failures like this will be reported in the Job.
            """
        ),
        request=serializers.BundleSerializer,
        responses={202: serializers.JobSerializer, 400: DEFAULT_400_RESPONSE},
    )
    @decorators.action(detail=True, methods=["POST"], url_path="bundle")
    def bundle(self, request, feed_id=None):
        """
        This will be considered as one job. If one or more objects in the upload fail,
        the job will continue. All successes and errors will be reported in the
        job individually.
        """
        feed = self.get_object()
        context = self.get_validation_context()
        s = serializers.BundleSerializer(data=request.data, context=context)
        s.is_valid(raise_exception=True)

        job = models.Job.objects.create(
            feed=feed,
            type=models.JobTypes.BUNDLE_UPLOAD,
            state=models.JobStates.PENDING,
            payload=request.data,
            warnings=(
                list(context["warnings"].values()) if context.get("warnings") else []
            ),
        )
        upload_bundle_task.delay(job_id=job.id, warnings=context.get("warnings"))

        job_serializer = serializers.JobSerializer(job)
        return Response(job_serializer.data, status=status.HTTP_202_ACCEPTED)

    def get_validation_context(self):
        from stix2arango.utils import generate_md5

        request = self.request
        feed_id = self.kwargs["feed_id"]
        context = self.get_serializer_context()
        objects = request.data.get("objects", [])
        helper = ArangoDBHelper("", None)
        feed = self.get_object()
        return helper.build_context(context, objects, feed)


@extend_schema_view(
    list=extend_schema(
        summary="List objects in a feed",
        description=textwrap.dedent(
            """
            Search an filter on all objects (SDOs, SCOs, SROs, and SMOs) found in this feed.

            Due to differences between SDOs, SCOs, SROs, and SMOs, you can perform more advanced filtering for the STIX object type on `object/sdo`, `object/sco`, `object/sro` and `object/smo` endpoints.
            """
        ),
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
                "show_embedded_refs",
                description="If `true`, will include embedded refs. Default is `false`.",
                type=OpenApiTypes.BOOL,
            ),
        ],
        responses=serializers.StixObjectsPlaceholderSerializer(many=True),
    ),
    retrieve=extend_schema(
        summary="Retrieve an object from a feed",
        description=textwrap.dedent(
            """
            Retrieve a single STIX object from a feed by its ID
            """
        ),
        responses=serializers.StixObjectsPlaceholderSerializer,
    ),
    destroy=extend_schema(
        summary="Delete an object from a feed",
        description=textwrap.dedent(
            """
            Delete an object from a feed.

            IMPORTANT: this request will also delete all SROs where the object being deleted is a `target_ref` or `source_ref`
            """
        ),
        responses={204: None},
    ),
    bundle=extend_schema(
        summary="Get bundle of related objects from a feed",
        description=textwrap.dedent(
            """
            Get a relationship bundle around the requested object.

            The response returns object IDs plus an opaque cursor token that can be sent back to continue scanning the bundle on the next request.
            """
        ),
        parameters=[
            OpenApiParameter(
                "types",
                description="Only include direct relationships whose related objects are in this STIX type list.",
                enum=ALL_SEARCH_TYPES,
                explode=False,
                style="form",
                many=True,
            ),
            OpenApiParameter(
                "secondary_types",
                description="Only include secondary relationships whose related objects are in this STIX type list. Defaults to `types` when omitted.",
                enum=ALL_SEARCH_TYPES,
                explode=False,
                style="form",
                many=True,
            ),
            OpenApiParameter(
                "secondary_relations",
                description="Set to `true` to include related objects reachable via secondary relationships.",
                type=OpenApiTypes.BOOL,
            ),
            OpenApiParameter(
                'limit',
                description='Maximum number of returned object IDs to include in a page. The server clamps this to a hard max of 100.',
                type=OpenApiTypes.INT,
            ),
            OpenApiParameter(
                'cursor',
                description="Opaque base64 cursor returned by the previous page.",
                type=OpenApiTypes.STR,
            ),
            OpenApiParameter(
                'show_embedded_refs',
                description="If set to false (default), the response will only include the directly requested object, and will not include any embedded SROs that link it to other objects. If set to true, the response will include all directly related objects, and will represent the relationships between them using STIX embedded relationships..",
                type=OpenApiTypes.BOOL,
            )
        ],
        responses=serializers.BundleObjects(),
        filters=False,
    ),
)
class FeedObjectsView(viewsets.GenericViewSet):
    """
    A small viewset mounted under `/feed/{feed_id}/objects` to handle
    feed object operations separately from `FeedView`.
    """

    openapi_tags = ["Feeds"]
    lookup_url_kwarg = "object_id"
    filter_backends = [DjangoFilterBackend]
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

    class filterset_class(FilterSet):
        stix_ids = BaseCSVFilter(lookup_expr="in", help_text="Filter by STIX IDs.")
        updated_since = DateTimeFilter(
            help_text="Only return objects updated since the specified date. Format must be ISO8601 (e.g. `2020-01-01T00:00:00Z`). We use this property instead of `modified` because SCOs do not have a modified time."
        )

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
    def bundle(self, request, object_id, feed_id=None):
        feed = get_object_or_404(models.Feed, id=feed_id)
        helper = ArangoDBHelper(feed.vertex_collection, request)
        return helper.get_bundle2(object_id, feed)


@extend_schema_view(
    list=extend_schema(
        responses={
            200: serializers.PlaceholderStixObjectSerializer(many=True),
            400: DEFAULT_400_RESPONSE,
        },
        summary="Search for objects",
        description=textwrap.dedent(
            """
            Use the endpoint to search for objects across all endpoints.

            This endpoint is particularly useful when you don't know the objects you want, or if the concept you're interested in is covered by a framework.
            """
        ),
    ),
    feeds=extend_schema(
        summary="Get feeds containing an object",
        description=textwrap.dedent(
            """
            Get a list of all feeds containing a specific object.
            """
        ),
        parameters=[
            OpenApiParameter(
                "object_id",
                type=OpenApiTypes.STR,
                location=OpenApiParameter.PATH,
                description="The  STIX ID of the Object.",
            ),
        ],
    ),
)
class SearchView(mixins.ListModelMixin, viewsets.GenericViewSet):
    pagination_class = CompositeCursorPagination("objects")
    openapi_tags = ["Search"]
    filter_backends = [DjangoFilterBackend, Ordering]
    ordering_fields = {
        "created_ascending": ["created", "id"],
        "created_descending": ["-created", "-id"],
        "modified_ascending": ["modified", "id"],
        "modified_descending": ["-modified", "-id"],
        "value_ascending": "values_sort",
        "value_descending": "-values_sort",
    }
    ordering = "modified_descending"
    lookup_url_kwarg = "object_id"
    lookup_field = "stix_id"

    class filterset_class(FilterSet):
        stix_id = BaseCSVFilter(lookup_expr="in", help_text="Filter by STIX IDs.")
        value = CharFilter(
            method="filter_value",
            help_text="The search query. e.g `denial of service`",
        )
        value_exact = BooleanFilter(
            method="filter_noop",
            help_text="Set to `true` to only return exact matches on the `value` field. Default behaviour is wildcard search.",
        )
        types = ChoiceCSVFilter(
            lookup_expr="in",
            field_name="type",
            choices=[(f, f) for f in type_value_map],
            help_text="Filter the results by STIX Object type.",
        )
        feed_ids = BaseCSVFilter(
            lookup_expr="in",
            field_name="feed_id",
            help_text="Filter results by containing feed_ids you want to search.",
            method='filter_feeds',
        )
        author_ids = BaseCSVFilter(
            lookup_expr="in",
            field_name="feed__identity_id",
            method='filter_authors',
            help_text="Filter results by containing the identity_id of the feed's author.",
        )
        knowledgebases = ChoiceCSVFilter(
            lookup_expr="in",
            field_name="knowledgebase",
            choices=[(f, f) for f in ALL_KNOWLEDGEBASES],
            help_text="Filter results by containing the knowledgebase assigned to the objects.",
        )

        def filter_value(self, queryset, name, value):
            if not value:
                return queryset

            value_exact = self.data.get("value_exact", "false").lower() == "true"
            if value_exact:
                return queryset.filter(hashed_values_list__contains=[uuid.UUID(hashlib.md5(value.lower().encode('utf-8')).hexdigest())])
            return queryset.filter(values_concat__contains=value.lower())

        def filter_noop(self, queryset, name, value):
            return queryset

        def filter_feeds(self, queryset, name, value):
            from django.db.models import Exists, OuterRef, functions, Value, Q, Subquery
            if not value:
                return queryset
            queryset = queryset.filter(
                Q(feed_id__in=value)
                # | Q(
                #     Exists(
                #         models.NewObjectValue.objects.filter(
                #             feed_id__in=value,
                #             stix_id=OuterRef("stix_id"),
                #         )
                #     )
                # ),
            )
            return queryset

        def filter_authors(self, queryset, name, value):
            if not value:
                return queryset
            feed_ids = list(models.Feed.objects.filter(identity_id__in=value).values_list(
                "id", flat=True
            ))
            return self.filter_feeds(queryset, name, feed_ids)

    def get_queryset(self):
        qs = models.NewObjectValue.objects.filter(is_dupe=False)
        return qs

    def get_serializer_context(self):
        ctx = super().get_serializer_context()
        ctx.update(
            objects=ArangoDBHelper(
                "semantic_search", self.request
            ).get_context_for_objects(self.object_ids)
        )
        return ctx

    # def get_serializer(self, page, *args, **kwargs):
    #     return super().get_serializer(page,*args, **kwargs)

    def list(self, request, *args, **kwargs):
        queryset = self.filter_queryset(self.get_queryset())
        page = self.paginate_queryset(queryset)
        self.object_ids = [obj.stix_id for obj in page]
        self.serializer_class = values_serializers.ValuesAsStixSerializer
        serializer = self.get_serializer(page, many=True)
        return self.get_paginated_response(serializer.data)

    @decorators.action(
        detail=True,
        methods=["GET"],
        serializer_class=serializers.ObjectFeedsDetailSerializer,
    )
    def feeds(self, request, object_id):
        obj = get_list_or_404(models.NewObjectValue, stix_id=object_id)[0]
        feed_ids = (
            models.NewObjectValue.objects.all()
            .filter(stix_id=obj.stix_id)
            .values_list("feed_id", flat=True)
            .distinct()
        )
        obj.feeds = models.Feed.objects.filter(id__in=feed_ids)
        serializer = serializers.ObjectFeedsDetailSerializer(obj)
        return Response(serializer.data)


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
        identity_id = Filter(
            "feed__identity_id", label="Filter Jobs by Feed's Identity `id`"
        )
        state = BaseCSVFilter(
            lookup_expr="in",
            help_text="Filter Jobs by their state. You can select multiple states. E.g. `processing,completed`",
        )

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


@extend_schema_view(
    list=extend_schema(
        responses={204: {}},
        summary="Check if the service is running",
        description=textwrap.dedent(
            """
            If this endpoint returns a 204, the service is running as expected.
            """
        ),
    ),
)
class HealthCheckView(viewsets.ViewSet):
    openapi_tags = ["Server Status"]

    def list(self, request, *args, **kwargs):
        return Response(status=status.HTTP_204_NO_CONTENT)
