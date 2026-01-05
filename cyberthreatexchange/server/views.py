"""
Views for the Cyber Threat Exchange server.
"""

import itertools
import logging
import textwrap
from django.utils import timezone

from cyberthreatexchange.worker.utils import md5_hash

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
from dogesec_commons.objects.helpers import SMO_TYPES
from dogesec_commons.objects.helpers import SCO_TYPES
from dogesec_commons.objects.helpers import SDO_TYPES

from dogesec_commons.identity import views as identity_view, serializers as identity_serializers


class ChoiceCSVFilter(BaseCSVFilter):
    field_class = ChoiceField


@extend_schema_view(
    list=extend_schema(
        summary="List Identities",
        description=textwrap.dedent(
            """
            List all STIX Identity objects that can be used to create feeds.
            """
        ),
    ),
    retrieve=extend_schema(
        summary="Retrieve an Identity",
        description=textwrap.dedent(
            """
            Retrieve a STIX Identity object by its ID.
            """
        ),
    ),
    create=extend_schema(
        summary="Create an Identity",
        description=textwrap.dedent(
            """
            Upload a valid STIX Identity object.

            The Identity object will be validated against the STIX specification.

            In order to create a feed, you must have a STIX Identity.
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

            * 
            """
        ),
    ),
    destroy=extend_schema(
        summary="Delete an Identity",
        description=textwrap.dedent(
            """
            Delete an Identity object.

            IMPORTANT: if an Identity object is linked to a feed, you cannot delete it. You must delete the Feed first.
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
            Create a new Feed.

            To create a Feed, you need to assign an Identity as the owner of the Feed. You must first create an Identity using the POST Identity endpoint.

            Once created, you can start uploading intelligence (as STIX objects) to the Feed.
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
        summary="Update a Feed",
        description=textwrap.dedent(
            """
            Update the metadata of the Feed.
            """
        ),
    ),
    destroy=extend_schema(
        summary="Delete a Feed",
        description=textwrap.dedent(
            """
            Delete the feed and all STIX objects that are inside it.

            IMPORTANT: this request will not delete the Identity object listed as the creator of this feed.
            """
        ),
    ),
)
class FeedView(viewsets.ModelViewSet):
    """
    A viewset for managing Feeds.
    """

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
            # OpenApiParameter(
            #     "text",
            #     description="Filter the results by the `name` and `description` property of the object.",
            #     type=OpenApiTypes.STR,
            # ),
        ],
        responses=serializers.StixObjectsPlaceholderSerializer(many=True),
    ),
    sdos=extend_schema(
        summary="List SDOs in a feed",
        description=textwrap.dedent(
            """
            Search and filter on SDO objects in a feed.
            """
        ),
        parameters=[
            OpenApiParameter(
                "types",
                description="Only show objects of selected types",
                enum=SDO_TYPES,
                explode=False,
                style="form",
                many=True,
            ),
            OpenApiParameter(
                "name",
                description="Filter the results by the name of the domain object",
                type=OpenApiTypes.STR,
            ),
            OpenApiParameter(
                "text",
                description="Filter the results by the `name` and `description` property of the object.",
                type=OpenApiTypes.STR,
            ),
        ],
        responses=serializers.StixObjectsPlaceholderSerializer(many=True),
    ),
    smos=extend_schema(
        summary="List SMOs in a feed",
        description=textwrap.dedent(
            """
            Search and filter on SMO objects in a feed.
            """
        ),
        parameters=[
            OpenApiParameter(
                "types",
                description="Only show objects of selected types",
                enum=SMO_TYPES,
                explode=False,
                style="form",
                many=True,
            ),
            # OpenApiParameter(
            #     "text",
            #     description="Filter the results by the `name` and `description` property of the object.",
            #     type=OpenApiTypes.STR,
            # ),
        ],
        responses=serializers.StixObjectsPlaceholderSerializer(many=True),
    ),
    scos=extend_schema(
        summary="List SCOs in a feed",
        description=textwrap.dedent(
            """
            Search and filter on SCO objects in a feed.
            """
        ),
        parameters=[
            OpenApiParameter(
                "types",
                description="Only show objects of selected types",
                enum=SCO_TYPES,
                explode=False,
                style="form",
                many=True,
            ),
            OpenApiParameter(
                "value",
                description="Filter the results by the observed value",
                type=OpenApiTypes.STR,
            ),
        ],
        responses=serializers.StixObjectsPlaceholderSerializer(many=True),
    ),
    sros=extend_schema(
        summary="List SROs in a feed",
        description=textwrap.dedent(
            """
            Search and filter on SRO objects in a feed.
            """
        ),
        parameters=[
            OpenApiParameter(
                "types",
                description="Only show objects of selected types",
                enum=["relationship", "sighting"],
                explode=False,
                style="form",
                many=True,
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
    versions=extend_schema(
        summary="Get object versions from a feed",
        description=textwrap.dedent(
            """
            Returns a list of all versions of the object in the database. You can then use the version returned on the GET objects endpoint to see the content for that version of the object.
            """
        ),
        responses=serializers.StixVersionsSerializer(),
    ),
    bundle=extend_schema(
        summary="Get bundle of related objects from a feed",
        description=textwrap.dedent(
            """
            Get all objects directly related to the specified object within the feed.
            """
        ),
        responses=serializers.StixObjectsPlaceholderSerializer(many=True),
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

    def list(self, request, feed_id=None):
        feed = get_object_or_404(models.Feed, id=feed_id)
        helper = ArangoDBHelper(feed.vertex_collection, request)
        return helper.semantic_search([feed.collection_name])
    
    @decorators.action(detail=False, methods=["GET"])
    def sdos(self, request, feed_id=None):
        feed = get_object_or_404(models.Feed, id=feed_id)
        helper = ArangoDBHelper(feed.vertex_collection, request)
        return helper.semantic_search([feed.collection_name], valid_types=SDO_TYPES)
    
    @decorators.action(detail=False, methods=["GET"])
    def scos(self, request, feed_id=None):
        feed = get_object_or_404(models.Feed, id=feed_id)
        helper = ArangoDBHelper(feed.vertex_collection, request)
        return helper.semantic_search([feed.collection_name], valid_types=SCO_TYPES)
    
    @decorators.action(detail=False, methods=["GET"])
    def smos(self, request, feed_id=None):
        feed = get_object_or_404(models.Feed, id=feed_id)
        helper = ArangoDBHelper(feed.vertex_collection, request)
        return helper.semantic_search([feed.collection_name], valid_types=SMO_TYPES)
    
    @decorators.action(detail=False, methods=["GET"])
    def sros(self, request, feed_id=None):
        SRO_TYPES = ["relationship"]
        feed = get_object_or_404(models.Feed, id=feed_id)
        helper = ArangoDBHelper(feed.vertex_collection, request)
        return helper.semantic_search([feed.collection_name], valid_types=SRO_TYPES)

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
        name = CharFilter()

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


class ObjectValueFilterSet(FilterSet):
    """Filter set for ObjectValue search."""
    value = CharFilter(
        field_name='value',
        lookup_expr='icontains',
        help_text='Search for values (full-text search)'
    )
    
    class Meta:
        model = models.ObjectValue
        fields = ['value']


@extend_schema_view(
    list=extend_schema(
        summary="Search Object Values",
        description="Search STIX object values with reference resolution using full-text search. "
                   "When searching by a value that matches a reference, objects containing that reference will also appear.",
        parameters=[
            OpenApiParameter(
                name='feed_ids',
                description='Comma-separated UUIDs of feeds to search within (optional, if omitted searches all feeds)',
                required=False,
                location=OpenApiParameter.QUERY,
            ),
            OpenApiParameter(
                name='value',
                description='Search term (full-text search)',
                required=True,
                location=OpenApiParameter.QUERY,
            ),
            OpenApiParameter(
                name='show_older_versions',
                description='If false (default), only return latest version of each object. If true, return all versions.',
                required=False,
                location=OpenApiParameter.QUERY,
            ),
        ],
        responses={200: serializers.ObjectValueSerializer, 400: DEFAULT_400_RESPONSE},
        
    ),
)
class ObjectValueSearchView(mixins.ListModelMixin, viewsets.GenericViewSet):
    """
    Search endpoint for STIX object values.
    
    Uses PostgreSQL full-text search (websearch) for better relevance and performance.
    When searching by a value that matches a reference:
    - Direct matches: Objects whose values match the search term
    - Reference matches: Objects that reference objects with matching values
    
    This enables transitive searching where searching for a malware name will also 
    return campaigns that reference that malware.
    
    Optional feed filtering:
    - If feed_ids provided: Only returns results found in those feeds
    - If feed_ids omitted: Returns results from all feeds
    
    Version filtering:
    - If show_older_versions=false (default): Only latest modified version per stix_id
    - If show_older_versions=true: All versions returned
    """
    
    openapi_tags = ["Search"]
    queryset = models.ObjectValue.objects.all()
    serializer_class = serializers.ObjectValueSerializer
    pagination_class = Pagination("values")
    filter_backends = [DjangoFilterBackend]
    filterset_class = ObjectValueFilterSet
    
    def get_queryset(self):
        """Search with optional feed filtering and version control using full-text search."""
        from django.db.models import Q, Case, When, Value, IntegerField, F, Window, Max
        from django.db.models.functions import RowNumber
        from django.contrib.postgres.search import SearchVector, SearchQuery, SearchRank
        
        search_value = self.request.query_params.get('value', '').strip()
        feed_ids_param = self.request.query_params.get('feed_ids', '').strip()
        show_older_versions = self.request.query_params.get('show_older_versions', 'false').lower() == 'true'
        
        if not search_value:
            raise exceptions.ValidationError({'value': 'This field is required.'})
        
        # Parse feed_ids if provided
        feed_ids_list = []
        if feed_ids_param:
            feed_ids_list = [fid.strip() for fid in feed_ids_param.split(',') if fid.strip()]
            # Validate feed IDs exist
            existing_feeds = models.Feed.objects.filter(id__in=feed_ids_list).count()
            if existing_feeds != len(feed_ids_list):
                raise exceptions.ValidationError({'feed_ids': 'One or more feed IDs not found.'})
        
        # Start with base queryset
        queryset = models.ObjectValue.objects.all()
        
        # Filter by feed_ids if provided
        if feed_ids_list:
            queryset = queryset.filter(feed_id__in=feed_ids_list)
        
        # Pre-filter to only latest versions if needed (before search)
        if not show_older_versions:
            # Subquery to get the max modified per stix_id per feed
            from django.db.models import OuterRef, Subquery
            max_modified_subquery = models.ObjectValue.objects.filter(
                stix_id=OuterRef('stix_id'),
                feed_id=OuterRef('feed_id')
            ).values('stix_id', 'feed_id').annotate(
                max_mod=Max('modified')
            ).values('max_mod')
            
            queryset = queryset.annotate(
                max_modified=Subquery(max_modified_subquery)
            ).filter(modified=F('max_modified'))
        
        # Split search value into individual words for independent matching
        search_words = [word.strip() for word in search_value.split() if word.strip()]
        
        if not search_words:
            raise exceptions.ValidationError({'value': 'No valid search terms provided.'})
        
        # Build Q objects for icontains matching on each word
        from django.db.models import Q
        word_q = Q()
        for word in search_words:
            word_q |= Q(value__icontains=word)
        
        # Get direct value matches using icontains
        direct_matches = queryset.filter(
            is_ref=False
        ).filter(word_q).values('id')
        
        # Get reference matches (objects that reference objects with matching values)
        # Step 1: Find all objects with values matching the search terms
        matching_stix_ids = queryset.filter(
            word_q
        ).values_list('stix_id', flat=True).distinct()
        
        # Step 2: Find objects that reference those matching objects
        ref_matches = queryset.filter(
            is_ref=True,
            ref_stix_id__in=matching_stix_ids
        ).values('id')
        
        # Combine all result sets
        combined_ids = direct_matches.union(ref_matches)
        
        # Query back to get full model instances and sort by modified date
        combined_queryset = models.ObjectValue.objects.filter(
            id__in=combined_ids
        ).order_by('-modified').distinct()
        return combined_queryset
    
    def list(self, request, *args, **kwargs):
        """List search results with relevance scoring."""
        return super().list(request, *args, **kwargs)
    

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

