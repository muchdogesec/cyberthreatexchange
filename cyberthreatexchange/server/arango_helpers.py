import base64
from collections import defaultdict
import contextlib
import itertools
import json
import struct
from types import SimpleNamespace
import typing
import uuid
from django.conf import settings
from dogesec_commons import objects
from cyberthreatexchange.server.utils import Pagination, Response
from drf_spectacular.utils import OpenApiParameter
from drf_spectacular.types import OpenApiTypes
from dogesec_commons.objects.helpers import (
    ArangoDBHelper as DSC_ArangoDBHelper,
    SCO_TYPES,
)
from rest_framework import exceptions
from cyberthreatexchange.server import models, utils
from arango.database import StandardDatabase
from rest_framework.request import Request

from cyberthreatexchange.worker.utils import md5_hash

if typing.TYPE_CHECKING:
    from .. import settings

import textwrap

TLP_TYPES = set(["marking-definition"])
ATTACK_TYPES = set(
    [
        "attack-pattern",
        "campaign",
        "course-of-action",
        "identity",
        "intrusion-set",
        "malware",
        "marking-definition",
        "tool",
        "x-mitre-data-component",
        "x-mitre-data-source",
        "x-mitre-matrix",
        "x-mitre-tactic",
        "x-mitre-asset",
        "x-mitre-detection-strategy",
        "x-mitre-analytic",
    ]
)

ATTACK_FORMS = {
    "Tactic": [dict(type="x-mitre-tactic")],
    "Analytic": [dict(type="x-mitre-analytic")],
    "Detection Strategy": [dict(type="x-mitre-detection-strategy")],
    "Technique": [
        dict(type="attack-pattern", x_mitre_is_subtechnique=False),
        dict(type="attack-pattern", x_mitre_is_subtechnique=None),
    ],
    "Sub-technique": [dict(type="attack-pattern", x_mitre_is_subtechnique=True)],
    "Mitigation": [dict(type="course-of-action")],
    "Group": [dict(type="intrusion-set")],
    "Software": [dict(type="malware"), dict(type="tool")],
    "Campaign": [dict(type="campaign")],
    "Data Source": [dict(type="x-mitre-data-source")],
    "Data Component": [dict(type="x-mitre-data-component")],
    "Asset": [dict(type="x-mitre-asset")],
}

BUNDLE2_CURSOR_VERSION = 1


ATLAS_FORMS = {
    "Tactic": [dict(type="x-mitre-tactic")],
    "Technique": [
        dict(type="attack-pattern", x_mitre_is_subtechnique=False),
        dict(type="attack-pattern", x_mitre_is_subtechnique=None),
    ],
    "Sub-technique": [dict(type="attack-pattern", x_mitre_is_subtechnique=True)],
    "Mitigation": [dict(type="course-of-action")],
}


DISARM_FORMS = {
    "Tactic": [dict(type="x-mitre-tactic")],
    "Technique": [
        dict(type="attack-pattern", x_mitre_is_subtechnique=False),
        dict(type="attack-pattern", x_mitre_is_subtechnique=None),
    ],
    "Sub-technique": [dict(type="attack-pattern", x_mitre_is_subtechnique=True)],
}

LOCATION_TYPES = set(["location"])
CWE_TYPES = set(
    [
        "weakness",
        "grouping",
        # "identity",
        # "marking-definition",
        # "extension-definition"
    ]
)

DISARM_TYPES = set(
    [
        "attack-pattern",
        "identity",
        "marking-definition",
        "x-mitre-matrix",
        "x-mitre-tactic",
    ]
)

ATLAS_TYPES = set(
    [
        "attack-pattern",
        "course-of-action",
        #   "identity",
        #   "marking-definition",
        "x-mitre-collection",
        "x-mitre-matrix",
        "x-mitre-tactic",
    ]
)

SOFTWARE_TYPES = set(["software", "identity", "marking-definition"])
CAPEC_TYPES = set(
    ["attack-pattern", "course-of-action", "identity", "marking-definition"]
)

RELATIONSHIP_TYPES = {"relationship", "sighting"}

LOCATION_SUBTYPES = set(["intermediate-region", "sub-region", "region", "country"])

CTI_SORT_FIELDS = [
    "modified_descending",
    "modified_ascending",
    "created_ascending",
    "created_descending",
    "name_ascending",
    "name_descending",
    "type_ascending",
    "type_descending",
]
SECTORS_SORT_FIELDS = [
    "name_ascending",
    "name_descending",
]

ALL_SEARCH_TYPES = CAPEC_TYPES.union(
    LOCATION_TYPES,
    SOFTWARE_TYPES,
    ATTACK_TYPES,
    DISARM_TYPES,
    CWE_TYPES,
    TLP_TYPES,
    ATLAS_TYPES,
    RELATIONSHIP_TYPES,
    ["report", "indicator"],
    SCO_TYPES,
)
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
ATTACK_SORT_FIELDS = CTI_SORT_FIELDS + ["attack_id_ascending", "attack_id_descending"]


class ArangoDBHelper(DSC_ArangoDBHelper):
    max_page_size = settings.MAXIMUM_PAGE_SIZE
    page_size = settings.DEFAULT_PAGE_SIZE

    @classmethod
    def get_paginated_response(
        cls, container, data, page_number, page_size=page_size, full_count=0
    ):
        return Response(
            {
                "page_size": page_size or cls.page_size,
                "page_number": page_number,
                "page_results_count": len(data),
                "total_results_count": full_count,
                container: data,
            }
        )

    @classmethod
    def get_paginated_response_schema(cls, container="objects", stix_type="identity"):
        if stix_type == "string":
            container_schema = {"type": "string"}
        else:
            container_schema = {
                "type": "object",
                "properties": {
                    "type": {
                        "example": stix_type,
                    },
                    "id": {
                        "example": f"{stix_type}--a86627d4-285b-5358-b332-4e33f3ec1075",
                    },
                },
                "additionalProperties": True,
            }
        return {
            "type": "object",
            "required": ["page_results_count", container],
            "properties": {
                "page_size": {
                    "type": "integer",
                    "example": cls.max_page_size,
                },
                "page_number": {
                    "type": "integer",
                    "example": 3,
                },
                "page_results_count": {
                    "type": "integer",
                    "example": cls.page_size,
                },
                "total_results_count": {
                    "type": "integer",
                    "example": cls.page_size * cls.max_page_size,
                },
                container: {"type": "array", "items": container_schema},
            },
        }

    @classmethod
    def get_schema_operation_parameters(self):
        parameters = [
            OpenApiParameter(
                Pagination.page_query_param,
                type=int,
                description=Pagination.page_query_description,
            ),
            OpenApiParameter(
                Pagination.page_size_query_param,
                type=int,
                description=Pagination.page_size_query_description,
            ),
        ]
        return parameters

    DB_NAME = f"{settings.ARANGODB_DATABASE}_database"

    def __init__(self, collection, request, container="objects") -> None:

        super().__init__(collection, request, container)
        self.container = container

    default_objects: list[str] = []

    def execute_query(self, query, bind_vars={}, paginate=True, container=None, full_count=True):
        if paginate:
            bind_vars["offset"], bind_vars["count"] = self.get_offset_and_count(
                self.count, self.page
            )
        cursor = self.db.aql.execute(
            query, bind_vars=bind_vars, count=True, full_count=full_count
        )
        if paginate:
            return self.get_paginated_response(
                container or self.container,
                list(cursor),
                self.page,
                self.page_size,
                cursor.statistics()["fullCount"],
            )
        return list(cursor)

    def get_object_by_external_id(
        self, ext_id: str, revokable=False, nav_mode=False
    ):
        bind_vars = {
            "@collection": self.collection,
            "ext_id": ext_id.lower(),
            "keep_values": None,
        }
        filters = ["FILTER doc.modified == @stix_version"]
        stix_version: str = None
        if q := self.query.get("version"):
            stix_version = q
            bind_vars.update(stix_version=stix_version)
        else:
            filters[0] = "FILTER doc._is_latest"

        if revokable:
            bind_vars["include_deprecated"] = self.query_as_bool(
                "include_deprecated", False
            )
            bind_vars["include_revoked"] = self.query_as_bool("include_revoked", False)
            filters.append(
                "FILTER (@include_revoked OR NOT doc.revoked) AND (@include_deprecated OR NOT doc.x_mitre_deprecated)"
            )

        main_filter = "FILTER LOWER(doc.external_references[0].external_id) == @ext_id"
        with contextlib.suppress(Exception):
            _, _ = ext_id.split("--")
            main_filter = "FILTER doc.id == @ext_id"

        query = """
            FOR doc in @@collection
            #main_filter
            #filters
            LIMIT @offset, @count
            RETURN KEEP(doc, @keep_values || KEYS(doc, TRUE))
            """
        query = query.replace("#main_filter", main_filter).replace(
            "#filters", "\n".join(filters)
        )
        if nav_mode:
            bind_vars.update(
                keep_values=[
                    "_id",
                    "name",
                    "external_references",
                    "id",
                    "type",
                ]
            )
        bind_vars.update(offset=0, count=None)
        matches = self.execute_query(query, bind_vars=bind_vars, paginate=False)

        if nav_mode:
            return self.get_nav(matches)

        matches = sorted(
            matches,
            key=lambda m: m.get("modified"),
            reverse=True,
        )
        matches = matches[:1]
        if not matches:
            raise exceptions.NotFound({"error": "No such object"})
        return Response(matches[0])
    
    def get_limit(self):
        limit = self.page_size
        if self.query.get("limit") is not None:
            with contextlib.suppress(TypeError, ValueError):
                limit = int(self.query.get("limit"))
        limit = max(1, min(self.max_page_size, limit))
        return limit

    def get_bundle(self, obj_id, feed: models.Feed):
        pair_limit = self.get_limit()
        query_cursor = decode_bundle_cursor(self.query.get("cursor")) or {}

        is_ref_matcher = [False, None]
        if self.query_as_bool('show_embedded_refs'):
            is_ref_matcher.append(True)

        query, binds = make_bundle_query(
            obj_id,
            pairLimit=pair_limit,
            cursor=query_cursor,
            secondary_relations=self.query_as_bool("secondary_relations", default=False),
            types=self.query_as_array("types"),
            secondary_types=self.query_as_array("secondary_types"),
            edge_collection=feed.edge_collection,
            vertex_collection=feed.vertex_collection,
            is_ref_matcher=is_ref_matcher
        )
        results = self.execute_query(query, bind_vars=binds, paginate=False)
        if not results:
            return Response({"objects": [], "next": None, "count": 0})
        v = results[0]
        next_window_cursor, obj_ids = make_cursor_for_next_page(
            v["level1Edges"], v["level2Edges"], binds["pairLimit"]
        )
        object_map = dict(v['objects'])
        if not query_cursor:
            obj_ids.insert(0, obj_id)
        objects = []
        for obj_id in obj_ids:
            if obj_id in object_map:
                objects.append(object_map[obj_id])
        return Response({
            "objects": objects,
            "next": next_window_cursor,
            "count": len(obj_ids),
        })
    
    def get_objects(self, feed):
        limit = self.get_limit()
        query, binds = make_objects_query(
            feed,
            types=self.query_as_array("types"),
            added_after=self.query.get("added_after") or None,
            limit=limit,
            show_embedded_refs=self.query_as_bool("show_embedded_refs", False),
        )
        results = self.execute_query(
            query,
            bind_vars=binds,
            paginate=False,
        )
        next_added_after = None
        for result in results:
            next_added_after = result.pop("_record_modified", next_added_after)
        return Response({
            "objects": results,
            "next": next_added_after,
            "count": len(results),
        })


    def get_existing_objects(
        self,
        feed_obj: models.Feed,
        object_ids: list[str],
        properties=["created", "modified", "created_by_ref", "_record_md5_hash"],
    ):
        from . import models

        properties = set(properties)
        properties.add("id")

        bind_vars = {
            "object_ids": object_ids,
            "properties": list(properties),
        }
        objects = {}
        for collection in [feed_obj.vertex_collection, feed_obj.edge_collection]:
            extra_filters = [
                "FILTER doc.id IN @object_ids",
                "FILTER doc._is_latest == TRUE",
            ]
            resp = self.generic_query(
                collection,
                [],
                extra_filters,
                bind_vars,
                return_verb="KEEP(doc, @properties)",
                use_limit=False,
                sort_statement='',
                scan_options="{ indexHint: 's2a_search', forceIndexHint: true }",
            )
            objects.update({x["id"]: x for x in resp})
        return objects

    def generic_query(
        self,
        collection_or_view,
        search_filters: list[str],
        extra_filters: list[str],
        binds,
        sort_statement="",
        sort_fields=SEMANTIC_SEARCH_SORT_FIELDS,
        return_verb=None,
        use_limit=True,
        scan_options='',
    ):
        search_filters_str = ""
        binds["@collection_or_view"] = collection_or_view
        return_verb = return_verb or "KEEP(doc, KEYS(doc, TRUE))"
        kwargs = dict(paginate=False)

        if not use_limit:
            limit_stmt = ""
        elif isinstance(use_limit, str):
            limit_stmt = use_limit
        else:
            limit_stmt = "LIMIT @offset, @count"
            kwargs.update(paginate=True)

        if not sort_statement:
            sort_statement = self.get_sort_stmt(sort_fields)

        if scan_options:
            scan_options = f"OPTIONS {scan_options}"

        query = """
            FOR doc IN @@collection_or_view
            #OPTIONS
            #SEARCH
            #FILTER
            #sort_stmt
            #LIMIT
            RETURN #return_verb
        """
        if search_filters:
            search_filters_str = "SEARCH " + (" AND ".join(search_filters))
        query = (
            query.replace("#SEARCH", search_filters_str)
            .replace("#FILTER", "\n".join(extra_filters))
            .replace("#return_verb", return_verb)
            .replace("#sort_stmt", sort_statement)
            .replace("#LIMIT", limit_stmt)
            .replace("#OPTIONS", scan_options)
        )
        # print(query, binds)
        resp = self.execute_query(query, bind_vars=binds, **kwargs)
        return resp
    
    def get_context_for_objects(self, object_ids):
        query = """
        FOR doc IN joined_view
        SEARCH doc.id IN @object_ids
        RETURN [KEEP(doc, KEYS(doc, TRUE)), doc._id]
        """
        objects = self.execute_query(query, bind_vars={
            'object_ids': list(object_ids.keys())
        }, paginate=False, full_count=False)
        retval = {}
        for obj, _id in objects:
            feed_id_stripped = _id.split('_')[1]
            if object_ids[obj['id']] == feed_id_stripped:
                retval[obj['id']] = obj
        
        return retval

    @staticmethod
    def add_feed_id(objects):
        feeds = dict(models.Feed.objects.all().values_list("collection_name", "id"))
        for obj in objects:
            collection_name, _, _ = obj.pop("_id").partition("/")
            collection_name = collection_name.removesuffix(
                "_vertex_collection"
            ).removesuffix("_edge_collection")
            feed_uuid = feeds.get(collection_name)
            # assert feed_uuid is not None, "Could not find feed for collection"
            obj["x_ctx_feed_id"] = feed_uuid

    def remove_object(self, feed_id, obj_id: str):
        feed = models.Feed.objects.get(id=feed_id)
        query = """
        LET FIRST = (
        FOR doc IN @@collection
        FILTER doc.id == @obj_id
        REMOVE doc IN @@collection
        RETURN doc._key
        )

        LET SECOND = (
        FOR doc IN @@edge_collection
        FILTER doc.source_ref == @obj_id OR doc.target_ref == @obj_id
        REMOVE doc IN @@edge_collection
        RETURN doc._key
        )
        FOR key IN UNION(FIRST, SECOND)
        RETURN key
        """
        bind_vars = {
            "@collection": feed.vertex_collection,
            "@edge_collection": feed.edge_collection,
            "obj_id": obj_id,
        }
        self.db.aql.execute(query, bind_vars=bind_vars, paginate=False)
        return True

    def build_context(self, context: dict, objects: list[dict], feed: models.Feed):
        obj_ids = []
        rel_ids = {}
        warnings = {}
        try:
            for obj in objects:
                obj_id = obj["id"]
                if obj["type"] == "relationship":
                    rel_ids[obj_id] = [obj.get("source_ref"), obj.get("target_ref")]
                obj_ids.append(obj.get("id"))
        except:
            return context
        if not obj_ids:
            return context

        context.update(
            obj_ids=obj_ids,
            rel_ids=rel_ids,
            existing_objects=self.get_existing_objects(
                feed, list(itertools.chain(obj_ids, *rel_ids.values()))
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
                obj_ids.remove(obj["id"])
            if obj["id"] in context["existing_objects"] and md5_hash(obj) == context[
                "existing_objects"
            ][obj["id"]].get("_record_md5_hash"):
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

def decode_bundle_cursor(cursor):
    if not cursor:
        return {}
    payload = base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4))
    version, k1_len, kid_len, k2_len, index = struct.unpack("!BIIIQ", payload[:21])
    if version != BUNDLE2_CURSOR_VERSION:
        raise ValueError(f"Unsupported bundle cursor version: {version}")

    offset = 21
    k1 = payload[offset : offset + k1_len].decode("utf-8") or None
    offset += k1_len
    kid = payload[offset : offset + kid_len].decode("utf-8") or None
    offset += kid_len
    k2 = payload[offset : offset + k2_len].decode("utf-8") or None
    return {"k1": k1, "kid": kid, "k2": k2, "index": int(index)}


def encode_bundle_cursor(cursor):
    if not cursor:
        return None
    values = []
    for key in ("k1", "kid", "k2"):
        value = cursor.get(key)
        values.append("" if value is None else str(value))
    index = int(cursor.get("index") or 0)

    encoded_values = [value.encode("utf-8") for value in values]
    payload = struct.pack(
        "!BIIIQ",
        BUNDLE2_CURSOR_VERSION,
        *(len(value) for value in encoded_values),
        index,
    )
    payload += b"".join(encoded_values)
    return base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")


def make_objects_query(
    feed: models.Feed,
    types: list[str],
    added_after: str,
    limit: int,
    show_embedded_refs: bool,
):
    query = """
    LET edges = @types == NULL OR CONTAINS(@types, "relationship") ? (
        FOR edge IN @@edge_collection
        FILTER edge._is_ref IN @is_ref_matcher
        FILTER @added_after == NULL OR edge._record_modified > @added_after
        SORT edge._record_modified ASC
        LIMIT @limit
        RETURN edge
    ) : []
    LET vertices = (
        FOR vertex IN @@vertex_collection
        FILTER @types == NULL OR vertex.type IN @types
        FILTER @added_after == NULL OR vertex._record_modified > @added_after
        SORT vertex._record_modified ASC
        LIMIT @limit
        RETURN vertex
    )
    FOR doc IN UNION(edges, vertices)
    SORT doc._record_modified ASC
    RETURN KEEP(doc, APPEND(KEYS(doc, TRUE), '_record_modified'))
    """
    bind_vars = {
        '@edge_collection': feed.edge_collection,
        '@vertex_collection': feed.vertex_collection,
        'types': types or None,
        'added_after': added_after,
        'is_ref_matcher': [True, False] if show_embedded_refs else [False],
        'limit': limit,
    }
    return query, bind_vars

def make_bundle_query(
    obj_id,
    pairLimit=400,
    cursor=None,
    secondary_relations=False,
    types=None,
    secondary_types=None,
    edge_collection=None,
    vertex_collection=None,
    is_ref_matcher=None,
):
    toplevel_query = """
    FOR e1 IN @@edgeCollection // OPTIONS {indexHint: <EDGE_INDEX>}
    FILTER e1.<FIELD> == @vertexId AND e1._is_ref IN @is_ref_matcher
    FILTER (@cursor == null) OR e1._record_modified > @cursor.k1
    FILTER @types == NULL OR e1.<TYPE_FIELD> IN @types
    LIMIT @pairLimit
    RETURN [e1._record_modified, e1.id, e1.<FIELD2>]
    """
    bindVars = {
        "vertexId": obj_id,
        "cursor": cursor or None,
        "pairLimit": pairLimit,
        "secondary_relations": secondary_relations,
        "@edgeCollection": edge_collection,
        "types": types or None,
        "secondary_types": secondary_types or types or None,
        "@vertexCollection": vertex_collection,
        "is_ref_matcher": is_ref_matcher,
    }

    queryJoined = f"""
    LET level1Edges = (
        FOR edge IN UNION(
            {toplevel_query.replace("<EDGE_INDEX>", repr('super_edge_to')).replace("<FIELD>", 'target_ref').replace('<FIELD2>', 'source_ref').replace('<TYPE_FIELD>', '_source_type')},
            {toplevel_query.replace("<EDGE_INDEX>", repr('super_edge_from')).replace("<FIELD>", 'source_ref').replace('<FIELD2>', 'target_ref').replace('<TYPE_FIELD>', '_target_type')}
        )
            SORT edge[0] ASC
            LIMIT @pairLimit
            RETURN edge
    )
    LET level1EdgeKeys = level1Edges[*][0]
    LET level1EdgeValues = level1Edges[*][2]
    LET level2_cursorEdges = (@cursor == null OR @cursor.kid == null) ? [] : (
        FOR e IN @@edgeCollection // OPTIONS {{ indexHint: 'super_edge_from' }}
        FILTER e.source_ref == @cursor.kid AND e._is_ref IN @is_ref_matcher
        FILTER e._record_modified > @cursor.k2
        FILTER @secondary_types == NULL OR e._target_type IN @secondary_types
        LIMIT @pairLimit
        RETURN [e._record_modified, e.id, e.source_ref, e.target_ref]
    )
    LET level2_nonCursorEdges = (
        FOR e IN @@edgeCollection // OPTIONS {{ indexHint: 'super_edge_from' }}
        FILTER e.source_ref IN level1EdgeValues AND e._is_ref IN @is_ref_matcher
        FILTER @secondary_types == NULL OR e._target_type IN @secondary_types
        LIMIT @pairLimit
        RETURN [e._record_modified, e.id, e.source_ref, e.target_ref]
    )
    LET level2Edges = @secondary_relations ? (
        FOR e2 IN UNION(level2_cursorEdges, level2_nonCursorEdges)
        SORT e2[2] ASC, e2[0] ASC
        LIMIT @pairLimit
        RETURN e2
    ) : []
    LET object_ids = UNION([@vertexId], level1Edges[*][1], level1Edges[*][-1], level2Edges[*][1], level2Edges[*][-2], level2Edges[*][-1])
    LET objects = (
        UNION(
            (
            FOR d IN @@vertexCollection
            FILTER d.id IN object_ids
            RETURN [d.id, KEEP(d, KEYS(d, TRUE))]
            ),
            (
            FOR d IN @@edgeCollection
            FILTER d.id IN object_ids
            RETURN [d.id, KEEP(d, KEYS(d, TRUE))]
            )
        )
    )
    return {{
        level1Edges,
        level2Edges,
        objects
    }}
    """

    return queryJoined, bindVars

def make_cursor_for_next_page(level1Edges, level2Edges, pairLimit):
    cursor = None
    edgedMap = defaultdict(list)
    for edge in level2Edges:
        edgedMap[edge[2]].append(edge)

    obj_ids = []
    seen = set()
    pairCount = 0

    def add_object_id(object_id):
        if object_id is None or object_id in seen:
            return
        seen.add(object_id)
        obj_ids.append(object_id)

    for edge in level1Edges:
        add_object_id(edge[-1])
        add_object_id(edge[1])
        cursor = dict(k1=edge[0], kid=edge[-1], k2=None)
        pairCount += 1
        for e2 in edgedMap[edge[2]]:
            add_object_id(e2[-1])
            add_object_id(e2[1])
            pairCount += 1
            cursor['k2'] = e2[0]
            if pairCount >= pairLimit:
                break
        if pairCount >= pairLimit:
            break
    if pairCount < pairLimit:
        cursor = None
    return encode_bundle_cursor(cursor), obj_ids
