import contextlib
import itertools
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
    semantic_search_view = "semantic_search_view"
    SEMANTIC_SEARCH_QUERY_TEXT = """
    (
        ANALYZER(TOKENS(@search_param, "text_en") ALL IN doc.name, "text_en") OR ANALYZER(TOKENS(@search_param, "text_en") ALL IN doc.description, "text_en")
        OR ANALYZER(TOKENS(@search_param, "text_en_no_stem_3_10p") ALL IN doc.name, "text_en_no_stem_3_10p") OR ANALYZER(TOKENS(@search_param, "text_en_no_stem_3_10p") ALL IN doc.description, "text_en_no_stem_3_10p")
    )
    """

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

    def execute_query(self, query, bind_vars={}, paginate=True, container=None):
        if paginate:
            bind_vars["offset"], bind_vars["count"] = self.get_offset_and_count(
                self.count, self.page
            )
        cursor = self.db.aql.execute(
            query, bind_vars=bind_vars, count=True, full_count=True
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
        self, ext_id: str, revokable=False, bundle=False, nav_mode=False
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
        if bundle:
            bind_vars.update(keep_values=["_id"])
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
        
        if bundle:
            return self.get_bundle(matches)
        return Response(matches[0])

    def get_versions(self, stix_id):
        query = """
    FOR d IN @@view SEARCH d.id == @stix_id
    SORT d.modified DESC
    RETURN DISTINCT d.modified
"""
        return Response(
            dict(
                versions=self.execute_query(
                    query,
                    bind_vars={"@view": self.semantic_search_view, "stix_id": stix_id},
                    paginate=False,
                )
            )
        )

    def get_bundle(self, matches):
        binds = {"@view": settings.VIEW_NAME, "matches": matches}
        more_search_filters = []
        late_filters = []

        if not self.query_as_bool("show_embedded_refs", True):
            more_search_filters.append("d._is_ref != TRUE")

        if not self.query_as_bool("show_embedded_sros", False):
            late_filters.append("FILTER d._is_ref != TRUE")

        if types := self.query_as_array("types"):
            late_filters.append("FILTER d.type IN @types")
            binds["types"] = types

        binds["more_bundle_ids"] = []

        query = """
    LET matched_ids = @matches[*]._id

    LET bundle_ids = FLATTEN(
        FOR d IN @@view SEARCH d.type == 'relationship' AND (d._from IN matched_ids OR d._to IN matched_ids) #more_search_filters
        COLLECT id = d.id INTO docs LET d = FIRST(FOR dd IN docs[*].d SORT dd.modified DESC, dd._record_modified DESC LIMIT 1 RETURN dd) // dedeuplicate across multiple actip runs
        RETURN [d._id, d._from, d._to]
    ) 
    
    FOR d IN @@view SEARCH d._id IN UNION(bundle_ids, matched_ids, @more_bundle_ids)
    #late_filters
    COLLECT id = d.id INTO docs LET d = FIRST(FOR dd IN docs[*].d SORT dd.modified DESC, dd._record_modified DESC LIMIT 1 RETURN dd) // dedeuplicate across multiple actip runs
    LIMIT @offset, @count
    RETURN KEEP(d, KEYS(d, TRUE))
"""
        query = query.replace(
            "#more_search_filters",
            (
                ""
                if not more_search_filters
                else f" AND {' and '.join(more_search_filters)}"
            ),
        ).replace("#late_filters", "\n".join(late_filters))
        return self.execute_query(query, bind_vars=binds)

    def semantic_search(self, collections=None, valid_types=ALL_SEARCH_TYPES):
        valid_types = set(valid_types.copy())
        binds = {}
        search_filters = []
        extra_filters = []
        if search_param := self.query.get("text"):
            search_filters.append(self.SEMANTIC_SEARCH_QUERY_TEXT)
            binds.update(search_param=search_param)

        if updated_since := self.query.get("updated_since"):
            extra_filters.append("FILTER doc._record_modified >= @updated_since")
            binds.update(updated_since=updated_since)

        if name := self.query.get("name"):
            extra_filters.append("FILTER CONTAINS(LOWER(doc.name), @name_param)")
            binds.update(name_param=name.lower())

        search_filters.append("doc._is_latest == TRUE")
        if stix_ids := self.query_as_array("stix_ids"):
            binds["stix_ids"] = stix_ids
            search_filters.append("doc.id IN @stix_ids")
            
        show_embedded_refs = self.query_as_bool("show_embedded_refs", False)
        if not show_embedded_refs:
            extra_filters.append("FILTER doc._is_ref != TRUE")

        if value := self.query.get("value"):
            binds["search_value"] = value.lower()
            extra_filters.append(
                """
                FILTER (
                    doc.type == 'artifact' AND CONTAINS(LOWER(doc.payload_bin), @search_value) OR
                    doc.type == 'autonomous-system' AND CONTAINS(LOWER(doc.number), @search_value) OR
                    doc.type == 'bank-account' AND CONTAINS(LOWER(doc.iban), @search_value) OR
                    doc.type == 'payment-card' AND CONTAINS(LOWER(doc.value), @search_value) OR
                    doc.type == 'cryptocurrency-transaction' AND CONTAINS(LOWER(doc.value), @search_value) OR
                    doc.type == 'cryptocurrency-wallet' AND CONTAINS(LOWER(doc.value), @search_value) OR
                    doc.type == 'directory' AND CONTAINS(LOWER(doc.path), @search_value) OR
                    doc.type == 'domain-name' AND CONTAINS(LOWER(doc.value), @search_value) OR
                    doc.type == 'email-addr' AND CONTAINS(LOWER(doc.value), @search_value) OR
                    doc.type == 'email-message' AND CONTAINS(LOWER(doc.body), @search_value) OR
                    doc.type == 'file' AND CONTAINS(LOWER(doc.name), @search_value) OR
                    doc.type == 'ipv4-addr' AND CONTAINS(LOWER(doc.value), @search_value) OR
                    doc.type == 'ipv6-addr' AND CONTAINS(LOWER(doc.value), @search_value) OR
                    doc.type == 'mac-addr' AND CONTAINS(LOWER(doc.value), @search_value) OR
                    doc.type == 'mutex' AND CONTAINS(LOWER(doc.value), @search_value) OR
                    doc.type == 'network-traffic' AND CONTAINS(LOWER(doc.protocols), @search_value) OR
                    doc.type == 'phone-number' AND CONTAINS(LOWER(doc.value), @search_value) OR
                    doc.type == 'process' AND CONTAINS(LOWER(doc.pid), @search_value) OR
                    doc.type == 'software' AND CONTAINS(LOWER(doc.name), @search_value) OR
                    doc.type == 'url' AND CONTAINS(LOWER(doc.value), @search_value) OR
                    doc.type == 'user-account' AND CONTAINS(LOWER(doc.display_name), @search_value) OR
                    doc.type == 'user-agent' AND CONTAINS(LOWER(doc.string), @search_value) OR
                    doc.type == 'windows-registry-key' AND CONTAINS(LOWER(doc.key), @search_value) OR
                    doc.type == 'x509-certificate' AND CONTAINS(LOWER(doc.subject), @search_value)
                    //generic
                    OR
                    CONTAINS(LOWER(doc.value), @search_value) OR
                    CONTAINS(LOWER(doc.name), @search_value) OR
                    CONTAINS(LOWER(doc.number), @search_value)
                )
                """.strip()
            )

        binds["types"] = list(valid_types)
        search_filters.append("doc.type IN @types")
        if types := self.query_as_array("types"):
            binds["types"] = list(valid_types.intersection(types))
        collections_set = [] if not collections else [set(collections)]
        if qq := self.query_as_array("feed_ids"):
            collections_set.append(
                set([f"ctx_{fid.replace('-', '')}_vertex_collection" for fid in qq])
            )

        if qq := self.query_as_array("author_ids"):
            author_collections = []
            for aid in qq:
                author_collections.extend(
                    [
                        feed.vertex_collection
                        for feed in models.Feed.objects.filter(identity_id=aid)
                    ]
                )
            collections_set.append(set(author_collections))
        if collections_set:
            collections = set.intersection(*collections_set)
            binds["filtered_collections"] = list(collections)
            search_filters.append(
                'ANALYZER(STARTS_WITH(doc._id, @filtered_collections), "identity")'
            )

        keep_verb = None
        if show_feed_id := self.query_as_bool("show_feed_id", False):
            keep_verb = 'KEEP(doc, APPEND(KEYS(doc, TRUE), "_id"))'
        resp = self.generic_query(
            self.semantic_search_view,
            search_filters,
            extra_filters,
            binds,
            return_verb=keep_verb,
        )
        if show_feed_id:
            self.add_feed_id(resp.data["objects"])
        return resp

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

        query = """
            FOR doc IN @@collection_or_view
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
        )
        # print(query, binds)
        resp = self.execute_query(query, bind_vars=binds, **kwargs)
        return resp
    
    def get_context_for_objects(self, object_ids):
        bind_vars = {
            "object_ids": tuple(set(object_ids)),
        }
        objects = self.generic_query(self.semantic_search_view, [
            'doc._is_latest == TRUE',
            'doc.id IN @object_ids',
        ], [], bind_vars, use_limit=False, sort_statement="SORT doc.modified ASC")
        objects_by_id = {obj["id"]: obj for obj in objects}
        return objects_by_id

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
