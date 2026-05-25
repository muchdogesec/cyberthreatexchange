import collections
import typing
import arango.exceptions
from django.conf import settings
from arango.client import ArangoClient
from arango.database import StandardDatabase, AsyncDatabase
from dogesec_commons.objects import db_view_creator

if typing.TYPE_CHECKING:
    from .. import settings

from stix2arango.stix2arango import Stix2Arango


def create_analyzer(db, *args, **kwargs):
    try:
        return db.create_analyzer(*args, **kwargs)
    except arango.exceptions.AnalyzerCreateError as e:  # pragma: no cover
        print(e.message)
        if e.error_code != 10:
            raise


def get_collection_names(db):
    collections = db.collections()
    if isinstance(db, AsyncDatabase):
        collections = collections.result()
    return [collection["name"] for collection in collections]


def get_semantic_search_properties(db: StandardDatabase):
    create_analyzer(
        db,
        "text_en_no_stem_3_10p",
        analyzer_type="text",
        properties={
            "locale": "",
            "case": "lower",
            "accent": False,
            "stemming": False,
            "edgeNgram": {"preserveOriginal": True},
        },
        features=["frequency", "position", "offset", "norm"],
    )
    links = {}
    for collection_name in get_collection_names(db):
        if collection_name.endswith("_vertex_collection") or collection_name.endswith(
            "_edge_collection"
        ):
            links[collection_name] = {
                "fields": {
                    "_is_latest": {"analyzers": ["identity"]},
                    "_record_modified": {"analyzers": ["identity"]},
                    "_id": {"analyzers": ["identity"]},
                    "id": {"analyzers": ["identity"]},
                    "type": {"analyzers": ["identity"]},
                },
                "inBackground": True
            }
    return {
        "links": links,
        "primarySort": [
            {
            "field": "_record_modified",
                "asc": True,
            },
        ]
    }


def setup_semantic_search_view(sync=True):

    semantic_view_name = settings.SEMANTIC_VIEW_NAME
    client = ArangoClient(settings.ARANGODB_HOST_URL)
    db = client.db(
        settings.ARANGODB_DATABASE + "_database",
        settings.ARANGODB_USERNAME,
        settings.ARANGODB_PASSWORD,
        verify=True,
    )
    if not sync:
        db = db.begin_async_execution()
    try:
        if sync:
            view = db.view(semantic_view_name)
        else:
            view = db.view(semantic_view_name).result()
        return db.update_view(semantic_view_name, get_semantic_search_properties(db))
    except Exception as e:
        print(f"Update failed: {e}, creating semantic search view '{semantic_view_name}'")
        return db.create_view(
            name=semantic_view_name,
            view_type="arangosearch",
            properties=get_semantic_search_properties(db),
        )


def setup_arangodb(sync=True):
    db_view_creator.startup_func()
    setup_semantic_search_view(sync=sync)


if __name__ == "__main__":  # pragma: no cover
    setup_arangodb()
