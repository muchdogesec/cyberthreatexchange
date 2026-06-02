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


def get_collection_names(db: StandardDatabase):
    collections = await_result_with_timeout(db.collections())
    return [collection["name"] for collection in collections]

def await_result_with_timeout(async_result, timeout=5):
    import time
    start_time = time.time()
    if not isinstance(async_result, arango.job.AsyncJob):
        return async_result
    while True:
        try:
            return async_result.result()
        except arango.exceptions.AsyncJobResultError as e:
            print(e.response)
            if time.time() - start_time > timeout:
                raise TimeoutError(f"Async job did not complete within {timeout} seconds") from e
            time.sleep(0.2)  # small sleep to prevent tight loop


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

def create_index_on_collection(collection_name):
    db = get_db().begin_async_execution()
    collection = db.collection(collection_name)
    print("creating indexes for bundle in ", collection_name)
    collection.add_index(dict(type='persistent', fields=['source_ref', '_is_ref', '_target_type', '_record_created'], name='bundle_source_type', inBackground=True, storedValues=['id', 'target_ref']))
    collection.add_index(dict(type='persistent', fields=['source_ref', '_is_ref', '_record_created'], name='bundle_source', inBackground=True, storedValues=['id', 'target_ref']))
    collection.add_index(dict(type='persistent', fields=['target_ref', '_is_ref', '_source_type', '_record_created'], name='bundle_target_type', inBackground=True, storedValues=['id', 'source_ref']))
    collection.add_index(dict(type='persistent', fields=['target_ref', '_is_ref', '_record_created'], name='bundle_target', inBackground=True, storedValues=['id', 'source_ref']))


def get_db():
    client = ArangoClient(settings.ARANGODB_HOST_URL)
    db = client.db(
        settings.ARANGODB_DATABASE + "_database",
        settings.ARANGODB_USERNAME,
        settings.ARANGODB_PASSWORD,
        verify=True,
    )
    return db

def setup_semantic_search_view(sync=True):
    semantic_view_name = settings.SEMANTIC_VIEW_NAME
    db = get_db()
    if not sync:
        db = db.begin_async_execution()
    try:
        if sync:
            view = db.view(semantic_view_name)
        else:
            view = await_result_with_timeout(db.view(semantic_view_name))
        return db.update_view(semantic_view_name, get_semantic_search_properties(db))
    except Exception as e:
        print(f"Update failed: {e}, creating semantic search view '{semantic_view_name}'")
        return db.create_view(
            name=semantic_view_name,
            view_type="arangosearch",
            properties=get_semantic_search_properties(db),
        )

def ensure_bundle_indexes():
    db = get_db()
    for collection_name in get_collection_names(db):
        if collection_name.endswith('_edge_collection'):
            create_index_on_collection(collection_name)

def setup_arangodb(sync=True):
    db_view_creator.startup_func()
    setup_semantic_search_view(sync=sync)
    ensure_bundle_indexes()


if __name__ == "__main__":  # pragma: no cover
    setup_arangodb()
