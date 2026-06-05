import collections
import time
import typing
import arango.exceptions, arango.job
from django.conf import settings
from arango.client import ArangoClient
from arango.database import StandardDatabase, AsyncDatabase, Request
from dogesec_commons.objects import db_view_creator
import argparse

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
    collections = await_result_with_timeout(db.collections(), 5)
    return [collection["name"] for collection in collections]

def await_result_with_timeout(async_result, timeout=5, sleep=0.2):
    start_time = time.time()
    if not isinstance(async_result, arango.job.AsyncJob):
        return async_result
    while True:
        try:
            return async_result.result()
        except arango.exceptions.AsyncJobResultError as e:
            print(e.response)
            if timeout and (time.time() - start_time) > timeout:
                raise TimeoutError(f"Async job did not complete within {timeout} seconds") from e
            time.sleep(sleep)  # small sleep to prevent tight loop


def get_joined_properties(db: StandardDatabase):
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
                    "id": {"analyzers": ["identity"]},
                },
                "inBackground": True
            }
    return {
        "links": links
    }


def maybe_wait(task, sync):
    if sync:
        return await_result_with_timeout(task, sleep=5, timeout=1000)
    return task

def create_index_on_collection(collection_name, sync=False):
    db = get_db().begin_async_execution()
    collection = db.collection(collection_name)
    def maybe_wait_sync(task):
        return maybe_wait(task, sync)
    if collection_name.endswith('vertex_collection'):
        maybe_wait_sync(collection.add_index(dict(type='persistent', fields=['type', '_record_modified'], name='objects_filter_type', inBackground=True, storedValues=['id'])))
        maybe_wait_sync(collection.add_index(dict(type='persistent', fields=['_record_modified'], name='objects_filter', inBackground=True, storedValues=['id'])))
    else:
        print("creating indexes for bundle in ", collection_name)
        maybe_wait_sync(collection.add_index(dict(type='persistent', fields=['source_ref', '_is_ref', '_target_type', '_record_modified'], name='bundle_source_type', inBackground=True, storedValues=['id', 'target_ref'])))
        maybe_wait_sync(collection.add_index(dict(type='persistent', fields=['source_ref', '_is_ref', '_record_modified'], name='bundle_source', inBackground=True, storedValues=['id', 'target_ref'])))
        maybe_wait_sync(collection.add_index(dict(type='persistent', fields=['target_ref', '_is_ref', '_source_type', '_record_modified'], name='bundle_target_type', inBackground=True, storedValues=['id', 'source_ref'])))
        maybe_wait_sync(collection.add_index(dict(type='persistent', fields=['target_ref', '_is_ref', '_record_modified'], name='bundle_target', inBackground=True, storedValues=['id', 'source_ref'])))
        ## get objects
        maybe_wait_sync(collection.add_index(dict(type='persistent', fields=['_is_ref', '_record_modified'], name='objects_filter', inBackground=True, storedValues=['id'])))


def get_db():
    client = ArangoClient(settings.ARANGODB_HOST_URL)
    db = client.db(
        settings.ARANGODB_DATABASE + "_database",
        settings.ARANGODB_USERNAME,
        settings.ARANGODB_PASSWORD,
        verify=True,
    )
    return db

def setup_joined_view(sync=True):
    joined_view = settings.JOINED_VIEW_NAME
    db = get_db()
    if not sync:
        db = db.begin_async_execution()
    try:
        if sync:
            view = db.view(joined_view)
        else:
            view = maybe_wait(db.view(joined_view), sync)
        return maybe_wait(db.update_view(joined_view, get_joined_properties(db)), sync)
    except Exception as e:
        print(f"Update failed: {e}, creating joined view '{joined_view}'")
        return maybe_wait(db.create_view(
            name=joined_view,
            view_type="arangosearch",
            properties=get_joined_properties(db),
        ), sync)

def ensure_bundle_indexes(sync):
    db = get_db()
    for collection_name in get_collection_names(db):
        if collection_name.startswith('ctx_'):
            create_index_on_collection(collection_name, sync=sync)

def setup_arangodb(sync=True):
    setup_joined_view(sync=sync)
    ensure_bundle_indexes(sync=sync)


if __name__ == "__main__":  # pragma: no cover
    parser = argparse.ArgumentParser()
    parser.add_argument("--sync", "-s", action="store_true")
    args = parser.parse_args()
    setup_arangodb(sync=args.sync)
