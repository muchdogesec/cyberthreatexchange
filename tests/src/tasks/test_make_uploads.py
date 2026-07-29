"""
Tests for tasks.make_uploads' warning-resolution handling (skip vs rewrite), and
for the relationship-resolution helpers used by the TAXII connector poller
(remove_problematic_relationships, rerun_relationship_uploads).
"""

import pytest
from unittest.mock import patch

from cyberthreatexchange.server import models
from cyberthreatexchange.server.arango_helpers import ArangoDBHelper
from cyberthreatexchange.worker.tasks import (
    make_uploads,
    remove_problematic_relationships,
    rerun_relationship_uploads,
)
from tests.src.data import apt29_malware, apt29_threat_actor


def _get_uploaded(feed, obj_id):
    helper = ArangoDBHelper(feed.vertex_collection, None)
    existing = helper.get_existing_objects(feed, [obj_id])
    return existing.get(obj_id)


class TestMakeUploadsWarningResolution:
    def test_object_without_warning_is_uploaded(self, job, feed):
        obj = apt29_malware.copy()
        with patch("cyberthreatexchange.worker.tasks.save_object_values"):
            make_uploads(job.id, [obj], warnings={})

        uploaded = _get_uploaded(feed, obj["id"])
        assert uploaded is not None
        assert uploaded["created"] == obj["created"]

    def test_object_with_skipped_warning_is_not_uploaded(self, job, feed):
        obj = apt29_threat_actor.copy()
        warnings = {
            0: {
                "type": "existing_object",
                "message": "stix object already exists in backend",
                "id": obj["id"],
                "resolution": "skipped",
                "index": 0,
            }
        }
        with patch("cyberthreatexchange.worker.tasks.save_object_values"):
            make_uploads(job.id, [obj], warnings=warnings)

        uploaded = _get_uploaded(feed, obj["id"])
        assert uploaded is None

    def test_object_with_rewrite_warning_is_uploaded_with_corrected_created(
        self, job, feed
    ):
        obj = apt29_malware.copy()
        obj["id"] = "malware--11111111-1111-4111-8111-111111111199"
        obj["created"] = "2030-01-01T00:00:00.000Z"  # wrong; expect this rewritten
        corrected_created = "2020-01-15T10:00:00.000Z"
        warnings = {
            0: {
                "type": "created_mismatch",
                "message": "'created' timestamp rewritten to match existing version",
                "id": obj["id"],
                "resolution": "rewrite",
                "index": 0,
                "created": corrected_created,
            }
        }
        with patch("cyberthreatexchange.worker.tasks.save_object_values"):
            make_uploads(job.id, [obj], warnings=warnings)

        uploaded = _get_uploaded(feed, obj["id"])
        assert uploaded is not None
        assert uploaded["created"] == corrected_created


class TestRemoveProblematicRelationships:
    def test_relationship_with_resolvable_refs_is_kept(self, job):
        objects = [
            {"type": "malware", "id": "malware--a"},
            {"type": "threat-actor", "id": "threat-actor--b"},
            {
                "type": "relationship",
                "id": "relationship--c",
                "source_ref": "malware--a",
                "target_ref": "threat-actor--b",
            },
        ]

        def build_context(context, objs, feed):
            context.update(
                obj_ids=["malware--a", "threat-actor--b", "relationship--c"],
                existing_objects={},
            )
            return context

        with patch.object(
            ArangoDBHelper, "build_context", side_effect=build_context
        ):
            result = remove_problematic_relationships(job, objects)

        assert result == objects
        assert not models.UnprocessedRelationship.objects.filter(job=job).exists()

    def test_relationship_with_unresolvable_ref_is_stashed_and_removed(self, job):
        objects = [
            {"type": "malware", "id": "malware--a"},
            {
                "type": "relationship",
                "id": "relationship--c",
                "source_ref": "malware--a",
                "target_ref": "threat-actor--missing",
            },
        ]

        def build_context(context, objs, feed):
            context.update(obj_ids=["malware--a", "relationship--c"], existing_objects={})
            return context

        with patch.object(
            ArangoDBHelper, "build_context", side_effect=build_context
        ):
            result = remove_problematic_relationships(job, objects)

        assert result == [objects[0]]
        unresolved = models.UnprocessedRelationship.objects.get(job=job)
        assert unresolved.stix_id == "relationship--c"
        assert unresolved.stix_data == objects[1]

    def test_ref_resolvable_via_existing_objects_is_kept(self, job):
        objects = [
            {
                "type": "relationship",
                "id": "relationship--c",
                "source_ref": "malware--a",
                "target_ref": "threat-actor--b",
            },
        ]

        def build_context(context, objs, feed):
            context.update(
                obj_ids=["relationship--c"],
                existing_objects={"malware--a": {}, "threat-actor--b": {}},
            )
            return context

        with patch.object(
            ArangoDBHelper, "build_context", side_effect=build_context
        ):
            result = remove_problematic_relationships(job, objects)

        assert result == objects
        assert not models.UnprocessedRelationship.objects.filter(job=job).exists()

    def test_non_relationship_objects_are_never_stashed(self, job):
        objects = [{"type": "malware", "id": "malware--a"}]

        def build_context(context, objs, feed):
            context.update(obj_ids=["malware--a"], existing_objects={})
            return context

        with patch.object(
            ArangoDBHelper, "build_context", side_effect=build_context
        ):
            result = remove_problematic_relationships(job, objects)

        assert result == objects
        assert not models.UnprocessedRelationship.objects.filter(job=job).exists()


class TestRerunRelationshipUploads:
    def test_still_unresolved_relationship_is_kept_and_warned(self, job):
        rel = models.UnprocessedRelationship.objects.create(
            job=job,
            stix_id="relationship--c",
            stix_data={
                "type": "relationship",
                "id": "relationship--c",
                "source_ref": "malware--a",
                "target_ref": "threat-actor--missing",
            },
        )

        def build_context(context, objs, feed):
            context.update(
                obj_ids=["relationship--c", "malware--a"], existing_objects={}
            )
            return context

        with patch.object(
            ArangoDBHelper, "build_context", side_effect=build_context
        ):
            objects, warnings = rerun_relationship_uploads(job)

        assert objects == [rel.stix_data]
        assert len(warnings) == 1
        warning = next(iter(warnings.values()))
        assert warning["type"] == "missing_target"
        assert warning["resolution"] == "skipped"
        assert models.UnprocessedRelationship.objects.filter(pk=rel.pk).exists()

    def test_now_resolved_relationship_is_deleted_and_not_warned(self, job):
        rel = models.UnprocessedRelationship.objects.create(
            job=job,
            stix_id="relationship--c",
            stix_data={
                "type": "relationship",
                "id": "relationship--c",
                "source_ref": "malware--a",
                "target_ref": "threat-actor--b",
            },
        )

        def build_context(context, objs, feed):
            context.update(
                obj_ids=["relationship--c"],
                existing_objects={"malware--a": {}, "threat-actor--b": {}},
            )
            return context

        with patch.object(
            ArangoDBHelper, "build_context", side_effect=build_context
        ):
            objects, warnings = rerun_relationship_uploads(job)

        assert warnings == {}
        assert not models.UnprocessedRelationship.objects.filter(pk=rel.pk).exists()
