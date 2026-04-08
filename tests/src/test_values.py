"""Tests for value extraction and persistence logic in values.py."""

import json
from datetime import datetime, timezone

import pytest
from stix2 import AttackPattern, File as StixFile, Indicator, Location, TLP_AMBER

from cyberthreatexchange.server import models
from cyberthreatexchange.server.values.values import (
    extract_object_metadata,
    get_file_values,
    get_location_values,
    get_marking_definitions_values,
    get_values,
    save_object_values,
)


def _to_dict(stix_object):
    return json.loads(stix_object.serialize())


class TestValueHelpers:
    def test_get_file_values_from_real_stix_file(self):
        stix_file = StixFile(
            name="payload.bin",
            hashes={"MD5": "b026324c6904b2a9cb4b88d6d61c81d1", "SHA-256": "4355a46b19d348dc2f57c046f8ef63d4538ebb936000f3c9ee954a27460dd865"},
        )

        values = get_file_values(_to_dict(stix_file))

        assert values == {
            "name": "payload.bin",
            "md5": "b026324c6904b2a9cb4b88d6d61c81d1",
            "sha256": "4355a46b19d348dc2f57c046f8ef63d4538ebb936000f3c9ee954a27460dd865",
        }

    def test_get_location_values_from_real_stix_location(self):
        location = Location(
            name="United Kingdom",
            region="northern-europe",
            external_references=[
                {"source_name": "type", "external_id": "country"},
                {"source_name": "alpha-3", "external_id": "GBR"},
            ],
        )

        values = get_location_values(_to_dict(location))

        assert values == {
            "name": "United Kingdom",
            "region": "northern-europe",
            "type": "country",
            "alpha-3": "GBR",
        }

    def test_get_marking_definition_values_from_real_stix_marking(self):
        values = get_marking_definitions_values(_to_dict(TLP_AMBER))

        assert values == {"tlp": "amber", 'name': "TLP:AMBER"}

    def test_get_values_raises_on_invalid_value_keys_type(self):
        with pytest.raises(
            ValueError,
            match="value_keys must be a list, a dictionary, or a callable",
        ):
            get_values({"name": "x"}, 123)


class TestExtractObjectMetadata:
    def test_extract_attack_pattern_metadata_from_real_stix_object(self):
        attack_pattern = AttackPattern(
            id="attack-pattern--11111111-1111-4111-8111-111111111111",
            name="Phishing",
            aliases=["T1566"],
            allow_custom=True,
            x_mitre_domains=["enterprise-attack"],
            external_references=[
                {"source_name": "mitre-attack", "external_id": "T1566"}
            ],
            created=datetime(2024, 1, 1, tzinfo=timezone.utc),
            modified=datetime(2024, 1, 1, tzinfo=timezone.utc),
        )

        metadata = extract_object_metadata(_to_dict(attack_pattern))

        assert metadata["stix_id"] == attack_pattern.id
        assert metadata["type"] == "attack-pattern"
        assert metadata["values"]["name"] == "Phishing"
        assert "T1566" in metadata["values"]["aliases"]
        assert metadata["knowledgebase"] == "enterprise-attack"
        assert metadata["values"]["kb_id"] == "T1566"
        assert "created" in metadata
        assert "modified" in metadata

    def test_extract_indicator_metadata_from_real_stix_object(self):
        indicator = Indicator(
            id="indicator--22222222-2222-4222-8222-222222222222",
            name="Malicious IP",
            pattern="[ipv4-addr:value = '198.51.100.10']",
            pattern_type="stix",
            valid_from=datetime(2024, 1, 1, tzinfo=timezone.utc),
            created=datetime(2024, 1, 1, tzinfo=timezone.utc),
            modified=datetime(2024, 1, 1, tzinfo=timezone.utc),
        )

        metadata = extract_object_metadata(_to_dict(indicator))

        assert metadata["stix_id"] == indicator.id
        assert metadata["type"] == "indicator"
        assert metadata["values"]["name"] == "Malicious IP"
        assert "ipv4-addr:value" in metadata["values"]["pattern"]
        assert metadata["knowledgebase"] is None
        assert "kb_id" not in metadata["values"]

    def test_extract_weakness_sets_cwe_knowledgebase_and_kb_id(self):
        weakness_obj = {
            "type": "weakness",
            "id": "weakness--aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            "name": "Improper Input Validation",
            "external_references": [
                {"source_name": "cwe", "external_id": "CWE-20"}
            ],
            "created": "2024-01-01T00:00:00Z",
            "modified": "2024-01-01T00:00:00Z",
        }

        metadata = extract_object_metadata(weakness_obj)

        assert metadata["type"] == "weakness"
        assert metadata["knowledgebase"] == "cwe"
        assert metadata["values"]["kb_id"] == "CWE-20"


@pytest.mark.django_db
class TestSaveObjectValues:
    def test_save_object_values_creates_records_for_real_stix_objects(self, feed):
        ipv4 = _to_dict(
            Indicator(
                id="indicator--33333333-3333-4333-8333-333333333333",
                name="Known bad IP",
                pattern="[ipv4-addr:value = '203.0.113.55']",
                pattern_type="stix",
                valid_from=datetime(2024, 1, 1, tzinfo=timezone.utc),
                created=datetime(2024, 1, 1, tzinfo=timezone.utc),
                modified=datetime(2024, 1, 1, tzinfo=timezone.utc),
            )
        )
        location = _to_dict(
            Location(
                id="location--44444444-4444-4444-8444-444444444444",
                name="France",
                region="western-europe",
                created=datetime(2024, 1, 1, tzinfo=timezone.utc),
                modified=datetime(2024, 1, 1, tzinfo=timezone.utc),
            )
        )

        created_count = save_object_values([ipv4, location], feed_id=str(feed.id))

        assert created_count == 2
        assert models.NewObjectValue.objects.filter(feed=feed).count() == 2
        assert models.ObjectVersion.objects.filter(feed=feed).count() == 2

    def test_save_object_values_keeps_latest_modified_for_same_stix_id(self, feed):
        created_at = datetime(2024, 1, 1, tzinfo=timezone.utc)
        stix_id = "indicator--55555555-5555-4555-8555-555555555555"

        old_version = _to_dict(
            Indicator(
                id=stix_id,
                name="Old indicator name",
                pattern="[ipv4-addr:value = '10.0.0.1']",
                pattern_type="stix",
                valid_from=created_at,
                created=created_at,
                modified=datetime(2024, 1, 1, tzinfo=timezone.utc),
            )
        )
        new_version = _to_dict(
            Indicator(
                id=stix_id,
                name="New indicator name",
                pattern="[ipv4-addr:value = '10.0.0.2']",
                pattern_type="stix",
                valid_from=created_at,
                created=created_at,
                modified=datetime(2024, 1, 2, tzinfo=timezone.utc),
            )
        )

        created_count = save_object_values(
            [old_version, new_version],
            feed_id=str(feed.id),
        )

        assert created_count == 1
        stored = models.NewObjectValue.objects.get(feed=feed, stix_id=stix_id)
        assert stored.values["name"] == "New indicator name"

        versions = models.ObjectVersion.objects.filter(feed=feed, stix_id=stix_id)
        assert versions.count() == 2

    def test_save_object_values_persists_knowledgebase_and_kb_id(self, feed):
        attack_pattern = _to_dict(
            AttackPattern(
                id="attack-pattern--77777777-7777-4777-8777-777777777777",
                name="Credential Access",
                aliases=["T1110"],
                allow_custom=True,
                x_mitre_domains=["enterprise-attack"],
                external_references=[
                    {"source_name": "mitre-attack", "external_id": "T1110"}
                ],
                created=datetime(2024, 1, 1, tzinfo=timezone.utc),
                modified=datetime(2024, 1, 1, tzinfo=timezone.utc),
            )
        )

        created_count = save_object_values([attack_pattern], feed_id=str(feed.id))

        assert created_count == 1
        stored = models.NewObjectValue.objects.get(
            feed=feed,
            stix_id="attack-pattern--77777777-7777-4777-8777-777777777777",
        )
        assert stored.knowledgebase == "enterprise-attack"
        assert stored.values["kb_id"] == "T1110"
