from stix2 import IPv4Address
from stix2extensions import BankAccount
from datetime import UTC, datetime
from typing import List, Dict, Tuple, Callable
import logging

from dogesec_commons.objects.helpers import TLP_VISIBLE_TO_ALL
from stix2arango.stix2arango.stix2arango import post_upload_hook
from cyberthreatexchange.server.models import (
    NewObjectValue,
    ObjectVersion,
    _refresh_stix_dedupe_state,
)


def external_id(obj):
    return [
        ref.get("external_id")
        for ref in obj.get("external_references", [])
        if ref.get("external_id")
    ][:1]


def guess_kb_data(obj: dict) -> tuple[str | None, dict]:
    """
    Infer knowledgebase only for ATT&CK objects and weakness.

    Returns:
        (knowledgebase, extra_values)
        knowledgebase: one of enterprise-attack/mobile-attack/ics-attack/cwe, or None
        extra_values: includes kb_id when available
    """
    obj_type = obj.get("type")
    kb_name = None

    extra = {}

    match obj_type:
        case "weakness":
            kb_name = "cwe"
    # Check for MITRE ATT&CK domains
    x_mitre_domains = obj.get("x_mitre_domains", [])
    if x_mitre_domains:
        domain = x_mitre_domains[0]
        if domain in ["enterprise-attack", "mobile-attack", "ics-attack"]:
            kb_name = domain

    # Check external references for other TTP types
    external_refs = obj.get("external_references", [])
    if external_refs:
        source_name = external_refs[0].get("source_name", "")
        ttp_source_name_mapping = {
            "capec": "capec",
            "mitre-atlas": "atlas",
            "DISARM": "disarm",
        }
        if source_name in ttp_source_name_mapping:
            kb_name = ttp_source_name_mapping[source_name]
    if kb_name and (kb_ids := external_id(obj)):
        extra["kb_id"] = kb_ids[0]
    return kb_name, extra


def get_file_values(obj):
    values = {}
    for k in ["name", "mime_type"]:
        if k in obj:
            values[k] = obj[k]
    if "hashes" in obj:
        values.update({k.lower().replace("-", ""): v for k, v in obj["hashes"].items()})
    return values


def get_cert_values(obj):
    values = {}
    for key in [
        "subject",
        "issuer",
        "serial_number",
        "signature_algorithm",
        "validity_not_before",
        "validity_not_after",
    ]:
        if key in obj:
            values[key] = obj[key]
    if "hashes" in obj:
        values.update({k.lower().replace("-", ""): v for k, v in obj["hashes"].items()})
    return values

def get_marking_definitions_values(obj):
    values = {}
    if name := obj.get("name"):
        values["name"] = name
    if def_type := obj.get("definition_type"):
        if def_type in obj.get("definition", {}):
            values[def_type] = obj["definition"][def_type]
    return values


def get_location_values(obj):
    values = {}
    for key in ["name", "region"]:
        if key in obj:
            values[key] = obj[key]
    for ext_ref in obj.get("external_references", []):
        source_name = ext_ref.get("source_name", "")
        if source_name in ["type", "alpha-3"]:
            values[source_name] = ext_ref["external_id"]
    return values


def get_values(obj: dict, value_keys: list[str] | dict[str, str] | Callable):
    if isinstance(value_keys, list):
        value_keys = {key: key for key in value_keys}
    if isinstance(value_keys, dict):
        return {key: str(obj[key]) for key in value_keys.keys() if key in obj}
    elif callable(value_keys):
        return value_keys(obj)
    else:
        raise ValueError("value_keys must be a list, a dictionary, or a callable")


s2e_sco_map = {
    "bank-account": dict(values=["iban", "bic", "currency"]),
    "cryptocurrency-wallet": dict(values=["value"]),
    "cryptocurrency-transaction": dict(values=["value", "symbol"]),
    "payment-card": dict(values=["value", "scheme", "currency"]),
    "phone-number": dict(values=["value", "country", "provider"]),
    "user-agent": dict(values=["value"]),
}
sco_value_map = {
    # Cyber Observable Objects (SCOs)
    "artifact": dict(values=["url", "mime_type"]),
    "autonomous-system": dict(values=["number", "name"]),
    "directory": dict(values=["path"]),
    "domain-name": dict(values=["value"]),
    "email-addr": dict(values=["value", "display_name"]),
    "email-message": dict(values=["subject", "body", "message_id"]),
    "file": dict(values=get_file_values),
    "ipv4-addr": dict(values=["value"]),
    "ipv6-addr": dict(values=["value"]),
    "mac-addr": dict(values=["value"]),
    "mutex": dict(values=["name"]),
    "network-traffic": dict(values=["protocols", "src_port", "dst_port", "src_packets", "dst_packets", "src_byte_count", "dst_byte_count"]),
    "process": dict(values=["command_line", "cwd"]),
    "software": dict(values=["name", "cpe", "vendor", "version", "swid"]),
    "url": dict(values=["value"]),
    "user-account": dict(values=["display_name", "account_login", "account_type", "user_id"]),
    "windows-registry-key": dict(values=["key", "values"]),
    "x509-certificate": dict(values=get_cert_values),
    **s2e_sco_map,
}
s2e_sdo_map = {
    "weakness": dict(values=["name"]),
    "exploit": dict(values=["name", "proof_of_concept"]),
}
# mitre ATT&CK TTP types can be identified by their x_mitre_domains property or specific external references
MITRE_VALUE_MAP = {
    "x-mitre-analytic": dict(values=["name"]),
    "x-mitre-asset": dict(values=["name"]),
    "x-mitre-collection": dict(values=["name"]),
    "x-mitre-data-component": dict(values=["name"]),
    "x-mitre-data-source": dict(values=["name"]),
    "x-mitre-detection-strategy": dict(values=["name"]),
    "x-mitre-matrix": dict(values=["name"]),
    "x-mitre-tactic": dict(values=["name"]),
}

sdo_value_map = {
    # Domain Objects (SDOs)
    "attack-pattern": dict(values=["name", "aliases"]),
    "campaign": dict(values=["name", "aliases"]),
    "course-of-action": dict(values=["name"]),
    "grouping": dict(values=["name", "context"]),
    "identity": dict(values=["name"]),
    "marking-definition": dict(values=get_marking_definitions_values),
    "incident": dict(values=["name"]),
    "indicator": dict(values=["name", "pattern"]),
    "infrastructure": dict(values=["name"]),
    "intrusion-set": dict(values=["name", "aliases"]),
    "location": dict(values=get_location_values),
    "malware": dict(values=["name", "x_mitre_aliases"]),
    "malware-analysis": dict(values=["product", "version"]),
    "note": dict(values=["abstract", "content"]),
    "observed-data": dict(values=["objects"]),
    "opinion": dict(values=["explanation", "opinion"]),
    "report": dict(values=["name"]),
    "threat-actor": dict(values=["name"]),
    "tool": dict(values=["name", "tool_version", "x_mitre_aliases"]),
    "vulnerability": dict(values=["name"]),
    **s2e_sdo_map,
    **MITRE_VALUE_MAP,
}
sro_value_map = {
    # Relationship Objects (SROs)
    "relationship": dict(values=["relationship_type"]),
    "sighting": dict(values=["summary"]),
}
type_value_map = {
    **sco_value_map,
    **sdo_value_map,
    **sro_value_map,
}

ALL_KNOWLEDGEBASES = {
    "enterprise-attack",
    "mobile-attack",
    "ics-attack",
    "cwe",
    "capec",
    "atlas",
    "disarm",
}

def extract_object_metadata(obj: dict) -> dict:
    """
    Extract key metadata from a STIX object.

    Args:
        obj: A STIX object dictionary

    Returns:
        A dictionary containing:
        - id: The STIX object ID
        - type: The STIX object type
        - values: The extracted values based on the object type
    """
    obj_id = obj["id"]
    obj_type = obj["type"]
    kb_name, kb_extra = guess_kb_data(obj)

    # Get the value configuration for this object type
    type_config = type_value_map.get(obj_type, {})
    value_keys = type_config.get("values", [])

    # Extract values using get_values function
    values = get_values(obj, value_keys) or {}
    values.update(kb_extra)

    retval = {
        "stix_id": obj_id,
        "type": obj_type,
        "knowledgebase": kb_name,
        "values": values,
    }

    for key in "modified", "created":
        if key in obj:
            retval[key] = obj[key]
    return retval


def save_object_values(stix_objects, feed_id: str) -> int:
    """
    Extract and save object values to the database.
    Deletes old versions first if they exist.

    Args:
        stix_objects: A STIX object dict or list of STIX object dicts
        feed_id: UUID of the feed

    Returns:
        The number of created object values
    """

    all_values_data_deduped = {}
    all_versions_data = []
    now = datetime.now(UTC)


    # Extract values from all objects
    for stix_obj in stix_objects:
        stix_id = stix_obj['id']
        metadata = extract_object_metadata(stix_obj)
        value_obj = NewObjectValue(**metadata, added_at=now, updated_at=now, feed_id=feed_id)
        if stix_id in all_values_data_deduped:
            existing_obj = all_values_data_deduped[stix_id]
            if existing_obj.modified and value_obj.modified and existing_obj.modified < value_obj.modified:
                all_values_data_deduped[stix_id] = value_obj
        if stix_id not in all_values_data_deduped:
            all_values_data_deduped[value_obj.stix_id] = value_obj

        all_versions_data.append(
            ObjectVersion(
                feed_id=feed_id,
                stix_id=value_obj.stix_id,
                modified=value_obj.modified,
                added_at=value_obj.updated_at,
            )
        )
    created = NewObjectValue.objects.bulk_create(
        all_values_data_deduped.values(),
        update_conflicts=True,
        batch_size=1000,
        update_fields=["modified", "created", "knowledgebase", "values", "updated_at"],
        unique_fields=["feed", "stix_id"],
    )

    _refresh_stix_dedupe_state([f.stix_id for f in created])

    ObjectVersion.objects.bulk_create(
        all_versions_data,
        ignore_conflicts=True,
        batch_size=1000,
    )
    return len(created)
