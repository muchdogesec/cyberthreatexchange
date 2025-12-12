from stix2 import IPv4Address
from stix2extensions import BankAccount
from datetime import datetime
from typing import List, Dict, Tuple


type_value_map = {
    # Cyber Observable Objects (SCOs)
    "artifact": dict(values=["url", "mime_type"]),
    "autonomous-system": dict(values=["number", "name"]),
    "directory": dict(values=["path"]),
    "domain-name": dict(values=["value"], refs=["resolves_to_refs"]),
    "email-addr": dict(values=["value"], refs=["belongs_to_ref"]),
    "email-message": dict(values=["subject", "body", "message_id"]),
    "file": dict(values=["name", "hashes"]),
    "ipv4-addr": dict(values=["value"], refs=["resolves_to_refs", "belongs_to_refs"]),
    "ipv6-addr": dict(values=["value"], refs=["resolves_to_refs", "belongs_to_refs"]),
    "mac-addr": dict(values=["value"]),
    "mutex": dict(values=["name"]),
    "network-traffic": dict(values=["protocols"], refs=["src_ref", "dst_ref"]),
    "process": dict(values=["command_line", "cwd"]),
    "software": dict(values=["name", "cpe", "vendor", "version"]),
    "url": dict(values=["value"]),
    "user-account": dict(values=["user_id", "account_login", "account_type"]),
    "windows-registry-key": dict(values=["key"]),
    "x509-certificate": dict(values=["subject", "issuer", "serial_number"]),
    
    # Domain Objects (SDOs)
    "attack-pattern": dict(values=["name"]),
    "campaign": dict(values=["name"]),
    "course-of-action": dict(values=["name"]),
    "grouping": dict(values=["name", "context"]),
    "identity": dict(values=["name"]),
    "incident": dict(values=["name"]),
    "indicator": dict(values=["name", "pattern"]),
    "infrastructure": dict(values=["name"]),
    "intrusion-set": dict(values=["name"]),
    "location": dict(values=["name", "country", "region"]),
    "malware": dict(values=["name"]),
    "malware-analysis": dict(values=["product", "version"]),
    "note": dict(values=["abstract", "content"]),
    "observed-data": dict(values=["objects"]),
    "opinion": dict(values=["explanation", "opinion"]),
    "report": dict(values=["name"]),
    "threat-actor": dict(values=["name"]),
    "tool": dict(values=["name", "tool_version"]),
    "vulnerability": dict(values=["name"]),
    
    # Relationship Objects (SROs)
    "relationship": dict(values=["relationship_type"], refs=["source_ref", "target_ref"]),
    "sighting": dict(values=["summary"], refs=["sighting_of_ref"]),
}


def extract_values_from_stix_object(stix_obj: dict, feed, feed_id: str) -> List[Dict]:
    """
    Extract searchable values and references from a STIX object.
    
    Args:
        stix_obj: A STIX object dictionary
        feed: The Feed model instance
        feed_id: UUID of the feed
        
    Returns:
        List of dicts containing ObjectValue model data
    """
    stix_id = stix_obj.get('id')
    stix_type = stix_obj.get('type')
    modified_str = stix_obj.get('modified')
    
    # Parse modified timestamp
    if modified_str:
        if isinstance(modified_str, str):
            modified_str = modified_str.replace('Z', '+00:00')
            modified = datetime.fromisoformat(modified_str)
        else:
            modified = modified_str
    else:
        modified = datetime.now()
    
    object_values = []
    
    if stix_type not in type_value_map:
        return object_values
    
    type_config = type_value_map[stix_type]
    
    # Extract direct values
    for value_attr in type_config.get('values', []):
        value = stix_obj.get(value_attr)
        
        if value is None:
            continue
        
        # Handle different value types
        if isinstance(value, list):
            for item in value:
                if item is not None:
                    object_values.append({
                        'feed_id': feed_id,
                        'stix_id': stix_id,
                        'stix_type': stix_type,
                        'modified': modified,
                        'value': str(item).lower(),
                        'value_type': value_attr,
                        'is_ref': False,
                        'ref_stix_id': None,
                    })
        elif isinstance(value, dict):
            # For hashes or other dict values, convert to string representation
            value_str = str(value).lower()
            object_values.append({
                'feed_id': feed_id,
                'stix_id': stix_id,
                'stix_type': stix_type,
                'modified': modified,
                'value': value_str,
                'value_type': value_attr,
                'is_ref': False,
                'ref_stix_id': None,
            })
        else:
            object_values.append({
                'feed_id': feed_id,
                'stix_id': stix_id,
                'stix_type': stix_type,
                'modified': modified,
                'value': str(value).lower(),
                'value_type': value_attr,
                'is_ref': False,
                'ref_stix_id': None,
            })
    
    # Extract reference values
    for ref_attr in type_config.get('refs', []):
        ref_value = stix_obj.get(ref_attr)
        
        if ref_value is None:
            continue
        
        # Handle different reference types
        if isinstance(ref_value, list):
            for ref_id in ref_value:
                if ref_id is not None:
                    object_values.append({
                        'feed_id': feed_id,
                        'stix_id': stix_id,
                        'stix_type': stix_type,
                        'modified': modified,
                        'value': str(ref_id).lower(),
                        'value_type': ref_attr,
                        'is_ref': True,
                        'ref_stix_id': str(ref_id),
                    })
        else:
            # Single reference
            object_values.append({
                'feed_id': feed_id,
                'stix_id': stix_id,
                'stix_type': stix_type,
                'modified': modified,
                'value': str(ref_value).lower(),
                'value_type': ref_attr,
                'is_ref': True,
                'ref_stix_id': str(ref_value),
            })
    
    return object_values


def save_object_values(stix_objects, feed, feed_id: str) -> Tuple[int, int]:
    """
    Extract and save object values to the database.
    Deletes old versions first if they exist.
    
    Args:
        stix_objects: A STIX object dict or list of STIX object dicts
        feed: The Feed model instance
        feed_id: UUID of the feed
        
    Returns:
        Tuple of (created_count, deleted_count)
    """
    from cyberthreatexchange.server.models import ObjectValue
    
    # Handle both single object and list of objects
    if isinstance(stix_objects, dict):
        stix_objects = [stix_objects]
    
    all_values_data = []
    stix_ids_to_delete = []
    
    # Extract values from all objects
    for stix_obj in stix_objects:
        stix_id = stix_obj.get('id')
        modified_str = stix_obj.get('modified')
        
        # Parse modified timestamp
        if modified_str:
            if isinstance(modified_str, str):
                modified_str = modified_str.replace('Z', '+00:00')
                modified = datetime.fromisoformat(modified_str)
            else:
                modified = modified_str
        else:
            modified = datetime.now()
        
        stix_ids_to_delete.append((stix_id, modified))
        
        # Extract values
        values_data = extract_values_from_stix_object(stix_obj, feed, feed_id)
        all_values_data.extend(values_data)
    
    # Delete existing records for all object versions
    deleted_count = 0
    for stix_id, modified in stix_ids_to_delete:
        count, _ = ObjectValue.objects.filter(
            feed=feed,
            stix_id=stix_id,
            modified=modified
        ).delete()
        deleted_count += count
    
    # Bulk create new records
    created_objects = ObjectValue.objects.bulk_create(
        [ObjectValue(**data) for data in all_values_data],
        ignore_conflicts=True
    )
    
    return len(created_objects), deleted_count