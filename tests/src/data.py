"""
Test data containing valid STIX 2.1 objects for testing.
"""

# Malware object representing a known threat
apt29_malware = {
    "type": "malware",
    "spec_version": "2.1",
    "id": "malware--d1c612bc-146f-4b65-b7b0-9a54a14150a4",
    "created": "2020-01-15T10:00:00.000Z",
    "modified": "2020-01-15T10:00:00.000Z",
    "name": "Cobalt Strike",
    "description": "Cobalt Strike is a commercial penetration testing tool that is widely used by APT29 and other threat actors.",
    "malware_types": ["backdoor", "remote-access-trojan"],
    "is_family": True
}

# Threat Actor object
apt29_threat_actor = {
    "type": "threat-actor",
    "spec_version": "2.1",
    "id": "threat-actor--899ce53f-13a0-479b-a0e4-67d46e241542",
    "created": "2020-01-15T10:00:00.000Z",
    "modified": "2020-01-15T10:00:00.000Z",
    "name": "APT29",
    "description": "APT29, also known as Cozy Bear, is a threat actor attributed to Russian intelligence services.",
    "threat_actor_types": ["nation-state"],
    "aliases": ["Cozy Bear", "The Dukes"],
    "sophistication": "strategic",
    "resource_level": "government",
    "primary_motivation": "organizational-gain"
}

# Attack Pattern object
spearphishing_attack = {
    "type": "attack-pattern",
    "spec_version": "2.1",
    "id": "attack-pattern--2e34237d-8574-43f6-aace-ae2915de8597",
    "created": "2020-01-15T10:00:00.000Z",
    "modified": "2020-01-15T10:00:00.000Z",
    "name": "Spearphishing Attachment",
    "description": "Adversaries may send spearphishing emails with a malicious attachment in an attempt to gain access to victim systems.",
    "external_references": [
        {
            "source_name": "mitre-attack",
            "external_id": "T1566.001",
            "url": "https://attack.mitre.org/techniques/T1566/001"
        }
    ]
}

# Identity object representing a victim organization
victim_organization = {
    "type": "identity",
    "spec_version": "2.1",
    "id": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
    "created": "2020-01-15T10:00:00.000Z",
    "modified": "2020-01-15T10:00:00.000Z",
    "name": "Government Agency Alpha",
    "description": "A government agency targeted by APT29 operations.",
    "identity_class": "organization",
    "sectors": ["government-national"]
}

# Indicator object for network detection
network_indicator = {
    "type": "indicator",
    "spec_version": "2.1",
    "id": "indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
    "created": "2020-01-15T10:00:00.000Z",
    "modified": "2020-01-15T10:00:00.000Z",
    "name": "Cobalt Strike C2 Domain",
    "description": "Domain associated with Cobalt Strike command and control infrastructure.",
    "pattern": "[domain-name:value = 'malicious-c2.example.com']",
    "pattern_type": "stix",
    "valid_from": "2020-01-15T10:00:00.000Z",
    "indicator_types": ["malicious-activity"]
}

# Campaign object
apt29_campaign = {
    "type": "campaign",
    "spec_version": "2.1",
    "id": "campaign--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
    "created": "2020-01-15T10:00:00.000Z",
    "modified": "2020-01-15T10:00:00.000Z",
    "name": "Operation Ghost Writer",
    "description": "A campaign by APT29 targeting government agencies using spearphishing and Cobalt Strike.",
    "first_seen": "2020-01-01T00:00:00.000Z",
    "last_seen": "2020-03-31T23:59:59.000Z",
    "objective": "Data theft and long-term access to government systems"
}

# Infrastructure object
c2_infrastructure = {
    "type": "infrastructure",
    "spec_version": "2.1",
    "id": "infrastructure--3f9b5f3c-5c3a-4f5d-9e5e-3c3c3c3c3c3c",
    "created": "2020-01-15T10:00:00.000Z",
    "modified": "2020-01-15T10:00:00.000Z",
    "name": "APT29 Command and Control Server",
    "description": "Command and control infrastructure used by APT29 for communicating with Cobalt Strike beacons.",
    "infrastructure_types": ["command-and-control"]
}

# Tool object
mimikatz_tool = {
    "type": "tool",
    "spec_version": "2.1",
    "id": "tool--242f3da3-4425-4d11-8f5c-b842886da966",
    "created": "2020-01-15T10:00:00.000Z",
    "modified": "2020-01-15T10:00:00.000Z",
    "name": "Mimikatz",
    "description": "Mimikatz is a credential dumping tool used to extract credentials from memory.",
    "tool_types": ["credential-exploitation"]
}

# Vulnerability object
cve_exploit = {
    "type": "vulnerability",
    "spec_version": "2.1",
    "id": "vulnerability--7d0e5d5e-2b5c-4c5e-8e5e-5e5e5e5e5e5e",
    "created": "2020-01-15T10:00:00.000Z",
    "modified": "2020-01-15T10:00:00.000Z",
    "name": "CVE-2020-0601",
    "description": "Windows CryptoAPI Spoofing Vulnerability exploited by APT29.",
    "external_references": [
        {
            "source_name": "cve",
            "external_id": "CVE-2020-0601",
            "url": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-0601"
        }
    ]
}

# Observed Data object
network_traffic_observation = {
    "type": "observed-data",
    "spec_version": "2.1",
    "id": "observed-data--b67d30ff-02ac-498a-92f9-32f845f448cf",
    "created": "2020-01-15T10:00:00.000Z",
    "modified": "2020-01-15T10:00:00.000Z",
    "first_observed": "2020-01-15T08:30:00.000Z",
    "last_observed": "2020-01-15T09:45:00.000Z",
    "number_observed": 1,
    "objects": {
        "0": {
            "type": "ipv4-addr",
            "value": "198.51.100.42"
        },
        "1": {
            "type": "network-traffic",
            "src_ref": "ipv4-addr--ff26c055-6336-4bc6-b60e-6d2c7e6d5e5e",
            "protocols": ["tcp", "https"]
        }
    }
}

# Location object
target_location = {
    "type": "location",
    "spec_version": "2.1",
    "id": "location--a6e9345f-5a54-4825-8b7e-9f4e5e5e5e5e",
    "created": "2020-01-15T10:00:00.000Z",
    "modified": "2020-01-15T10:00:00.000Z",
    "name": "Washington D.C.",
    "description": "Geographic location of targeted government agencies.",
    "country": "US",
    "administrative_area": "DC",
    "latitude": 38.9072,
    "longitude": -77.0369
}

# IPv4 Address object
malicious_ip = {
    "type": "ipv4-addr",
    "spec_version": "2.1",
    "id": "ipv4-addr--ff26c055-6336-4bc6-b60e-6d2c7e6d5e5e",
    "value": "198.51.100.42",
    "resolves_to_refs": ["mac-addr--a8b2c3d4-e5f6-4a5b-8c7d-9e8f7a6b5c4d"],
    "belongs_to_refs": ["autonomous-system--f91b6a7a-2e9c-4e5e-8e5e-5e5e5e5e5e5e"]
}

# MAC Address object (referenced by resolves_to_refs)
mac_address = {
    "type": "mac-addr",
    "spec_version": "2.1",
    "id": "mac-addr--a8b2c3d4-e5f6-4a5b-8c7d-9e8f7a6b5c4d",
    "value": "00:1a:2b:3c:4d:5e"
}

# Autonomous System object (referenced by belongs_to_refs)
autonomous_system = {
    "type": "autonomous-system",
    "spec_version": "2.1",
    "id": "autonomous-system--f91b6a7a-2e9c-4e5e-8e5e-5e5e5e5e5e5e",
    "number": 64512,
    "name": "Example Hosting AS",
    "rir": "ARIN"
}

# Relationship: APT29 uses Cobalt Strike malware
relationship_uses_malware = {
    "type": "relationship",
    "spec_version": "2.1",
    "id": "relationship--a1b2c3d4-e5f6-4a5b-8c9d-0e1f2a3b4c5d",
    "created": "2020-01-15T10:00:00.000Z",
    "modified": "2020-01-15T10:00:00.000Z",
    "relationship_type": "uses",
    "source_ref": "threat-actor--899ce53f-13a0-479b-a0e4-67d46e241542",
    "target_ref": "malware--d1c612bc-146f-4b65-b7b0-9a54a14150a4"
}

# Relationship: APT29 uses Mimikatz tool
relationship_uses_tool = {
    "type": "relationship",
    "spec_version": "2.1",
    "id": "relationship--b2c3d4e5-f6a7-4b6c-9d0e-1f2a3b4c5d6e",
    "created": "2020-01-15T10:00:00.000Z",
    "modified": "2020-01-15T10:00:00.000Z",
    "relationship_type": "uses",
    "source_ref": "threat-actor--899ce53f-13a0-479b-a0e4-67d46e241542",
    "target_ref": "tool--242f3da3-4425-4d11-8f5c-b842886da966"
}

# Relationship: APT29 uses spearphishing attack pattern
relationship_uses_attack_pattern = {
    "type": "relationship",
    "spec_version": "2.1",
    "id": "relationship--c3d4e5f6-a7b8-4c7d-8e1f-2a3b4c5d6e7f",
    "created": "2020-01-15T10:00:00.000Z",
    "modified": "2020-01-15T10:00:00.000Z",
    "relationship_type": "uses",
    "source_ref": "threat-actor--899ce53f-13a0-479b-a0e4-67d46e241542",
    "target_ref": "attack-pattern--2e34237d-8574-43f6-aace-ae2915de8597"
}

# Relationship: APT29 targets victim organization
relationship_targets = {
    "type": "relationship",
    "spec_version": "2.1",
    "id": "relationship--d4e5f6a7-b8c9-4d8e-9f2a-3b4c5d6e7f8a",
    "created": "2020-01-15T10:00:00.000Z",
    "modified": "2020-01-15T10:00:00.000Z",
    "relationship_type": "targets",
    "source_ref": "threat-actor--899ce53f-13a0-479b-a0e4-67d46e241542",
    "target_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5"
}

# Relationship: Campaign attributed to APT29
relationship_attributed_to = {
    "type": "relationship",
    "spec_version": "2.1",
    "id": "relationship--e5f6a7b8-c9d0-4e9f-aa3b-4c5d6e7f8a9b",
    "created": "2020-01-15T10:00:00.000Z",
    "modified": "2020-01-15T10:00:00.000Z",
    "relationship_type": "attributed-to",
    "source_ref": "campaign--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
    "target_ref": "threat-actor--899ce53f-13a0-479b-a0e4-67d46e241542"
}

# Relationship: Campaign uses malware
relationship_campaign_uses_malware = {
    "type": "relationship",
    "spec_version": "2.1",
    "id": "relationship--f6a7b8c9-d0e1-4f0a-bb4c-5d6e7f8a9b0c",
    "created": "2020-01-15T10:00:00.000Z",
    "modified": "2020-01-15T10:00:00.000Z",
    "relationship_type": "uses",
    "source_ref": "campaign--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
    "target_ref": "malware--d1c612bc-146f-4b65-b7b0-9a54a14150a4"
}

# Relationship: Malware uses infrastructure
relationship_uses_infrastructure = {
    "type": "relationship",
    "spec_version": "2.1",
    "id": "relationship--a7b8c9d0-e1f2-4a1b-8c5d-6e7f8a9b0c1d",
    "created": "2020-01-15T10:00:00.000Z",
    "modified": "2020-01-15T10:00:00.000Z",
    "relationship_type": "uses",
    "source_ref": "malware--d1c612bc-146f-4b65-b7b0-9a54a14150a4",
    "target_ref": "infrastructure--3f9b5f3c-5c3a-4f5d-9e5e-3c3c3c3c3c3c"
}

# Relationship: Indicator indicates malware
relationship_indicates = {
    "type": "relationship",
    "spec_version": "2.1",
    "id": "relationship--b8c9d0e1-f2a3-4b2c-9d6e-7f8a9b0c1d2e",
    "created": "2020-01-15T10:00:00.000Z",
    "modified": "2020-01-15T10:00:00.000Z",
    "relationship_type": "indicates",
    "source_ref": "indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
    "target_ref": "malware--d1c612bc-146f-4b65-b7b0-9a54a14150a4"
}

# Relationship: APT29 exploits vulnerability
relationship_exploits = {
    "type": "relationship",
    "spec_version": "2.1",
    "id": "relationship--c9d0e1f2-a3b4-4c3d-ae7f-8a9b0c1d2e3f",
    "created": "2020-01-15T10:00:00.000Z",
    "modified": "2020-01-15T10:00:00.000Z",
    "relationship_type": "exploits",
    "source_ref": "threat-actor--899ce53f-13a0-479b-a0e4-67d46e241542",
    "target_ref": "vulnerability--7d0e5d5e-2b5c-4c5e-8e5e-5e5e5e5e5e5e"
}

# Relationship: Infrastructure located at location
relationship_located_at = {
    "type": "relationship",
    "spec_version": "2.1",
    "id": "relationship--d0e1f2a3-b4c5-4d4e-bf8a-9b0c1d2e3f4a",
    "created": "2020-01-15T10:00:00.000Z",
    "modified": "2020-01-15T10:00:00.000Z",
    "relationship_type": "located-at",
    "source_ref": "identity--c78cb6e5-0c4b-4611-8297-d1b8b55e40b5",
    "target_ref": "location--a6e9345f-5a54-4825-8b7e-9f4e5e5e5e5e"
}

# Relationship: Infrastructure consists of IPv4 address
relationship_consists_of = {
    "type": "relationship",
    "spec_version": "2.1",
    "id": "relationship--e1f2a3b4-c5d6-4e5f-8a9b-0c1d2e3f4a5b",
    "created": "2020-01-15T10:00:00.000Z",
    "modified": "2020-01-15T10:00:00.000Z",
    "relationship_type": "consists-of",
    "source_ref": "infrastructure--3f9b5f3c-5c3a-4f5d-9e5e-3c3c3c3c3c3c",
    "target_ref": "ipv4-addr--ff26c055-6336-4bc6-b60e-6d2c7e6d5e5e"
}

# List of all relationship objects
relationships = [
    relationship_uses_malware,
    relationship_uses_tool,
    relationship_uses_attack_pattern,
    relationship_targets,
    relationship_attributed_to,
    relationship_campaign_uses_malware,
    relationship_uses_infrastructure,
    relationship_indicates,
    relationship_exploits,
    relationship_located_at,
    relationship_consists_of,
]

# List of all objects
non_relationship_objects = [
    apt29_malware,
    apt29_threat_actor,
    spearphishing_attack,
    victim_organization,
    network_indicator,
    apt29_campaign,
    c2_infrastructure,
    mimikatz_tool,
    cve_exploit,
    network_traffic_observation,
    target_location,
    malicious_ip,
    mac_address,
    autonomous_system
]

# List of all objects including relationships
all_objects = non_relationship_objects + relationships

from stix2 import parse as parse_stix

for obj in all_objects:
    print(parse_stix(obj).serialize(indent=4))