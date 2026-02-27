import json
import hashlib

def md5_hash(stix_obj):
    "hash without any hidden fields"
    stix_obj = stix_obj.copy()
    stix_obj.pop("modified", None)
    stix_str = str(json.dumps(stix_obj, sort_keys=True)).encode('utf-8')
    return hashlib.md5(stix_str).hexdigest()