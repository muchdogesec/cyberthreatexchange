## Add valid identity

```shell
curl -X 'POST' \
  'http://localhost:8007/api/v1/identities/' \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d '{
    "type": "identity",
    "spec_version": "2.1",
    "id": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
    "created": "2020-01-01T00:00:00.000Z",
    "modified": "2020-01-01T00:00:00.000Z",
    "name": "dogesec",
    "description": "https://github.com/muchdogesec/",
    "identity_class": "organization",
    "sectors": [
        "technology"
    ],
    "contact_information": "https://www.dogesec.com/contact/",
    "confidence": 100,
    "object_marking_refs": [
        "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
        "marking-definition--97ba4e8b-04f6-57e8-8f6e-3a0f0a7dc0fb"
    ]
}'
```

## Create a Feed (min required data)

```json
{
  "identity_id": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
  "name": "My basic feed"
}
```

Expected ID `9779a2db-f98c-5f4b-8d08-8ee04e02dbb5` (`My basic feed+identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5`) = `be8a67b0-c975-57ad-94b7-60f29d170e80`

## Create a Feed (all data)

```json
{
  "identity_id": "identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5",
  "name": "My full feed",
  "description": "Long desc",
  "short_description": "Short desc",
  "tags": [
    "tag-1"
  ],
  "categories": [
    "apt_group",
    "ttp"
  ]
}
```

Expected ID `9779a2db-f98c-5f4b-8d08-8ee04e02dbb5` (`My full feed+identity--9779a2db-f98c-5f4b-8d08-8ee04e02dbb5`) = `9fb026ee-8559-52c9-8d70-b19d4010d00e`