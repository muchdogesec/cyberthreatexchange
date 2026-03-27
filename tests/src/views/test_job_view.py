import pytest
from unittest.mock import patch, Mock
from rest_framework import status
from rest_framework.response import Response
from cyberthreatexchange.server import models, serializers
from cyberthreatexchange.server.arango_helpers import ArangoDBHelper
from tests.src.data import all_objects
from tests.utils import create_identity, Transport


@pytest.mark.parametrize(
    "filters,expected_ids",
    [
        (dict(feed_id="ec8fec0c-10d8-476f-8a51-0c71d94bbda7"), ['16cc28a9-da88-40de-8749-7e7ac9436366']),
        (dict(identity_id="f3a5f413-0ccd-4821-9778-f4b70ecbb47f"), []),
        (dict(identity_id="identity--73faab8f-9a95-4417-a2db-c1a8b73c7029"), ['16cc28a9-da88-40de-8749-7e7ac9436366']),
    ],
)
def test_list_jobs(client, job, filters, expected_ids, api_schema):
    response = client.get("/api/v1/jobs/", query_params=filters)

    assert response.status_code == status.HTTP_200_OK
    assert "jobs" in response.data
    assert {j["id"] for j in response.data["jobs"]} == set(expected_ids)
    api_schema["/api/v1/jobs/"]["GET"].validate_response(
        Transport.get_st_response(response)
    )
