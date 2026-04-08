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


@pytest.mark.parametrize(
    "states,expected_ids",
    [
        (['pending'], {"9e0d79ed-94d9-42a3-aa41-4772ae922176"}),
        (['processing'], {"2583d09b-6535-4f15-9fd1-5dcb55230f08"}),
        (
            ['pending', 'processing'],
            {
                "9e0d79ed-94d9-42a3-aa41-4772ae922176",
                "2583d09b-6535-4f15-9fd1-5dcb55230f08",
            },
        ),
        (['failed'], {"0014c5a1-7a5e-408f-88ea-83ec5a1b8af1"}),
        (['completed'], set()),
        (
            [],
            {
                "9e0d79ed-94d9-42a3-aa41-4772ae922176",
                "2583d09b-6535-4f15-9fd1-5dcb55230f08",
                "0014c5a1-7a5e-408f-88ea-83ec5a1b8af1",
            },
        ),
    ],
)
@pytest.mark.django_db
def test_jobs_filter_by_multiple_states(client, api_schema, feed, states, expected_ids):
    models.Job.objects.create(
        feed_id=feed.id,
        id="9e0d79ed-94d9-42a3-aa41-4772ae922176",
        type=models.JobTypes.BUNDLE_UPLOAD,
        state=models.JobStates.PENDING,
    )
    models.Job.objects.create(
        feed_id=feed.id,
        id="2583d09b-6535-4f15-9fd1-5dcb55230f08",
        type=models.JobTypes.SINGLE_UPLOAD,
        state=models.JobStates.PROCESSING,
    )
    models.Job.objects.create(
        feed_id=feed.id,
        id="0014c5a1-7a5e-408f-88ea-83ec5a1b8af1",
        type=models.JobTypes.SINGLE_DELETE,
        state=models.JobStates.FAILED,
    )

    filters = {}
    if states:
        filters["state"] = ",".join(states)
    response = client.get("/api/v1/jobs/", query_params=filters)

    assert response.status_code == status.HTTP_200_OK
    assert response.data["total_results_count"] == len(expected_ids)
    returned = {item["id"] for item in response.data["jobs"]}
    assert returned == expected_ids

    api_schema["/api/v1/jobs/"]["GET"].validate_response(
        Transport.get_st_response(response)
    )
