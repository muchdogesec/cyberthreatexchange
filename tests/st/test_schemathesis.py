import json
import random
import time
from unittest.mock import patch
from urllib.parse import urlencode
import uuid
import schemathesis
import pytest
from schemathesis.core.transport import Response as SchemathesisResponse
from cyberthreatexchange.server import models
from cyberthreatexchange.wsgi import application as wsgi_app
from rest_framework.response import Response as DRFResponse
from hypothesis import given, settings
from hypothesis import strategies
from schemathesis.specs.openapi.checks import (
    negative_data_rejection,
    positive_data_acceptance,
    status_code_conformance
)
from schemathesis.config import GenerationConfig
from schemathesis.transport.serialization import (
    serialize_binary,
    serialize_json,
    serialize_xml,
    serialize_yaml,
)
from ..src.data import all_objects

schema = schemathesis.openapi.from_wsgi("/api/schema/?format=json", wsgi_app)
schema.config.base_url = "http://localhost:8007/"
schema.config.generation = GenerationConfig(allow_x00=False)



@pytest.fixture()
def test_feed(feed, arango_helper, disconnect_signals):
    """Create a feed that uses the same collections as arango_helper.

    Since Feed.save() always overwrites collection_name and the post_save signal
    creates collections, we need to disable the signal and manually set collection_name.
    """

    identity = models.Identity.objects.create(
        id="identity--f3a5f413-0ccd-4821-9778-f4b70ecbb47f",
        name="Test Identity",
        identity_class="organization",
    )
    feed2 = models.Feed.objects.create(
        name="Test Feed for Objects",
        description="Feed for testing object queries",
        identity=identity,
        collection_name=arango_helper.feed.collection_name,
        id="24d019ea-e2b2-43f7-ac5d-fd0078f05a00",
    )
    yield feed2



@pytest.fixture(autouse=True)
def override_transport(monkeypatch):
    ## patch transport.get
    from schemathesis import transport
    from ..utils import Transport
    monkeypatch.setattr(transport, "get", lambda _: Transport())

@schema.given(
        feed_id=strategies.sampled_from(["24d019ea-e2b2-43f7-ac5d-fd0078f05a00", ]),
        object_id=strategies.sampled_from([x['id'] for x in all_objects]),
)
@schema.parametrize()
@settings(max_examples=30)
def test_api(case: schemathesis.Case, **kwargs):
    for k, v in kwargs.items():
        if k in case.path_parameters:
            case.path_parameters[k] = v
    case.call_and_validate(
        excluded_checks=[negative_data_rejection, positive_data_acceptance]
    )
