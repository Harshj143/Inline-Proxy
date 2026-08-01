"""The three SIEM sinks, exercised against injected transports (no network).

Each sink's job is small and specific — encode a batch the way its destination
expects, POST/PUT it, and turn any non-success into a SinkError so the forwarder
retries rather than advancing past unshipped events. These tests pin the wire
shape (NDJSON vs HEC envelope vs gzipped S3 object under a dt=/hour= key) and the
all-or-nothing error contract, without a socket or an AWS account.
"""

from __future__ import annotations

import gzip
import json

import pytest

from mcp_gateway.audit.sinks.base import SinkError
from mcp_gateway.audit.sinks.s3 import S3Sink
from mcp_gateway.audit.sinks.splunk import SplunkHecSink
from mcp_gateway.audit.sinks.webhook import WebhookSink

BATCH = [
    {"event": "tool_call_blocked", "ts": "2026-07-31T14:05:00Z", "tool": "db.drop"},
    {"event": "tool_call_allowed", "ts": "2026-07-31T14:05:01Z", "tool": "search"},
]


class Poster:
    """Captures POSTs and returns a scripted status."""

    def __init__(self, status=200):
        self.status = status
        self.calls: list[tuple] = []

    def __call__(self, url, headers, body, timeout):
        self.calls.append((url, headers, body.decode("utf-8"), timeout))
        return self.status


# --------------------------------------------------------------- webhook
def test_webhook_posts_ndjson_by_default():
    poster = Poster()
    WebhookSink("https://siem.example/in", poster=poster).deliver(BATCH)
    url, headers, body, _ = poster.calls[0]
    assert url == "https://siem.example/in"
    assert headers["Content-Type"] == "application/x-ndjson"
    lines = body.strip().split("\n")
    assert len(lines) == 2 and json.loads(lines[0])["tool"] == "db.drop"


def test_webhook_can_send_a_json_array():
    poster = Poster()
    WebhookSink("https://x/in", as_array=True, poster=poster).deliver(BATCH)
    _, headers, body, _ = poster.calls[0]
    assert headers["Content-Type"] == "application/json"
    assert isinstance(json.loads(body), list) and len(json.loads(body)) == 2


def test_webhook_custom_headers_are_sent():
    poster = Poster()
    WebhookSink("https://x/in", headers={"Authorization": "Bearer t"}, poster=poster).deliver(BATCH)
    assert poster.calls[0][1]["Authorization"] == "Bearer t"


@pytest.mark.parametrize("status", [400, 401, 500, 503])
def test_webhook_non_2xx_raises_sink_error(status):
    with pytest.raises(SinkError, match=f"HTTP {status}"):
        WebhookSink("https://x/in", poster=Poster(status)).deliver(BATCH)


# ---------------------------------------------------------------- splunk
def test_splunk_wraps_each_event_in_a_hec_envelope():
    poster = Poster()
    sink = SplunkHecSink("https://splunk:8088", "tok-123", sourcetype="mcp:gw", poster=poster)
    sink.deliver(BATCH)
    url, headers, body, _ = poster.calls[0]
    assert url == "https://splunk:8088/services/collector/event"
    assert headers["Authorization"] == "Splunk tok-123"
    first = json.loads(body.strip().split("\n")[0])
    assert first["sourcetype"] == "mcp:gw"
    assert first["event"]["tool"] == "db.drop"
    assert first["time"] == "2026-07-31T14:05:00Z"      # gateway ts, not ingest time


def test_splunk_reads_ts_from_ocsf_unmapped():
    """When events are OCSF-mapped, the original ts lives under `unmapped`."""
    poster = Poster()
    ocsf_batch = [{"class_name": "App Activity", "unmapped": {"ts": "2026-01-01T00:00:00Z"}}]
    SplunkHecSink("https://s:8088", "t", poster=poster).deliver(ocsf_batch)
    assert json.loads(poster.calls[0][2].strip())["time"] == "2026-01-01T00:00:00Z"


def test_splunk_requires_a_token():
    with pytest.raises(SinkError, match="token"):
        SplunkHecSink("https://s:8088", "")


def test_splunk_non_2xx_raises():
    with pytest.raises(SinkError, match="HTTP 500"):
        SplunkHecSink("https://s:8088", "t", poster=Poster(500)).deliver(BATCH)


# -------------------------------------------------------------------- s3
class FakeS3:
    def __init__(self):
        self.objects: list[dict] = []

    def put_object(self, **kw):
        self.objects.append(kw)


def test_s3_writes_one_gzipped_ndjson_object_under_a_time_partition():
    client = FakeS3()
    S3Sink("audit-bucket", prefix="mcp", client=client).deliver(BATCH)
    obj = client.objects[0]
    assert obj["Bucket"] == "audit-bucket"
    # Partition derived from the batch's own event timestamp (14:05 UTC).
    assert obj["Key"].startswith("mcp/dt=2026-07-31/hour=14/")
    assert obj["Key"].endswith(".ndjson.gz")
    assert obj["ContentEncoding"] == "gzip"
    # Round-trips back to the two events.
    lines = gzip.decompress(obj["Body"]).decode("utf-8").strip().split("\n")
    assert [json.loads(x)["tool"] for x in lines] == ["db.drop", "search"]


def test_s3_partition_falls_back_to_now_without_a_timestamp():
    client = FakeS3()
    S3Sink("b", client=client).deliver([{"event": "x"}])
    assert "/dt=" in client.objects[0]["Key"]           # still partitioned, on today


def test_s3_put_failure_becomes_a_sink_error():
    class Boom:
        def put_object(self, **kw):
            raise RuntimeError("access denied")

    with pytest.raises(SinkError, match="access denied"):
        S3Sink("b", client=Boom()).deliver(BATCH)


def test_s3_requires_a_bucket():
    with pytest.raises(SinkError, match="bucket"):
        S3Sink("", client=FakeS3())
