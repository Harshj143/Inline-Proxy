"""S3 sink — land audit batches as gzipped NDJSON under time-partitioned keys.

S3 is the archival/data-lake destination: cheap, durable, and queryable in place
by Athena, AWS Security Lake, or a Spark job. Each batch becomes one gzipped
NDJSON object under a **Hive-style time partition**:

    <prefix>/dt=2026-07-31/hour=14/<epoch_ms>-<n>.ndjson.gz

The `dt=`/`hour=` layout is what lets Athena/Glue prune by time without listing
the whole bucket — a query for "yesterday's blocks" reads one day's prefix, not
the archive. The object name carries the batch's wall-clock and size so two
batches in the same hour never collide and an operator can eyeball throughput.

boto3 lives behind the `[s3]` extra and its import is guarded: a forwarder asked
to use S3 without it raises a clear `SinkError` at construction (fail-closed setup
error), never a confusing crash mid-run. The client is injectable so tests
exercise key layout, gzip, and batching against a fake, with no AWS and no
network.

Partition time comes from the *batch's own* events when they carry a timestamp,
so a backlog drained after an outage lands in the partitions the events belong to
— not all dumped into the recovery hour.
"""

from __future__ import annotations

import gzip
import json
import time
from datetime import UTC, datetime
from typing import Any

from mcp_gateway.audit.sinks.base import Sink, SinkError


def _load_boto3_client(region: str | None):
    try:
        import boto3
    except ImportError:
        raise SinkError(
            "the S3 sink needs the [s3] extra (boto3): pip install 'mcp-gateway[s3]'"
        ) from None
    return boto3.client("s3", region_name=region) if region else boto3.client("s3")


class S3Sink(Sink):
    """Write each batch as one gzipped NDJSON object under a dt=/hour= prefix."""

    name = "s3"

    def __init__(
        self,
        bucket: str,
        *,
        prefix: str = "mcp-audit",
        region: str | None = None,
        client: Any | None = None,
    ):
        if not bucket:
            raise SinkError("the S3 sink needs a bucket")
        self.bucket = bucket
        self.prefix = prefix.strip("/")
        # Constructing the client is where a missing [s3] extra surfaces — do it
        # eagerly so a misconfigured forwarder fails at startup, not mid-drain.
        self._client = client if client is not None else _load_boto3_client(region)

    def _partition_time(self, batch: list[dict]) -> datetime:
        for event in batch:
            ts = event.get("ts") or event.get("time") if isinstance(event, dict) else None
            if isinstance(ts, str):
                try:
                    return datetime.fromisoformat(ts.replace("Z", "+00:00")).astimezone(UTC)
                except ValueError:
                    continue
        return datetime.now(UTC)

    def _key(self, batch: list[dict]) -> str:
        when = self._partition_time(batch)
        return (
            f"{self.prefix}/dt={when:%Y-%m-%d}/hour={when:%H}/"
            f"{int(time.time() * 1000)}-{len(batch)}.ndjson.gz"
        )

    def deliver(self, batch: list[dict]) -> None:
        ndjson = "\n".join(json.dumps(e, default=str) for e in batch) + "\n"
        body = gzip.compress(ndjson.encode("utf-8"))
        try:
            self._client.put_object(
                Bucket=self.bucket,
                Key=self._key(batch),
                Body=body,
                ContentType="application/x-ndjson",
                ContentEncoding="gzip",
            )
        except Exception as exc:  # noqa: BLE001 — any boto/transport failure → retry the batch
            raise SinkError(f"S3 put_object to s3://{self.bucket} failed: {exc}") from None
