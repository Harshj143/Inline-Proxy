"""Splunk HEC sink — ship batches to Splunk's HTTP Event Collector.

HEC ingests newline-delimited JSON envelopes at `/services/collector/event`,
each `{"event": <payload>, "sourcetype": …, "time": …}`, authenticated with an
`Authorization: Splunk <token>` header. We batch the whole delivery into one POST
so a busy gateway is a handful of large requests, not a request per event.

Stdlib `urllib` (the POST is injectable for tests). The `[splunk]` extra exists
for teams that prefer `httpx`, but nothing here requires it — an HTTP POST with a
token header needs no dependency, and this runs off the hot path regardless.

All-or-nothing: any non-2xx or transport error raises `SinkError`, so the
forwarder retries the whole batch and never advances its watermark past events
HEC did not acknowledge.
"""

from __future__ import annotations

import json
from typing import Any

from mcp_gateway.audit.sinks.base import Sink, SinkError
from mcp_gateway.audit.sinks.webhook import Poster, _urllib_post


class SplunkHecSink(Sink):
    """POST batches to a Splunk HTTP Event Collector endpoint."""

    name = "splunk"

    def __init__(
        self,
        base_url: str,
        token: str,
        *,
        sourcetype: str = "mcp:gateway",
        index: str | None = None,
        timeout: float = 10.0,
        poster: Poster | None = None,
    ):
        if not token:
            raise SinkError("Splunk HEC needs a token")
        self.url = base_url.rstrip("/") + "/services/collector/event"
        self.token = token
        self.sourcetype = sourcetype
        self.index = index
        self.timeout = timeout
        self._post = poster or _urllib_post

    def _envelope(self, event: dict) -> dict[str, Any]:
        env: dict[str, Any] = {"event": event, "sourcetype": self.sourcetype}
        # Carry the gateway's own timestamp when present so HEC doesn't stamp
        # ingestion time (Splunk accepts epoch or ISO-8601 in `time`).
        if isinstance(event, dict):
            unmapped = event.get("unmapped")
            ts = event.get("ts") or event.get("time")
            if not ts and isinstance(unmapped, dict):
                ts = unmapped.get("ts")     # OCSF wraps the original under `unmapped`
            if ts:
                env["time"] = ts
        if self.index:
            env["index"] = self.index
        return env

    def deliver(self, batch: list[dict]) -> None:
        body = "\n".join(json.dumps(self._envelope(e), default=str) for e in batch)
        headers = {
            "Authorization": f"Splunk {self.token}",
            "Content-Type": "application/json",
        }
        status = self._post(self.url, headers, (body + "\n").encode("utf-8"), self.timeout)
        if not (200 <= status < 300):
            raise SinkError(f"Splunk HEC returned HTTP {status} for {len(batch)} event(s)")
