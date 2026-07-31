"""Generic webhook sink — POST a batch of audit events to any HTTP endpoint.

The lowest-common-denominator SIEM integration: if a system can receive an HTTP
POST it can receive your audit trail. Events go up as **NDJSON** (one JSON object
per line) by default, the format most log collectors (Vector, Fluent Bit,
Logstash, Datadog) ingest directly; set `as_array=True` to send one JSON array
instead for endpoints that expect a single document.

Stdlib `urllib` only — no dependency, because a webhook is just an HTTP POST and
this runs off the hot path anyway. The actual POST is injectable (`poster=`) so
tests exercise the batching, headers, and error handling without a socket.

Delivery is all-or-nothing: any non-2xx, timeout, or connection error raises
`SinkError`, and the forwarder retries the whole batch. A 2xx is the only success.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from collections.abc import Callable

from mcp_gateway.audit.sinks.base import Sink, SinkError

# (url, headers, body_bytes, timeout) -> HTTP status code. Injected in tests.
Poster = Callable[[str, dict[str, str], bytes, float], int]


def _urllib_post(url: str, headers: dict[str, str], body: bytes, timeout: float) -> int:
    if not url.lower().startswith(("http://", "https://")):
        raise SinkError(f"webhook url must be http(s): {url!r}")
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (scheme checked)
            return resp.status
    except urllib.error.HTTPError as exc:
        return exc.code                      # a real response; deliver() judges it
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise SinkError(f"webhook POST to {url} failed: {exc}") from None


class WebhookSink(Sink):
    """POST batches to an HTTP endpoint as NDJSON (or a JSON array)."""

    name = "webhook"

    def __init__(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        as_array: bool = False,
        timeout: float = 10.0,
        poster: Poster | None = None,
    ):
        self.url = url
        self.headers = dict(headers or {})
        self.as_array = as_array
        self.timeout = timeout
        self._post = poster or _urllib_post

    def _encode(self, batch: list[dict]) -> tuple[bytes, str]:
        if self.as_array:
            return json.dumps(batch, default=str).encode("utf-8"), "application/json"
        lines = "\n".join(json.dumps(e, default=str) for e in batch)
        return (lines + "\n").encode("utf-8"), "application/x-ndjson"

    def deliver(self, batch: list[dict]) -> None:
        body, content_type = self._encode(batch)
        headers = {"Content-Type": content_type, **self.headers}
        status = self._post(self.url, headers, body, self.timeout)
        if not (200 <= status < 300):
            raise SinkError(f"webhook returned HTTP {status} for {len(batch)} event(s)")
