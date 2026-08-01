"""The SIEM sink interface — where audit events go *after* the spool.

The spool (`audit/spool.py`) is the source of truth and the hot path only ever
appends to it. A **sink** is a downstream consumer that ships those events out to
somewhere durable and searchable — an S3 bucket, a Splunk HEC endpoint, a
generic webhook. Crucially a sink is driven by the `Forwarder` (`forwarder.py`),
which *reads from the spool*, never by the gateway on the request path. That is
the whole design: a sink can be slow, flaky, or down for an hour and a tool call
never notices, because nothing on the hot path is waiting on it.

The contract is deliberately tiny — one method that either delivers a whole
batch or raises:

    deliver(batch) -> None       # all-or-nothing; raise SinkError on any failure

`deliver` is **synchronous and blocking**, and that is fine: the forwarder runs
in its own process (`mcp-gateway audit forward`), off the event loop, so blocking
on network I/O costs nothing a request can feel. It must be **all-or-nothing** at
the batch level so the forwarder's watermark stays honest — a partial success
that returned normally would let the watermark advance past events that never
landed, turning at-least-once into at-most-once. When in doubt, raise: the
forwarder will retry the whole batch, and re-delivery (a duplicate in the SIEM)
is the acceptable failure mode, not a dropped security event.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from mcp_gateway.core.errors import GatewayError


class SinkError(GatewayError):
    """A sink could not deliver a batch. The forwarder retries with backoff and
    does not advance its watermark, so the batch is re-attempted, never lost."""


class Sink(ABC):
    """A destination the forwarder ships batches of audit events to."""

    #: Short, stable name for logs and the watermark file (e.g. "splunk", "s3").
    name: str = "sink"

    @abstractmethod
    def deliver(self, batch: list[dict]) -> None:
        """Ship every event in `batch`, or raise `SinkError`. All-or-nothing.

        `batch` is a non-empty list of event dicts, already mapped to the sink's
        wire shape (OCSF/ECS/raw) by the forwarder.
        """

    def close(self) -> None:  # pragma: no cover - optional
        """Flush/close any held resource. Default: nothing to do."""
        return None
