"""The forwarder: drain the audit spool to a SIEM sink, losing nothing.

This is the realization of a promise the spool made from day one (see
`audit/spool.py`): the hot path only appends to the spool, and *downstream sinks
read from it*. The forwarder is that reader. It runs in its own process
(`mcp-gateway audit forward`), tails the JSONL spool from a persisted byte-offset
**watermark**, batches new events, hands each batch to a `Sink`, and advances the
watermark **only after the sink accepts the batch**.

That ordering is the entire correctness argument, and it is worth stating as
invariants because the exit criterion (a SIEM down for an hour, zero loss, zero
hot-path stalls, drains on recovery) falls straight out of them:

  * **At-least-once, never at-most-once.** The watermark advances after a
    successful `deliver`, never before. If the sink is down, `deliver` raises,
    the watermark stays put, and the same events are retried next tick. If the
    process dies between a successful deliver and the watermark write, the batch
    is re-delivered on restart — a duplicate in the SIEM, not a hole in the audit
    trail. For a security log that trade is the only acceptable one.

  * **Zero hot-path coupling.** The forwarder shares *nothing* with the request
    path except the spool file, which it only reads. A sink that blocks for an
    hour blocks the forwarder, never a `tools/call`. The gateway keeps appending;
    the backlog is just unread bytes.

  * **Zero loss across an outage.** The spool is durable and append-only, so
    "the sink was down" degrades to "the watermark is behind." When the sink
    recovers, the forwarder reads from exactly where it stopped and drains the
    backlog batch by batch. Nothing written during the outage is skipped.

Backoff keeps a dead sink from being hammered; a **lag alarm** (watermark falling
too far behind the spool tail) is how an operator learns the SIEM is down before
the backlog becomes a disk problem. Pure stdlib + the reader — no server extra.
"""

from __future__ import annotations

import contextlib
import json
import os
import tempfile
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from mcp_gateway.audit.reader import read_spool
from mcp_gateway.audit.sinks.base import Sink, SinkError

# event dict -> mapped dict, or None to drop the event (filtering/mapping).
EventMapper = Callable[[dict], "dict | None"]

DEFAULT_BATCH = 500
DEFAULT_POLL_SECONDS = 2.0
DEFAULT_MAX_BACKOFF = 60.0
# Warn when the unread tail passes this many bytes — the sink is likely down.
DEFAULT_ALARM_LAG_BYTES = 8 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class ForwardResult:
    """Outcome of one `pump_once`."""

    ok: bool                 # did the (attempted) delivery succeed?
    delivered: int           # events handed to the sink and acked this tick
    watermark: int           # byte offset consumed through
    lag_bytes: int           # spool tail - watermark (unread backlog)
    bad_lines: int           # unparseable spool lines skipped this read
    error: str | None = None


class Watermark:
    """A persistent byte offset into the spool, written atomically.

    A crash mid-write must never corrupt the watermark into a garbage offset that
    skips events, so it is written to a temp file and `os.replace`d (atomic on
    POSIX). A missing or unreadable watermark reads as 0 — re-forward from the
    start, which is safe under at-least-once (duplicates, never loss)."""

    def __init__(self, path: str | Path):
        self.path = Path(path)

    def load(self) -> int:
        try:
            doc = json.loads(self.path.read_text(encoding="utf-8"))
            offset = int(doc.get("offset", 0))
            return offset if offset >= 0 else 0
        except (FileNotFoundError, ValueError, OSError, TypeError):
            return 0

    def store(self, offset: int) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=".wm-", suffix=".json")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump({"offset": offset}, fh)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, self.path)
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(tmp)
            raise


class Forwarder:
    """Pumps the spool to one sink, tracking a durable watermark."""

    def __init__(
        self,
        spool_path: str | Path,
        watermark_path: str | Path,
        sink: Sink,
        *,
        batch_size: int = DEFAULT_BATCH,
        mapper: EventMapper | None = None,
        alarm_lag_bytes: int = DEFAULT_ALARM_LAG_BYTES,
        on_alarm: Callable[[int], None] | None = None,
    ):
        self.spool_path = Path(spool_path)
        self.watermark = Watermark(watermark_path)
        self.sink = sink
        self.batch_size = max(1, batch_size)
        self.mapper = mapper
        self.alarm_lag_bytes = alarm_lag_bytes
        self._on_alarm = on_alarm

    def _spool_size(self) -> int:
        try:
            return self.spool_path.stat().st_size
        except OSError:
            return 0

    def pump_once(self) -> ForwardResult:
        """Read up to one batch from the watermark and deliver it.

        Delivers at most `batch_size` events, advancing the watermark only if the
        sink accepts them. A large backlog drains across successive calls.
        """
        start = self.watermark.load()
        result = read_spool(self.spool_path, start=start)
        tail = self._spool_size()

        if not result.records:
            # Nothing new. `next_offset` may still move past bad/blank lines, so
            # persist it — we never want to re-scan skipped garbage forever.
            if result.next_offset != start:
                self.watermark.store(result.next_offset)
            return ForwardResult(
                ok=True, delivered=0, watermark=result.next_offset,
                lag_bytes=max(0, tail - result.next_offset),
                bad_lines=result.bad_lines,
            )

        chunk = result.records[: self.batch_size]
        new_watermark = chunk[-1].end_offset

        # Map (and optionally drop) events. An all-dropped batch still advances
        # the watermark — those events were consumed, just not forwarded.
        batch: list[dict] = []
        for record in chunk:
            mapped = self.mapper(record.event) if self.mapper else record.event
            if mapped is not None:
                batch.append(mapped)

        if batch:
            try:
                self.sink.deliver(batch)
            except SinkError as exc:
                # Fail-in-place: do NOT advance the watermark. Retried next tick.
                lag = max(0, tail - start)
                self._maybe_alarm(lag)
                return ForwardResult(
                    ok=False, delivered=0, watermark=start, lag_bytes=lag,
                    bad_lines=result.bad_lines, error=str(exc),
                )

        self.watermark.store(new_watermark)
        lag = max(0, tail - new_watermark)
        self._maybe_alarm(lag)
        return ForwardResult(
            ok=True, delivered=len(batch), watermark=new_watermark,
            lag_bytes=lag, bad_lines=result.bad_lines,
        )

    def _maybe_alarm(self, lag_bytes: int) -> None:
        if lag_bytes >= self.alarm_lag_bytes and self._on_alarm is not None:
            self._on_alarm(lag_bytes)

    def drain(self) -> ForwardResult:
        """Pump batches until the spool is caught up or a delivery fails.

        Returns the last `ForwardResult`. Used by `--once` and by tests; the
        long-running `run` loop calls `pump_once` on a timer instead.
        """
        last = ForwardResult(ok=True, delivered=0, watermark=self.watermark.load(),
                             lag_bytes=0, bad_lines=0)
        total = 0
        while True:
            last = self.pump_once()
            if not last.ok or last.delivered == 0:
                break
            total += last.delivered
        # Report the cumulative delivered count for a drain.
        return ForwardResult(
            ok=last.ok, delivered=total if last.ok else 0, watermark=last.watermark,
            lag_bytes=last.lag_bytes, bad_lines=last.bad_lines, error=last.error,
        )

    def run(
        self,
        *,
        poll_seconds: float = DEFAULT_POLL_SECONDS,
        max_backoff: float = DEFAULT_MAX_BACKOFF,
        should_stop: Callable[[], bool] | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        """Forward forever: drain, then poll, backing off while a sink is down.

        `should_stop`/`sleep` are injectable so a test can run a bounded loop.
        On a delivery failure the wait grows exponentially (capped) and resets to
        `poll_seconds` on the next success, so a dead sink is retried gently and a
        recovered one is drained promptly.
        """
        backoff = poll_seconds
        while should_stop is None or not should_stop():
            result = self.pump_once()
            if not result.ok:
                sleep(min(backoff, max_backoff))
                backoff = min(backoff * 2, max_backoff)
                continue
            backoff = poll_seconds
            if result.delivered == 0:      # caught up — wait for new events
                sleep(poll_seconds)
        self.sink.close()
