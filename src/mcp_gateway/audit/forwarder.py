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

from mcp_gateway.audit.reader import Cursor, _locate, _segment_files, read_segmented
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
    cursor: Cursor           # rotation-safe resume point consumed through
    lag_bytes: int           # unread backlog across all segments
    bad_lines: int           # unparseable spool lines skipped this read
    gap: bool = False        # a rotated-out segment was detected — events lost
    error: str | None = None


class Watermark:
    """A persistent rotation-safe `Cursor` into the spool, written atomically.

    A crash mid-write must never corrupt the cursor into a garbage position that
    skips events, so it is written to a temp file and `os.replace`d (atomic on
    POSIX). A missing/unreadable cursor reads as an empty `Cursor` — re-forward
    from the oldest available segment, safe under at-least-once (duplicates,
    never loss). A legacy `{"offset": N}` file (pre-rotation) loads as a cursor
    with no inode, so it, too, resumes from the oldest segment rather than
    trusting a bare offset that rotation may have invalidated."""

    def __init__(self, path: str | Path):
        self.path = Path(path)

    def load(self) -> Cursor:
        try:
            doc = json.loads(self.path.read_text(encoding="utf-8"))
            return Cursor.from_dict(doc)
        except (FileNotFoundError, ValueError, OSError, TypeError):
            return Cursor()

    def store(self, cursor: Cursor) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=".wm-", suffix=".json")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(cursor.to_dict(), fh)
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
        on_gap: Callable[[str], None] | None = None,
    ):
        self.spool_path = Path(spool_path)
        self.watermark = Watermark(watermark_path)
        self.sink = sink
        self.batch_size = max(1, batch_size)
        self.mapper = mapper
        self.alarm_lag_bytes = alarm_lag_bytes
        self._on_alarm = on_alarm
        self._on_gap = on_gap

    def _lag_bytes(self, cursor: Cursor) -> int:
        """Unread bytes across every segment from `cursor` forward."""
        segments = _segment_files(self.spool_path)
        start_idx, start_offset, _gap, _detail = _locate(cursor, segments)
        lag = 0
        for i in range(start_idx, len(segments)):
            try:
                size = segments[i].path.stat().st_size
            except OSError:
                continue
            lag += size - (start_offset if i == start_idx else 0)
        return max(0, lag)

    def pump_once(self) -> ForwardResult:
        """Read up to one batch from the cursor and deliver it.

        Reads at most `batch_size` events, transparently crossing rotation
        boundaries, and advances the cursor only if the sink accepts them. A
        rotated-out segment (real loss) is reported once, loudly, and does not
        stop the drain — the remaining events still ship.
        """
        start = self.watermark.load()
        result = read_segmented(self.spool_path, start, max_records=self.batch_size)
        if result.gap and self._on_gap is not None:
            self._on_gap(result.gap_detail)

        if not result.records:
            # Nothing new. The cursor may still move (past bad/blank lines, or to
            # a fresh segment after a gap), so persist it — never re-scan forever.
            if result.cursor != start:
                self.watermark.store(result.cursor)
            lag = self._lag_bytes(result.cursor)
            self._maybe_alarm(lag)
            return ForwardResult(
                ok=True, delivered=0, cursor=result.cursor, lag_bytes=lag,
                bad_lines=result.bad_lines, gap=result.gap,
            )

        # Map (and optionally drop) events. An all-dropped batch still advances
        # the cursor — those events were consumed, just not forwarded.
        batch: list[dict] = []
        for record in result.records:
            mapped = self.mapper(record.event) if self.mapper else record.event
            if mapped is not None:
                batch.append(mapped)

        if batch:
            try:
                self.sink.deliver(batch)
            except SinkError as exc:
                # Fail-in-place: do NOT advance the cursor. Retried next tick.
                lag = self._lag_bytes(start)
                self._maybe_alarm(lag)
                return ForwardResult(
                    ok=False, delivered=0, cursor=start, lag_bytes=lag,
                    bad_lines=result.bad_lines, gap=result.gap, error=str(exc),
                )

        self.watermark.store(result.cursor)
        lag = self._lag_bytes(result.cursor)
        self._maybe_alarm(lag)
        return ForwardResult(
            ok=True, delivered=len(batch), cursor=result.cursor,
            lag_bytes=lag, bad_lines=result.bad_lines, gap=result.gap,
        )

    def _maybe_alarm(self, lag_bytes: int) -> None:
        if lag_bytes >= self.alarm_lag_bytes and self._on_alarm is not None:
            self._on_alarm(lag_bytes)

    def drain(self) -> ForwardResult:
        """Pump batches until the spool is caught up or a delivery fails.

        Returns the last `ForwardResult`. Used by `--once` and by tests; the
        long-running `run` loop calls `pump_once` on a timer instead.
        """
        last = ForwardResult(ok=True, delivered=0, cursor=self.watermark.load(),
                             lag_bytes=0, bad_lines=0)
        total = 0
        gap = False
        while True:
            last = self.pump_once()
            gap = gap or last.gap
            if not last.ok or last.delivered == 0:
                break
            total += last.delivered
        # Report the cumulative delivered count for a drain.
        return ForwardResult(
            ok=last.ok, delivered=total if last.ok else 0, cursor=last.cursor,
            lag_bytes=last.lag_bytes, bad_lines=last.bad_lines, gap=gap,
            error=last.error,
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
