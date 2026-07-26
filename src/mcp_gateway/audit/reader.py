"""Tolerant reader over the JSONL audit spool.

The spool (`audit/spool.py`) is an append-only, flush-per-line file written on
the hot path. Any reader — the SQLite index, the SSE live feed, the backtester
— must survive the two things that happen to a live append-only file:

  * a *torn final line*: the process died (or was `kill -9`'d) mid-write, so
    the last line is a truncated fragment with no trailing newline. That line
    is not yet a durable event; skip it silently and resume from there next
    time the file grows.
  * a *bad line*: a complete line (newline-terminated) that does not parse as
    JSON. This should never happen from our own writer, but a reader that
    aborts the whole scan on one corrupt line is a denial-of-service on the
    audit trail. Count it, skip it, keep going.

Every yielded record carries its *byte offset* (`offset`) — the position of the
line's first byte in the file. That offset is the stable, monotonic event id
the SQLite index stores and the SSE feed hands back as `Last-Event-ID`: it lets
any consumer resume from exactly where it stopped without re-reading the file
and without a separate sequence counter that could drift from the spool.

Pure stdlib. No dependency on the server extra — the index and backtester use
this directly.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True, slots=True)
class SpoolRecord:
    offset: int          # byte offset of this line's first byte in the file
    end_offset: int      # byte offset just past this line's trailing newline
    event: dict[str, Any]


@dataclass(frozen=True, slots=True)
class ReadResult:
    records: list[SpoolRecord]
    next_offset: int     # resume point: first byte not yet durably consumed
    bad_lines: int       # complete-but-unparseable lines skipped
    torn_tail: bool      # a truncated final line (no newline) was present


def read_spool(path: str | Path, start: int = 0) -> ReadResult:
    """Read newline-terminated JSON events from `path` starting at byte `start`.

    A trailing fragment with no newline is treated as not-yet-durable: it is
    excluded from `records` and `next_offset` stops before it, so a later read
    (after the writer finishes the line) picks it up whole. `bad_lines` counts
    complete lines that failed to parse — skipped, never fatal.
    """
    p = Path(path)
    records: list[SpoolRecord] = []
    bad_lines = 0
    torn_tail = False
    if not p.exists():
        return ReadResult(records, start, 0, False)

    with p.open("rb") as fh:
        fh.seek(start)
        offset = start
        for raw in fh:
            has_newline = raw.endswith(b"\n")
            if not has_newline:
                # Torn final line: writer died mid-append. Leave `next_offset`
                # pointing at its start so we retry it once complete.
                torn_tail = True
                break
            end_offset = offset + len(raw)
            text = raw.rstrip(b"\n").rstrip(b"\r")
            if text.strip():
                try:
                    event = json.loads(text)
                except (json.JSONDecodeError, UnicodeDecodeError):
                    bad_lines += 1
                else:
                    if isinstance(event, dict):
                        records.append(SpoolRecord(offset, end_offset, event))
                    else:
                        bad_lines += 1
            offset = end_offset

    next_offset = records[-1].end_offset if records else start
    return ReadResult(records, next_offset, bad_lines, torn_tail)


def iter_spool(path: str | Path, start: int = 0) -> Iterator[SpoolRecord]:
    """Convenience generator over `read_spool(...).records`."""
    yield from read_spool(path, start).records
