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

import contextlib
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


# --------------------------------------------------------------------------
# Rotation-safe reading.
#
# A byte offset is only meaningful *within one file*. The moment the spool
# rotates — `audit.log` renamed to `audit.log.00000007`, a fresh `audit.log`
# opened — an offset into "audit.log" points into a different, smaller file, so
# a plain `read_spool(path, start=offset)` silently skips the rotated segment's
# tail AND re-reads the new file from the wrong place. For the durable consumers
# (the SIEM forwarder, the SQLite index) that is data loss in the audit trail.
#
# The fix is to track the **inode** — the file's identity, which survives a
# rename — alongside the offset, and to walk the ordered set of segments
# (rotated ones oldest-first, then the live file) forward from the cursor,
# draining each rotated segment before the live one. If the segment the cursor
# was in has been *pruned* (rotated out beyond the retained window before a slow
# reader consumed it), that is real loss — reported as a `gap`, never silent.


@dataclass(frozen=True, slots=True)
class Cursor:
    """A rotation-safe resume point: which file (by inode) and how far in."""

    inode: int | None = None     # None = "nothing consumed yet"
    offset: int = 0

    def to_dict(self) -> dict[str, int]:
        return {"inode": self.inode or 0, "offset": self.offset}

    @classmethod
    def from_dict(cls, doc: Any) -> Cursor:
        if not isinstance(doc, dict):
            return cls()
        inode = doc.get("inode")
        # A legacy watermark stored only {"offset": N}. Treat inode 0/absent as
        # "unknown file": start from the oldest available segment (at-least-once,
        # so re-reading is safe — the alternative would skip a rotated segment).
        return cls(inode=inode or None, offset=int(doc.get("offset", 0)))


@dataclass(frozen=True, slots=True)
class SegmentedReadResult:
    records: list[SpoolRecord]
    cursor: Cursor               # resume point after these records
    bad_lines: int
    torn_tail: bool
    gap: bool = False            # a segment was rotated out unread — LOSS
    gap_detail: str = ""


def _segment_files(spool_path: Path) -> list[tuple[int, Path]]:
    """Every spool segment in chronological order, as (inode, path).

    Rotated segments `audit.log.<NNNNNNNN>` (ascending seq = older→newer) come
    first, then the live `audit.log` last. A file that vanishes mid-scan (pruned
    under us) is skipped — the caller's gap check handles a missing cursor inode.
    """
    rotated: list[tuple[int, int, Path]] = []   # (seq, inode, path)
    for child in spool_path.parent.glob(spool_path.name + ".*"):
        suffix = child.name[len(spool_path.name) + 1:]
        if not suffix.isdigit():
            continue                     # not a rotation segment (e.g. .wm, .db)
        try:
            rotated.append((int(suffix), child.stat().st_ino, child))
        except OSError:
            continue
    rotated.sort(key=lambda t: t[0])     # ascending seq = chronological
    files: list[tuple[int, Path]] = [(ino, path) for _seq, ino, path in rotated]
    if spool_path.exists():
        with contextlib.suppress(OSError):
            files.append((spool_path.stat().st_ino, spool_path))
    return files


def read_segmented(
    spool_path: str | Path, cursor: Cursor, *, max_records: int | None = None
) -> SegmentedReadResult:
    """Read forward from `cursor` across rotated segments and the live file.

    Resumes at the file whose inode the cursor names (found wherever rotation has
    since moved it), reads its remainder, then drains each newer segment from the
    start, up to `max_records`. The returned cursor is the exact resume point;
    `gap` is True iff the cursor's segment had been rotated out (events lost).
    """
    spool_path = Path(spool_path)
    files = _segment_files(spool_path)
    if not files:
        return SegmentedReadResult([], cursor, 0, False)

    inodes = [ino for ino, _ in files]
    gap = False
    gap_detail = ""
    if cursor.inode is None:
        start_idx, start_offset = 0, 0
    elif cursor.inode in inodes:
        start_idx, start_offset = inodes.index(cursor.inode), cursor.offset
    else:
        # The segment we were mid-read on is gone — rotated out before we caught
        # up. Everything between the cursor and the oldest surviving segment is
        # lost. Resume at the oldest available and shout about it.
        gap = True
        gap_detail = (
            f"cursor segment (inode {cursor.inode}) was rotated out before it was "
            f"read — audit events were lost; resuming at the oldest surviving segment"
        )
        start_idx, start_offset = 0, 0

    records: list[SpoolRecord] = []
    bad_lines = 0
    torn_tail = False
    result_cursor = cursor

    for i in range(start_idx, len(files)):
        inode, path = files[i]
        offset = start_offset if i == start_idx else 0
        is_live = i == len(files) - 1
        res = read_spool(path, start=offset)
        bad_lines += res.bad_lines
        torn_tail = res.torn_tail        # only the live file can carry a torn tail

        for rec in res.records:
            records.append(rec)
            result_cursor = Cursor(inode=inode, offset=rec.end_offset)
            if max_records is not None and len(records) >= max_records:
                return SegmentedReadResult(
                    records, result_cursor, bad_lines, torn_tail, gap, gap_detail
                )

        # Finished this file. If it's a drained rotated segment, advance the
        # cursor to the next segment's start so a later prune of *this* segment
        # can't be mistaken for a gap. If it's the live file, park at its end.
        if is_live:
            result_cursor = Cursor(inode=inode, offset=res.next_offset)
        else:
            next_inode, _next_path = files[i + 1]
            result_cursor = Cursor(inode=next_inode, offset=0)

    return SegmentedReadResult(records, result_cursor, bad_lines, torn_tail, gap, gap_detail)
