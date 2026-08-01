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
    """A rotation-safe resume point.

    A rotated segment is identified by its monotonic **sequence number** (`seq`),
    which the writer never reuses — so a pruned segment can never be confused with
    a later one, even when the OS recycles the freed inode number (it does). The
    **live** file has no seq yet, so it is identified by `inode` (a rename keeps
    the inode, so a rotation of the live file is still followed correctly). A fresh
    cursor has neither.
    """

    seq: int | None = None       # rotated-segment sequence; None = on the live file
    inode: int | None = None     # live-file inode; None (with seq None) = fresh
    offset: int = 0

    def to_dict(self) -> dict[str, int]:
        return {"seq": self.seq if self.seq is not None else -1,
                "inode": self.inode or 0, "offset": self.offset}

    @classmethod
    def from_dict(cls, doc: Any) -> Cursor:
        if not isinstance(doc, dict):
            return cls()
        seq = doc.get("seq")
        seq = int(seq) if isinstance(seq, int) and seq >= 0 else None
        inode = doc.get("inode")
        # A legacy watermark stored only {"offset": N} (no seq/inode). Resume from
        # the oldest available segment rather than trust a bare offset rotation may
        # have invalidated — safe under at-least-once (duplicates, never loss).
        return cls(seq=seq, inode=inode or None, offset=int(doc.get("offset", 0)))


@dataclass(frozen=True, slots=True)
class SegmentedReadResult:
    records: list[SpoolRecord]
    cursor: Cursor               # resume point after these records
    bad_lines: int
    torn_tail: bool
    gap: bool = False            # a segment was rotated out unread — LOSS
    gap_detail: str = ""


@dataclass(frozen=True, slots=True)
class _Segment:
    seq: int | None              # rotation sequence, or None for the live file
    inode: int
    path: Path


def _segment_files(spool_path: Path) -> list[_Segment]:
    """Every spool segment in chronological order: rotated `audit.log.<NNNN>`
    (ascending seq = older→newer), then the live `audit.log` last."""
    rotated: list[_Segment] = []
    for child in spool_path.parent.glob(spool_path.name + ".*"):
        suffix = child.name[len(spool_path.name) + 1:]
        if not suffix.isdigit():
            continue                     # not a rotation segment (e.g. .wm, .db)
        with contextlib.suppress(OSError):
            rotated.append(_Segment(int(suffix), child.stat().st_ino, child))
    rotated.sort(key=lambda s: s.seq)    # type: ignore[arg-type,return-value]
    segments: list[_Segment] = list(rotated)
    if spool_path.exists():
        with contextlib.suppress(OSError):
            segments.append(_Segment(None, spool_path.stat().st_ino, spool_path))
    return segments


def read_segmented(
    spool_path: str | Path, cursor: Cursor, *, max_records: int | None = None
) -> SegmentedReadResult:
    """Read forward from `cursor` across rotated segments and the live file.

    Resumes at the segment the cursor names — a rotated one by its (reuse-proof)
    sequence number, the live one by inode — reads its remainder, then drains each
    newer segment from the start, up to `max_records`. `gap` is True iff the
    cursor's segment had been pruned before it was read (events genuinely lost).
    """
    spool_path = Path(spool_path)
    segments = _segment_files(spool_path)
    if not segments:
        return SegmentedReadResult([], cursor, 0, False)

    start_idx, start_offset, gap, gap_detail = _locate(cursor, segments)

    records: list[SpoolRecord] = []
    bad_lines = 0
    torn_tail = False
    result_cursor = cursor

    for i in range(start_idx, len(segments)):
        seg = segments[i]
        offset = start_offset if i == start_idx else 0
        res = read_spool(seg.path, start=offset)
        bad_lines += res.bad_lines
        torn_tail = res.torn_tail        # only the live file can carry a torn tail

        for rec in res.records:
            records.append(rec)
            result_cursor = Cursor(seq=seg.seq, inode=seg.inode, offset=rec.end_offset)
            if max_records is not None and len(records) >= max_records:
                return SegmentedReadResult(
                    records, result_cursor, bad_lines, torn_tail, gap, gap_detail
                )

        # Finished this segment. Advance the cursor to the NEXT segment's start so
        # a later prune of *this* (now fully-drained) segment can't look like a
        # gap. Parking on the live file's end is the steady-state resume point.
        if i + 1 < len(segments):
            nxt = segments[i + 1]
            result_cursor = Cursor(seq=nxt.seq, inode=nxt.inode, offset=0)
        else:
            result_cursor = Cursor(seq=seg.seq, inode=seg.inode, offset=res.next_offset)

    return SegmentedReadResult(records, result_cursor, bad_lines, torn_tail, gap, gap_detail)


def _locate(cursor: Cursor, segments: list[_Segment]) -> tuple[int, int, bool, str]:
    """Where in `segments` the cursor resumes: (start index, start offset, gap?,
    gap detail).

    A rotated cursor (has a seq) is matched by seq — never reused, so a missing
    seq means the segment was pruned unread = a gap. A live cursor (seq None,
    inode set) is matched by inode, following the live file even after it rotated
    into a segment. A fresh or legacy cursor (both None) starts at the oldest
    segment from offset 0 — its stored offset, if any, is meaningless here and is
    NOT applied to a segment it never named.
    """
    if cursor.seq is None and cursor.inode is None:
        return 0, 0, False, ""                     # fresh/legacy: oldest, from 0
    if cursor.seq is not None:
        for idx, seg in enumerate(segments):
            if seg.seq == cursor.seq:
                return idx, cursor.offset, False, ""
        return 0, 0, True, (
            f"rotated segment #{cursor.seq} was pruned before it was read — audit "
            f"events were lost; resuming at the oldest surviving segment"
        )
    # Live cursor: match the inode (a rename keeps it), so a live file that has
    # since rotated is still resumed at its now-rotated position.
    for idx, seg in enumerate(segments):
        if seg.inode == cursor.inode:
            return idx, cursor.offset, False, ""
    return 0, 0, True, (
        "the live segment being read was rotated out before it was caught up — "
        "audit events may have been lost; resuming at the oldest surviving segment"
    )
