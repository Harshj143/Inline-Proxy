"""Spool rotation (the writer) + the rotation-safe segmented reader.

Left uncapped the audit log grows forever; capped, it must roll without dropping
or splitting an event, and readers must follow the roll by inode so a rename is
invisible to them. These tests pin the writer's rotation/pruning and the reader's
lossless forward walk (including the two hard cases: multiple rotations between
reads, and a segment pruned before it was consumed).
"""

from __future__ import annotations

import asyncio

from mcp_gateway.audit.reader import Cursor, read_segmented
from mcp_gateway.audit.spool import JsonlSpool


def _emit(spool, n, start=0):
    async def run():
        for i in range(start, start + n):
            await spool.emit({"event": "e", "seq": i})
    asyncio.run(run())


def _segments(path):
    return sorted(p.name for p in path.parent.glob(path.name + ".*"))


def _read_all(path, batch=None):
    """Drain the whole spool via the segmented reader; return the seqs, in order."""
    cursor = Cursor()
    seqs: list[int] = []
    while True:
        r = read_segmented(path, cursor, max_records=batch)
        if not r.records:
            break
        seqs += [rec.event["seq"] for rec in r.records]
        cursor = r.cursor
    return seqs


# ---------------------------------------------------------------- writer
def test_no_max_bytes_never_rotates(tmp_path):
    path = tmp_path / "audit.log"
    spool = JsonlSpool(path)                    # rotation off (backward compatible)
    _emit(spool, 100)
    assert _segments(path) == []                # one file, no segments
    assert _read_all(path) == list(range(100))


def test_rotation_rolls_at_the_size_cap(tmp_path):
    path = tmp_path / "audit.log"
    spool = JsonlSpool(path, max_bytes=60, keep=100)
    _emit(spool, 10)
    assert _segments(path), "expected rotated segments"
    # Every event landed exactly once across all segments.
    assert _read_all(path) == list(range(10))


def test_an_oversized_event_still_lands_whole(tmp_path):
    """A single event larger than the cap must not be split across segments."""
    path = tmp_path / "audit.log"
    spool = JsonlSpool(path, max_bytes=10, keep=100)

    async def run():
        await spool.emit({"event": "big", "payload": "x" * 500, "seq": 0})
        await spool.emit({"event": "e", "seq": 1})
    asyncio.run(run())
    # Both events are individually parseable (each on its own line, whole).
    assert _read_all(path) == [0, 1]


def test_pruning_keeps_only_the_most_recent_segments(tmp_path):
    path = tmp_path / "audit.log"
    spool = JsonlSpool(path, max_bytes=50, keep=2)
    _emit(spool, 30)
    # At most `keep` rotated segments survive (plus the live file).
    assert len(_segments(path)) <= 2


def test_rotation_survives_a_restart(tmp_path):
    """A new JsonlSpool over an existing rotated set continues the sequence."""
    path = tmp_path / "audit.log"
    _emit(JsonlSpool(path, max_bytes=60, keep=100), 6)
    before = set(_segments(path))
    _emit(JsonlSpool(path, max_bytes=60, keep=100), 6, start=6)   # reopen, keep rolling
    after = set(_segments(path))
    assert before <= after                       # old segments preserved, new ones added
    assert _read_all(path) == list(range(12))     # nothing lost across the restart


# ---------------------------------------------------------------- reader
def test_segmented_read_batches_across_segments(tmp_path):
    path = tmp_path / "audit.log"
    _emit(JsonlSpool(path, max_bytes=60, keep=100), 10)
    assert _read_all(path, batch=3) == list(range(10))   # batched, still complete + ordered


def test_segmented_read_resumes_from_a_cursor(tmp_path):
    path = tmp_path / "audit.log"
    spool = JsonlSpool(path, max_bytes=60, keep=100)
    _emit(spool, 5)
    r = read_segmented(path, Cursor(), max_records=3)
    assert [rec.event["seq"] for rec in r.records] == [0, 1, 2]
    _emit(spool, 5, start=5)                      # more events + rotations
    rest: list[int] = []
    cur = r.cursor
    while True:
        r2 = read_segmented(path, cur, max_records=4)
        if not r2.records:
            break
        rest += [rec.event["seq"] for rec in r2.records]
        cur = r2.cursor
    assert [0, 1, 2] + rest == list(range(10))


def test_segmented_read_flags_a_pruned_cursor_as_a_gap(tmp_path):
    path = tmp_path / "audit.log"
    spool = JsonlSpool(path, max_bytes=60, keep=1)
    _emit(spool, 2)
    r = read_segmented(path, Cursor(), max_records=1)
    cursor = r.cursor                            # parked on a segment about to be pruned
    _emit(spool, 30, start=2)                    # floods rotations → prunes that segment
    r2 = read_segmented(path, cursor)
    assert r2.gap is True and "lost" in r2.gap_detail
    assert r2.records                            # still recovers what survives


def test_legacy_offset_only_cursor_resumes_from_the_start(tmp_path):
    """A pre-rotation watermark ({"offset": N}, no inode) must not trust a bare
    offset that rotation may have invalidated — it resumes from the oldest segment."""
    path = tmp_path / "audit.log"
    _emit(JsonlSpool(path, max_bytes=60, keep=100), 6)
    legacy = Cursor.from_dict({"offset": 999})   # no inode
    assert legacy.inode is None
    r = read_segmented(path, legacy)
    assert [rec.event["seq"] for rec in r.records] == list(range(6))  # re-reads from oldest


def test_empty_and_missing_spool(tmp_path):
    missing = tmp_path / "nope.log"
    assert read_segmented(missing, Cursor()).records == []
    empty = tmp_path / "empty.log"
    empty.write_text("")
    assert read_segmented(empty, Cursor()).records == []
