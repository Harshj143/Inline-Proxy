"""Tolerant JSONL spool reader: offsets, torn tails, bad lines, resume."""

from __future__ import annotations

import json

from mcp_gateway.audit.reader import read_spool


def _write(path, *events, torn=None):
    with path.open("wb") as fh:
        for ev in events:
            fh.write((json.dumps(ev) + "\n").encode("utf-8"))
        if torn is not None:
            fh.write(json.dumps(torn).encode("utf-8"))  # no trailing newline


def test_reads_all_complete_lines_with_offsets(tmp_path):
    spool = tmp_path / "audit.log"
    _write(spool, {"event": "a", "i": 1}, {"event": "b", "i": 2})
    result = read_spool(spool)
    assert [r.event["event"] for r in result.records] == ["a", "b"]
    assert result.records[0].offset == 0
    assert result.records[1].offset == result.records[0].end_offset
    assert result.next_offset == result.records[-1].end_offset
    assert result.bad_lines == 0
    assert result.torn_tail is False


def test_missing_file_is_empty_not_error(tmp_path):
    result = read_spool(tmp_path / "nope.log")
    assert result.records == []
    assert result.next_offset == 0


def test_torn_final_line_is_skipped_and_resumable(tmp_path):
    spool = tmp_path / "audit.log"
    _write(spool, {"event": "a"}, torn={"event": "half"})
    result = read_spool(spool)
    assert [r.event["event"] for r in result.records] == ["a"]
    assert result.torn_tail is True
    # next_offset stops before the torn fragment: the completed 'a' line only.
    assert result.next_offset == result.records[0].end_offset

    # Writer finishes the torn line + appends another; resume picks both up.
    with spool.open("wb") as fh:
        fh.write((json.dumps({"event": "a"}) + "\n").encode())
        fh.write((json.dumps({"event": "half"}) + "\n").encode())
        fh.write((json.dumps({"event": "c"}) + "\n").encode())
    resumed = read_spool(spool, start=result.next_offset)
    assert [r.event["event"] for r in resumed.records] == ["half", "c"]


def test_bad_line_is_counted_not_fatal(tmp_path):
    spool = tmp_path / "audit.log"
    with spool.open("wb") as fh:
        fh.write((json.dumps({"event": "a"}) + "\n").encode())
        fh.write(b"{not json at all}\n")
        fh.write((json.dumps({"event": "b"}) + "\n").encode())
    result = read_spool(spool)
    assert [r.event["event"] for r in result.records] == ["a", "b"]
    assert result.bad_lines == 1


def test_non_object_json_line_counts_as_bad(tmp_path):
    spool = tmp_path / "audit.log"
    with spool.open("wb") as fh:
        fh.write(b"[1, 2, 3]\n")
        fh.write((json.dumps({"event": "ok"}) + "\n").encode())
    result = read_spool(spool)
    assert [r.event["event"] for r in result.records] == ["ok"]
    assert result.bad_lines == 1


def test_start_offset_reads_only_the_tail(tmp_path):
    spool = tmp_path / "audit.log"
    _write(spool, {"event": "a"}, {"event": "b"}, {"event": "c"})
    first = read_spool(spool)
    after_a = first.records[0].end_offset
    tail = read_spool(spool, start=after_a)
    assert [r.event["event"] for r in tail.records] == ["b", "c"]
