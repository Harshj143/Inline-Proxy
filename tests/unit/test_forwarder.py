"""The audit forwarder: an outage must cost duplicates at worst, never loss.

The exit criterion for Phase 11 is a SIEM down for an hour with zero loss, zero
hot-path stalls, and a clean drain on recovery. The hot-path part is structural —
the forwarder only ever *reads* the spool — so these tests hammer the other two:
the watermark advances only after a batch is accepted, so a down sink freezes it
in place while events keep spooling, and a recovered sink resumes from exactly
where it stopped and drains the backlog in order.
"""

from __future__ import annotations

import json

import pytest

from mcp_gateway.audit.forwarder import Forwarder, Watermark
from mcp_gateway.audit.sinks.base import Sink, SinkError


class RecordingSink(Sink):
    """Collects delivered events; can be toggled 'down' to raise like a real one."""

    name = "recording"

    def __init__(self):
        self.up = True
        self.received: list[dict] = []
        self.deliveries = 0

    def deliver(self, batch):
        if not self.up:
            raise SinkError("sink is down")
        self.deliveries += 1
        self.received.extend(batch)


@pytest.fixture
def spool(tmp_path):
    path = tmp_path / "audit.log"
    path.write_text("")

    def append(n, start=0, event="tool_call_allowed"):
        with path.open("a") as fh:
            for i in range(start, start + n):
                fh.write(json.dumps({"event": event, "seq": i}) + "\n")

    return path, append


def _forwarder(spool_path, sink, **kw):
    return Forwarder(spool_path, str(spool_path) + ".wm", sink, **kw)


def _seqs(sink):
    return [e["seq"] for e in sink.received]


# ------------------------------------------------------ the exit criterion
def test_outage_freezes_the_watermark_then_drains_zero_loss(spool):
    path, append = spool
    sink = RecordingSink()
    fwd = _forwarder(path, sink, batch_size=3)

    append(5)                                   # written while the sink is UP
    fwd.drain()
    assert _seqs(sink) == [0, 1, 2, 3, 4]
    watermark_up = fwd.watermark.load()

    # SIEM goes DOWN. More events keep spooling (the hot path never stalls).
    sink.up = False
    append(4, start=5)
    result = fwd.pump_once()
    assert not result.ok and "down" in result.error
    assert fwd.watermark.load() == watermark_up   # frozen — not advanced past unshipped events
    assert _seqs(sink) == [0, 1, 2, 3, 4]          # nothing new delivered

    # SIEM recovers: the backlog drains from exactly where we stopped, in order.
    sink.up = True
    fwd.drain()
    assert _seqs(sink) == list(range(9))           # all nine, once each, in order


def test_watermark_advances_only_after_a_successful_delivery(spool):
    path, append = spool
    sink = RecordingSink()
    fwd = _forwarder(path, sink, batch_size=10)
    append(3)

    sink.up = False
    assert fwd.pump_once().ok is False
    assert fwd.watermark.load() == 0               # no delivery → no advance

    sink.up = True
    result = fwd.pump_once()
    assert result.ok and result.delivered == 3
    assert fwd.watermark.load() == result.watermark > 0


def test_a_fresh_forwarder_resumes_from_the_persisted_watermark(spool):
    path, append = spool
    append(4)
    first = _forwarder(path, RecordingSink())
    first.drain()
    offset = first.watermark.load()

    # A brand-new forwarder (process restart) over the same spool + watermark
    # must not re-ship what the first one already delivered.
    append(2, start=4)
    second_sink = RecordingSink()
    second = _forwarder(path, second_sink)
    second.drain()
    assert _seqs(second_sink) == [4, 5]            # only the new events
    assert second.watermark.load() > offset


def test_batches_respect_batch_size(spool):
    path, append = spool
    sink = RecordingSink()
    fwd = _forwarder(path, sink, batch_size=2)
    append(5)
    result = fwd.pump_once()
    assert result.delivered == 2                   # one batch, not all five
    assert sink.deliveries == 1
    fwd.drain()
    assert _seqs(sink) == [0, 1, 2, 3, 4]           # the rest drain in later batches


def test_empty_spool_is_a_no_op(spool):
    path, _ = spool
    result = _forwarder(path, RecordingSink()).pump_once()
    assert result.ok and result.delivered == 0 and result.watermark == 0


# ------------------------------------------------------------ mapping/filter
def test_mapper_transforms_each_event(spool):
    path, append = spool
    sink = RecordingSink()
    fwd = _forwarder(path, sink, mapper=lambda e: {"mapped": e["seq"]})
    append(2)
    fwd.drain()
    assert sink.received == [{"mapped": 0}, {"mapped": 1}]


def test_mapper_returning_none_drops_the_event_but_still_advances(spool):
    """A dropped (filtered) event is consumed, not re-scanned forever."""
    path, append = spool
    sink = RecordingSink()
    # Keep only odd seqs.
    fwd = _forwarder(path, sink, mapper=lambda e: e if e["seq"] % 2 else None)
    append(4)
    fwd.drain()
    assert _seqs(sink) == [1, 3]
    assert fwd.watermark.load() > 0                # advanced past the dropped ones


def test_all_dropped_batch_still_advances_the_watermark(spool):
    path, append = spool
    sink = RecordingSink()
    fwd = _forwarder(path, sink, mapper=lambda e: None)   # drop everything
    append(3)
    result = fwd.pump_once()
    assert result.ok and result.delivered == 0
    assert result.watermark > 0                    # consumed, just not forwarded
    assert sink.deliveries == 0                     # sink never called for an empty batch


# ------------------------------------------------------------ alarm / backoff
def test_lag_alarm_fires_when_the_backlog_grows(spool):
    path, append = spool
    fired: list[int] = []
    sink = RecordingSink()
    sink.up = False
    fwd = _forwarder(path, sink, alarm_lag_bytes=10, on_alarm=fired.append)
    append(20)                                     # well over 10 bytes of backlog
    fwd.pump_once()                                # delivery fails; lag is large
    assert fired and fired[0] >= 10


def test_run_loop_backs_off_while_down_and_stops_on_signal(spool):
    path, append = spool
    sink = RecordingSink()
    sink.up = False
    fwd = _forwarder(path, sink)
    append(2)

    slept: list[float] = []
    calls = {"n": 0}

    def should_stop():
        calls["n"] += 1
        return calls["n"] > 3                       # let it loop a few times

    fwd.run(poll_seconds=1.0, max_backoff=8.0, should_stop=should_stop,
            sleep=slept.append)
    # Backed off on each failed tick: 1, 2, 4 (growing, capped at max_backoff).
    assert slept == [1.0, 2.0, 4.0]


def test_run_loop_polls_when_caught_up(spool):
    path, append = spool
    sink = RecordingSink()
    fwd = _forwarder(path, sink)
    append(1)
    slept: list[float] = []
    calls = {"n": 0}

    def should_stop():
        calls["n"] += 1
        return calls["n"] > 3       # tick 1 delivers (no sleep); ticks 2-3 poll

    fwd.run(poll_seconds=3.0, should_stop=should_stop, sleep=slept.append)
    assert _seqs(sink) == [0]
    assert slept == [3.0, 3.0]                       # steady poll interval, no backoff


# ------------------------------------------------------------ watermark file
def test_watermark_survives_a_corrupt_file(tmp_path):
    wm = Watermark(tmp_path / "wm.json")
    wm.store(42)
    assert wm.load() == 42
    (tmp_path / "wm.json").write_text("{ not json")
    assert wm.load() == 0                            # corrupt → re-forward from 0 (safe)


def test_bad_spool_lines_are_skipped_not_fatal(spool):
    path, append = spool
    with path.open("a") as fh:
        fh.write("this is not json\n")
        fh.write(json.dumps({"event": "tool_call_allowed", "seq": 99}) + "\n")
    sink = RecordingSink()
    fwd = _forwarder(path, sink)
    fwd.drain()
    assert _seqs(sink) == [99]                        # good event delivered, garbage skipped
    assert fwd.watermark.load() == path.stat().st_size  # consumed the whole file


# ------------------------------------------------------------ CLI: audit forward
def test_cli_forward_once_drains_through_a_webhook(spool, monkeypatch, capsys):
    """`audit forward --once` builds the sink, maps, delivers, advances watermark."""
    import mcp_gateway.audit.sinks.webhook as webhook
    from mcp_gateway.cli import main

    path, append = spool
    append(3, event="tool_call_blocked")
    posts: list[str] = []
    monkeypatch.setattr(
        webhook, "_urllib_post",
        lambda url, headers, body, timeout: (posts.append(body.decode()), 200)[1],
    )
    code = main([
        "audit", "forward", "--audit", str(path),
        "--sink", "webhook", "--url", "https://siem.example/in",
        "--format", "ocsf", "--once",
    ])
    assert code == 0
    assert len(posts) == 1
    first = json.loads(posts[0].strip().split("\n")[0])
    assert first["class_name"] == "Application Activity"      # OCSF mapping applied
    assert "drained 3 event(s)" in capsys.readouterr().out
    assert (path.parent / (path.name + ".webhook.wm")).exists()


def test_cli_forward_missing_required_option_fails_closed(spool):
    from mcp_gateway.cli import main

    path, _ = spool
    # --sink s3 without --bucket is a config error, not a silent no-op.
    assert main(["audit", "forward", "--audit", str(path), "--sink", "s3"]) == 1


def test_cli_forward_reports_a_delivery_failure(spool, monkeypatch):
    import mcp_gateway.audit.sinks.webhook as webhook
    from mcp_gateway.cli import main

    path, append = spool
    append(1)
    monkeypatch.setattr(
        webhook, "_urllib_post",
        lambda url, headers, body, timeout: 503,       # sink down
    )
    code = main([
        "audit", "forward", "--audit", str(path),
        "--sink", "webhook", "--url", "https://x/in", "--once",
    ])
    assert code == 1                                    # --once surfaces the failure
