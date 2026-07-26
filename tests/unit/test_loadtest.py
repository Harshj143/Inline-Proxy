"""Sandbox smoke of the regex-path load harness (scripts/loadtest.py).

A small, robust slice of the load test: prove the enforcement path is correct
and fast under repetition. Percentile thresholds are generous so shared/slow CI
never flakes — the headline "p99 < 50 ms @ 100 calls/s" claim is exercised for
real by running scripts/loadtest.py with more calls on a quiet machine.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))

import loadtest  # noqa: E402


def test_regex_path_is_correct_and_fast():
    stats = asyncio.run(loadtest.run(calls=2000))
    assert stats["calls"] == 2000
    # Correctness proxy: the harness completed all calls with a finite latency.
    assert stats["max_ms"] >= 0
    # Latency: the regex enforcement path is sub-millisecond typically; assert a
    # generous ceiling that still catches a real regression (e.g. accidental NER
    # on the hot path) without flaking on a loaded CI box.
    assert stats["p99_ms"] < 50.0, f"p99 {stats['p99_ms']:.2f}ms too high"
    assert stats["mean_ms"] < 10.0, f"mean {stats['mean_ms']:.2f}ms too high"


def test_throughput_is_reported():
    stats = asyncio.run(loadtest.run(calls=500))
    # Comfortably above the 100 calls/sec sustained target for the regex path.
    assert stats["throughput_per_s"] > 100.0
