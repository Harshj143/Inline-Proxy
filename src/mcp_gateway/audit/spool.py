"""The JSONL spool: the gateway's audit source of truth.

Append-only, one JSON object per line, crash-tolerant (a torn final line is
detectable and skippable by readers). Downstream sinks (SQLite index, S3,
Splunk) *read from this file*; the hot path only ever appends here. That
separation is what makes "never block a tool call on a slow SIEM, never drop an
event" cheap to guarantee (docs/SYSTEM_DESIGN.md §6.1).

Writes are buffered file appends guarded by an asyncio lock: microseconds of
blocking at our event rates, not worth a thread hop. Revisit only if profiling
of a real deployment says otherwise.

**Rotation.** Left uncapped, an audit log grows without bound — a Day-2 disk
problem, and a security log you cannot afford to just delete. Set `max_bytes` and
the spool rolls itself: when the live file would exceed the cap it is renamed to
`audit.log.<NNNNNNNN>` (a monotonic, zero-padded sequence — ascending = newer)
and a fresh live file is opened; segments beyond `keep` are pruned. The writer
owns rotation rather than an external `logrotate` so there is no copy/truncate
race that could drop an event mid-roll, and because readers resume by **inode**
(see `audit/reader.py`), a rename is transparent to them — a slow consumer keeps
draining the rotated segment it was on. Rotation is opt-in; `max_bytes=None`
keeps the original single-file behavior exactly.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
from pathlib import Path
from typing import Any, TextIO


class JsonlSpool:
    def __init__(
        self, path: str | Path, *, max_bytes: int | None = None, keep: int = 10
    ):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.max_bytes = max_bytes if (max_bytes and max_bytes > 0) else None
        self.keep = max(1, keep)
        self._fh: TextIO = self.path.open("a", encoding="utf-8")
        # Track the live file's size so rotation never has to stat on the hot path.
        try:
            self._size = self.path.stat().st_size
        except OSError:
            self._size = 0
        self._lock = asyncio.Lock()

    async def emit(self, event: dict[str, Any]) -> None:
        line = json.dumps(event, separators=(",", ":"), ensure_ascii=False, default=str)
        data = (line + "\n").encode("utf-8")
        async with self._lock:
            # Roll BEFORE writing, only when the file already holds something —
            # a single event larger than the cap still lands whole (never split
            # across segments), which keeps every line parseable.
            if self.max_bytes and self._size > 0 and self._size + len(data) > self.max_bytes:
                self._rotate()
            self._fh.write(line + "\n")
            self._fh.flush()
            self._size += len(data)

    def _rotate(self) -> None:
        self._fh.close()
        seq = self._next_seq()
        rotated = self.path.with_name(f"{self.path.name}.{seq:08d}")
        os.replace(self.path, rotated)          # atomic; readers follow by inode
        self._fh = self.path.open("a", encoding="utf-8")
        self._size = 0
        self._prune()

    def _rotated_segments(self) -> list[tuple[int, Path]]:
        out: list[tuple[int, Path]] = []
        for child in self.path.parent.glob(self.path.name + ".*"):
            suffix = child.name[len(self.path.name) + 1:]
            if suffix.isdigit():
                out.append((int(suffix), child))
        return sorted(out)

    def _next_seq(self) -> int:
        segments = self._rotated_segments()
        return (segments[-1][0] + 1) if segments else 1

    def _prune(self) -> None:
        """Keep the `keep` most-recent rotated segments; delete the oldest.

        This is the one place the audit trail can lose events: a segment pruned
        before a lagging reader consumed it. The reader detects and reports that
        as a gap; `keep` sizes the window a consumer may fall behind.
        """
        segments = self._rotated_segments()
        for _seq, path in segments[: max(0, len(segments) - self.keep)]:
            with contextlib.suppress(OSError):
                path.unlink()

    async def close(self) -> None:
        async with self._lock:
            if not self._fh.closed:
                self._fh.close()
