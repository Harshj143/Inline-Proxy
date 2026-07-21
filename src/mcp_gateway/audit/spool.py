"""The JSONL spool: the gateway's audit source of truth.

Append-only, one JSON object per line, crash-tolerant (a torn final line is
detectable and skippable by readers). Downstream sinks (SQLite index, S3,
Splunk — later phases) *read from this file*; the hot path only ever appends
here. That separation is what makes "never block a tool call on a slow SIEM,
never drop an event" cheap to guarantee (docs/SYSTEM_DESIGN.md §6.1).

Writes are buffered file appends guarded by an asyncio lock: microseconds of
blocking at our event rates, not worth a thread hop. Revisit only if profiling
of a real deployment says otherwise.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any, TextIO


class JsonlSpool:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._fh: TextIO = self.path.open("a", encoding="utf-8")
        self._lock = asyncio.Lock()

    async def emit(self, event: dict[str, Any]) -> None:
        line = json.dumps(event, separators=(",", ":"), ensure_ascii=False, default=str)
        async with self._lock:
            self._fh.write(line + "\n")
            self._fh.flush()

    async def close(self) -> None:
        async with self._lock:
            if not self._fh.closed:
                self._fh.close()
