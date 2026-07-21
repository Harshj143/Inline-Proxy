"""Structured audit logging for the MCP security gateway.

Every policy decision and redaction event is written as one JSON object per
line (JSONL), the same shape you'd ship to Splunk, Datadog, or S3. This is
the "panopticon" property: who called what tool, when, with what decision.
"""

from __future__ import annotations

import json
import sys
import threading
import time
from pathlib import Path


class AuditLog:
    def __init__(self, path: str | Path, echo_stderr: bool = True):
        self.path = Path(path)
        self.echo = echo_stderr
        self._lock = threading.Lock()
        self._fh = open(self.path, "a", encoding="utf-8")
        # Fields merged into every record (e.g. the session id), so the console
        # can group interleaved writes from concurrent gateways correctly.
        self.default_fields: dict = {}

    def write(self, event_type: str, **fields) -> None:
        record = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "event": event_type,
            **self.default_fields,
            **fields,
        }
        line = json.dumps(record, ensure_ascii=False)
        with self._lock:
            self._fh.write(line + "\n")
            self._fh.flush()
            if self.echo:
                # stderr keeps audit output out of the JSON-RPC stdio stream
                print(f"[audit] {line}", file=sys.stderr, flush=True)

    def close(self) -> None:
        with self._lock:
            self._fh.close()
