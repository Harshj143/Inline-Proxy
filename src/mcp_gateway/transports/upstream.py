"""Upstream MCP server connections, decoupled from the client-facing transport.

In sidecar (stdio) mode the client-facing side and the upstream are both wired
inside one `StdioTransport`. Central mode (Phase 5) inverts that: one long-lived
process fronts *many* client sessions over HTTP, each needing its own upstream.
So the upstream half is factored out here behind a small protocol:

    Upstream: start() -> pump upstream lines to a callback; send(line); shutdown()

`SubprocessUpstream` is the production implementation — the same "launch a
subprocess, pump its stdout as newline-JSON, write to its stdin, terminate with
a grace period then kill" logic the stdio transport uses, but per client
session. Tests inject an in-process fake instead of paying for a subprocess.

The 16 MiB frame limit and fail-closed-on-overrun posture are preserved: a lost
frame boundary means the stream can't be trusted, so the upstream is torn down
rather than resynchronised heuristically (docs/SYSTEM_DESIGN.md §1.3).
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import Awaitable, Callable
from typing import Protocol

from mcp_gateway.core.errors import TransportError

LINE_LIMIT = 16 * 1024 * 1024
TERMINATE_GRACE_S = 5.0

# Called for each decoded upstream line (already stripped, non-empty).
LineHandler = Callable[[str], Awaitable[None]]
# Called once with the exit code (or None) when the upstream ends on its own.
ExitHandler = Callable[[int | None], Awaitable[None]]


class Upstream(Protocol):
    async def start(self, on_line: LineHandler, on_exit: ExitHandler) -> None: ...
    async def send(self, line: str) -> None: ...
    async def shutdown(self) -> int | None: ...


class SubprocessUpstream:
    """An upstream MCP server run as a child process, one per client session."""

    def __init__(self, command: list[str]):
        if not command:
            raise TransportError("no upstream server command given")
        self.command = command
        self._proc: asyncio.subprocess.Process | None = None
        self._pump: asyncio.Task | None = None

    async def start(self, on_line: LineHandler, on_exit: ExitHandler) -> None:
        self._proc = await asyncio.create_subprocess_exec(
            *self.command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=None,  # inherit: upstream diagnostics reach the operator's console
            limit=LINE_LIMIT,
        )
        self._pump = asyncio.create_task(
            self._pump_stdout(on_line, on_exit), name="upstream-pump"
        )

    async def _pump_stdout(self, on_line: LineHandler, on_exit: ExitHandler) -> None:
        assert self._proc is not None and self._proc.stdout is not None
        stdout = self._proc.stdout
        while True:
            try:
                raw = await stdout.readline()
            except ValueError:
                # Frame exceeded LINE_LIMIT: framing is lost, fail closed.
                await on_exit(None)
                return
            if not raw:
                break  # upstream EOF
            text = raw.decode("utf-8", errors="replace").strip()
            if text:
                await on_line(text)
        await self._proc.wait()
        await on_exit(self._proc.returncode)

    async def send(self, line: str) -> None:
        proc = self._proc
        if proc is None or proc.stdin is None or proc.returncode is not None:
            raise TransportError("upstream server is not running")
        proc.stdin.write(line.encode("utf-8") + b"\n")
        await proc.stdin.drain()

    async def shutdown(self) -> int | None:
        proc = self._proc
        if self._pump is not None:
            self._pump.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._pump
        if proc is None:
            return None
        if proc.returncode is None:
            proc.terminate()
            try:
                await asyncio.wait_for(proc.wait(), TERMINATE_GRACE_S)
            except TimeoutError:
                proc.kill()
                await proc.wait()
        return proc.returncode
