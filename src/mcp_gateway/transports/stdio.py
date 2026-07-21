"""stdio transport: the sidecar (wrap) mode.

The MCP client launches *us*; we launch the real server as a subprocess and
pump newline-delimited JSON-RPC in both directions through the gateway:

    client stdin ──> gateway pipeline ──> upstream stdin
    client stdout <── gateway         <── upstream stdout

Design notes:
  * asyncio end-to-end; each direction is one task. Client EOF is the
    session ending: the upstream is terminated (grace period, then kill).
    Upstream EOF/crash ends the run and is audited — the client sees a dead
    server, which is the safe failure direction.
  * LINE_LIMIT bounds one frame at 16 MiB (p99 tool results are ~1 MiB;
    docs/SYSTEM_DESIGN.md §1.3). An overrun means framing is lost and the
    stream cannot be trusted — the transport audits and shuts down rather
    than resynchronizing heuristically (fail closed).
  * The upstream's stderr is inherited so its diagnostics reach the user's
    console untouched.
"""

from __future__ import annotations

import asyncio
import contextlib
import sys
from asyncio.subprocess import Process

from mcp_gateway.audit import events as audit_events
from mcp_gateway.core.errors import TransportError
from mcp_gateway.core.gateway import SecurityGateway

LINE_LIMIT = 16 * 1024 * 1024
TERMINATE_GRACE_S = 5.0


class _BlockingLineReader:
    """Fallback when stdin is a regular file, not a pipe (e.g. `< session.txt`).

    asyncio's connect_read_pipe only accepts pipes/sockets/character devices;
    for a regular file a brief executor hop per line is fine — this path never
    occurs when a real MCP client launches the gateway.
    """

    def __init__(self, fh):
        self._fh = fh

    async def readline(self) -> bytes:
        return await asyncio.get_running_loop().run_in_executor(None, self._fh.readline)


class _BlockingLineWriter:
    """Fallback when stdout is a regular file, not a pipe (e.g. `> out.txt`)."""

    def __init__(self, fh):
        self._fh = fh

    async def write_line(self, data: bytes) -> None:
        def _write() -> None:
            self._fh.write(data)
            self._fh.flush()

        await asyncio.get_running_loop().run_in_executor(None, _write)


class _StreamLineWriter:
    """Normal path: pipe-backed StreamWriter with flow control."""

    def __init__(self, writer: asyncio.StreamWriter):
        self._writer = writer

    async def write_line(self, data: bytes) -> None:
        self._writer.write(data)
        await self._writer.drain()


class StdioTransport:
    def __init__(self, upstream_cmd: list[str], gateway: SecurityGateway):
        if not upstream_cmd:
            raise TransportError("no upstream server command given")
        self.upstream_cmd = upstream_cmd
        self.gateway = gateway
        self._proc: Process | None = None
        self._client_writer: _StreamLineWriter | _BlockingLineWriter | None = None
        self._write_lock = asyncio.Lock()

    # ------------------------------------------------------------ wire setup
    async def _open_client_reader(self) -> asyncio.StreamReader | _BlockingLineReader:
        loop = asyncio.get_running_loop()
        try:
            reader = asyncio.StreamReader(limit=LINE_LIMIT)
            await loop.connect_read_pipe(
                lambda: asyncio.StreamReaderProtocol(reader), sys.stdin
            )
            return reader
        except (ValueError, OSError):
            return _BlockingLineReader(sys.stdin.buffer)

    async def _open_client_writer(self) -> _StreamLineWriter | _BlockingLineWriter:
        loop = asyncio.get_running_loop()
        try:
            w_transport, w_protocol = await loop.connect_write_pipe(
                asyncio.streams.FlowControlMixin, sys.stdout
            )
            writer = asyncio.StreamWriter(w_transport, w_protocol, None, loop)
            return _StreamLineWriter(writer)
        except (ValueError, OSError):
            return _BlockingLineWriter(sys.stdout.buffer)

    # -------------------------------------------------------------- lifecycle
    async def run(self) -> int:
        self._proc = await asyncio.create_subprocess_exec(
            *self.upstream_cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=None,  # inherit: upstream diagnostics go straight through
            limit=LINE_LIMIT,
        )
        client_reader = await self._open_client_reader()
        self._client_writer = await self._open_client_writer()

        self.gateway.bind_transport(self)
        await self.gateway.on_start(self.upstream_cmd)

        client_task = asyncio.create_task(
            self._pump(client_reader, self.gateway.on_client_line, "client_to_upstream"),
            name="pump-client",
        )
        assert self._proc.stdout is not None
        upstream_task = asyncio.create_task(
            self._pump(self._proc.stdout, self.gateway.on_upstream_line, "upstream_to_client"),
            name="pump-upstream",
        )

        try:
            done, pending = await asyncio.wait(
                {client_task, upstream_task}, return_when=asyncio.FIRST_COMPLETED
            )
            for task in pending:
                task.cancel()
            for task in pending:
                with contextlib.suppress(asyncio.CancelledError):
                    await task
            # Surface pump errors (LimitOverrun etc. are handled inside _pump;
            # anything else is unexpected and should be visible).
            for task in done:
                task.result()
        finally:
            returncode = await self._shutdown_upstream()
            await self.gateway.on_upstream_exit(returncode)
            await self.gateway.on_stop()
        return 0

    async def _shutdown_upstream(self) -> int | None:
        proc = self._proc
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

    # ------------------------------------------------------------------ pumps
    async def _pump(
        self,
        reader: asyncio.StreamReader | _BlockingLineReader,
        handler,
        direction: str,
    ) -> None:
        while True:
            try:
                line = await reader.readline()
            except ValueError:
                # A frame exceeded LINE_LIMIT: framing is lost, the stream can
                # no longer be trusted. Audit and end the session (fail closed).
                await self.gateway.audit.emit(
                    audit_events.TRANSPORT_OVERRUN,
                    direction=direction,
                    limit=LINE_LIMIT,
                )
                return
            if not line:
                return  # EOF
            text = line.decode("utf-8", errors="replace").strip()
            if text:
                await handler(text)

    # ------------------------------------------------------------------ sends
    async def send_client(self, line: str) -> None:
        assert self._client_writer is not None
        async with self._write_lock:
            await self._client_writer.write_line(line.encode("utf-8") + b"\n")

    async def send_upstream(self, line: str) -> None:
        proc = self._proc
        if proc is None or proc.stdin is None or proc.returncode is not None:
            raise TransportError("upstream server is not running")
        proc.stdin.write(line.encode("utf-8") + b"\n")
        await proc.stdin.drain()
