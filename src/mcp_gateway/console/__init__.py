"""The Security Ops Console (Phase 4b/4c).

A FastAPI app served from the `[server]` extra, sitting *on top of* the Phase 4a
audit index and the JSONL spool. It never touches the enforcement hot path: it
reads the derived index for history, tails the spool for the live feed, and
implements the approvals endpoint the gateway's `HttpChannel` already POSTs to.

Import lazily — `create_app` pulls in FastAPI, which core installs must not
require. Callers that lack the extra get a clear error from `console.app`.
"""

from __future__ import annotations
