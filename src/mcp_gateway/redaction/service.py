"""RedactionService — the runtime front door to the redaction subsystem.

One service per gateway. It owns:
  * a per-profile engine cache (detectors reused; a profile that hashes gets a
    stable key across calls so tokens correlate within a session);
  * a token vault, so every tokenize operator in every engine shares one store
    and detokenize can reverse any token the gateway produced;
  * any custom recognizers, appended to every engine it builds.

The service never decides fail-closed behavior itself: it returns the redacted
value and a report, or raises. The gateway wraps the call and, on failure,
withholds the result rather than releasing it unscanned — that policy belongs
to the enforcement path, not the library.
"""

from __future__ import annotations

from mcp_gateway.redaction.detectors.base import DetectionContext, Detector
from mcp_gateway.redaction.detectors.custom import CustomDetector, Recognizer
from mcp_gateway.redaction.engine import RedactionEngine
from mcp_gateway.redaction.operators.tokenize import TokenizeOperator
from mcp_gateway.redaction.profiles import build_engine
from mcp_gateway.redaction.report import RedactionReport
from mcp_gateway.redaction.spec import RedactionSpec
from mcp_gateway.redaction.structured import StructuredPolicy
from mcp_gateway.redaction.vault import InMemoryVault, TokenVault


class RedactionService:
    def __init__(
        self,
        vault: TokenVault | None = None,
        recognizers: list[Recognizer] | None = None,
    ):
        self.vault: TokenVault = vault or InMemoryVault()
        self._tokenize = TokenizeOperator(self.vault)
        self._recognizers = recognizers or []
        self._engines: dict[str, RedactionEngine] = {}

    def engine_for(self, profile: str) -> RedactionEngine:
        engine = self._engines.get(profile)
        if engine is None:
            extra: list[Detector] = (
                [CustomDetector(self._recognizers)] if self._recognizers else []
            )
            engine = build_engine(
                profile,
                operators={"tokenize": self._tokenize},  # shared vault-backed op
                extra_detectors=extra,
            )
            self._engines[profile] = engine
        return engine

    def redact(self, value: object, spec: RedactionSpec) -> tuple[object, RedactionReport]:
        """Redact any JSON-like value per the spec. May raise; caller fails closed."""
        engine = self.engine_for(spec.profile)
        ctx = DetectionContext(
            allowlist=spec.allowlist,
            denylist=spec.denylist,
            context_words=spec.context_words,
        )
        structured = StructuredPolicy(exclude_keys=spec.exclude_keys)
        return engine.redact_json(value, ctx, structured)

    def detokenize(self, token: str) -> str | None:
        """Reverse a token to its original value (authorized/audited use only)."""
        return self.vault.detokenize(token)
