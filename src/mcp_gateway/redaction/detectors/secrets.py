"""Secrets detector — API keys, tokens, and private keys.

Secrets are a distinct category from PII (entities.Category.SECRET) and matter
most for the connector packs: a leaked GitHub PAT or AWS key in a tool result
is a live incident. Provider tokens have fixed, recognizable shapes (prefixes,
lengths, alphabets), so these fire at high confidence. A last-resort
high-entropy heuristic catches unknown-shaped secrets at LOW confidence, to be
gated by profile/threshold rather than trusted blindly.
"""

from __future__ import annotations

import re

from mcp_gateway.redaction import entities
from mcp_gateway.redaction.detectors.base import DetectionContext, Detector
from mcp_gateway.redaction.detectors.validators import shannon_entropy
from mcp_gateway.redaction.spans import Span
from mcp_gateway.redaction.structured import StructuredPolicy

# Provider tokens: shape is distinctive enough to trust at high confidence.
_PROVIDER_PATTERNS: list[tuple[str, re.Pattern, float]] = [
    # AWS access key id: AKIA/ASIA/AGPA/... + 16 uppercase alnum.
    (entities.AWS_ACCESS_KEY_ID, re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA)[0-9A-Z]{16}\b"), 0.98),
    # GitHub tokens: ghp_/gho_/ghu_/ghs_/ghr_ + 36, or fine-grained github_pat_.
    (entities.GITHUB_TOKEN, re.compile(r"\bgh[posur]_[A-Za-z0-9]{36}\b"), 0.98),
    (entities.GITHUB_TOKEN, re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,}\b"), 0.98),
    # Slack tokens: xoxb-/xoxp-/xoxa-/xoxr-/xoxs- followed by digit-dash groups.
    (entities.SLACK_TOKEN, re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), 0.97),
    # JWT: three base64url segments; the header almost always starts eyJ.
    (entities.JWT,
     re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b"), 0.90),
]

# ---------------------------------------------------------- labeled secrets
# A secret's VALUE is often shapeless — `DB_PASSWORD=hunter2` says nothing about
# "hunter2" — but the LABEL gives it away. `structured.py` already does this for
# real dict keys; this is its text-mode counterpart, which matters because MCP
# tool results are overwhelmingly JSON-or-config-in-text, where no dict key is
# ever visible to the structured pass (a documented Phase 2b gap).
#
# Only the value is redacted, never the label: `DB_PASSWORD=[REDACTED]` stays
# debuggable, and blanking the name would tell a reader nothing was protected.
# The key vocabulary is shared with structured.py so there is ONE place to tune.
_LABELED = re.compile(
    r"""(?P<key>[A-Za-z][A-Za-z0-9_.\-]{1,60})   # a config/JSON-ish key name
        \s*(?::|=|"\s*:)\s*                       # : or = (incl. JSON "key": )
        (?P<quote>["']?)                          # optional quoting
        (?P<value>[^\s"',;}\]]{4,})               # the value itself
        (?P=quote)""",
    re.VERBOSE,
)
_LABELED_CONFIDENCE = 0.90

# AWS secret access keys are 40 chars of base64 with NO distinguishing prefix, so
# matching them by shape alone would flag every hash and base64 blob. Anchoring on
# a nearby AWS-ish label makes them unambiguous — the same trade-off every
# credential scanner makes. (The entity was registered from the start but nothing
# emitted it until now: an AWS secret key sailed through the default profile,
# which the GitHub-pack e2e caught.)
_AWS_SECRET = re.compile(
    r"""(?:aws.{0,20}?(?:secret|access).{0,20}?key|secret[_\-]?access[_\-]?key)
        \s*(?::|=|"\s*:)\s*["']?
        (?P<value>[A-Za-z0-9/+=]{40})\b""",
    re.VERBOSE | re.IGNORECASE,
)
_AWS_SECRET_CONFIDENCE = 0.95

# PEM private-key blocks (any key type). Non-greedy to a single block.
_PRIVATE_KEY = re.compile(
    r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"
    r".*?-----END (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----",
    re.DOTALL,
)

# Candidate tokens for the entropy heuristic: long contiguous secret-shaped runs.
# `=` is accepted ONLY as trailing base64 padding, never mid-run — in real base64
# it never appears in the middle, and allowing it there made `SOME_LABEL=<secret>`
# match as ONE token, so the reported span covered the label and the entropy was
# computed over label+value. The value alone is the secret.
_ENTROPY_CANDIDATE = re.compile(
    r"\b[A-Za-z0-9+/][A-Za-z0-9+/_-]{23,}={0,2}(?![A-Za-z0-9+/=_-])"
)
_ENTROPY_MIN_BITS = 4.0
_ENTROPY_CONFIDENCE = 0.55


class SecretsDetector(Detector):
    name = "secrets"

    def __init__(
        self,
        include_high_entropy: bool = True,
        include_labeled: bool = True,
        structured: StructuredPolicy | None = None,
    ):
        # High-entropy detection is powerful but noisy; a profile can turn it
        # off (e.g. for a payload class full of legitimate hashes/UUIDs).
        self.include_high_entropy = include_high_entropy
        # Label-driven detection for text payloads; shares its key vocabulary
        # with the structured (dict-key) pass.
        self.include_labeled = include_labeled
        self.structured = structured or StructuredPolicy()

    def detect(self, text: str, ctx: DetectionContext) -> list[Span]:
        spans: list[Span] = []

        for entity, pattern, confidence in _PROVIDER_PATTERNS:
            for m in pattern.finditer(text):
                spans.append(self._span(entity, m.start(), m.end(), m.group(), confidence))

        for m in _PRIVATE_KEY.finditer(text):
            spans.append(
                self._span(entities.PRIVATE_KEY, m.start(), m.end(), m.group(), 0.99)
            )

        # AWS secret access key, anchored on its label. Higher confidence than the
        # generic labeled pass so the specific entity wins overlap resolution.
        for m in _AWS_SECRET.finditer(text):
            spans.append(self._span(
                entities.AWS_SECRET_ACCESS_KEY, m.start("value"), m.end("value"),
                m.group("value"), _AWS_SECRET_CONFIDENCE,
            ))

        if self.include_labeled:
            for m in _LABELED.finditer(text):
                if not self.structured.key_is_sensitive(m.group("key")):
                    continue
                if self.structured.key_is_excluded(m.group("key")):
                    continue  # a policy deliberately protects this field
                spans.append(self._span(
                    entities.SENSITIVE_FIELD, m.start("value"), m.end("value"),
                    m.group("value"), _LABELED_CONFIDENCE,
                ))

        if self.include_high_entropy:
            claimed = [(s.start, s.end) for s in spans]
            for m in _ENTROPY_CANDIDATE.finditer(text):
                if _covered(m.start(), m.end(), claimed):
                    continue  # already a known-shaped secret; don't double-claim
                if shannon_entropy(m.group()) >= _ENTROPY_MIN_BITS:
                    spans.append(self._span(
                        entities.GENERIC_SECRET, m.start(), m.end(), m.group(),
                        _ENTROPY_CONFIDENCE,
                    ))

        return [s for s in spans if s.text not in ctx.allowlist]

    def _span(self, entity, start, end, text, confidence) -> Span:
        return Span(
            entity=entity, start=start, end=end,
            confidence=confidence, detector=self.name, text=text,
        )


def _covered(start: int, end: int, ranges: list[tuple[int, int]]) -> bool:
    return any(start < r_end and r_start < end for r_start, r_end in ranges)
