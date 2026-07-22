"""Regex + validator PII detector — the always-on, zero-dependency tier.

Every pattern here pairs with a validator (validators.py) so a match is only
claimed at high confidence when it satisfies the structure a real identifier
must have. Patterns that can't be validated structurally (email, phone) get a
lower confidence that reflects their false-positive rate, and the engine's
`min_confidence` and overlap resolution take it from there.

Confidences are deliberate, not decorative:
  0.95  structurally validated (SSN rules, Luhn, IPv4 octet ranges)
  0.90  email (well-shaped, rarely a false positive)
  0.60  phone (format varies wildly; noisiest of the group)
"""

from __future__ import annotations

import re

from mcp_gateway.redaction import entities
from mcp_gateway.redaction.detectors.base import DetectionContext, Detector
from mcp_gateway.redaction.detectors.validators import (
    ipv4_octets_valid,
    luhn_valid,
    ssn_valid,
)
from mcp_gateway.redaction.spans import Span

_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_SSN = re.compile(r"\b(\d{3})-(\d{2})-(\d{4})\b")
# 13-19 digits allowing space/hyphen separators BETWEEN digits (never trailing,
# which would otherwise swallow the following space); validated by Luhn.
_CARD = re.compile(r"\b\d(?:[ -]?\d){12,18}\b")
# No leading \b: a word boundary never matches before "(", which would let
# "(415) 555-0142" slip through. A real lesson in PII-regex formatting variants.
_PHONE = re.compile(
    r"(?<![\w.-])(?:\+?1[ .-]?)?(?:\(\d{3}\)\s?|\d{3}[ .-])\d{3}[ .-]?\d{4}\b"
)
_IPV4 = re.compile(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b")


class RegexPiiDetector(Detector):
    name = "regex_pii"

    def detect(self, text: str, ctx: DetectionContext) -> list[Span]:
        spans: list[Span] = []

        for m in _EMAIL.finditer(text):
            spans.append(self._span(entities.EMAIL, m, 0.90))

        for m in _SSN.finditer(text):
            area, group, serial = int(m[1]), int(m[2]), int(m[3])
            if ssn_valid(area, group, serial):
                spans.append(self._span(entities.SSN, m, 0.95))

        for m in _CARD.finditer(text):
            if luhn_valid(m.group()):
                spans.append(self._span(entities.CREDIT_CARD, m, 0.95))

        for m in _PHONE.finditer(text):
            spans.append(self._span(entities.PHONE, m, 0.60))

        for m in _IPV4.finditer(text):
            if ipv4_octets_valid([m[1], m[2], m[3], m[4]]):
                spans.append(self._span(entities.IP_ADDRESS, m, 0.95))

        return [s for s in spans if s.text not in ctx.allowlist]

    def _span(self, entity: str, m: re.Match, confidence: float) -> Span:
        return Span(
            entity=entity,
            start=m.start(),
            end=m.end(),
            confidence=confidence,
            detector=self.name,
            text=m.group(),
        )
