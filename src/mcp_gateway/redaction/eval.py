"""Redaction accuracy evaluation — the "how good is it?" answer, shippable.

A labeled corpus (positives + deliberate look-alike negatives) and count-based
precision/recall/F1 scoring. Lives in the package (not just tests) so it backs
both the CI gate and the `mcp-gateway redact --eval` command a user can run to
see the numbers for themselves. Phase 2c upgrades to span-level scoring and a
larger corpus.
"""

from __future__ import annotations

from dataclasses import dataclass

from mcp_gateway.redaction import entities

# ghp_ + 36-char body; AWS AKIA + 16 — both structurally valid tokens.
_GITHUB = "ghp_0123456789abcdefghijklmnopqrstuvwxyz"
_AWS = "AKIAIOSFODNN7EXAMPLE"

BUILTIN_CORPUS: list[dict] = [
    # ---- positives: real, validated identifiers ----
    {"text": "Please contact alice@example.com about the invoice.",
     "expect": {entities.EMAIL: 1}},
    {"text": "Customer SSN on file is 123-45-6789 per the form.",
     "expect": {entities.SSN: 1}},
    {"text": "We charged card 4111 1111 1111 1111 last night.",
     "expect": {entities.CREDIT_CARD: 1}},
    {"text": "The server at 10.0.0.5 returned a 500.",
     "expect": {entities.IP_ADDRESS: 1}},
    {"text": "Call the customer back at (415) 555-0142 today.",
     "expect": {entities.PHONE: 1}},
    {"text": f"CI leaked a token: {_GITHUB} in the build log.",
     "expect": {entities.GITHUB_TOKEN: 1}},
    {"text": f"Found {_AWS} committed to the repo.",
     "expect": {entities.AWS_ACCESS_KEY_ID: 1}},
    {"text": "Reach alice@example.com or bob@example.com for access.",
     "expect": {entities.EMAIL: 2}},
    {"text": "Reset for user carol@example.org, phone 212-555-0199.",
     "expect": {entities.EMAIL: 1, entities.PHONE: 1}},
    {"text": "Wire details: SSN 078-05-1120, card 5500005555555559.",
     "expect": {entities.SSN: 1, entities.CREDIT_CARD: 1}},

    # ---- negatives: look-alikes that must NOT redact ----
    {"text": "Order number 4111111111111112 shipped on Tuesday.", "expect": {}},
    {"text": "Reference ticket 666-45-6789 was escalated.", "expect": {}},
    {"text": "The build host is 999.1.1.1 in the config.", "expect": {}},
    {"text": "The quick brown fox jumps over the lazy dog.", "expect": {}},
    {"text": "Trace id 550e8400e29b41d4a716446655440000 recorded.", "expect": {}},
    {"text": "Meeting moved to 2025-01-15 at 09:30 in room 214.", "expect": {}},
]


# Span-labeled corpus for the NER tier: (start, end, entity) per document.
# Count-based scoring can't tell a name from a location; span scoring can, and
# it is the only honest way to measure PERSON/LOCATION recall. Offsets are
# character positions into `text`.
def _span(text: str, needle: str, entity: str) -> tuple[int, int, str]:
    i = text.index(needle)
    return (i, i + len(needle), entity)


_NER_1 = "Please email Ada Verne in Portland about the Q3 review."
_NER_2 = "Dr. Sarah Okafor flew from Nairobi to Berlin on Tuesday."
_NER_3 = "The contract with alice@example.com covers the London office."

SPAN_CORPUS: list[dict] = [
    {"text": _NER_1, "spans": [_span(_NER_1, "Ada Verne", "PERSON"),
                               _span(_NER_1, "Portland", "LOCATION")]},
    {"text": _NER_2, "spans": [_span(_NER_2, "Sarah Okafor", "PERSON"),
                               _span(_NER_2, "Nairobi", "LOCATION"),
                               _span(_NER_2, "Berlin", "LOCATION")]},
    {"text": _NER_3, "spans": [_span(_NER_3, "alice@example.com", "EMAIL"),
                               _span(_NER_3, "London", "LOCATION")]},
]


@dataclass(frozen=True, slots=True)
class Metrics:
    tp: int
    fp: int
    fn: int

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) else 1.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) else 1.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0


def evaluate(engine, corpus=None) -> tuple[Metrics, dict[str, Metrics]]:
    """Count-based TP/FP/FN of an engine over the corpus; overall + per-entity."""
    corpus = corpus if corpus is not None else BUILTIN_CORPUS
    tp = fp = fn = 0
    per_entity: dict[str, list[int]] = {}

    for entry in corpus:
        _, report = engine.redact_text(entry["text"])
        detected = report.counts_by_entity()
        expected = entry["expect"]
        for entity in set(detected) | set(expected):
            d, g = detected.get(entity, 0), expected.get(entity, 0)
            e_tp, e_fp, e_fn = min(d, g), max(0, d - g), max(0, g - d)
            tp, fp, fn = tp + e_tp, fp + e_fp, fn + e_fn
            acc = per_entity.setdefault(entity, [0, 0, 0])
            acc[0] += e_tp
            acc[1] += e_fp
            acc[2] += e_fn

    return Metrics(tp, fp, fn), {e: Metrics(*c) for e, c in per_entity.items()}


def evaluate_spans(engine, corpus=None) -> tuple[Metrics, dict[str, Metrics]]:
    """Span-level TP/FP/FN: a detected span is a true positive when it overlaps
    a gold span of the SAME entity (one-to-one greedy match). This is the
    metric that distinguishes PERSON from LOCATION — count scoring can't.
    """
    corpus = corpus if corpus is not None else SPAN_CORPUS
    tp = fp = fn = 0
    per_entity: dict[str, list[int]] = {}

    def bump(entity: str, i: int) -> None:
        per_entity.setdefault(entity, [0, 0, 0])[i] += 1

    for entry in corpus:
        detected = engine.detect_spans(entry["text"])
        matched: set[int] = set()
        for gs, ge, gent in entry["spans"]:
            hit = next(
                (i for i, d in enumerate(detected)
                 if i not in matched and d.entity == gent
                 and d.start < ge and gs < d.end),
                None,
            )
            if hit is not None:
                matched.add(hit)
                tp += 1
                bump(gent, 0)
            else:
                fn += 1
                bump(gent, 2)
        for i, d in enumerate(detected):
            if i not in matched:
                fp += 1
                bump(d.entity, 1)

    return Metrics(tp, fp, fn), {e: Metrics(*c) for e, c in per_entity.items()}


def format_report(overall: Metrics, by_entity: dict[str, Metrics]) -> str:
    lines = [
        f"overall   precision={overall.precision:.3f}  recall={overall.recall:.3f}  "
        f"f1={overall.f1:.3f}  (tp={overall.tp} fp={overall.fp} fn={overall.fn})",
        "",
    ]
    for entity in sorted(by_entity):
        m = by_entity[entity]
        lines.append(
            f"  {entity:<20} precision={m.precision:.3f}  recall={m.recall:.3f}  "
            f"(tp={m.tp} fp={m.fp} fn={m.fn})"
        )
    return "\n".join(lines)
