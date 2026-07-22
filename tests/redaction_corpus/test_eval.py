"""Gate the redaction engine's accuracy in CI.

These thresholds are the Phase 2 exit criteria made executable: if a detector
change regresses recall (misses real PII) or precision (redacts junk), the
build fails. Printed metrics show up in CI logs for the "how good is it?"
answer. The corpus and harness ship in the package (mcp_gateway.redaction.eval)
so `mcp-gateway redact --eval` prints the same numbers.
"""

from mcp_gateway.redaction import build_engine
from mcp_gateway.redaction.eval import BUILTIN_CORPUS, evaluate, format_report


def test_standard_profile_meets_accuracy_bar():
    overall, by_entity = evaluate(build_engine("standard"))
    print("\n" + format_report(overall, by_entity))

    # Recall: catching the sensitive data is safety-critical — a miss is a leak.
    assert overall.recall >= 0.95, "redaction missed sensitive data"
    # Precision: the validated detectors keep this high despite look-alikes.
    assert overall.precision >= 0.90, "redaction over-redacted clean content"


def test_no_false_positives_on_negative_documents():
    engine = build_engine("standard")
    for entry in (e for e in BUILTIN_CORPUS if not e["expect"]):
        _, report = engine.redact_text(entry["text"])
        assert report.total == 0, (
            f"false positive on negative doc: {entry['text']!r} -> "
            f"{report.counts_by_entity()}"
        )
