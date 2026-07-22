"""Custom recognizers: config validation, detection, service integration."""

import pytest

from mcp_gateway.redaction import entities
from mcp_gateway.redaction.detectors.base import DetectionContext
from mcp_gateway.redaction.detectors.custom import (
    CustomDetector,
    load_recognizers,
)
from mcp_gateway.redaction.service import RedactionService
from mcp_gateway.redaction.spec import RedactionSpec

EMP_CONFIG = [{"entity": "EMPLOYEE_ID", "pattern": r"\bEMP-\d{5}\b", "confidence": 0.95}]


def test_load_and_detect():
    recognizers = load_recognizers(EMP_CONFIG)
    det = CustomDetector(recognizers)
    spans = det.detect("ticket from EMP-48213 about laptop", DetectionContext())
    assert len(spans) == 1
    assert spans[0].entity == "EMPLOYEE_ID"
    assert spans[0].text == "EMP-48213"
    # The entity is registered in the CUSTOM category for reports/audit.
    assert entities.get("EMPLOYEE_ID").category is entities.Category.CUSTOM


def test_custom_recognizer_honors_allowlist():
    det = CustomDetector(load_recognizers(EMP_CONFIG))
    ctx = DetectionContext(allowlist=frozenset({"EMP-00000"}))
    assert det.detect("test account EMP-00000", ctx) == []


def test_invalid_configs_rejected():
    with pytest.raises(ValueError, match="'entity'"):
        load_recognizers([{"pattern": "x"}])
    with pytest.raises(ValueError, match="invalid regex"):
        load_recognizers([{"entity": "X", "pattern": "("}])
    with pytest.raises(ValueError, match="unknown field"):
        load_recognizers([{"entity": "X", "pattern": "y", "bogus": 1}])
    with pytest.raises(ValueError, match="confidence"):
        load_recognizers([{"entity": "X", "pattern": "y", "confidence": 2}])


def test_service_applies_custom_recognizers():
    svc = RedactionService(recognizers=load_recognizers(EMP_CONFIG))
    out, report = svc.redact({"note": "assigned to EMP-48213"},
                             RedactionSpec("standard"))
    assert out["note"] == "assigned to [REDACTED:EMPLOYEE_ID]"
    assert report.counts_by_entity()["EMPLOYEE_ID"] == 1
