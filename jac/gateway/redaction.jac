"""Deterministic PII and secret redaction with counts-only reporting.

Matches are replaced from right to left so offsets remain stable. The cleaned
text is returned to the transport; audit receives only aggregate entity counts.
"""

import re;
import hashlib;
import from gateway.context { RedactionReport }

obj Detector {
    has label: str,
        pattern: str,
        category: str,
        confidence: float,
        operator: str = "mask";
}

def _detectors -> list[Detector] {
    return [
        Detector(
            label="EMAIL",
            category="PII",
            confidence=0.9,
            operator="mask",
            pattern=r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
        ),
        Detector(
            label="US_SSN",
            category="PII",
            confidence=0.85,
            operator="partial",
            pattern=r"\b\d{3}-\d{2}-\d{4}\b"
        ),
        Detector(
            label="PHONE",
            category="PII",
            confidence=0.6,
            operator="partial",
            pattern=r"(?<![A-Za-z0-9])\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}(?![A-Za-z0-9])"
        ),
        Detector(
            label="AWS_ACCESS_KEY_ID",
            category="SECRET",
            confidence=0.9,
            operator="mask",
            pattern=r"AKIA[0-9A-Z]{16}"
        ),
        Detector(
            label="AWS_SECRET_ACCESS_KEY",
            category="SECRET",
            confidence=0.95,
            operator="mask",
            pattern=r"(?i)aws_secret_access_key['\"]?\s*[=:]\s*['\"]?[A-Za-z0-9/+]{40}"
        ),
        Detector(
            label="GITHUB_PAT",
            category="SECRET",
            confidence=0.95,
            operator="mask",
            pattern=r"gh[pousr]_[A-Za-z0-9]{36,}"
        ),
        Detector(
            label="GITHUB_PAT",
            category="SECRET",
            confidence=0.95,
            operator="mask",
            pattern=r"github_pat_[A-Za-z0-9_]{50,}"
        ),
        Detector(
            label="SLACK_TOKEN",
            category="SECRET",
            confidence=0.95,
            operator="mask",
            pattern=r"xox[baprs]-[A-Za-z0-9-]{20,}"
        ),
        Detector(
            label="JWT",
            category="SECRET",
            confidence=0.9,
            operator="mask",
            pattern=r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"
        ),
        Detector(
            label="LABELED_SECRET",
            category="SECRET",
            confidence=0.8,
            operator="labeled",
            pattern=r"(?i)(password|passwd|api_key|apikey|secret|token)\s*[=:]\s*['\"]?[^\s'\"\\]{3,}"
        )
    ];
}

def _profile_detectors(profile: str) -> list[Detector] {
    detectors = _detectors();
    if profile == "secrets" {
        return [
            detector
            for detector in detectors
            if detector.category == "SECRET"
        ];
    }
    if profile == "strict" {
        return detectors;
    }
    return [
        detector
        for detector in detectors
        if detector.confidence >= 0.6
    ];
}

def _operate(operator: str, found: any, label: str) -> str {
    value = found.group(0) as str;
    if operator == "partial" {
        return ("****" + value[-4:]) if len(value) > 4 else "****";
    }
    if operator == "hash" {
        return label + "_" + hashlib.blake2b(value.encode(), digest_size=4).hexdigest();
    }
    if operator == "labeled" {
        key = found.group(1) as str;
        return key + "=[REDACTED]";
    }
    return "[REDACTED_" + label + "]";
}

def redact_text(text: str, profile: str) -> RedactionReport {
    outcome = RedactionReport();
    scrubbed = text;
    for detector in _profile_detectors(profile) {
        matches = list(re.finditer(detector.pattern, scrubbed));
        for found in reversed(matches) {
            replacement = _operate(detector.operator, found, detector.label);
            scrubbed = scrubbed[:found.start()] + replacement + scrubbed[found.end():];
            outcome.total += 1;
            outcome.entity_counts[detector.label] = (
                outcome.entity_counts.get(detector.label, 0) + 1
            );
        }
    }
    outcome.scrubbed = scrubbed;
    return outcome;
}
