"""Detectors: validators must reject look-alikes and catch real identifiers."""

import pytest

from mcp_gateway.redaction import entities
from mcp_gateway.redaction.detectors.base import DetectionContext
from mcp_gateway.redaction.detectors.regex_pii import RegexPiiDetector
from mcp_gateway.redaction.detectors.secrets import SecretsDetector
from mcp_gateway.redaction.detectors.validators import (
    ipv4_octets_valid,
    luhn_valid,
    shannon_entropy,
    ssn_valid,
)

PII = RegexPiiDetector()
SECRETS = SecretsDetector()
CTX = DetectionContext()


def found_entities(detector, text):
    return {s.entity for s in detector.detect(text, CTX)}


# ------------------------------------------------------------- validators
def test_luhn():
    assert luhn_valid("4111111111111111")       # Visa test number
    assert not luhn_valid("4111111111111112")   # one digit off
    assert not luhn_valid("1234567890123")       # arbitrary


def test_ssn_rules():
    assert ssn_valid(123, 45, 6789)
    assert not ssn_valid(0, 45, 6789)     # area 000 never issued
    assert not ssn_valid(666, 45, 6789)   # area 666 never issued
    assert not ssn_valid(900, 45, 6789)   # area 900+ never issued
    assert not ssn_valid(123, 0, 6789)    # group 00
    assert not ssn_valid(123, 45, 0)      # serial 0000


def test_ipv4_octets():
    assert ipv4_octets_valid(["192", "168", "1", "1"])
    assert not ipv4_octets_valid(["256", "1", "1", "1"])   # > 255
    assert not ipv4_octets_valid(["1", "1", "1"])          # too few
    assert not ipv4_octets_valid(["01", "1", "1", "1"])    # leading zero


def test_entropy():
    assert shannon_entropy("aaaaaaaa") == 0.0
    assert shannon_entropy("abababab") == 1.0            # two symbols, uniform
    assert abs(shannon_entropy("0123456789abcdef" * 2) - 4.0) < 1e-9  # 16 uniform


# ---------------------------------------------------------------- PII tier
def test_pii_catches_validated_identifiers():
    assert found_entities(PII, "email alice@example.com here") == {entities.EMAIL}
    assert found_entities(PII, "ssn 123-45-6789") == {entities.SSN}
    assert found_entities(PII, "card 4111 1111 1111 1111") == {entities.CREDIT_CARD}
    assert found_entities(PII, "ip 10.0.0.5 up") == {entities.IP_ADDRESS}
    assert found_entities(PII, "call (415) 555-0142") == {entities.PHONE}


def test_pii_rejects_lookalikes():
    # An invalid-Luhn 16-digit run (order number) is NOT a card.
    assert entities.CREDIT_CARD not in found_entities(PII, "order 4111111111111112")
    # A never-issued SSN area is NOT an SSN.
    assert entities.SSN not in found_entities(PII, "ref 666-45-6789")
    # Octet out of range is NOT an IP.
    assert entities.IP_ADDRESS not in found_entities(PII, "build 999.1.1.1")


def test_pii_confidence_ordering():
    # Validated entities outrank phone, which the engine relies on.
    ssn = PII.detect("123-45-6789", CTX)[0]
    phone = PII.detect("(415) 555-0142", CTX)[0]
    assert ssn.confidence > phone.confidence


def test_allowlist_suppresses_a_known_value():
    ctx = DetectionContext(allowlist=frozenset({"alice@example.com"}))
    assert PII.detect("mail alice@example.com", ctx) == []


# ------------------------------------------------------------ secrets tier
def test_secrets_provider_tokens():
    assert found_entities(SECRETS, "key AKIAIOSFODNN7EXAMPLE") == {
        entities.AWS_ACCESS_KEY_ID
    }
    ghp = "ghp_0123456789abcdefghijklmnopqrstuvwxyz"
    assert found_entities(SECRETS, f"token {ghp}") == {entities.GITHUB_TOKEN}
    assert found_entities(SECRETS, "slack xoxb-123456789012-abcdefGHIJKL") == {
        entities.SLACK_TOKEN
    }
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.abcDEF123456_-xyz"
    assert found_entities(SECRETS, f"auth {jwt}") == {entities.JWT}


def test_secrets_private_key_block():
    block = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX\n"
        "-----END RSA PRIVATE KEY-----"
    )
    assert entities.PRIVATE_KEY in found_entities(SECRETS, block)


def test_secrets_high_entropy_heuristic():
    # A 32-char, entropy-4.0 token is flagged as a generic secret...
    assert entities.GENERIC_SECRET in found_entities(
        SECRETS, "value 0123456789abcdef0123456789abcdef end"
    )
    # ...but a low-entropy long run is not.
    assert entities.GENERIC_SECRET not in found_entities(
        SECRETS, "value aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa end"
    )


def test_high_entropy_can_be_disabled():
    quiet = SecretsDetector(include_high_entropy=False)
    assert quiet.detect("0123456789abcdef0123456789abcdef", CTX) == []


def test_entropy_does_not_double_claim_provider_token():
    # A GitHub token is long enough to also match the entropy candidate; it
    # must be claimed once, as GITHUB_TOKEN, not also as GENERIC_SECRET.
    ghp = "ghp_0123456789abcdefghijklmnopqrstuvwxyz"
    entities_found = [s.entity for s in SECRETS.detect(ghp, CTX)]
    assert entities_found == [entities.GITHUB_TOKEN]


# ------------------------------------------------- AWS secret access keys
# Regression guard: AWS_SECRET_ACCESS_KEY was a registered entity that NO detector
# emitted, and the high-entropy net that might have caught it sits below the
# default profile's confidence floor — so an AWS secret key passed through the
# `standard` profile unredacted. Found by the GitHub-pack e2e (a .env read).
AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"


@pytest.mark.parametrize("line", [
    f"AWS_SECRET_ACCESS_KEY={AWS_SECRET}",
    f"aws_secret_access_key = {AWS_SECRET}",
    f'"awsSecretAccessKey": "{AWS_SECRET}"',
    f"secret_access_key: {AWS_SECRET}",
])
def test_aws_secret_access_key_is_detected(line):
    spans = [s for s in SECRETS.detect(line, CTX)
             if s.entity == entities.AWS_SECRET_ACCESS_KEY]
    assert spans, f"missed the AWS secret key in: {line}"
    # Only the VALUE is claimed — the label stays readable.
    assert spans[0].text == AWS_SECRET


def test_aws_secret_key_needs_its_label():
    # 40 base64 chars with no AWS-ish label must NOT be called an AWS secret key:
    # that shape is also every base64 hash, and mislabeling would be a lie.
    assert entities.AWS_SECRET_ACCESS_KEY not in found_entities(
        SECRETS, f"checksum {AWS_SECRET}"
    )


def test_aws_secret_survives_the_default_profile():
    """The actual bug: end-to-end through the DEFAULT profile, not just the detector."""
    from mcp_gateway.redaction import build_engine

    out, _ = build_engine("standard").redact_text(f"AWS_SECRET_ACCESS_KEY={AWS_SECRET}")
    assert AWS_SECRET not in out


# ------------------------------------------------------- labeled secrets
def test_labeled_secret_in_text_is_detected():
    # `hunter2` is shapeless — only the key name reveals it. structured.py does
    # this for dict keys; this is the text path (MCP results are JSON-in-text).
    spans = [s for s in SECRETS.detect("DB_PASSWORD=hunter2-not-a-pattern", CTX)
             if s.entity == entities.SENSITIVE_FIELD]
    assert spans and spans[0].text == "hunter2-not-a-pattern"


@pytest.mark.parametrize("line,expected", [
    ("password: s3cr3t-value", True),
    ('"client_secret": "abc12345"', True),
    ("api_key=abcd1234efgh", True),
    ("passphrase = correct-horse", True),
    # Vocabulary shared with structured.py, so its careful non-matches hold:
    ("token_count: 4096", False),        # an LLM field, not a credential
    ("authorized_users: alice", False),  # contains "auth", not as a token
    ("file_path: /vault/records", False),
])
def test_labeled_secret_vocabulary_matches_structured_pass(line, expected):
    hit = entities.SENSITIVE_FIELD in found_entities(SECRETS, line)
    assert hit is expected, line


def test_labeled_detection_can_be_disabled():
    quiet = SecretsDetector(include_high_entropy=False, include_labeled=False)
    assert quiet.detect("DB_PASSWORD=hunter2-not-a-pattern", CTX) == []


def test_entropy_candidate_does_not_swallow_the_label():
    # The candidate regex used to match `LABEL=<secret>` as one run, so the
    # reported span covered the label too. It must start at the value.
    secret = "0123456789abcdef0123456789abcdef"
    spans = [s for s in SECRETS.detect(f"OPAQUE_BLOB={secret}", CTX)
             if s.entity == entities.GENERIC_SECRET]
    assert spans and spans[0].text == secret
