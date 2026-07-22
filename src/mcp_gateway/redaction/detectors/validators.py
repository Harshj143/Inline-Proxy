"""Structural validators that turn pattern matches into high-confidence hits.

A regex that matches "any 16 digits" flags order numbers, tracking codes, and
timestamps as credit cards. The industry-standard fix is to validate the
structure a real identifier must satisfy — a checksum or a range rule — and
only then claim high confidence. These validators are why the regex tier can
be trusted enough to redact on: a Luhn-valid 16-digit run is almost certainly
a card; an arbitrary one is almost certainly not.
"""

from __future__ import annotations


def luhn_valid(number: str) -> bool:
    """The Luhn (mod-10) checksum used by all major payment cards."""
    digits = [int(c) for c in number if c.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    checksum = 0
    # Double every second digit counting from the right.
    parity = len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def ssn_valid(area: int, group: int, serial: int) -> bool:
    """US SSN structural rules (never-issued ranges are not real SSNs).

    area 000, 666, and 900-999 were never assigned; group and serial are
    never all-zero. This rejects the bulk of formatting-lookalikes such as
    dates and phone fragments.
    """
    if area == 0 or area == 666 or area >= 900:
        return False
    return group != 0 and serial != 0


def ipv4_octets_valid(octets: list[str]) -> bool:
    """Each of the four parts must be 0-255 with no leading-zero ambiguity."""
    if len(octets) != 4:
        return False
    for part in octets:
        if not part.isdigit() or (len(part) > 1 and part[0] == "0"):
            return False
        if int(part) > 255:
            return False
    return True


def shannon_entropy(text: str) -> float:
    """Bits of entropy per character — the classic high-entropy-secret signal.

    Random tokens (keys, hashes) sit around 4.5-6.0 bits/char; English prose
    and identifiers sit lower. Used only to give GENERIC_SECRET a modest
    confidence, never a decisive one.
    """
    if not text:
        return 0.0
    from collections import Counter
    from math import log2

    counts = Counter(text)
    n = len(text)
    return -sum((c / n) * log2(c / n) for c in counts.values())
