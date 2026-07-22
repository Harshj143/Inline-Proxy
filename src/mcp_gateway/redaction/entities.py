"""The entity registry.

Entity NAMES are the stable public interface of the redaction subsystem:
policies, profiles, and audit events all speak these names, never a detector
library's internal type names (so Presidio, custom recognizers, and our regex
tier can all contribute the same "EMAIL" without the policy caring which found
it). Categories let a profile say "all SECRETs" without enumerating them.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class Category(StrEnum):
    PII = "pii"          # identifies a person: email, phone, SSN, card, IP
    SECRET = "secret"    # a credential: API key, token, private key
    CUSTOM = "custom"    # company-defined (employee id, internal hostname) — Phase 2c


@dataclass(frozen=True, slots=True)
class Entity:
    name: str
    category: Category
    description: str


_REGISTRY: dict[str, Entity] = {}


def register(name: str, category: Category, description: str) -> str:
    _REGISTRY[name] = Entity(name=name, category=category, description=description)
    return name


def get(name: str) -> Entity | None:
    return _REGISTRY.get(name)


def names_in(category: Category) -> frozenset[str]:
    return frozenset(n for n, e in _REGISTRY.items() if e.category is category)


def all_names() -> frozenset[str]:
    return frozenset(_REGISTRY)


# ---- PII (structured; regex + validators) ----
EMAIL = register("EMAIL", Category.PII, "Email address")
PHONE = register("PHONE", Category.PII, "Telephone number")
SSN = register("SSN", Category.PII, "US Social Security Number")
CREDIT_CARD = register("CREDIT_CARD", Category.PII, "Payment card number (Luhn-valid)")
IP_ADDRESS = register("IP_ADDRESS", Category.PII, "IPv4 address")

# ---- PII (unstructured; NER, the Presidio tier) ----
PERSON = register("PERSON", Category.PII, "Person name (NER)")
LOCATION = register("LOCATION", Category.PII, "Geographic location (NER)")
NRP = register("NRP", Category.PII, "Nationality, religion, or political group (NER)")

# ---- Secrets ----
AWS_ACCESS_KEY_ID = register("AWS_ACCESS_KEY_ID", Category.SECRET, "AWS access key id")
AWS_SECRET_ACCESS_KEY = register(
    "AWS_SECRET_ACCESS_KEY", Category.SECRET, "AWS secret access key"
)
GITHUB_TOKEN = register("GITHUB_TOKEN", Category.SECRET, "GitHub personal/OAuth token")
SLACK_TOKEN = register("SLACK_TOKEN", Category.SECRET, "Slack API token")
JWT = register("JWT", Category.SECRET, "JSON Web Token")
PRIVATE_KEY = register("PRIVATE_KEY", Category.SECRET, "PEM private key block")
GENERIC_SECRET = register(
    "GENERIC_SECRET", Category.SECRET, "High-entropy token (heuristic)"
)
SENSITIVE_FIELD = register(
    "SENSITIVE_FIELD", Category.SECRET,
    "Value under a key whose NAME marks it sensitive (password, api_key, ...)",
)

# ---- Custom ----
CUSTOM_TERM = register(
    "CUSTOM_TERM", Category.CUSTOM, "Literal term from a deployment's denylist"
)
