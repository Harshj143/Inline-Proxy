"""Turn verified token claims into a `Principal` the policy engine understands.

A validated JWT proves *who* the caller is and *what groups* the IdP puts them
in. The policy engine speaks a different vocabulary — `roles` like `reviewer` or
`release-manager` that a pack's `roles.yaml` overlays. This module is the
translation, driven entirely by config (`identity.yaml`) so which IdP group maps
to which gateway role is an operator decision, never code.

Two deliberate choices:

  * **Group→role order is the config's order, and the engine uses the first
    role.** A user can be in several mapped groups; the policy engine evaluates a
    single role (`principal.roles[0]`). So the mapping preserves the order the
    operator wrote the groups in — the most-privileged group listed first — which
    makes "admin beats reviewer when someone is both" a legible line in the
    config rather than emergent behavior.

  * **No group match is not an error; no identity IS.** A validated token whose
    groups map to nothing falls back to `default_role` when one is configured
    (a sensible least-privilege floor), or to no role at all — which under a
    default-deny pack means the caller can do only what the base policy permits.
    But a token with no usable subject claim fails closed: an unnamed principal
    can't be audited, and an unauditable call is one we don't make.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from mcp_gateway.core.context import Principal
from mcp_gateway.core.errors import IdentityError


@dataclass(frozen=True, slots=True)
class RoleMapping:
    """How token claims become a principal's id and roles."""

    subject_claim: str = "sub"
    groups_claim: str = "groups"
    # Ordered {group: role}; a user in several mapped groups gets all their roles
    # in this order (the engine uses the first).
    groups: dict[str, str] = field(default_factory=dict)
    default_role: str | None = None

    def to_principal(self, claims: dict[str, Any]) -> Principal:
        subject = claims.get(self.subject_claim)
        if not subject or not isinstance(subject, str):
            raise IdentityError(
                f"token has no usable {self.subject_claim!r} claim to name the "
                f"principal — refusing an anonymous caller"
            )

        raw_groups = claims.get(self.groups_claim, [])
        if isinstance(raw_groups, str):
            raw_groups = [raw_groups]          # some IdPs emit a single group as a string
        member = {g for g in raw_groups if isinstance(g, str)}

        # Preserve config order (most-privileged first), de-duplicated.
        roles: list[str] = []
        for group, role in self.groups.items():
            if group in member and role not in roles:
                roles.append(role)
        if not roles and self.default_role:
            roles.append(self.default_role)

        return Principal(id=subject, roles=tuple(roles))
