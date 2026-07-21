"""Exception hierarchy for the gateway.

Every error the gateway raises derives from GatewayError so callers (CLI,
tests, embedding applications) can catch one type. Enforcement-path code
must never let an unexpected exception escape as an *allow* — failure on
the enforcement path is always resolved in the closed (deny) direction.
"""


class GatewayError(Exception):
    """Base class for all gateway errors."""


class PolicyError(GatewayError):
    """The policy document is invalid and must not be enforced.

    Raised at load time only: a gateway refuses to start (or to reload)
    on a bad policy rather than guessing at intent.
    """


class TransportError(GatewayError):
    """The transport failed in a way that ends the session."""
