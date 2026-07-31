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


class ConnectorError(GatewayError):
    """A connector pack is missing, malformed, or references an unknown name.

    Raised at load/resolve time only, like PolicyError: the gateway refuses to
    bind an ill-formed connector rather than guessing at its security intent.
    """


class IdentityError(GatewayError):
    """A caller could not be authenticated, or identity is misconfigured.

    Covers both a bad request-time credential (missing/expired/forged token, an
    unknown API key) and a bad startup config (unparseable identity.yaml, no
    crypto support). Either way the resolution failed, so — like every other
    failure on the enforcement path — it is resolved closed: the call is refused,
    never admitted as an anonymous or default principal.
    """
