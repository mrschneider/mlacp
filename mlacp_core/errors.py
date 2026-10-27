"""MLACP typed refusals — layer vocabulary shared by every layer.

Two families, mirroring the doctrine that a field grid either *refuses a
transmission on stated grounds* (business refusal) or *reports a channel
failure and may be retried* (infrastructure failure).
"""

from __future__ import annotations


class MlacpError(Exception):
    """Base of every MLACP refusal."""


class BusinessRefusal(MlacpError):
    """Permanent, in-protocol refusal. Never retry as-is."""


class InfrastructureFailure(MlacpError):
    """Channel-level failure. ``retryable`` says whether a resend may help."""

    def __init__(self, code: str, message: str, retryable: bool):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message
        self.retryable = retryable


# --- business refusals ------------------------------------------------------

class UnknownKind(BusinessRefusal):
    """A wire kind outside the closed vocabulary. The refusal names the word
    the peer sent and the legal set — that refusal IS the feature."""


class UnknownService(BusinessRefusal):
    def __init__(self, urn: str):
        super().__init__(f"no service registered under '{urn}'")
        self.urn = urn


class BadAddress(BusinessRefusal):
    pass


class DuplicateName(BusinessRefusal):
    def __init__(self, urn: str):
        super().__init__(f"'{urn}' is already registered in this directory")


class NotPermitted(BusinessRefusal):
    """The capability chain of custody does not authorize the operation."""


class DelegationEscalation(BusinessRefusal):
    """A delegation tried to carry an authority its parent does not have."""


class QuotaExceeded(BusinessRefusal):
    """Per-organization accounting refused the message (Akademset rateo)."""


class HopsExhausted(BusinessRefusal):
    pass


class VersionMismatch(BusinessRefusal):
    """A different major version is refused; a different minor is additive."""


# --- infrastructure failures ------------------------------------------------

def malformed(reason: str) -> InfrastructureFailure:
    return InfrastructureFailure("malformed_frame", reason, False)


def unavailable(what: str) -> InfrastructureFailure:
    return InfrastructureFailure("unavailable", what, True)


def timeout(what: str) -> InfrastructureFailure:
    return InfrastructureFailure("timeout", what, True)


def mac_failure() -> InfrastructureFailure:
    return InfrastructureFailure("mac_verification_failed",
                                 "frame altered in transit", False)
