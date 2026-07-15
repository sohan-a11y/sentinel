class PhaseZeroError(Exception):
    """Base class for every Phase 0 (authorization/environment gate) failure."""


class OwnershipVerificationFailedError(PhaseZeroError):
    """Neither the well-known token file nor the DNS TXT record was found."""


class DomainAlreadyRegisteredError(PhaseZeroError):
    pass


class TargetNotRegisteredError(PhaseZeroError):
    pass
