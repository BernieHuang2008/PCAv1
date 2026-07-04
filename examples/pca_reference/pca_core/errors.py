class PCAError(Exception):
    """Base class for PCA reference implementation errors."""


class PCAValidationError(PCAError, ValueError):
    """Raised when user supplied data violates PCA encoding or naming rules."""


class PCAAuthenticationError(PCAError):
    """Raised when authenticated data or a digital signature fails verification."""


class PCARevokedNamespaceError(PCAError):
    """Raised when a verified revocation statement revokes the active namespace."""

