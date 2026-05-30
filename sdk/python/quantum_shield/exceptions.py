"""QuantumShield SDK — typed exceptions."""
from __future__ import annotations


class QuantumShieldError(Exception):
    """Base class for all QuantumShield SDK errors."""

    def __init__(self, message: str, status_code: int | None = None, body: dict | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.body = body or {}

    def __repr__(self) -> str:
        return f"{type(self).__name__}(status={self.status_code}, message={self!s})"


class AuthenticationError(QuantumShieldError):
    """Raised when the server returns 401 Unauthorized.

    Common causes:
    - Token expired or revoked
    - Wrong bootstrap secret at /auth/token
    - Token signed by a different server instance
    """


class AuthorizationError(QuantumShieldError):
    """Raised when the server returns 403 Forbidden.

    The token is valid but the caller's role does not permit the operation.
    """


class NotFoundError(QuantumShieldError):
    """Raised when the server returns 404 Not Found (e.g. unknown key_id)."""


class ValidationError(QuantumShieldError):
    """Raised when the server returns 400 Bad Request (invalid parameters)."""


class RateLimitError(QuantumShieldError):
    """Raised when the server returns 429 Too Many Requests."""


class ServerError(QuantumShieldError):
    """Raised when the server returns 5xx."""


class CANotInitialisedError(QuantumShieldError):
    """Raised when a CA operation is attempted before POST /ca/init."""


class CertificateVerificationError(QuantumShieldError):
    """Raised when /ca/verify reports the certificate is invalid."""


class ReplayError(QuantumShieldError):
    """Raised when the server detects a ciphertext replay attack."""


def _raise_for_status(status_code: int, body: dict) -> None:
    """Map HTTP status codes to typed SDK exceptions."""
    message = body.get("error", f"HTTP {status_code}")

    if status_code == 400:
        raise ValidationError(message, status_code, body)
    if status_code == 401:
        raise AuthenticationError(message, status_code, body)
    if status_code == 403:
        raise AuthorizationError(message, status_code, body)
    if status_code == 404:
        raise NotFoundError(message, status_code, body)
    if status_code == 429:
        raise RateLimitError(message, status_code, body)
    if status_code == 503:
        raise CANotInitialisedError(message, status_code, body)
    if status_code >= 500:
        raise ServerError(message, status_code, body)
    if status_code >= 400:
        raise QuantumShieldError(message, status_code, body)
