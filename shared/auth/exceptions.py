"""Authentication error types for ALUSKORT services."""

from __future__ import annotations

from typing import Any, Optional

# Error code constants
TOKEN_EXPIRED = "TOKEN_EXPIRED"
TOKEN_INVALID_SIGNATURE = "TOKEN_INVALID_SIGNATURE"
TOKEN_INVALID_AUDIENCE = "TOKEN_INVALID_AUDIENCE"
TOKEN_INVALID_ISSUER = "TOKEN_INVALID_ISSUER"
TOKEN_MALFORMED = "TOKEN_MALFORMED"
JWKS_FETCH_FAILED = "JWKS_FETCH_FAILED"
MTLS_INVALID_CERT = "MTLS_INVALID_CERT"
MTLS_INVALID_KEY = "MTLS_INVALID_KEY"
MTLS_CA_NOT_FOUND = "MTLS_CA_NOT_FOUND"


class AuthenticationError(Exception):
    """Raised on any authentication failure."""

    def __init__(
        self,
        message: str,
        error_code: str,
        detail: Optional[dict[str, Any]] = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        self.detail = detail or {}
