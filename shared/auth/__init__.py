"""ALUSKORT authentication utilities."""

from shared.auth.exceptions import (
    JWKS_FETCH_FAILED,
    MTLS_CA_NOT_FOUND,
    MTLS_INVALID_CERT,
    MTLS_INVALID_KEY,
    TOKEN_EXPIRED,
    TOKEN_INVALID_AUDIENCE,
    TOKEN_INVALID_ISSUER,
    TOKEN_INVALID_SIGNATURE,
    TOKEN_MALFORMED,
    AuthenticationError,
)
from shared.auth.mtls import create_mtls_context
from shared.auth.oidc import OIDCValidator, validate_oidc_token

__all__ = [
    "AuthenticationError",
    "JWKS_FETCH_FAILED",
    "MTLS_CA_NOT_FOUND",
    "MTLS_INVALID_CERT",
    "MTLS_INVALID_KEY",
    "OIDCValidator",
    "TOKEN_EXPIRED",
    "TOKEN_INVALID_AUDIENCE",
    "TOKEN_INVALID_ISSUER",
    "TOKEN_INVALID_SIGNATURE",
    "TOKEN_MALFORMED",
    "create_mtls_context",
    "validate_oidc_token",
]
