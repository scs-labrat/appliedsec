"""OIDC token validation using PyJWT and JWKS."""

from __future__ import annotations

import json
import logging
import time
import urllib.request
from typing import Any, Optional

import jwt

from shared.auth.exceptions import (
    JWKS_FETCH_FAILED,
    TOKEN_EXPIRED,
    TOKEN_INVALID_AUDIENCE,
    TOKEN_INVALID_ISSUER,
    TOKEN_INVALID_SIGNATURE,
    TOKEN_MALFORMED,
    AuthenticationError,
)

logger = logging.getLogger(__name__)


class OIDCValidator:
    """Validates OIDC/JWT tokens using a remote JWKS endpoint."""

    def __init__(
        self,
        *,
        jwks_url: str,
        audience: Optional[str] = None,
        issuer: Optional[str] = None,
        algorithms: Optional[list[str]] = None,
        jwks_cache_ttl: int = 3600,
    ) -> None:
        self._jwks_url = jwks_url
        self._audience = audience
        self._issuer = issuer
        self._algorithms = algorithms or ["RS256"]
        self._jwks_cache_ttl = jwks_cache_ttl
        self._jwks_cache: Optional[dict[str, Any]] = None
        self._jwks_cache_time: float = 0.0

    def _fetch_jwks(self) -> dict[str, Any]:
        """Fetch JWKS from the endpoint, with caching."""
        now = time.monotonic()
        if (
            self._jwks_cache is not None
            and (now - self._jwks_cache_time) < self._jwks_cache_ttl
        ):
            return self._jwks_cache

        try:
            with urllib.request.urlopen(self._jwks_url, timeout=10) as resp:
                data = json.loads(resp.read())
            self._jwks_cache = data
            self._jwks_cache_time = now
            return data
        except Exception as exc:
            raise AuthenticationError(
                f"Failed to fetch JWKS from {self._jwks_url}: {exc}",
                error_code=JWKS_FETCH_FAILED,
                detail={"url": self._jwks_url},
            ) from exc

    def _get_signing_key(self, token: str) -> jwt.algorithms.RSAAlgorithm:
        """Extract the signing key matching the token's kid."""
        try:
            unverified_header = jwt.get_unverified_header(token)
        except jwt.DecodeError as exc:
            raise AuthenticationError(
                f"Malformed JWT header: {exc}",
                error_code=TOKEN_MALFORMED,
            ) from exc

        kid = unverified_header.get("kid")
        jwks_data = self._fetch_jwks()

        for key_data in jwks_data.get("keys", []):
            if key_data.get("kid") == kid:
                return jwt.algorithms.RSAAlgorithm.from_jwk(key_data)

        # Cache miss on kid — force refetch once
        self._jwks_cache = None
        jwks_data = self._fetch_jwks()
        for key_data in jwks_data.get("keys", []):
            if key_data.get("kid") == kid:
                return jwt.algorithms.RSAAlgorithm.from_jwk(key_data)

        raise AuthenticationError(
            f"No key found for kid={kid}",
            error_code=TOKEN_INVALID_SIGNATURE,
            detail={"kid": kid},
        )

    def validate_token(self, token: str) -> dict[str, Any]:
        """Decode and validate a JWT token. Returns the claims dict."""
        key = self._get_signing_key(token)

        options: dict[str, Any] = {}
        if self._audience is None:
            options["verify_aud"] = False

        try:
            claims = jwt.decode(
                token,
                key=key,
                algorithms=self._algorithms,
                audience=self._audience,
                issuer=self._issuer,
                options=options,
            )
            return claims
        except jwt.ExpiredSignatureError as exc:
            raise AuthenticationError(
                "Token has expired",
                error_code=TOKEN_EXPIRED,
            ) from exc
        except jwt.InvalidSignatureError as exc:
            raise AuthenticationError(
                "Token has invalid signature",
                error_code=TOKEN_INVALID_SIGNATURE,
            ) from exc
        except jwt.InvalidAudienceError as exc:
            raise AuthenticationError(
                "Token has invalid audience",
                error_code=TOKEN_INVALID_AUDIENCE,
            ) from exc
        except jwt.InvalidIssuerError as exc:
            raise AuthenticationError(
                "Token has invalid issuer",
                error_code=TOKEN_INVALID_ISSUER,
            ) from exc
        except jwt.DecodeError as exc:
            raise AuthenticationError(
                f"Token is malformed: {exc}",
                error_code=TOKEN_MALFORMED,
            ) from exc


def validate_oidc_token(
    token: str,
    *,
    jwks_url: str,
    audience: Optional[str] = None,
    issuer: Optional[str] = None,
) -> dict[str, Any]:
    """Convenience function — creates a one-shot OIDCValidator."""
    validator = OIDCValidator(
        jwks_url=jwks_url, audience=audience, issuer=issuer
    )
    return validator.validate_token(token)
