"""Tests for OIDCValidator — AC-1.6.1 through AC-1.6.5."""

from __future__ import annotations

import json
import time
from unittest.mock import MagicMock, patch

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from shared.auth.exceptions import (
    TOKEN_EXPIRED,
    TOKEN_INVALID_AUDIENCE,
    TOKEN_INVALID_SIGNATURE,
    TOKEN_MALFORMED,
    AuthenticationError,
)
from shared.auth.oidc import OIDCValidator


# --- Test RSA key fixtures ---

@pytest.fixture(scope="module")
def rsa_keypair():
    """Generate a test RSA key pair."""
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048
    )
    public_key = private_key.public_key()
    return private_key, public_key


@pytest.fixture(scope="module")
def wrong_keypair():
    """Generate a different RSA key pair (for wrong-key tests)."""
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048
    )
    return private_key, private_key.public_key()


@pytest.fixture
def jwks_data(rsa_keypair):
    """JWKS response containing the test public key."""
    _, pub = rsa_keypair
    pub_numbers = pub.public_numbers()
    import base64

    def _int_to_base64(n: int) -> str:
        byte_len = (n.bit_length() + 7) // 8
        return base64.urlsafe_b64encode(
            n.to_bytes(byte_len, byteorder="big")
        ).rstrip(b"=").decode()

    return {
        "keys": [
            {
                "kty": "RSA",
                "kid": "test-kid-1",
                "use": "sig",
                "alg": "RS256",
                "n": _int_to_base64(pub_numbers.n),
                "e": _int_to_base64(pub_numbers.e),
            }
        ]
    }


def _make_token(
    private_key,
    kid: str = "test-kid-1",
    exp_offset: int = 3600,
    audience: str = "aluskort",
    issuer: str = "https://auth.example.com",
    sub: str = "user-1",
) -> str:
    """Create a signed JWT."""
    now = int(time.time())
    claims = {
        "sub": sub,
        "iss": issuer,
        "aud": audience,
        "exp": now + exp_offset,
        "iat": now,
    }
    return jwt.encode(
        claims,
        private_key,
        algorithm="RS256",
        headers={"kid": kid},
    )


def _mock_urlopen(jwks_data: dict):
    """Mock urllib.request.urlopen to return JWKS JSON."""
    mock_resp = MagicMock()
    mock_resp.__enter__ = MagicMock(return_value=mock_resp)
    mock_resp.__exit__ = MagicMock(return_value=False)
    mock_resp.read = MagicMock(return_value=json.dumps(jwks_data).encode())
    return mock_resp


class TestValidToken:
    """AC-1.6.1: Valid token returns claims."""

    def test_valid_token(self, rsa_keypair, jwks_data):
        priv, _ = rsa_keypair
        token = _make_token(priv, audience="aluskort")

        validator = OIDCValidator(
            jwks_url="https://auth.example.com/.well-known/jwks.json",
            audience="aluskort",
            issuer="https://auth.example.com",
        )

        with patch("shared.auth.oidc.urllib.request.urlopen", return_value=_mock_urlopen(jwks_data)):
            claims = validator.validate_token(token)

        assert claims["sub"] == "user-1"
        assert claims["iss"] == "https://auth.example.com"
        assert claims["aud"] == "aluskort"
        assert "exp" in claims


class TestExpiredToken:
    """AC-1.6.2: Expired token raises AuthenticationError."""

    def test_expired_token(self, rsa_keypair, jwks_data):
        priv, _ = rsa_keypair
        token = _make_token(priv, exp_offset=-3600)  # 1 hour ago

        validator = OIDCValidator(
            jwks_url="https://auth.example.com/.well-known/jwks.json",
        )

        with patch("shared.auth.oidc.urllib.request.urlopen", return_value=_mock_urlopen(jwks_data)):
            with pytest.raises(AuthenticationError) as exc_info:
                validator.validate_token(token)

        assert exc_info.value.error_code == TOKEN_EXPIRED
        assert "expired" in exc_info.value.message.lower()


class TestInvalidSignature:
    """AC-1.6.3: Wrong key raises AuthenticationError."""

    def test_wrong_key(self, wrong_keypair, jwks_data):
        wrong_priv, _ = wrong_keypair
        token = _make_token(wrong_priv, kid="test-kid-1")

        validator = OIDCValidator(
            jwks_url="https://auth.example.com/.well-known/jwks.json",
        )

        with patch("shared.auth.oidc.urllib.request.urlopen", return_value=_mock_urlopen(jwks_data)):
            with pytest.raises(AuthenticationError) as exc_info:
                validator.validate_token(token)

        assert exc_info.value.error_code == TOKEN_INVALID_SIGNATURE
        assert "signature" in exc_info.value.message.lower()


class TestWrongAudience:
    """AC-1.6.4: Wrong audience raises AuthenticationError."""

    def test_wrong_audience(self, rsa_keypair, jwks_data):
        priv, _ = rsa_keypair
        token = _make_token(priv, audience="wrong-app")

        validator = OIDCValidator(
            jwks_url="https://auth.example.com/.well-known/jwks.json",
            audience="aluskort",
        )

        with patch("shared.auth.oidc.urllib.request.urlopen", return_value=_mock_urlopen(jwks_data)):
            with pytest.raises(AuthenticationError) as exc_info:
                validator.validate_token(token)

        assert exc_info.value.error_code == TOKEN_INVALID_AUDIENCE
        assert "audience" in exc_info.value.message.lower()


class TestJWKSCaching:
    """AC-1.6.5: JWKS keys are cached."""

    def test_second_call_uses_cache(self, rsa_keypair, jwks_data):
        priv, _ = rsa_keypair
        validator = OIDCValidator(
            jwks_url="https://auth.example.com/.well-known/jwks.json",
            jwks_cache_ttl=3600,
        )

        mock = MagicMock(return_value=_mock_urlopen(jwks_data))
        with patch("shared.auth.oidc.urllib.request.urlopen", mock):
            token1 = _make_token(priv)
            validator.validate_token(token1)
            call_count_1 = mock.call_count

            token2 = _make_token(priv, sub="user-2")
            validator.validate_token(token2)
            call_count_2 = mock.call_count

        assert call_count_2 == call_count_1  # no extra fetch

    def test_unknown_kid_triggers_refetch(self, rsa_keypair, jwks_data):
        priv, _ = rsa_keypair
        validator = OIDCValidator(
            jwks_url="https://auth.example.com/.well-known/jwks.json",
        )

        # Token with unknown kid
        token = _make_token(priv, kid="unknown-kid")

        mock = MagicMock(return_value=_mock_urlopen(jwks_data))
        with patch("shared.auth.oidc.urllib.request.urlopen", mock):
            with pytest.raises(AuthenticationError) as exc_info:
                validator.validate_token(token)

        # Should have fetched twice (initial + refetch on unknown kid)
        assert mock.call_count == 2
        assert exc_info.value.error_code == TOKEN_INVALID_SIGNATURE


class TestMalformedToken:
    def test_malformed_token(self):
        validator = OIDCValidator(
            jwks_url="https://auth.example.com/.well-known/jwks.json",
        )
        with pytest.raises(AuthenticationError) as exc_info:
            validator.validate_token("not.a.jwt")
        assert exc_info.value.error_code == TOKEN_MALFORMED
