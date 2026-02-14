"""Tests for AuthenticationError — AC-1.6.8."""

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


class TestAuthenticationError:
    def test_has_message(self):
        err = AuthenticationError("test message", error_code=TOKEN_EXPIRED)
        assert err.message == "test message"
        assert str(err) == "test message"

    def test_has_error_code(self):
        err = AuthenticationError("msg", error_code=TOKEN_INVALID_SIGNATURE)
        assert err.error_code == "TOKEN_INVALID_SIGNATURE"

    def test_has_detail(self):
        err = AuthenticationError(
            "msg", error_code=TOKEN_EXPIRED, detail={"user": "test"}
        )
        assert err.detail == {"user": "test"}

    def test_detail_defaults_to_empty_dict(self):
        err = AuthenticationError("msg", error_code=TOKEN_EXPIRED)
        assert err.detail == {}

    def test_is_exception(self):
        err = AuthenticationError("msg", error_code=TOKEN_EXPIRED)
        assert isinstance(err, Exception)


class TestErrorCodeConstants:
    def test_all_constants_defined(self):
        expected = {
            "TOKEN_EXPIRED",
            "TOKEN_INVALID_SIGNATURE",
            "TOKEN_INVALID_AUDIENCE",
            "TOKEN_INVALID_ISSUER",
            "TOKEN_MALFORMED",
            "JWKS_FETCH_FAILED",
            "MTLS_INVALID_CERT",
            "MTLS_INVALID_KEY",
            "MTLS_CA_NOT_FOUND",
        }
        actual = {
            TOKEN_EXPIRED,
            TOKEN_INVALID_SIGNATURE,
            TOKEN_INVALID_AUDIENCE,
            TOKEN_INVALID_ISSUER,
            TOKEN_MALFORMED,
            JWKS_FETCH_FAILED,
            MTLS_INVALID_CERT,
            MTLS_INVALID_KEY,
            MTLS_CA_NOT_FOUND,
        }
        assert actual == expected
