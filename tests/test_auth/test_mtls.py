"""Tests for mTLS context creation — AC-1.6.6, AC-1.6.7."""

from __future__ import annotations

import ssl
from unittest.mock import MagicMock, patch

import pytest

from shared.auth.exceptions import (
    MTLS_CA_NOT_FOUND,
    MTLS_INVALID_CERT,
    MTLS_INVALID_KEY,
    AuthenticationError,
)
from shared.auth.mtls import create_mtls_context


class TestMtlsContext:
    """AC-1.6.6: mTLS context creation."""

    def test_creates_ssl_context(self, tmp_path):
        ca = tmp_path / "ca.pem"
        cert = tmp_path / "client.pem"
        key = tmp_path / "client.key"
        ca.write_text("CA")
        cert.write_text("CERT")
        key.write_text("KEY")

        with patch("shared.auth.mtls.ssl.SSLContext") as MockCtx:
            mock_ctx = MagicMock()
            MockCtx.return_value = mock_ctx

            result = create_mtls_context(str(ca), str(cert), str(key))

            MockCtx.assert_called_once_with(ssl.PROTOCOL_TLS_CLIENT)
            mock_ctx.load_verify_locations.assert_called_once_with(str(ca))
            mock_ctx.load_cert_chain.assert_called_once_with(
                certfile=str(cert), keyfile=str(key)
            )
            assert result is mock_ctx


class TestMtlsRejectsInvalid:
    """AC-1.6.7: Invalid paths raise AuthenticationError."""

    def test_missing_ca_cert(self, tmp_path):
        cert = tmp_path / "client.pem"
        key = tmp_path / "client.key"
        cert.write_text("CERT")
        key.write_text("KEY")

        with pytest.raises(AuthenticationError) as exc_info:
            create_mtls_context(
                str(tmp_path / "missing_ca.pem"), str(cert), str(key)
            )
        assert exc_info.value.error_code == MTLS_CA_NOT_FOUND

    def test_missing_client_cert(self, tmp_path):
        ca = tmp_path / "ca.pem"
        key = tmp_path / "client.key"
        ca.write_text("CA")
        key.write_text("KEY")

        with pytest.raises(AuthenticationError) as exc_info:
            create_mtls_context(
                str(ca), str(tmp_path / "missing_cert.pem"), str(key)
            )
        assert exc_info.value.error_code == MTLS_INVALID_CERT

    def test_missing_client_key(self, tmp_path):
        ca = tmp_path / "ca.pem"
        cert = tmp_path / "client.pem"
        ca.write_text("CA")
        cert.write_text("CERT")

        with pytest.raises(AuthenticationError) as exc_info:
            create_mtls_context(
                str(ca), str(cert), str(tmp_path / "missing.key")
            )
        assert exc_info.value.error_code == MTLS_INVALID_KEY
