"""mTLS context creation for inter-service communication."""

from __future__ import annotations

import logging
import ssl
from pathlib import Path

from shared.auth.exceptions import (
    MTLS_CA_NOT_FOUND,
    MTLS_INVALID_CERT,
    MTLS_INVALID_KEY,
    AuthenticationError,
)

logger = logging.getLogger(__name__)


def create_mtls_context(
    ca_cert_path: str,
    client_cert_path: str,
    client_key_path: str,
    *,
    check_hostname: bool = True,
) -> ssl.SSLContext:
    """Create an SSLContext configured for mutual TLS."""
    # Validate paths exist
    if not Path(ca_cert_path).is_file():
        raise AuthenticationError(
            f"CA certificate not found: {ca_cert_path}",
            error_code=MTLS_CA_NOT_FOUND,
            detail={"path": ca_cert_path},
        )
    if not Path(client_cert_path).is_file():
        raise AuthenticationError(
            f"Client certificate not found: {client_cert_path}",
            error_code=MTLS_INVALID_CERT,
            detail={"path": client_cert_path},
        )
    if not Path(client_key_path).is_file():
        raise AuthenticationError(
            f"Client key not found: {client_key_path}",
            error_code=MTLS_INVALID_KEY,
            detail={"path": client_key_path},
        )

    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = check_hostname
        ctx.load_verify_locations(ca_cert_path)
        ctx.load_cert_chain(certfile=client_cert_path, keyfile=client_key_path)
        logger.info("mTLS context created successfully")
        return ctx
    except ssl.SSLError as exc:
        raise AuthenticationError(
            f"mTLS context creation failed: {exc}",
            error_code=MTLS_INVALID_CERT,
            detail={"error": str(exc)},
        ) from exc
