"""Unit tests for pikvm_aio TLS and SSL management."""

from __future__ import annotations

import ssl
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from pikvm_aio.exceptions import PiKVMCertificateError, PiKVMTimeoutError
from pikvm_aio.tls import create_ssl_context, fetch_remote_cert, parse_host_port


def test_parse_host_port() -> None:
    """Test URL and host parsing into (host, port)."""
    assert parse_host_port("pikvm.local") == ("pikvm.local", 443)
    assert parse_host_port("https://pikvm.local") == ("pikvm.local", 443)
    assert parse_host_port("http://192.168.1.50") == ("192.168.1.50", 80)
    assert parse_host_port("192.168.1.50:8443") == ("192.168.1.50", 8443)
    assert parse_host_port("https://192.168.1.50:8443/api/info") == ("192.168.1.50", 8443)
    assert parse_host_port("[2001:db8::1]:9443") == ("2001:db8::1", 9443)


def test_create_ssl_context_insecure() -> None:
    """Test creating an insecure SSL context."""
    ctx = create_ssl_context(verify_ssl=False)
    assert ctx.check_hostname is False
    assert ctx.verify_mode == ssl.CERT_NONE


def test_create_ssl_context_with_cert(sample_cert_pem: str) -> None:
    """Test loading PEM certificate in-memory without temporary disk files."""
    ctx = create_ssl_context(verify_ssl=True, ssl_cert=sample_cert_pem, check_hostname=False)
    assert ctx.check_hostname is False
    assert ctx.verify_mode == ssl.CERT_REQUIRED


def test_create_ssl_context_invalid_cert() -> None:
    """Test handling invalid PEM certificate string."""
    with pytest.raises(PiKVMCertificateError):
        create_ssl_context(verify_ssl=True, ssl_cert="NOT A VALID PEM")


@pytest.mark.asyncio
async def test_fetch_remote_cert_success(sample_cert_pem: str) -> None:
    """Test successful asynchronous certificate retrieval."""
    mock_ssl_obj = MagicMock()
    # Create valid DER bytes from sample PEM
    lines = [line for line in sample_cert_pem.splitlines() if not line.startswith("---")]
    import base64

    der_bytes = base64.b64decode("".join(lines))
    mock_ssl_obj.getpeercert.return_value = der_bytes

    mock_writer = AsyncMock()
    mock_writer.get_extra_info = MagicMock(return_value=mock_ssl_obj)
    mock_writer.close = MagicMock()
    mock_writer.wait_closed = AsyncMock()

    with patch("asyncio.open_connection", new=AsyncMock(return_value=(MagicMock(), mock_writer))):
        pem = await fetch_remote_cert("pikvm.local", timeout=5.0)
        assert "-----BEGIN CERTIFICATE-----" in pem
        assert "-----END CERTIFICATE-----" in pem


@pytest.mark.asyncio
async def test_fetch_remote_cert_timeout() -> None:
    """Test handling timeout during certificate fetch."""
    with patch("asyncio.open_connection", side_effect=TimeoutError()):
        with pytest.raises(PiKVMTimeoutError):
            await fetch_remote_cert("pikvm.local", timeout=0.1)


@pytest.mark.asyncio
async def test_fetch_remote_cert_connection_error() -> None:
    """Test handling socket/SSL error during certificate fetch."""
    with patch("asyncio.open_connection", side_effect=OSError("Connection refused")):
        with pytest.raises(PiKVMCertificateError):
            await fetch_remote_cert("pikvm.local", timeout=1.0)
