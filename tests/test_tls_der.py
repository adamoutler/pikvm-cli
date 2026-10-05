"""Unit tests for binary DER certificate support, fingerprinting, and safe TLS."""

from __future__ import annotations

import base64
import json
import ssl
from unittest.mock import AsyncMock, patch

import pytest

from pikvm_aio.cli import async_main, build_parser
from pikvm_aio.client import PiKVMClient
from pikvm_aio.exceptions import PiKVMCertificateError
from pikvm_aio.tls import create_ssl_context, get_cert_fingerprint


def test_create_ssl_context_der_bytes(sample_cert_pem: str) -> None:
    """Test loading raw DER bytes into SSLContext without UnicodeDecodeError."""
    lines = [line for line in sample_cert_pem.splitlines() if not line.startswith("---")]
    der_bytes = base64.b64decode("".join(lines))

    ctx = create_ssl_context(verify_ssl=True, ssl_cert=der_bytes)
    assert ctx.check_hostname is False
    assert ctx.verify_mode == ssl.CERT_REQUIRED


def test_create_ssl_context_pem_bytes(sample_cert_pem: str) -> None:
    """Test loading PEM certificate supplied as ASCII bytes."""
    pem_bytes = sample_cert_pem.encode("utf-8")
    ctx = create_ssl_context(verify_ssl=True, ssl_cert=pem_bytes)
    assert ctx.check_hostname is False
    assert ctx.verify_mode == ssl.CERT_REQUIRED


def test_create_ssl_context_empty_or_invalid_bytes() -> None:
    """Test rejecting empty or malformed DER/PEM bytes."""
    with pytest.raises(PiKVMCertificateError):
        create_ssl_context(verify_ssl=True, ssl_cert=b"")

    with pytest.raises(PiKVMCertificateError):
        create_ssl_context(verify_ssl=True, ssl_cert=b"\x00\x01\x02\x03\x04")


def test_create_ssl_context_invalid_cert_type() -> None:
    """Test rejecting non-str/non-bytes cert input."""
    with pytest.raises(PiKVMCertificateError, match="must be str or bytes"):
        create_ssl_context(verify_ssl=True, ssl_cert=12345)  # type: ignore[arg-type]


def test_create_ssl_context_hostname_resolution(sample_cert_pem: str) -> None:
    """Test hostname verification resolution logic."""
    # When ssl_cert is provided, default check_hostname is False
    ctx1 = create_ssl_context(verify_ssl=True, ssl_cert=sample_cert_pem)
    assert ctx1.check_hostname is False

    # When ssl_cert is None, default check_hostname is True
    ctx2 = create_ssl_context(verify_ssl=True)
    assert ctx2.check_hostname is True

    # Explicit check_hostname overrides are respected
    ctx3 = create_ssl_context(verify_ssl=True, ssl_cert=sample_cert_pem, check_hostname=True)
    assert ctx3.check_hostname is True


def test_get_cert_fingerprint_formats(sample_cert_pem: str) -> None:
    """Test SHA-256 fingerprint calculation across PEM str, PEM bytes, and DER bytes."""
    lines = [line for line in sample_cert_pem.splitlines() if not line.startswith("---")]
    der_bytes = base64.b64decode("".join(lines))
    pem_bytes = sample_cert_pem.encode("utf-8")

    fp_str = get_cert_fingerprint(sample_cert_pem)
    fp_bytes = get_cert_fingerprint(pem_bytes)
    fp_der = get_cert_fingerprint(der_bytes)

    expected = (
        "45:65:C0:08:F4:A5:EC:92:57:91:12:4F:4D:55:BB:4B:"
        "9A:34:D9:31:9C:A1:44:D5:D5:87:49:1C:1A:04:3E:A9"
    )
    assert fp_str == expected
    assert fp_bytes == expected
    assert fp_der == expected


def test_get_cert_fingerprint_sha1(sample_cert_pem: str) -> None:
    """Test fingerprint calculation with sha1."""
    fp_sha1 = get_cert_fingerprint(sample_cert_pem, algorithm="sha1")
    assert fp_sha1 == "6E:3B:7F:11:CD:82:56:86:F5:CC:A2:15:54:1B:49:55:EC:62:AA:37"


def test_get_cert_fingerprint_error_handling() -> None:
    """Test error handling in get_cert_fingerprint."""
    with pytest.raises(PiKVMCertificateError, match="cannot be empty"):
        get_cert_fingerprint("")

    with pytest.raises(PiKVMCertificateError, match="cannot be empty"):
        get_cert_fingerprint(b"")

    with pytest.raises(PiKVMCertificateError, match="Expected str or bytes"):
        get_cert_fingerprint(12345)  # type: ignore[arg-type]

    with pytest.raises(PiKVMCertificateError, match="contains no body data"):
        get_cert_fingerprint("-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----")

    with pytest.raises(PiKVMCertificateError, match="contains no body data"):
        get_cert_fingerprint(b"-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----")

    invalid_pem = "-----BEGIN CERTIFICATE-----\n!invalid_base64!\n-----END CERTIFICATE-----"
    with pytest.raises(PiKVMCertificateError, match="Failed to parse certificate data"):
        get_cert_fingerprint(invalid_pem)

    with pytest.raises(
        PiKVMCertificateError, match="Unsupported certificate fingerprint algorithm"
    ):
        get_cert_fingerprint(b"\x30\x82\x01\x00", algorithm="unsupported_algorithm_xyz")


def test_client_check_hostname_defaults(sample_cert_pem: str) -> None:
    """Test PiKVMClient check_hostname defaulting logic."""
    c1 = PiKVMClient("192.168.1.50", ssl_cert=sample_cert_pem)
    assert c1.check_hostname is False
    assert c1._ssl_context.check_hostname is False

    c2 = PiKVMClient("pikvm.local")
    assert c2.check_hostname is True
    assert c2._ssl_context.check_hostname is True

    c3 = PiKVMClient("192.168.1.50", ssl_cert=sample_cert_pem, check_hostname=True)
    assert c3.check_hostname is True
    assert c3._ssl_context.check_hostname is True


@pytest.mark.asyncio
async def test_cli_fetch_cert_fingerprint_text(
    capsys: pytest.CaptureFixture[str], sample_cert_pem: str
) -> None:
    """Test fetch-cert command prints PEM and SHA-256 fingerprint."""
    parser = build_parser()
    args = parser.parse_args(["-H", "pikvm.local", "fetch-cert"])

    with patch("pikvm_aio.cli.fetch_remote_cert", new=AsyncMock(return_value=sample_cert_pem)):
        code = await async_main(args)
        assert code == 0
        captured = capsys.readouterr()
        assert "-----BEGIN CERTIFICATE-----" in captured.out
        assert "SHA256 Fingerprint: 45:65:C0:08:" in captured.out


@pytest.mark.asyncio
async def test_cli_fetch_cert_fingerprint_json(
    capsys: pytest.CaptureFixture[str], sample_cert_pem: str
) -> None:
    """Test fetch-cert command with --json includes fingerprint."""
    parser = build_parser()
    args = parser.parse_args(["-H", "pikvm.local", "--json", "fetch-cert"])

    with patch("pikvm_aio.cli.fetch_remote_cert", new=AsyncMock(return_value=sample_cert_pem)):
        code = await async_main(args)
        assert code == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["host"] == "pikvm.local"
        assert "-----BEGIN CERTIFICATE-----" in data["certificate"]
        assert data["fingerprint"] == (
            "45:65:C0:08:F4:A5:EC:92:57:91:12:4F:4D:55:BB:4B:"
            "9A:34:D9:31:9C:A1:44:D5:D5:87:49:1C:1A:04:3E:A9"
        )
