"""TLS and SSL certificate management with in-memory validation."""

from __future__ import annotations

import asyncio
import base64
import binascii
import hashlib
import logging
import ssl
from urllib.parse import urlparse

from .exceptions import PiKVMCertificateError, PiKVMTimeoutError
from .security import SensitiveDataFilter

_LOGGER = logging.getLogger(__name__)
_LOGGER.addFilter(SensitiveDataFilter())


def parse_host_port(target: str, default_port: int = 443) -> tuple[str, int]:
    """Parse a host string or URL into (hostname, port).

    Supports formats like:
      - 'pikvm.local'
      - 'pikvm.local:8443'
      - 'https://192.168.1.50:8443/'
      - '[2001:db8::1]:8443'
    """
    if "://" not in target:
        target = f"https://{target}"

    parsed = urlparse(target)
    hostname = parsed.hostname or "localhost"
    if parsed.port is not None:
        port = parsed.port
    elif parsed.scheme == "http":
        port = 80
    else:
        port = default_port
    return hostname, port


def create_ssl_context(
    verify_ssl: bool = True,
    ssl_cert: str | bytes | None = None,
    check_hostname: bool | None = None,
) -> ssl.SSLContext:
    """Create an SSL context.

    If ssl_cert is provided, loads the certificate in-memory via cadata without
    writing temporary files to disk.
    """
    if not verify_ssl:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return context

    effective_check_hostname = check_hostname if check_hostname is not None else (ssl_cert is None)

    if ssl_cert is not None:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = effective_check_hostname
        context.verify_mode = ssl.CERT_REQUIRED
        try:
            if isinstance(ssl_cert, bytes):
                if ssl_cert.strip().startswith(b"-----BEGIN"):
                    cadata: str | bytes = ssl_cert.decode("ascii").strip()
                else:
                    cadata = ssl_cert
            elif isinstance(ssl_cert, str):
                cadata = ssl_cert.strip()
            else:
                raise PiKVMCertificateError(
                    f"ssl_cert must be str or bytes, got {type(ssl_cert).__name__}"
                )
            if not cadata:
                raise PiKVMCertificateError("ssl_cert cannot be empty")
            context.load_verify_locations(cadata=cadata)
        except (ssl.SSLError, UnicodeDecodeError, ValueError) as err:
            raise PiKVMCertificateError(
                f"Failed to load certificate into SSLContext: {err}"
            ) from err
        return context

    context = ssl.create_default_context()
    context.check_hostname = effective_check_hostname
    context.verify_mode = ssl.CERT_REQUIRED
    return context


def get_cert_fingerprint(
    cert_pem_or_der: str | bytes,
    algorithm: str = "sha256",
) -> str:
    """Calculate the cryptographic fingerprint of an X.509 certificate.

    Args:
        cert_pem_or_der: Certificate content in PEM (str or bytes) or raw DER (bytes).
        algorithm: Hashing algorithm supported by hashlib (default: 'sha256').

    Returns:
        Colon-delimited uppercase hexadecimal fingerprint string (e.g. 'AA:BB:CC:...').

    Raises:
        PiKVMCertificateError: If certificate data is empty, malformed, or algorithm is unsupported.

    """
    if not cert_pem_or_der:
        raise PiKVMCertificateError("Certificate data cannot be empty")

    try:
        if isinstance(cert_pem_or_der, str):
            lines = [
                line.strip()
                for line in cert_pem_or_der.splitlines()
                if line.strip() and not line.strip().startswith("-----")
            ]
            if not lines:
                raise PiKVMCertificateError("PEM certificate contains no body data")
            der = base64.b64decode("".join(lines), validate=True)
        elif isinstance(cert_pem_or_der, (bytes, bytearray)):
            if b"-----BEGIN" in cert_pem_or_der:
                lines = [
                    line.strip()
                    for line in cert_pem_or_der.decode("ascii").splitlines()
                    if line.strip() and not line.strip().startswith("-----")
                ]
                if not lines:
                    raise PiKVMCertificateError("PEM certificate contains no body data")
                der = base64.b64decode("".join(lines), validate=True)
            else:
                der = bytes(cert_pem_or_der)
        else:
            raise PiKVMCertificateError(
                f"Expected str or bytes for certificate, got {type(cert_pem_or_der).__name__}"
            )
    except (binascii.Error, ValueError, UnicodeDecodeError) as err:
        raise PiKVMCertificateError(f"Failed to parse certificate data: {err}") from err

    if not der:
        raise PiKVMCertificateError("Certificate DER payload is empty")

    try:
        digest = hashlib.new(algorithm, der).hexdigest()
    except (ValueError, TypeError) as err:
        raise PiKVMCertificateError(
            f"Unsupported certificate fingerprint algorithm '{algorithm}': {err}"
        ) from err

    return ":".join(digest[i : i + 2].upper() for i in range(0, len(digest), 2))


async def fetch_remote_cert(
    target: str,
    default_port: int = 443,
    timeout: float = 10.0,
) -> str:
    """Fetch the PEM certificate presented by a remote PiKVM instance asynchronously.

    Does not require pyOpenSSL; uses standard library asyncio and ssl.
    """
    hostname, port = parse_host_port(target, default_port)
    _LOGGER.debug("Fetching SSL certificate from %s:%s", hostname, port)

    # Use a permissive in-memory context purely to complete the handshake
    # and read the peer certificate
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                hostname,
                port,
                ssl=ctx,
                server_hostname=hostname,
            ),
            timeout=timeout,
        )
    except TimeoutError as err:
        raise PiKVMTimeoutError(
            f"Timed out after {timeout}s connecting to {hostname}:{port}"
        ) from err
    except (OSError, ssl.SSLError) as err:
        raise PiKVMCertificateError(
            f"Failed to connect to {hostname}:{port} to retrieve certificate: {err}"
        ) from err

    try:
        ssl_obj = writer.get_extra_info("ssl_object")
        if ssl_obj is None:
            raise PiKVMCertificateError(f"No SSL object established with {hostname}:{port}")

        der_cert = ssl_obj.getpeercert(binary_form=True)
        if not der_cert:
            raise PiKVMCertificateError(f"No peer certificate returned by {hostname}:{port}")

        return ssl.DER_cert_to_PEM_cert(der_cert)
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:  # noqa: BLE001
            pass
