"""TLS and SSL certificate management with in-memory validation."""

from __future__ import annotations

import asyncio
import logging
import ssl
from urllib.parse import urlparse

from .exceptions import PiKVMCertificateError, PiKVMTimeoutError

_LOGGER = logging.getLogger(__name__)


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
    check_hostname: bool = True,
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

    if ssl_cert is not None:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = check_hostname
        context.verify_mode = ssl.CERT_REQUIRED
        cert_data = (ssl_cert if isinstance(ssl_cert, str) else ssl_cert.decode("utf-8")).strip()
        try:
            context.load_verify_locations(cadata=cert_data)
        except ssl.SSLError as err:
            raise PiKVMCertificateError(
                f"Failed to load certificate into SSLContext: {err}"
            ) from err
        return context

    context = ssl.create_default_context()
    context.check_hostname = check_hostname
    context.verify_mode = ssl.CERT_REQUIRED
    return context


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
