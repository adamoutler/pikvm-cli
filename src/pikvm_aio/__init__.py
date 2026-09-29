"""pikvm-aio: Asynchronous client library and CLI for PiKVM."""

from __future__ import annotations

from .client import PiKVMClient, format_url
from .exceptions import (
    PiKVMAuthenticationError,
    PiKVMCertificateError,
    PiKVMConnectionError,
    PiKVMDeviceError,
    PiKVMError,
    PiKVMTimeoutError,
)
from .models import (
    HardwareHealth,
    HardwareInfo,
    HardwarePerformance,
    MsdDrive,
    MsdInfo,
    MsdStorage,
    PiKVMDeviceInfo,
    PlatformInfo,
    ServerMeta,
    ThrottlingInfo,
)
from .tls import create_ssl_context, fetch_remote_cert, parse_host_port

async_fetch_peer_certificate = fetch_remote_cert

__version__ = "0.1.4"

__all__ = [
    "HardwareHealth",
    "HardwareInfo",
    "HardwarePerformance",
    "MsdDrive",
    "MsdInfo",
    "MsdStorage",
    "PiKVMAuthenticationError",
    "PiKVMCertificateError",
    "PiKVMClient",
    "PiKVMConnectionError",
    "PiKVMDeviceInfo",
    "PiKVMDeviceError",
    "PiKVMError",
    "PiKVMTimeoutError",
    "PlatformInfo",
    "ServerMeta",
    "ThrottlingInfo",
    "__version__",
    "async_fetch_peer_certificate",
    "create_ssl_context",
    "fetch_remote_cert",
    "format_url",
    "parse_host_port",
]
