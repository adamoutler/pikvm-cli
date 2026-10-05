"""pikvm-aio: Asynchronous client library and CLI for PiKVM."""

from __future__ import annotations

from .client import PiKVMClient, format_url
from .exceptions import (
    PiKVMAuthenticationError,
    PiKVMCertificateError,
    PiKVMConnectionError,
    PiKVMDeviceError,
    PiKVMError,
    PiKVMInvalidKeyError,
    PiKVMInvalidTextError,
    PiKVMSafetyError,
    PiKVMTimeoutError,
    PiKVMValidationError,
)
from .models import (
    HardwareHealth,
    HardwareInfo,
    HardwarePerformance,
    HidDeviceState,
    HidMacro,
    HidMacroStep,
    KeyboardKeymaps,
    MsdDrive,
    MsdDriveParams,
    MsdInfo,
    MsdRemoteProgress,
    MsdStorage,
    MsdUploadProgress,
    OcrResult,
    PiKVMDeviceInfo,
    PlatformInfo,
    ServerMeta,
    ThrottlingInfo,
)
from .security import (
    SensitiveDataFilter,
    attach_sensitive_data_filter,
    configure_secure_logging,
    scrub_process_argv,
)
from .tls import (
    create_ssl_context,
    fetch_remote_cert,
    get_cert_fingerprint,
    parse_host_port,
)

async_fetch_peer_certificate = fetch_remote_cert

__version__ = "0.1.5"

__all__ = [
    "HardwareHealth",
    "HardwareInfo",
    "HardwarePerformance",
    "HidDeviceState",
    "HidMacro",
    "HidMacroStep",
    "KeyboardKeymaps",
    "MsdDrive",
    "MsdDriveParams",
    "MsdInfo",
    "MsdRemoteProgress",
    "MsdStorage",
    "MsdUploadProgress",
    "OcrResult",
    "PiKVMAuthenticationError",
    "PiKVMCertificateError",
    "PiKVMClient",
    "PiKVMConnectionError",
    "PiKVMDeviceError",
    "PiKVMDeviceInfo",
    "PiKVMError",
    "PiKVMInvalidKeyError",
    "PiKVMInvalidTextError",
    "PiKVMSafetyError",
    "PiKVMTimeoutError",
    "PiKVMValidationError",
    "PlatformInfo",
    "SensitiveDataFilter",
    "ServerMeta",
    "ThrottlingInfo",
    "__version__",
    "async_fetch_peer_certificate",
    "attach_sensitive_data_filter",
    "configure_secure_logging",
    "create_ssl_context",
    "fetch_remote_cert",
    "format_url",
    "get_cert_fingerprint",
    "parse_host_port",
    "scrub_process_argv",
]
