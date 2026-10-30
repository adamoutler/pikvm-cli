"""Exception hierarchy for pikvm-aio."""

from __future__ import annotations


class PiKVMError(Exception):
    """Base exception for all PiKVM errors."""


class PiKVMConnectionError(PiKVMError):
    """Raised when communication with PiKVM fails due to network or socket issues."""


class PiKVMTimeoutError(PiKVMConnectionError):
    """Raised when an operation against PiKVM times out."""


class PiKVMCertificateError(PiKVMConnectionError):
    """Raised when SSL/TLS validation fails or certificate cannot be retrieved."""


class PiKVMAuthenticationError(PiKVMError):
    """Raised when authentication fails due to invalid credentials, expired session, or bad TOTP."""


class PiKVMInvalidTOTPError(PiKVMAuthenticationError):
    """Raised when the supplied TOTP value is unusable.

    Covers malformed base32 secrets and, when ``allow_static_totp=False``, static
    numeric one-time codes (which expire and cannot sustain long-running sessions).
    Subclasses :class:`PiKVMAuthenticationError` for backward compatibility.
    """


class PiKVMDeviceError(PiKVMError):
    """Raised when PiKVM reports an internal error or unexpected API response."""


class PiKVMValidationError(PiKVMError):
    """Raised when input parameters, filenames, or coordinates fail validation."""


class PiKVMInvalidHostError(PiKVMValidationError, ValueError):
    """Raised when a host, URL, or port string cannot be parsed.

    Examples: non-numeric or out-of-range ports (``host:abc``, ``host:99999``), unbalanced
    brackets, or bare IPv6 literals without brackets (``fe80::1`` must be ``[fe80::1]``).
    Also subclasses :class:`ValueError` so existing ``except ValueError`` callers keep working.
    """


class PiKVMInvalidKeyError(PiKVMValidationError):
    """Raised when an unrecognized key or shortcut sequence is supplied."""


class PiKVMInvalidTextError(PiKVMValidationError):
    """Raised when text for typing contains unprintable or invalid characters."""


class PiKVMSafetyError(PiKVMError):
    """Raised when a high-consequence action is attempted without required confirmation."""
