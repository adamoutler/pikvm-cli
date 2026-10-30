"""Hardening tests for Home Assistant Core readiness.

Covers: per-request timeouts with injected sessions, TOTP input validation
(PiKVMInvalidTOTPError / allow_static_totp), host validation (PiKVMInvalidHostError),
and IPv6 bracket preservation in format_url.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import AsyncIterator
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import aiohttp
import pytest
from aiohttp import web

import pikvm_aio
import pikvm_cli
import pikvm_client
from pikvm_aio.client import PiKVMClient, format_url
from pikvm_aio.exceptions import (
    PiKVMAuthenticationError,
    PiKVMError,
    PiKVMInvalidHostError,
    PiKVMInvalidTOTPError,
    PiKVMTimeoutError,
    PiKVMValidationError,
)

VALID_SECRET = "JBSWY3DPEHPK3PXP"


# -----------------------------------------------------------------------------
# 1. Timeout applied to injected sessions
# -----------------------------------------------------------------------------


@pytest.fixture
async def slow_server() -> AsyncIterator[str]:
    """Run a loopback HTTP server whose /api/info handler stalls until teardown."""
    release = asyncio.Event()

    async def _stall(_request: web.Request) -> web.Response:
        await release.wait()
        return web.json_response({"ok": True, "result": {}})

    app = web.Application()
    app.router.add_get("/api/info", _stall)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = runner.addresses[0][1]
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        release.set()
        await runner.cleanup()


@pytest.mark.asyncio
async def test_injected_session_honours_client_timeout(slow_server: str) -> None:
    """An injected session with a long default timeout must not override client timeout."""
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=300)) as session:
        client = PiKVMClient(slow_server, session=session, verify_ssl=False, timeout=0.3)
        start = time.monotonic()
        # Outer guard makes a regression fail fast (plain TimeoutError) instead of hanging
        # for the injected session's 300 s default.
        with pytest.raises(PiKVMTimeoutError):
            async with asyncio.timeout(5):
                await client.get_raw_info()
        elapsed = time.monotonic() - start
        await client.close()
        # Injected session must remain owned (and left open) by the caller.
        assert not session.closed
    assert elapsed < 5.0


@pytest.mark.asyncio
async def test_request_passes_explicit_client_timeout() -> None:
    """_request must pass an explicit ClientTimeout(total=self.timeout) on every call."""
    captured: dict[str, Any] = {}

    class _Resp:
        status = 200

        async def __aenter__(self) -> _Resp:
            return self

        async def __aexit__(self, *_: Any) -> None:
            return None

        def raise_for_status(self) -> None:
            return None

        async def json(self) -> Any:
            return {"ok": True, "result": {"x": 1}}

    def _request(**kwargs: Any) -> _Resp:
        captured.update(kwargs)
        return _Resp()

    session = MagicMock()
    session.closed = False
    session.close = AsyncMock()
    session.request = _request

    client = PiKVMClient("pikvm.local", session=session, verify_ssl=False, timeout=7.5)
    assert await client.get_raw_info() == {"x": 1}
    timeout = captured["timeout"]
    assert isinstance(timeout, aiohttp.ClientTimeout)
    assert timeout.total == 7.5
    # Injected sessions are never closed by the client.
    await client.close()
    session.close.assert_not_awaited()


# -----------------------------------------------------------------------------
# 2. TOTP validation
# -----------------------------------------------------------------------------


def test_invalid_base32_raises_invalid_totp_error() -> None:
    with pytest.raises(PiKVMInvalidTOTPError, match="Invalid TOTP base32 secret") as exc_info:
        PiKVMClient("pikvm.local", totp_secret="INVALID_BASE32!@#$")
    # Backward compatibility: still an authentication error.
    assert isinstance(exc_info.value, PiKVMAuthenticationError)
    # The secret must never be echoed back in the error message.
    assert "INVALID_BASE32" not in str(exc_info.value)


@pytest.mark.parametrize("code", ["123456", "12345678", " 123 456 "])
def test_static_code_rejected_when_disallowed(code: str) -> None:
    with pytest.raises(PiKVMInvalidTOTPError, match="Static numeric one-time codes"):
        PiKVMClient("pikvm.local", totp_secret=code, allow_static_totp=False)


@pytest.mark.parametrize("code", ["123456", "12345678"])
def test_static_code_accepted_by_default(code: str) -> None:
    client = PiKVMClient("pikvm.local", totp_secret=code)
    assert client._static_totp == code
    assert client._totp is None


def test_valid_secret_accepted_when_static_disallowed() -> None:
    client = PiKVMClient("pikvm.local", totp_secret=VALID_SECRET, allow_static_totp=False)
    assert client._totp is not None
    assert client._static_totp is None


def test_allow_static_totp_is_keyword_only() -> None:
    with pytest.raises(TypeError):
        PiKVMClient(  # type: ignore[misc]
            "pikvm.local", "admin", "admin", None, None, True, None, None, 10.0, None, False
        )


# -----------------------------------------------------------------------------
# 3. Invalid host input -> PiKVMInvalidHostError
# -----------------------------------------------------------------------------


@pytest.mark.parametrize(
    "host",
    [
        "foo:bar",
        "host:99999",
        "fe80::1",
        "::1",
        "https://fe80::1:443",
        "[fe80::1",
        "user:secretpw@host:notaport",
    ],
)
def test_invalid_host_raises_library_error(host: str) -> None:
    with pytest.raises(PiKVMInvalidHostError) as exc_info:
        PiKVMClient(host)
    err = exc_info.value
    assert isinstance(err, PiKVMValidationError)
    assert isinstance(err, PiKVMError)
    # Backward compatibility with callers catching ValueError.
    assert isinstance(err, ValueError)
    # Embedded credentials must never be echoed into the exception message.
    assert "secretpw" not in str(err)


def test_bare_ipv6_error_suggests_brackets() -> None:
    with pytest.raises(PiKVMInvalidHostError, match=r"\[fe80::1\]"):
        format_url("fe80::1")


def test_new_exceptions_exported_from_all_namespaces() -> None:
    for module in (pikvm_aio, pikvm_cli, pikvm_client):
        assert module.PiKVMInvalidHostError is PiKVMInvalidHostError
        assert module.PiKVMInvalidTOTPError is PiKVMInvalidTOTPError
        assert "PiKVMInvalidHostError" in module.__all__
        assert "PiKVMInvalidTOTPError" in module.__all__


# -----------------------------------------------------------------------------
# 4. IPv6 bracket preservation
# -----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("[fe80::1]", "https://[fe80::1]"),
        ("[fe80::1]:443", "https://[fe80::1]:443"),
        ("[fe80::1]:8443", "https://[fe80::1]:8443"),
        ("https://[2001:db8::1]:8443/api", "https://[2001:db8::1]:8443"),
        ("http://[::1]", "http://[::1]"),
        ("https://admin:pw@[2001:db8::1]:9443/", "https://[2001:db8::1]:9443"),
    ],
)
def test_format_url_preserves_ipv6_brackets(raw: str, expected: str) -> None:
    assert format_url(raw) == expected


def test_client_base_url_ipv6() -> None:
    client = PiKVMClient("[fe80::1]:8443")
    assert client.base_url == "https://[fe80::1]:8443"
