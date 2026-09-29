"""Unit tests for PiKVMClient."""

from __future__ import annotations

import base64
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import aiohttp
import pytest

from pikvm_aio.client import PiKVMClient, format_url
from pikvm_aio.exceptions import (
    PiKVMAuthenticationError,
    PiKVMConnectionError,
    PiKVMDeviceError,
    PiKVMTimeoutError,
)


class MockClientResponse:
    """Mock aiohttp response context manager."""

    def __init__(
        self,
        status: int = 200,
        payload: Any = None,
        text: str = "",
        raise_on_status: bool = False,
    ) -> None:
        self.status = status
        self._payload = payload if payload is not None else {"ok": True, "result": {}}
        self._text = text
        self._raise_on_status = raise_on_status

    async def __aenter__(self) -> MockClientResponse:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: Any,
    ) -> None:
        pass

    def raise_for_status(self) -> None:
        if self._raise_on_status or self.status >= 400:
            raise aiohttp.ClientResponseError(
                request_info=MagicMock(),
                history=(),
                status=self.status,
                message=self._text or f"HTTP {self.status}",
            )

    async def json(self) -> Any:
        return self._payload

    async def text(self) -> str:
        return self._text


def _create_mock_session(request_func: Any) -> MagicMock:
    """Helper to create a mock session with async close support."""
    session = MagicMock()
    session.closed = False
    session.close = AsyncMock()
    session.request = request_func
    return session


def test_format_url() -> None:
    """Test URL normalization."""
    assert format_url("pikvm.local") == "https://pikvm.local"
    assert format_url("http://192.168.1.100") == "http://192.168.1.100"
    assert format_url("https://192.168.1.100/") == "https://192.168.1.100"
    assert format_url("  pikvm.local:8443/  ") == "https://pikvm.local:8443"


def test_client_totp_setup() -> None:
    """Test TOTP initialization."""
    valid_secret = "JBSWY3DPEHPK3PXP"
    client = PiKVMClient("pikvm.local", totp_secret=valid_secret)
    assert client.totp_secret == valid_secret

    with pytest.raises(PiKVMAuthenticationError):
        PiKVMClient("pikvm.local", totp_secret="INVALID_BASE32!@#$")


def test_client_auth_header() -> None:
    """Test calculation of Basic auth header with and without TOTP."""
    client = PiKVMClient("pikvm.local", username="admin", password="password123")
    header = client._get_auth_header()
    assert header.startswith("Basic ")
    encoded = header.split(" ")[1]
    decoded = base64.b64decode(encoded).decode("utf-8")
    assert decoded == "admin:password123"

    # With TOTP
    client_totp = PiKVMClient(
        "pikvm.local",
        username="admin",
        password="password123",
        totp_secret="JBSWY3DPEHPK3PXP",
    )
    totp_header = client_totp._get_auth_header()
    totp_decoded = base64.b64decode(totp_header.split(" ")[1]).decode("utf-8")
    assert totp_decoded.startswith("admin:password123")
    assert len(totp_decoded) == len("admin:password123") + 6

    # With static 6-digit OTP
    client_static_otp = PiKVMClient(
        "pikvm.local",
        username="admin",
        password="password123",
        totp_secret="123456",
    )
    static_header = client_static_otp._get_auth_header()
    static_decoded = base64.b64decode(static_header.split(" ")[1]).decode("utf-8")
    assert static_decoded == "admin:password123123456"


@pytest.mark.asyncio
async def test_get_info_success(sample_info_payload: dict, sample_msd_payload: dict) -> None:
    """Test successful info and msd retrieval."""
    client = PiKVMClient("pikvm.local", verify_ssl=False)

    def mock_request(method: str, url: str, **kwargs: Any) -> MockClientResponse:
        if "/api/info" in url:
            return MockClientResponse(status=200, payload=sample_info_payload)
        if "/api/msd" in url:
            return MockClientResponse(status=200, payload=sample_msd_payload)
        return MockClientResponse(status=404)

    client._session = _create_mock_session(MagicMock(side_effect=mock_request))

    async with client:
        device = await client.get_info()
        assert device.name == "Lab PiKVM"
        assert device.serial == "a1b2c3d4e5f6"
        assert device.cpu_temp == 48.5
        assert device.msd.is_enabled is True
        assert device.msd.drive.is_mounted is True


@pytest.mark.asyncio
async def test_get_msd_failure_fallback(sample_info_payload: dict) -> None:
    """Test graceful fallback when MSD endpoint fails."""
    client = PiKVMClient("pikvm.local", verify_ssl=False)

    def mock_request(method: str, url: str, **kwargs: Any) -> MockClientResponse:
        if "/api/info" in url:
            return MockClientResponse(status=200, payload=sample_info_payload)
        return MockClientResponse(status=500, text="Internal error", raise_on_status=True)

    client._session = _create_mock_session(MagicMock(side_effect=mock_request))

    async with client:
        device = await client.get_info()
        assert device.name == "Lab PiKVM"
        assert device.msd.is_enabled is False


@pytest.mark.asyncio
async def test_auth_failure_raises() -> None:
    """Test 401 response raises PiKVMAuthenticationError."""
    client = PiKVMClient("pikvm.local", verify_ssl=False)
    client._session = _create_mock_session(
        MagicMock(return_value=MockClientResponse(status=401, text="Invalid credentials"))
    )

    async with client:
        with pytest.raises(PiKVMAuthenticationError) as exc_info:
            await client.get_info()
        assert "401" in str(exc_info.value)


@pytest.mark.asyncio
async def test_device_server_error_raises() -> None:
    """Test 502 Bad Gateway raises PiKVMDeviceError."""
    client = PiKVMClient("pikvm.local", verify_ssl=False)
    client._session = _create_mock_session(
        MagicMock(return_value=MockClientResponse(status=502, text="Bad Gateway"))
    )

    async with client:
        with pytest.raises(PiKVMDeviceError) as exc_info:
            await client.get_info()
        assert "502" in str(exc_info.value)


@pytest.mark.asyncio
async def test_api_ok_false_raises() -> None:
    """Test payload with ok=false raises PiKVMDeviceError."""
    client = PiKVMClient("pikvm.local", verify_ssl=False)
    client._session = _create_mock_session(
        MagicMock(
            return_value=MockClientResponse(
                status=200, payload={"ok": False, "error": "Hardware busy"}
            )
        )
    )

    async with client:
        with pytest.raises(PiKVMDeviceError) as exc_info:
            await client.get_info()
        assert "Hardware busy" in str(exc_info.value)


@pytest.mark.asyncio
async def test_power_action_success() -> None:
    """Test ATX power action execution."""
    client = PiKVMClient("pikvm.local", verify_ssl=False)
    client._session = _create_mock_session(
        MagicMock(return_value=MockClientResponse(status=200, payload={"ok": True, "result": True}))
    )

    async with client:
        success = await client.power_action("click")
        assert success is True


@pytest.mark.asyncio
async def test_power_action_invalid() -> None:
    """Test rejecting invalid power action argument."""
    client = PiKVMClient("pikvm.local", verify_ssl=False)
    with pytest.raises(ValueError):
        await client.power_action("destroy")


@pytest.mark.asyncio
async def test_timeout_error_handling() -> None:
    """Test mapping TimeoutError to PiKVMTimeoutError."""
    client = PiKVMClient("pikvm.local", verify_ssl=False)

    class MockTimeoutSession:
        closed = False

        def request(self, *args: Any, **kwargs: Any) -> Any:
            raise TimeoutError("Request timed out")

        async def close(self) -> None:
            pass

    client._session = MockTimeoutSession()  # type: ignore[assignment]

    async with client:
        with pytest.raises(PiKVMTimeoutError):
            await client.get_info()


@pytest.mark.asyncio
async def test_connection_error_handling() -> None:
    """Test mapping ClientConnectorError to PiKVMConnectionError."""
    client = PiKVMClient("pikvm.local", verify_ssl=False)

    class MockConnErrorSession:
        closed = False

        def request(self, *args: Any, **kwargs: Any) -> Any:
            raise aiohttp.ClientConnectorError(
                connection_key=MagicMock(),
                os_error=OSError("Cannot connect"),
            )

        async def close(self) -> None:
            pass

    client._session = MockConnErrorSession()  # type: ignore[assignment]

    async with client:
        with pytest.raises(PiKVMConnectionError):
            await client.get_info()


@pytest.mark.asyncio
async def test_non_dict_response_raises() -> None:
    """Test handling invalid non-dict JSON response."""
    client = PiKVMClient("pikvm.local", verify_ssl=False)
    client._session = _create_mock_session(
        MagicMock(return_value=MockClientResponse(status=200, payload="Not a dictionary"))
    )

    async with client:
        with pytest.raises(PiKVMDeviceError):
            await client.get_info()


def test_client_custom_ssl_context() -> None:
    """Test initializing client with custom pre-configured SSL context."""
    custom_ctx = MagicMock()
    client = PiKVMClient("pikvm.local", ssl_context=custom_ctx)
    assert client._ssl_context is custom_ctx

