"""Live integration tests against an online PiKVM hardware device.

If the configured PiKVM device is not online or reachable, tests are automatically
and cleanly skipped with pytest.skip, ensuring offline and CI runners pass without error.
"""

from __future__ import annotations

import os
import socket
from urllib.parse import unquote, urlparse

import pytest

# Ensure live socket testing is permitted even when pytest-socket is installed
try:
    import pytest_socket

    if hasattr(pytest_socket, "_remove_restrictions"):
        pytest_socket._remove_restrictions()
    elif hasattr(pytest_socket, "enable_socket"):
        pytest_socket.enable_socket()
except Exception:
    pass

from pikvm_aio import (
    PiKVMAuthenticationError,
    PiKVMClient,
    PiKVMDeviceInfo,
    fetch_remote_cert,
)
from pikvm_aio.tls import parse_host_port

LIVE_TARGET = os.environ.get("PIKVM_LIVE_HOST", "https://admin:admin@192.168.1.108")
LIVE_USER = os.environ.get("PIKVM_LIVE_USER")
LIVE_PASS = os.environ.get("PIKVM_LIVE_PASSWORD")


def is_port_open(host: str, port: int, timeout: float = 1.0) -> bool:
    """Quick socket check to verify TCP connectivity to live device."""
    try:
        import pytest_socket

        if hasattr(pytest_socket, "_remove_restrictions"):
            pytest_socket._remove_restrictions()
    except Exception:
        pass
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.close()
        return True
    except (OSError, TimeoutError):
        return False


@pytest.fixture(autouse=True)
def socket_enabled() -> None:
    """Fixture to ensure sockets are unblocked for live tests."""
    try:
        import pytest_socket

        if hasattr(pytest_socket, "_remove_restrictions"):
            pytest_socket._remove_restrictions()
        elif hasattr(pytest_socket, "enable_socket"):
            pytest_socket.enable_socket()
    except Exception:
        pass


@pytest.fixture(scope="module")
def live_device() -> dict[str, str]:
    """Verify live PiKVM device is online and yield connection parameters."""
    target = LIVE_TARGET.strip()
    parsed = urlparse(target if "://" in target else f"https://{target}")

    user = LIVE_USER or (unquote(parsed.username) if parsed.username else "admin")
    password = LIVE_PASS or (unquote(parsed.password) if parsed.password else "admin")

    hostname, port = parse_host_port(target)

    if not is_port_open(hostname, port, timeout=1.0):
        pytest.skip(f"Live PiKVM device is not reachable at {hostname}:{port}")

    return {
        "target": target,
        "hostname": hostname,
        "port": str(port),
        "username": user,
        "password": password,
    }


@pytest.mark.asyncio
async def test_live_fetch_remote_cert(live_device: dict[str, str]) -> None:
    """Validate remote TLS handshake and peer certificate extraction on live PiKVM."""
    hostname = live_device["hostname"]
    port = int(live_device["port"])

    cert_pem = await fetch_remote_cert(hostname, default_port=port, timeout=5.0)

    assert cert_pem is not None
    assert cert_pem.startswith("-----BEGIN CERTIFICATE-----")
    assert cert_pem.strip().endswith("-----END CERTIFICATE-----")
    assert len(cert_pem) > 500


@pytest.mark.asyncio
async def test_live_auth_and_get_info(live_device: dict[str, str]) -> None:
    """Validate authentication and complete model hydration from live PiKVM."""
    async with PiKVMClient(
        host=live_device["target"],
        username=live_device["username"],
        password=live_device["password"],
        verify_ssl=False,
        check_hostname=False,
        timeout=10.0,
    ) as client:
        # Validate authentication check endpoint
        auth_check = await client.get_raw_auth_check()
        assert isinstance(auth_check, dict)

        # Validate consolidated info model
        info = await client.get_info()
        assert isinstance(info, PiKVMDeviceInfo)

        # Device identity assertions
        assert info.name != ""
        known_models = ("v2", "v3", "v4", "v4plus", "v4mini", "v4-plus", "v4-mini", "pikvm")
        assert info.model.lower() in known_models
        assert len(info.serial) > 0
        assert info.kvmd_version is not None
        assert "." in info.kvmd_version

        # Telemetry & performance metrics assertions
        assert info.cpu_temp is not None
        assert 10.0 < info.cpu_temp < 95.0

        assert info.cpu_utilization is not None
        assert 0.0 <= info.cpu_utilization <= 100.0

        assert info.memory_utilization is not None
        assert 0.0 < info.memory_utilization <= 100.0

        if info.fan_speed is not None:
            assert info.fan_speed >= 0

        # Raw dictionary normalization assertions (for HA sensors compatibility)
        raw = info.raw
        assert "hw" in raw
        assert "performance" in raw["hw"]
        assert raw["hw"]["performance"]["cpu"]["utilization"] == info.cpu_utilization
        assert raw["hw"]["performance"]["memory"]["utilization"] == info.memory_utilization
        assert raw["hw"]["performance"]["fan"]["speed"] == info.fan_speed


@pytest.mark.asyncio
async def test_live_get_msd(live_device: dict[str, str]) -> None:
    """Validate Mass Storage Device status and partition space from live PiKVM."""
    async with PiKVMClient(
        host=live_device["target"],
        username=live_device["username"],
        password=live_device["password"],
        verify_ssl=False,
        check_hostname=False,
        timeout=10.0,
    ) as client:
        msd = await client.get_msd()

        assert msd.is_enabled is True
        assert isinstance(msd.drive.is_mounted, bool)

        # Partitions and capacity checks
        assert msd.storage.total_mb is not None
        assert msd.storage.total_mb > 1000.0  # Real PiKVM has at least ~1GB storage
        assert msd.storage.free_mb is not None
        assert msd.storage.free_mb > 0.0
        assert msd.storage.used_mb is not None
        assert msd.storage.percent_used is not None
        assert 0.0 <= msd.storage.percent_used <= 100.0

        # ISO images
        assert isinstance(msd.storage.images, dict)


@pytest.mark.asyncio
async def test_live_raw_endpoints_and_diagnostics(live_device: dict[str, str]) -> None:
    """Validate raw diagnostics across all KVMD endpoints on live device."""
    async with PiKVMClient(
        host=live_device["target"],
        username=live_device["username"],
        password=live_device["password"],
        verify_ssl=False,
        check_hostname=False,
        timeout=10.0,
    ) as client:
        # ATX status (read-only query)
        atx = await client.get_raw_atx()
        assert "enabled" in atx or "acts" in atx or "leds" in atx

        # GPIO status
        gpio = await client.get_raw_gpio()
        assert "state" in gpio or "model" in gpio

        # HID status
        hid = await client.get_raw_hid()
        assert "mouse" in hid or "keyboard" in hid or "online" in hid

        # Streamer status
        streamer = await client.get_raw_streamer()
        assert "streamer" in streamer or "params" in streamer or "applied" in streamer

        # Aggregated diagnostics
        diag = await client.get_all_diagnostics()
        assert set(diag.keys()) == {"info", "msd", "atx", "gpio", "hid", "streamer"}


@pytest.mark.asyncio
async def test_live_embedded_credentials_url(live_device: dict[str, str]) -> None:
    """Validate URL parsing with embedded user:pass@host on live device."""
    user = live_device["username"]
    password = live_device["password"]
    host = live_device["hostname"]
    port = live_device["port"]

    url_with_auth = f"https://{user}:{password}@{host}:{port}"
    async with PiKVMClient(
        host=url_with_auth,
        verify_ssl=False,
        check_hostname=False,
        timeout=10.0,
    ) as client:
        info = await client.get_info()
        assert info.name != ""
        assert info.serial != ""


@pytest.mark.asyncio
async def test_live_auth_failure(live_device: dict[str, str]) -> None:
    """Validate that invalid credentials on live PiKVM raise PiKVMAuthenticationError."""
    async with PiKVMClient(
        host=live_device["hostname"],
        username=live_device["username"],
        password="completely_invalid_password_for_testing_12345",
        verify_ssl=False,
        check_hostname=False,
        timeout=5.0,
    ) as client:
        with pytest.raises(PiKVMAuthenticationError):
            await client.get_info()
