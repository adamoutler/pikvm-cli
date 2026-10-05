"""Unit tests for safety errors, hardware confirmation gates, and upload rollback safety."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from pikvm_aio.client import PiKVMClient
from pikvm_aio.exceptions import (
    PiKVMDeviceError,
    PiKVMSafetyError,
    PiKVMTimeoutError,
    PiKVMValidationError,
)
from pikvm_aio.models import MsdInfo, MsdStorage


@pytest.mark.asyncio
async def test_power_action_safety_error_when_not_force() -> None:
    """Verify off_hard and reset_hard require force=True."""
    client = PiKVMClient("pikvm.local", verify_ssl=False)

    with pytest.raises(PiKVMSafetyError, match="requires explicit force=True confirmation"):
        await client.power_action("off_hard")

    with pytest.raises(PiKVMSafetyError, match="requires explicit force=True confirmation"):
        await client.power_action("reset_hard")


@pytest.mark.asyncio
async def test_power_action_success_with_force() -> None:
    """Verify off_hard and reset_hard succeed when force=True."""
    client = PiKVMClient("pikvm.local", verify_ssl=False)
    client._request = AsyncMock(return_value={"ok": True})

    assert await client.power_action("off_hard", force=True) is True
    client._request.assert_awaited_with("POST", "/api/atx/power", params={"action": "off_hard"})

    assert await client.power_action("reset_hard", force=True) is True
    client._request.assert_awaited_with("POST", "/api/atx/power", params={"action": "reset_hard"})


@pytest.mark.asyncio
async def test_reset_msd_safety_error_when_not_force() -> None:
    """Verify reset_msd raises PiKVMSafetyError when force=True is omitted."""
    client = PiKVMClient("pikvm.local", verify_ssl=False)
    with pytest.raises(PiKVMSafetyError, match="requires explicit force=True confirmation"):
        await client.reset_msd()


@pytest.mark.asyncio
async def test_reset_msd_success_with_force() -> None:
    """Verify reset_msd succeeds when force=True is provided."""
    client = PiKVMClient("pikvm.local", verify_ssl=False)
    client._request = AsyncMock(return_value={"ok": True})
    assert await client.reset_msd(force=True) is True
    client._request.assert_awaited_with("POST", "/api/msd/reset")


@pytest.mark.asyncio
async def test_play_macro_max_steps_exceeded() -> None:
    """Verify macro exceeding max_steps limit is rejected with PiKVMValidationError."""
    client = PiKVMClient("pikvm.local", verify_ssl=False)
    steps = [{"event_type": "delay", "event": {"millis": 1}}] * 1001

    with pytest.raises(PiKVMValidationError, match="Macro step count .* exceeds maximum"):
        await client.play_macro(steps, max_steps=1000)


@pytest.mark.asyncio
async def test_play_macro_invalid_type() -> None:
    """Verify invalid macro argument type raises PiKVMValidationError."""
    client = PiKVMClient("pikvm.local", verify_ssl=False)
    with pytest.raises(PiKVMValidationError, match="Unsupported macro input type"):
        await client.play_macro("not_a_valid_macro_type")  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_play_macro_hardware_safety_error() -> None:
    """Verify macro with GPIO/ATX operations raises PiKVMSafetyError without permission."""
    client = PiKVMClient("pikvm.local", verify_ssl=False)

    macro_with_gpio = [{"event_type": "gpio_switch", "event": {"channel": "relay", "state": True}}]
    with pytest.raises(PiKVMSafetyError, match="requires allow_hardware_control=True"):
        await client.play_macro(macro_with_gpio)

    macro_with_pulse = [{"event_type": "gpio_pulse", "event": {"channel": "btn"}}]
    with pytest.raises(PiKVMSafetyError, match="requires allow_hardware_control=True"):
        await client.play_macro(macro_with_pulse)

    macro_with_atx = [{"event_type": "atx_button", "event": {"button": "power"}}]
    with pytest.raises(PiKVMSafetyError, match="requires allow_hardware_control=True"):
        await client.play_macro(macro_with_atx)


@pytest.mark.asyncio
async def test_play_macro_timeout_exceeded() -> None:
    """Verify macro exceeding execution timeout raises PiKVMTimeoutError."""
    client = PiKVMClient("pikvm.local", verify_ssl=False)

    async def slow_action(*args: Any, **kwargs: Any) -> bool:
        await asyncio.sleep(0.5)
        return True

    client.send_key = slow_action  # type: ignore[method-assign]
    steps = [{"event_type": "key", "event": {"key": "Enter"}}]

    with pytest.raises(PiKVMTimeoutError, match="timed out after"):
        await client.play_macro(steps, timeout=0.01)


@pytest.mark.asyncio
async def test_move_mouse_bounds_validation() -> None:
    """Verify move_mouse validates coordinate bounds."""
    client = PiKVMClient("pikvm.local", verify_ssl=False)

    with pytest.raises(PiKVMValidationError, match="to_x .* out of safe bounds"):
        await client.move_mouse(-10, 100)

    with pytest.raises(PiKVMValidationError, match="to_y .* out of safe bounds"):
        await client.move_mouse(100, 5000)


@pytest.mark.asyncio
async def test_send_mouse_button_validation() -> None:
    """Verify send_mouse_button validates button identifier."""
    client = PiKVMClient("pikvm.local", verify_ssl=False)

    with pytest.raises(PiKVMValidationError, match="Invalid mouse button"):
        await client.send_mouse_button("unknown_btn")


@pytest.mark.asyncio
async def test_click_mouse_bounds_and_delays() -> None:
    """Verify click_mouse validates coordinates, button, and delays."""
    client = PiKVMClient("pikvm.local", verify_ssl=False)

    with pytest.raises(PiKVMValidationError, match="Both to_x and to_y must be provided"):
        await client.click_mouse(to_x=100, to_y=None)

    with pytest.raises(PiKVMValidationError, match="Both to_x and to_y must be provided"):
        await client.click_mouse(to_x=None, to_y=200)

    with pytest.raises(PiKVMValidationError, match="Mouse delay .* out of safe bounds"):
        await client.click_mouse(delay=-0.1)


@pytest.mark.asyncio
async def test_switch_gpio_validation() -> None:
    """Verify switch_gpio validates channel format."""
    client = PiKVMClient("pikvm.local", verify_ssl=False)

    with pytest.raises(PiKVMValidationError, match="Invalid GPIO channel"):
        await client.switch_gpio("bad channel name with spaces!", True)


@pytest.mark.asyncio
async def test_pulse_gpio_validation() -> None:
    """Verify pulse_gpio validates channel and delay bounds."""
    client = PiKVMClient("pikvm.local", verify_ssl=False)

    with pytest.raises(PiKVMValidationError, match="Invalid GPIO channel"):
        await client.pulse_gpio("invalid@channel")

    with pytest.raises(PiKVMValidationError, match="GPIO pulse delay .* out of safe range"):
        await client.pulse_gpio("valid_channel", delay=0.001)


@pytest.mark.asyncio
async def test_upload_msd_image_preserves_preexisting_on_rollback(tmp_path: Path) -> None:
    """Verify that an interrupted upload of a pre-existing image
    does NOT delete the golden image.
    """
    iso_file = tmp_path / "existing.iso"
    iso_file.write_bytes(b"NEW_DATA" * 500)

    client = PiKVMClient("pikvm.local", verify_ssl=False)

    # Mock get_msd() returning existing image in storage
    mock_storage = MagicMock(spec=MsdStorage)
    mock_storage.images = ["existing.iso", "other.iso"]
    mock_msd_info = MagicMock(spec=MsdInfo)
    mock_msd_info.storage = mock_storage

    client.get_msd = AsyncMock(return_value=mock_msd_info)  # type: ignore[method-assign]
    client.remove_msd_image = AsyncMock()  # type: ignore[method-assign]

    # Session upload fails
    session = MagicMock()
    session.closed = False
    session.close = AsyncMock()

    class MockFailingUploadResp:
        status = 500

        async def text(self) -> str:
            return "Internal error"

        async def __aenter__(self) -> MockFailingUploadResp:
            return self

        async def __aexit__(self, *args: Any) -> None:
            pass

    session.post = MagicMock(return_value=MockFailingUploadResp())
    client._session = session

    async with client:
        with pytest.raises(PiKVMDeviceError, match="MSD upload failed"):
            await client.upload_msd_image(
                file_path=iso_file,
                remove_incomplete=True,
            )

    # Verify remove_msd_image was NOT called, preserving remote storage image
    client.remove_msd_image.assert_not_called()
