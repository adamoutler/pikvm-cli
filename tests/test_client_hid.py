"""Unit tests for PiKVMClient HID operations and macro execution."""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from pikvm_aio.client import PiKVMClient
from pikvm_aio.models import HidDeviceState, KeyboardKeymaps


@pytest.mark.asyncio
async def test_get_hid_state() -> None:
    client = PiKVMClient("pikvm.local", verify_ssl=False)
    client._request = AsyncMock(
        return_value={
            "online": True,
            "busy": False,
            "keyboard": {"online": True, "leds": {"caps": True, "num": False, "scroll": False}},
            "mouse": {"online": True},
            "jiggler": {"active": False},
        }
    )

    async with client:
        state = await client.get_hid_state()

    assert isinstance(state, HidDeviceState)
    assert state.online is True
    assert state.caps_lock is True
    assert state.num_lock is False
    assert state.keyboard_online is True


@pytest.mark.asyncio
async def test_get_keymaps() -> None:
    client = PiKVMClient("pikvm.local", verify_ssl=False)
    client._request = AsyncMock(
        return_value={"keymaps": {"available": ["en-us", "de", "fr"], "default": "en-us"}}
    )

    async with client:
        keymaps = await client.get_keymaps()

    assert isinstance(keymaps, KeyboardKeymaps)
    assert keymaps.default == "en-us"
    assert "de" in keymaps.available


@pytest.mark.asyncio
async def test_send_key_and_tap() -> None:
    client = PiKVMClient("pikvm.local", verify_ssl=False)
    client._request = AsyncMock(return_value={"ok": True})

    async with client:
        assert await client.send_key("Enter", state=True) is True
        client._request.assert_awaited_with(
            "POST", "/api/hid/events/send_key", params={"key": "Enter", "state": "1"}
        )

        # Tap key
        assert await client.tap_key("KeyA", delay=0.01) is True
        assert client._request.await_count == 3


@pytest.mark.asyncio
async def test_send_shortcut() -> None:
    client = PiKVMClient("pikvm.local", verify_ssl=False)
    client._request = AsyncMock(return_value={"ok": True})

    async with client:
        assert await client.send_shortcut("ctrl+alt+del") is True
        client._request.assert_awaited_with(
            "POST",
            "/api/hid/events/send_shortcut",
            params={"keys": "ControlLeft,AltLeft,Delete"},
        )


@pytest.mark.asyncio
async def test_print_text() -> None:
    client = PiKVMClient("pikvm.local", verify_ssl=False)
    session = MagicMock()
    session.closed = False
    session.close = AsyncMock()

    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_resp.raise_for_status = MagicMock()
    mock_resp.json = AsyncMock(return_value={"ok": True})

    class MockContext:
        async def __aenter__(self) -> MagicMock:
            return mock_resp

        async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
            pass

    session.post = MagicMock(return_value=MockContext())
    client._session = session

    async with client:
        assert await client.print_text("echo 'hello'\n", keymap="en-us", slow=True) is True

    call_args = session.post.call_args
    assert "/api/hid/print" in call_args[0][0]
    assert call_args[1]["data"] == b"echo 'hello'\n"
    assert call_args[1]["params"]["keymap"] == "en-us"
    assert call_args[1]["params"]["slow"] == "1"


@pytest.mark.asyncio
async def test_mouse_actions() -> None:
    client = PiKVMClient("pikvm.local", verify_ssl=False)
    client._request = AsyncMock(return_value={"ok": True})

    async with client:
        assert await client.send_mouse_button("left", state=True) is True
        client._request.assert_awaited_with(
            "POST", "/api/hid/events/send_mouse_button", params={"button": "left", "state": "1"}
        )

        assert await client.move_mouse(100, 200) is True
        client._request.assert_awaited_with(
            "POST", "/api/hid/events/send_mouse_move", params={"to_x": "100", "to_y": "200"}
        )

        # Click with move and double click
        assert (
            await client.click_mouse("right", to_x=50, to_y=50, delay=0.01, double_click=True)
            is True
        )


@pytest.mark.asyncio
async def test_play_macro() -> None:
    client = PiKVMClient("pikvm.local", verify_ssl=False)
    client.send_key = AsyncMock(return_value=True)
    client.print_text = AsyncMock(return_value=True)
    client.send_mouse_button = AsyncMock(return_value=True)
    client.move_mouse = AsyncMock(return_value=True)
    client.switch_gpio = AsyncMock(return_value=True)
    client.pulse_gpio = AsyncMock(return_value=True)
    client.power_action = AsyncMock(return_value=True)

    macro_script = [
        {"event_type": "delay", "event": {"millis": 10}},
        {"event_type": "key", "event": {"key": "Enter", "state": True}},
        {"event_type": "print", "event": {"text": "hello"}},
        {"event_type": "mouse_button", "event": {"button": "left", "state": True}},
        {"event_type": "mouse_move", "event": {"to": {"x": 10, "y": 20}}},
        {"event_type": "gpio_switch", "event": {"channel": "relay", "state": True}},
        {"event_type": "gpio_pulse", "event": {"channel": "btn"}},
        {"event_type": "atx_button", "event": {"button": "power"}},
    ]

    with patch("asyncio.sleep", new=AsyncMock()):
        results = await client.play_macro(macro_script)

    assert len(results) == 8
    assert all(results)
    client.send_key.assert_awaited()
    client.print_text.assert_awaited_with(text="hello", keymap=None, delay=None, slow=False)
    client.send_mouse_button.assert_awaited_with("left", state=True)
    client.move_mouse.assert_awaited_with(10, 20)
    client.switch_gpio.assert_awaited_with("relay", True)
    client.pulse_gpio.assert_awaited_with("btn")
    client.power_action.assert_awaited_with("power")
