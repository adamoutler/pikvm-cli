"""Unit tests for PiKVMClient GPIO operations."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from pikvm_aio.client import PiKVMClient


@pytest.mark.asyncio
async def test_gpio_operations() -> None:
    client = PiKVMClient("pikvm.local", verify_ssl=False)
    client._request = AsyncMock(return_value={"ok": True})

    async with client:
        # Read GPIO
        client._request.return_value = {"state": {"inputs": {}, "outputs": {}}}
        res = await client.read_gpio()
        assert "state" in res
        client._request.assert_awaited_with("GET", "/api/gpio")

        # Switch GPIO
        client._request.return_value = {"ok": True}
        assert await client.switch_gpio("relay1", state=True, wait=True) is True
        client._request.assert_awaited_with(
            "POST", "/api/gpio/switch", params={"channel": "relay1", "state": "1", "wait": "1"}
        )

        # Pulse GPIO
        assert await client.pulse_gpio("power_btn", delay=0.5, wait=False) is True
        client._request.assert_awaited_with(
            "POST", "/api/gpio/pulse", params={"channel": "power_btn", "wait": "0", "delay": "0.5"}
        )
