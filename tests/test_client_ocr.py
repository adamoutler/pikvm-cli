"""Unit tests for PiKVMClient OCR operations."""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from pikvm_aio.client import PiKVMClient


@pytest.mark.asyncio
async def test_get_ocr_text_full_screen() -> None:
    client = PiKVMClient("pikvm.local", verify_ssl=False)
    session = MagicMock()
    session.closed = False
    session.close = AsyncMock()

    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_resp.raise_for_status = MagicMock()
    mock_resp.text = AsyncMock(return_value="Ubuntu 24.04 LTS login:\n")

    class MockContext:
        async def __aenter__(self) -> MagicMock:
            return mock_resp

        async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
            pass

    session.get = MagicMock(return_value=MockContext())
    client._session = session

    async with client:
        text = await client.get_ocr_text(langs="eng", allow_offline=True)

    assert "Ubuntu 24.04" in text
    call_args = session.get.call_args
    assert "/api/streamer/snapshot" in call_args[0][0]
    assert call_args[1]["params"]["ocr"] == "1"
    assert call_args[1]["params"]["ocr_langs"] == "eng"
    assert "ocr_left" not in call_args[1]["params"]


@pytest.mark.asyncio
async def test_get_ocr_text_bounded_box() -> None:
    client = PiKVMClient("pikvm.local", verify_ssl=False)
    session = MagicMock()
    session.closed = False
    session.close = AsyncMock()

    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_resp.raise_for_status = MagicMock()
    mock_resp.text = AsyncMock(return_value="camserver login:")

    class MockContext:
        async def __aenter__(self) -> MagicMock:
            return mock_resp

        async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
            pass

    session.get = MagicMock(return_value=MockContext())
    client._session = session

    async with client:
        text = await client.get_ocr_text(left=0, top=2, right=281, bottom=81, langs="eng")

    assert text == "camserver login:"
    call_args = session.get.call_args
    params = call_args[1]["params"]
    assert params["ocr_left"] == "0"
    assert params["ocr_top"] == "2"
    assert params["ocr_right"] == "281"
    assert params["ocr_bottom"] == "81"
