"""Unit tests for PiKVMClient ISO and MSD operations."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from pikvm_aio.client import PiKVMClient
from pikvm_aio.exceptions import PiKVMAuthenticationError, PiKVMDeviceError
from pikvm_aio.models import MsdUploadProgress


class MockStreamReader:
    """Mock async stream reader."""

    def __init__(self, lines: list[bytes]) -> None:
        self._lines = lines

    def __aiter__(self) -> MockStreamReader:
        self._iter = iter(self._lines)
        return self

    async def __anext__(self) -> bytes:
        try:
            return next(self._iter)
        except StopIteration:
            raise StopAsyncIteration from None


class MockStreamResponse:
    """Mock response supporting post with streaming generator."""

    def __init__(
        self,
        status: int = 200,
        payload: Any = None,
        text: str = "",
        content_lines: list[bytes] | None = None,
    ) -> None:
        self.status = status
        self._payload = payload if payload is not None else {"ok": True, "result": {}}
        self._text = text
        self.content = MockStreamReader(content_lines or [])

    async def __aenter__(self) -> MockStreamResponse:
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        pass

    def raise_for_status(self) -> None:
        if self.status >= 400:
            raise Exception(f"HTTP {self.status}")

    async def json(self) -> Any:
        return self._payload

    async def text(self) -> str:
        return self._text


@pytest.mark.asyncio
async def test_upload_msd_image_success(tmp_path: Path) -> None:
    iso_file = tmp_path / "ubuntu.iso"
    iso_file.write_bytes(b"A" * (2 * 1024 * 1024))  # 2MB file

    progress_events: list[MsdUploadProgress] = []

    def on_progress(p: MsdUploadProgress) -> None:
        progress_events.append(p)

    client = PiKVMClient("pikvm.local", verify_ssl=False)
    session = MagicMock()
    session.closed = False
    session.close = AsyncMock()

    mock_resp = MockStreamResponse(status=200, payload={"ok": True, "result": {}})

    class MockUploadContext:
        def __init__(self, data: Any) -> None:
            self.data = data

        async def __aenter__(self) -> MockStreamResponse:
            if hasattr(self.data, "__aiter__"):
                async for _ in self.data:
                    pass
            return mock_resp

        async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
            pass

    def mock_post(url: str, **kwargs: Any) -> MockUploadContext:
        return MockUploadContext(kwargs.get("data"))

    session.post = MagicMock(side_effect=mock_post)
    client._session = session

    async with client:
        success = await client.upload_msd_image(
            file_path=iso_file,
            image_name="ubuntu.iso",
            chunk_size=1024 * 1024,
            progress_callback=on_progress,
        )

    assert success is True
    assert len(progress_events) >= 2
    assert progress_events[-1].percent == 100.0
    assert progress_events[-1].bytes_sent == 2 * 1024 * 1024
    assert progress_events[-1].speed_mbps >= 0.0

    call_args = session.post.call_args
    assert "/api/msd/write" in call_args[0][0]
    assert call_args[1]["params"]["image"] == "ubuntu.iso"
    assert call_args[1]["params"]["remove_incomplete"] == "1"


@pytest.mark.asyncio
async def test_upload_msd_image_failure_rollback(tmp_path: Path) -> None:
    iso_file = tmp_path / "corrupt.iso"
    iso_file.write_bytes(b"DATA" * 1000)

    client = PiKVMClient("pikvm.local", verify_ssl=False)
    session = MagicMock()
    session.closed = False
    session.close = AsyncMock()

    # Upload fails with 500
    mock_upload_resp = MockStreamResponse(status=500, text="Internal storage error")
    mock_rollback_resp = MockStreamResponse(status=200, payload={"ok": True, "result": {}})

    def mock_post(url: str, **kwargs: Any) -> MockStreamResponse:
        if "/api/msd/write" in url:
            return mock_upload_resp
        return mock_rollback_resp

    session.post = MagicMock(side_effect=mock_post)
    client._request = AsyncMock(return_value={"ok": True})
    client._session = session

    async with client:
        with pytest.raises(PiKVMDeviceError, match="MSD upload failed"):
            await client.upload_msd_image(
                file_path=iso_file,
                remove_incomplete=True,
            )

    # Rollback should have called remove
    client._request.assert_awaited()
    assert client._request.call_args[0][1] == "/api/msd/remove"


@pytest.mark.asyncio
async def test_upload_msd_image_auth_failure(tmp_path: Path) -> None:
    iso_file = tmp_path / "auth_test.iso"
    iso_file.write_bytes(b"DATA")

    client = PiKVMClient("pikvm.local", verify_ssl=False)
    session = MagicMock()
    session.closed = False
    session.close = AsyncMock()
    session.post = MagicMock(return_value=MockStreamResponse(status=401, text="Unauthorized"))
    client._session = session

    async with client:
        with pytest.raises(PiKVMAuthenticationError, match="Authentication failed"):
            await client.upload_msd_image(file_path=iso_file, remove_incomplete=False)


@pytest.mark.asyncio
async def test_download_msd_remote() -> None:
    client = PiKVMClient("pikvm.local", verify_ssl=False)
    session = MagicMock()
    session.closed = False
    session.close = AsyncMock()

    d1 = {
        "status": "downloading",
        "result": {"image": {"written": 1000, "size": 5000, "percent": 20.0}},
    }
    d2 = {
        "status": "downloading",
        "result": {"image": {"written": 5000, "size": 5000, "percent": 100.0}},
    }
    ndjson_lines = [
        json.dumps(d1).encode() + b"\n",
        json.dumps(d2).encode() + b"\n",
    ]
    mock_resp = MockStreamResponse(status=200, content_lines=ndjson_lines)
    session.post = MagicMock(return_value=mock_resp)
    client._session = session

    events = []
    async with client:
        async for progress in client.download_msd_remote(
            "https://example.com/live.iso", image_name="live.iso"
        ):
            events.append(progress)

    assert len(events) == 2
    assert events[0].written_bytes == 1000
    assert events[0].percent == 20.0
    assert events[1].percent == 100.0


@pytest.mark.asyncio
async def test_msd_management_helpers() -> None:
    client = PiKVMClient("pikvm.local", verify_ssl=False)
    client._request = AsyncMock(return_value={"ok": True})

    async with client:
        assert await client.remove_msd_image("old.iso") is True
        client._request.assert_awaited_with("POST", "/api/msd/remove", params={"image": "old.iso"})

        assert await client.set_msd_params(image="new.iso", cdrom=True, rw=False) is True
        client._request.assert_awaited_with(
            "POST", "/api/msd/set_params", params={"image": "new.iso", "cdrom": "1", "rw": "0"}
        )

        assert await client.set_msd_connected(True) is True
        client._request.assert_awaited_with(
            "POST", "/api/msd/set_connected", params={"connected": "1"}
        )

        assert await client.reset_msd() is True
        client._request.assert_awaited_with("POST", "/api/msd/reset")

        # Mount helper
        assert await client.mount_msd_image("boot.iso", cdrom=True, connect=True) is True

        # Unmount helper
        assert await client.unmount_msd_image(disconnect=True) is True
