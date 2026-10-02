"""Unit tests for PiKVM-CLI expanded subcommands."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from pikvm_aio.cli import async_main, build_parser, normalize_cli_args


@pytest.mark.asyncio
async def test_cli_iso_upload(tmp_path: Path) -> None:
    iso_file = tmp_path / "test.iso"
    iso_file.write_bytes(b"DATA")

    parser = build_parser()
    args = parser.parse_args(["-H", "pikvm.local", "iso", "upload", str(iso_file)])

    with patch(
        "pikvm_aio.client.PiKVMClient.upload_msd_image", new=AsyncMock(return_value=True)
    ) as mock_upload:
        ret = await async_main(args)
        assert ret == 0
        mock_upload.assert_awaited()


@pytest.mark.asyncio
async def test_cli_iso_mount_unmount() -> None:
    parser = build_parser()

    # mount
    args_mount = parser.parse_args(["-H", "pikvm.local", "iso", "mount", "test.iso", "--rw"])
    with patch(
        "pikvm_aio.client.PiKVMClient.mount_msd_image", new=AsyncMock(return_value=True)
    ) as mock_mount:
        ret = await async_main(args_mount)
        assert ret == 0
        mock_mount.assert_awaited_with(image="test.iso", cdrom=True, rw=True, connect=True)

    # unmount
    args_unmount = parser.parse_args(["-H", "pikvm.local", "iso", "unmount"])
    with patch(
        "pikvm_aio.client.PiKVMClient.unmount_msd_image", new=AsyncMock(return_value=True)
    ) as mock_unmount:
        ret = await async_main(args_unmount)
        assert ret == 0
        mock_unmount.assert_awaited_with(disconnect=True)


@pytest.mark.asyncio
async def test_cli_hid_subcommands(tmp_path: Path) -> None:
    parser = build_parser()

    # key
    args_key = parser.parse_args(["-H", "pikvm.local", "hid", "key", "Enter"])
    with patch(
        "pikvm_aio.client.PiKVMClient.send_key", new=AsyncMock(return_value=True)
    ) as mock_key:
        assert await async_main(args_key) == 0
        mock_key.assert_awaited_with("Enter", state=True, finish=False)

    # tap
    args_tap = parser.parse_args(["-H", "pikvm.local", "hid", "tap", "KeyA"])
    with patch(
        "pikvm_aio.client.PiKVMClient.tap_key", new=AsyncMock(return_value=True)
    ) as mock_tap:
        assert await async_main(args_tap) == 0
        mock_tap.assert_awaited_with("KeyA", delay=0.05)

    # text
    args_text = parser.parse_args(["-H", "pikvm.local", "hid", "text", "hello world", "--slow"])
    with patch(
        "pikvm_aio.client.PiKVMClient.print_text", new=AsyncMock(return_value=True)
    ) as mock_text:
        assert await async_main(args_text) == 0
        mock_text.assert_awaited_with(text="hello world", keymap=None, delay=None, slow=True)

    # shortcut
    args_sc = parser.parse_args(
        ["-H", "pikvm.local", "hid", "shortcut", "ControlLeft", "AltLeft", "Delete"]
    )
    with patch(
        "pikvm_aio.client.PiKVMClient.send_shortcut", new=AsyncMock(return_value=True)
    ) as mock_sc:
        assert await async_main(args_sc) == 0
        mock_sc.assert_awaited_with(["ControlLeft", "AltLeft", "Delete"])

    # click
    args_click = parser.parse_args(
        ["-H", "pikvm.local", "hid", "click", "--button", "right", "--to", "10,20"]
    )
    with patch(
        "pikvm_aio.client.PiKVMClient.click_mouse", new=AsyncMock(return_value=True)
    ) as mock_click:
        assert await async_main(args_click) == 0
        mock_click.assert_awaited_with(button="right", to_x=10, to_y=20, double_click=False)

    # macro run
    script_file = tmp_path / "script.json"
    script_file.write_text(
        json.dumps([{"event_type": "key", "event": {"key": "Enter"}}]), encoding="utf-8"
    )
    args_macro = parser.parse_args(["-H", "pikvm.local", "hid", "macro", "run", str(script_file)])
    with patch(
        "pikvm_aio.client.PiKVMClient.play_macro", new=AsyncMock(return_value=[True])
    ) as mock_macro:
        assert await async_main(args_macro) == 0
        mock_macro.assert_awaited()


@pytest.mark.asyncio
async def test_cli_ocr() -> None:
    parser = build_parser()
    args_ocr = parser.parse_args(
        normalize_cli_args(["-H", "pikvm.local", "ocr", "--xywh", "0,2,281,79", "--json"])
    )

    with patch(
        "pikvm_aio.client.PiKVMClient.get_ocr_text", new=AsyncMock(return_value="login:")
    ) as mock_ocr:
        ret = await async_main(args_ocr)
        assert ret == 0
        mock_ocr.assert_awaited_with(left=0, top=2, right=281, bottom=81, langs="eng")


@pytest.mark.asyncio
async def test_cli_gpio() -> None:
    parser = build_parser()

    # read
    args_read = parser.parse_args(["-H", "pikvm.local", "gpio", "read"])
    with patch(
        "pikvm_aio.client.PiKVMClient.read_gpio", new=AsyncMock(return_value={"state": {}})
    ) as mock_read:
        assert await async_main(args_read) == 0
        mock_read.assert_awaited()

    # switch
    args_sw = parser.parse_args(["-H", "pikvm.local", "gpio", "switch", "relay1", "on"])
    with patch(
        "pikvm_aio.client.PiKVMClient.switch_gpio", new=AsyncMock(return_value=True)
    ) as mock_sw:
        assert await async_main(args_sw) == 0
        mock_sw.assert_awaited_with("relay1", state=True, wait=False)

    # pulse
    args_pulse = parser.parse_args(
        ["-H", "pikvm.local", "gpio", "pulse", "pwr_btn", "--delay", "0.2"]
    )
    with patch(
        "pikvm_aio.client.PiKVMClient.pulse_gpio", new=AsyncMock(return_value=True)
    ) as mock_pulse:
        assert await async_main(args_pulse) == 0
        mock_pulse.assert_awaited_with("pwr_btn", delay=0.2, wait=False)
