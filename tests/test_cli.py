"""Unit tests for pikvm-cli."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

import pytest

from pikvm_aio.cli import async_main, build_parser
from pikvm_aio.exceptions import PiKVMAuthenticationError
from pikvm_aio.models import MsdInfo, PiKVMDeviceInfo


def test_cli_parser_defaults() -> None:
    """Test CLI argument parsing."""
    parser = build_parser()
    args = parser.parse_args(["-H", "pikvm.local", "info"])
    assert args.host == "pikvm.local"
    assert args.username == "admin"
    assert args.password == "admin"
    assert args.command == "info"
    assert args.insecure is False


@pytest.mark.asyncio
async def test_cli_missing_host(capsys: pytest.CaptureFixture) -> None:
    """Test error when no host is provided."""
    parser = build_parser()
    args = parser.parse_args(["info"])
    code = await async_main(args)
    assert code == 1
    captured = capsys.readouterr()
    assert "PiKVM host not specified" in captured.err


@pytest.mark.asyncio
async def test_cli_fetch_cert(capsys: pytest.CaptureFixture, sample_cert_pem: str) -> None:
    """Test fetch-cert command."""
    parser = build_parser()
    args = parser.parse_args(["-H", "pikvm.local", "fetch-cert"])

    with patch("pikvm_aio.cli.fetch_remote_cert", new=AsyncMock(return_value=sample_cert_pem)):
        code = await async_main(args)
        assert code == 0
        captured = capsys.readouterr()
        assert "-----BEGIN CERTIFICATE-----" in captured.out


@pytest.mark.asyncio
async def test_cli_info_and_json(
    capsys: pytest.CaptureFixture,
    sample_info_payload: dict,
    sample_msd_payload: dict,
) -> None:
    """Test info command in text and json mode."""
    raw = dict(sample_info_payload["result"])
    raw["msd"] = sample_msd_payload["result"]
    mock_device = PiKVMDeviceInfo.from_dict(raw)

    parser = build_parser()
    args = parser.parse_args(["-H", "pikvm.local", "--json", "info"])

    with patch.object(PiKVMDeviceInfo, "from_dict", return_value=mock_device):
        with patch(
            "pikvm_aio.client.PiKVMClient.get_info", new=AsyncMock(return_value=mock_device)
        ):
            code = await async_main(args)
            assert code == 0
            captured = capsys.readouterr()
            data = json.loads(captured.out)
            assert "hw" in data


@pytest.mark.asyncio
async def test_cli_health(capsys: pytest.CaptureFixture, sample_info_payload: dict) -> None:
    """Test health command."""
    mock_device = PiKVMDeviceInfo.from_dict(sample_info_payload["result"])
    parser = build_parser()
    args = parser.parse_args(["-H", "pikvm.local", "health"])

    with patch("pikvm_aio.client.PiKVMClient.get_info", new=AsyncMock(return_value=mock_device)):
        code = await async_main(args)
        assert code == 0
        captured = capsys.readouterr()
        assert "CPU Temperature: 48.5 °C" in captured.out
        assert "Throttled: False" in captured.out


@pytest.mark.asyncio
async def test_cli_msd(capsys: pytest.CaptureFixture, sample_msd_payload: dict) -> None:
    """Test msd command."""
    from pikvm_aio.models import MsdInfo

    mock_msd = MsdInfo.from_dict(sample_msd_payload["result"])
    parser = build_parser()
    args = parser.parse_args(["-H", "pikvm.local", "msd"])

    with patch("pikvm_aio.client.PiKVMClient.get_msd", new=AsyncMock(return_value=mock_msd)):
        code = await async_main(args)
        assert code == 0
        captured = capsys.readouterr()
        assert "Drive Mounted: True" in captured.out
        assert "Total Storage (MB): 15360.0" in captured.out


@pytest.mark.asyncio
async def test_cli_power(capsys: pytest.CaptureFixture) -> None:
    """Test power command."""
    parser = build_parser()
    args = parser.parse_args(["-H", "pikvm.local", "power", "click"])

    with patch("pikvm_aio.client.PiKVMClient.power_action", new=AsyncMock(return_value=True)):
        code = await async_main(args)
        assert code == 0
        captured = capsys.readouterr()
        assert "ATX power action 'click' succeeded" in captured.out


@pytest.mark.asyncio
async def test_cli_auth_error(capsys: pytest.CaptureFixture) -> None:
    """Test handling authentication failure gracefully in CLI."""
    parser = build_parser()
    args = parser.parse_args(["-H", "pikvm.local", "info"])

    with patch(
        "pikvm_aio.client.PiKVMClient.get_info",
        side_effect=PiKVMAuthenticationError("Invalid credentials"),
    ):
        code = await async_main(args)
        assert code == 1
        captured = capsys.readouterr()
        assert "PiKVM Error: Invalid credentials" in captured.err


@pytest.mark.asyncio
async def test_cli_collect(
    capsys: pytest.CaptureFixture, sample_info_payload: dict, sample_msd_payload: dict
) -> None:
    """Test collect command."""
    parser = build_parser()
    args = parser.parse_args(["-H", "pikvm.local", "collect"])

    combined = dict(sample_info_payload["result"])
    combined["msd"] = sample_msd_payload["result"]
    mock_dev_info = PiKVMDeviceInfo.from_dict(combined)
    mock_msd_info = MsdInfo.from_dict(sample_msd_payload["result"])
    mock_diag = {
        "info": combined,
        "msd": sample_msd_payload["result"],
        "atx": {"enabled": True},
        "gpio": {},
        "hid": {},
        "streamer": {},
    }

    with (
        patch("pikvm_aio.client.PiKVMClient.get_info", new=AsyncMock(return_value=mock_dev_info)),
        patch("pikvm_aio.client.PiKVMClient.get_msd", new=AsyncMock(return_value=mock_msd_info)),
        patch(
            "pikvm_aio.client.PiKVMClient.get_all_diagnostics",
            new=AsyncMock(return_value=mock_diag),
        ),
    ):
        code = await async_main(args)
        assert code == 0
        captured = capsys.readouterr()
        assert "Device:" in captured.out
        assert "Performance:" in captured.out
        assert "MSD:" in captured.out
        assert "ATX:" in captured.out


def test_cli_accept_any_cert_flag() -> None:
    """Test --accept-any-cert option."""
    parser = build_parser()
    args1 = parser.parse_args(["-H", "pikvm.local", "--accept-any-cert"])
    assert args1.insecure is True
    assert args1.command == "info"

    args2 = parser.parse_args(["-H", "pikvm.local", "-k"])
    assert args2.insecure is True

    args3 = parser.parse_args(["-H", "pikvm.local", "--verify-ssl"])
    assert args3.insecure is False


def test_cli_normalize_args() -> None:
    """Test argument normalization for positional host and subcommands."""
    from pikvm_aio.cli import normalize_cli_args

    assert normalize_cli_args(["192.168.1.108"]) == ["-H", "192.168.1.108", "info"]
    assert normalize_cli_args(["192.168.1.108", "info"]) == ["-H", "192.168.1.108", "info"]
    assert normalize_cli_args(["info", "192.168.1.108"]) == ["-H", "192.168.1.108", "info"]
    assert normalize_cli_args(["192.168.1.108", "--accept-any-cert"]) == [
        "-H",
        "192.168.1.108",
        "--accept-any-cert",
        "info",
    ]
    assert normalize_cli_args(["192.168.1.108", "fetch-cert", "--json"]) == [
        "-H",
        "192.168.1.108",
        "--json",
        "fetch-cert",
    ]
    assert normalize_cli_args(["192.168.1.108", "power", "click"]) == [
        "-H",
        "192.168.1.108",
        "power",
        "click",
    ]


@pytest.mark.asyncio
async def test_cli_fetch_cert_json(capsys: pytest.CaptureFixture, sample_cert_pem: str) -> None:
    """Test fetch-cert command with --json."""
    parser = build_parser()
    args = parser.parse_args(["-H", "pikvm.local", "--json", "fetch-cert"])

    with patch("pikvm_aio.cli.fetch_remote_cert", new=AsyncMock(return_value=sample_cert_pem)):
        code = await async_main(args)
        assert code == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["host"] == "pikvm.local"
        assert "-----BEGIN CERTIFICATE-----" in data["certificate"]
