"""Unit tests for pikvm-cli."""

from __future__ import annotations

import json
from pathlib import Path
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


def test_cli_user_reported_invocations() -> None:
    """Test the exact CLI command patterns reported by user."""
    from pikvm_aio.cli import normalize_cli_args

    parser = build_parser()

    # 1. pikvm-cli 192.168.1.108 -k
    norm = normalize_cli_args(["192.168.1.108", "-k"])
    args = parser.parse_args(norm)
    assert args.host == "192.168.1.108"
    assert args.insecure is True
    assert args.command == "info"

    # 2. pikvm-cli 192.168.1.108 health -k
    norm = normalize_cli_args(["192.168.1.108", "health", "-k"])
    args = parser.parse_args(norm)
    assert args.host == "192.168.1.108"
    assert args.insecure is True
    assert args.command == "health"

    # 3. pikvm-cli health 192.168.1.108 -k
    norm = normalize_cli_args(["health", "192.168.1.108", "-k"])
    args = parser.parse_args(norm)
    assert args.host == "192.168.1.108"
    assert args.insecure is True
    assert args.command == "health"

    # 4. pikvm-cli info 192.168.1.108 -k
    norm = normalize_cli_args(["info", "192.168.1.108", "-k"])
    args = parser.parse_args(norm)
    assert args.host == "192.168.1.108"
    assert args.insecure is True
    assert args.command == "info"

    # 5. pikvm-cli info 192.168.1.108
    norm = normalize_cli_args(["info", "192.168.1.108"])
    args = parser.parse_args(norm)
    assert args.host == "192.168.1.108"
    assert args.insecure is False
    assert args.command == "info"


@pytest.mark.asyncio
async def test_cli_end_to_end_positional_host_and_insecure(
    capsys: pytest.CaptureFixture, sample_info_payload: dict
) -> None:
    """Test full async_main execution with normalized positional host and -k."""
    from pikvm_aio.cli import normalize_cli_args

    mock_device = PiKVMDeviceInfo.from_dict(sample_info_payload["result"])
    parser = build_parser()
    args = parser.parse_args(normalize_cli_args(["192.168.1.108", "health", "-k"]))

    with patch("pikvm_aio.client.PiKVMClient.get_info", new=AsyncMock(return_value=mock_device)):
        code = await async_main(args)
        assert code == 0
        captured = capsys.readouterr()
        assert "CPU Temperature: 48.5 °C" in captured.out


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


def test_cli_load_cert_helper(tmp_path: Path) -> None:
    """Test _load_cert helper with file, string, and None."""
    from pikvm_aio.cli import _load_cert

    assert _load_cert(None) is None
    assert _load_cert("some-raw-cert-pem") == "some-raw-cert-pem"

    cert_file = tmp_path / "cert.pem"
    cert_file.write_text("cert-from-file", encoding="utf-8")
    assert _load_cert(str(cert_file)) == "cert-from-file"


@pytest.mark.asyncio
async def test_cli_fetch_cert_output_file(
    tmp_path: Path, capsys: pytest.CaptureFixture, sample_cert_pem: str
) -> None:
    """Test fetch-cert command saving to output file."""
    out_file = tmp_path / "saved.crt"
    parser = build_parser()
    args = parser.parse_args(["-H", "pikvm.local", "fetch-cert", "-o", str(out_file)])

    with patch("pikvm_aio.cli.fetch_remote_cert", new=AsyncMock(return_value=sample_cert_pem)):
        code = await async_main(args)
        assert code == 0
        assert out_file.read_text(encoding="utf-8") == sample_cert_pem
        captured = capsys.readouterr()
        assert "Certificate successfully written to" in captured.out
        assert "SHA256 Fingerprint:" in captured.out


@pytest.mark.asyncio
async def test_cli_fetch_cert_error_handling(capsys: pytest.CaptureFixture) -> None:
    """Test fetch-cert command when an exception is raised."""
    from pikvm_aio.exceptions import PiKVMConnectionError

    parser = build_parser()
    args = parser.parse_args(["-H", "pikvm.local", "fetch-cert"])

    with patch(
        "pikvm_aio.cli.fetch_remote_cert",
        new=AsyncMock(side_effect=PiKVMConnectionError("Connection failed")),
    ):
        code = await async_main(args)
        assert code == 1
        captured = capsys.readouterr()
        assert "Error fetching certificate: Connection failed" in captured.err


@pytest.mark.asyncio
async def test_cli_collect_output_file(
    tmp_path: Path,
    capsys: pytest.CaptureFixture,
    sample_info_payload: dict,
    sample_msd_payload: dict,
) -> None:
    """Test collect command with -o output file."""
    out_file = tmp_path / "diag.json"
    parser = build_parser()
    args = parser.parse_args(["-H", "pikvm.local", "collect", "-o", str(out_file)])

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
        assert out_file.exists()
        saved = json.loads(out_file.read_text(encoding="utf-8"))
        assert "Device" in saved
        assert "Performance" in saved
        assert "MSD" in saved
        captured = capsys.readouterr()
        assert f"Saved diagnostic report to {out_file}" in captured.out


@pytest.mark.asyncio
async def test_cli_iso_download_commands(capsys: pytest.CaptureFixture) -> None:
    """Test iso download CLI command in text and json mode."""
    from pikvm_aio.models import MsdRemoteProgress

    parser = build_parser()

    # Text mode
    args_text = parser.parse_args(
        [
            "-H",
            "pikvm.local",
            "iso",
            "download",
            "http://example.com/test.iso",
            "--name",
            "test.iso",
        ]
    )

    async def mock_download_text(*args, **kwargs):
        yield MsdRemoteProgress(
            status="ok", written_bytes=1024, percent=100.0, raw={"status": "ok"}
        )

    with patch("pikvm_aio.client.PiKVMClient.download_msd_remote", side_effect=mock_download_text):
        code = await async_main(args_text)
        assert code == 0
        captured = capsys.readouterr()
        assert "Download finished." in captured.out

    # JSON mode
    args_json = parser.parse_args(
        ["-H", "pikvm.local", "--json", "iso", "download", "http://example.com/test.iso"]
    )

    async def mock_download_json(*args, **kwargs):
        yield MsdRemoteProgress(
            status="ok", written_bytes=2048, percent=50.0, raw={"status": "downloading"}
        )

    with patch("pikvm_aio.client.PiKVMClient.download_msd_remote", side_effect=mock_download_json):
        code = await async_main(args_json)
        assert code == 0
        captured = capsys.readouterr()
        assert '"status": "downloading"' in captured.out
