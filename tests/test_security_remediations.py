"""Unit tests for secret leakage prevention and secure logging remediations."""

from __future__ import annotations

import io
import logging
import sys
from unittest.mock import AsyncMock, patch

import pytest

from pikvm_aio.cli import async_main, build_parser, main
from pikvm_aio.client import _LOGGER as client_logger
from pikvm_aio.security import (
    SensitiveDataFilter,
    attach_sensitive_data_filter,
    configure_secure_logging,
    scrub_process_argv,
)
from pikvm_aio.tls import _LOGGER as tls_logger


def test_cli_main_preserves_password_and_scrubs_argv() -> None:
    """Verify main() parses authentic password before scrubbing sys.argv."""
    original_argv = list(sys.argv)
    sys.argv = ["pikvm-cli", "-H", "pikvm.local", "-p", "supersecret123", "-t", "654321", "info"]
    try:
        with patch("pikvm_aio.cli.async_main", new=AsyncMock(return_value=0)) as mock_main:
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 0

            parsed_args = mock_main.call_args[0][0]
            assert parsed_args.password == "supersecret123"
            assert parsed_args.totp == "654321"

            assert sys.argv[4] == "******"
            assert sys.argv[6] == "******"
            assert sys.argv[1] == "-H"
            assert sys.argv[2] == "pikvm.local"
    finally:
        sys.argv = original_argv


def test_cli_main_preserves_equals_syntax() -> None:
    """Verify main() parses --password=val before scrubbing."""
    original_argv = list(sys.argv)
    sys.argv = ["pikvm-cli", "-H", "pikvm.local", "--password=mypassword", "--totp=112233", "info"]
    try:
        with patch("pikvm_aio.cli.async_main", new=AsyncMock(return_value=0)) as mock_main:
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 0

            parsed_args = mock_main.call_args[0][0]
            assert parsed_args.password == "mypassword"
            assert parsed_args.totp == "112233"
            assert sys.argv[3] == "--password=******"
            assert sys.argv[4] == "--totp=******"
    finally:
        sys.argv = original_argv


def test_cli_main_with_custom_argv() -> None:
    """Verify main() handles explicit custom argv list."""
    custom_argv = ["-H", "pikvm.local", "-p", "custompass", "info"]
    with patch("pikvm_aio.cli.async_main", new=AsyncMock(return_value=0)) as mock_main:
        with pytest.raises(SystemExit) as exc_info:
            main(custom_argv)
        assert exc_info.value.code == 0
        parsed_args = mock_main.call_args[0][0]
        assert parsed_args.password == "custompass"
        assert custom_argv[3] == "******"


def test_scrub_process_argv_with_custom_list() -> None:
    """Verify scrub_process_argv accepts custom argument list."""
    custom = ["pikvm-cli", "-p", "custompass", "--totp=999888"]
    scrub_process_argv(custom)
    assert custom[2] == "******"
    assert custom[3] == "--totp=******"


def test_sensitive_data_filter_dict_args_no_typeerror() -> None:
    """Verify logging with mapping arguments succeeds without TypeError and redacts values."""
    filt = SensitiveDataFilter()
    record = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname=__file__,
        lineno=10,
        msg="User %(user)s with password %(password)s and token %(token)s from %(url)s",
        args={
            "user": "admin",
            "password": "my_secret_password",
            "token": "tok_xyz_123",
            "url": "https://admin:urlsecret@pikvm.local/api",
        },
        exc_info=None,
    )
    assert filt.filter(record) is True
    formatted = record.getMessage()

    assert "my_secret_password" not in formatted
    assert "tok_xyz_123" not in formatted
    assert "urlsecret" not in formatted
    assert "[REDACTED]" in formatted
    assert isinstance(record.args, dict)


def test_sensitive_data_filter_dict_nested_mapping() -> None:
    """Verify nested mapping within dict args is sanitized."""
    filt = SensitiveDataFilter()
    record = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname=__file__,
        lineno=15,
        msg="Nested %(data)s and %(extra)s",
        args={
            "data": {
                "auth": "Basic secrettoken123",
                "normal": "hello",
            },
            "extra": "info",
        },
        exc_info=None,
    )
    assert filt.filter(record) is True
    assert isinstance(record.args, dict)
    assert record.args["data"]["auth"] == "[REDACTED]"


def test_sensitive_data_filter_tuple_with_nested_dict() -> None:
    """Verify nested dictionary inside tuple args is sanitized."""
    filt = SensitiveDataFilter()
    record = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname=__file__,
        lineno=20,
        msg="Context: %s, Data: %s",
        args=("auth_event", {"password": "topsecret", "status": "ok"}),
        exc_info=None,
    )
    filt.filter(record)
    assert isinstance(record.args, tuple)
    assert record.args[1]["password"] == "[REDACTED]"
    assert record.args[1]["status"] == "ok"


def test_sensitive_data_filter_single_string_arg() -> None:
    """Verify single string arg is sanitized."""
    filt = SensitiveDataFilter()
    record = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname=__file__,
        lineno=25,
        msg="Token: %s",
        args="Bearer eyJhbGciOiJIUzI1NiJ9.test",
        exc_info=None,
    )
    filt.filter(record)
    assert "[REDACTED]" in str(record.args)


def test_sensitive_data_filter_non_string_msg() -> None:
    """Verify non-string log message is converted and sanitized."""
    filt = SensitiveDataFilter()
    record = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname=__file__,
        lineno=30,
        msg=12345,  # type: ignore[arg-type]
        args=(),
        exc_info=None,
    )
    assert filt.filter(record) is True
    assert record.msg == "12345"


def test_sensitive_data_filter_redacts_exc_info_traceback() -> None:
    """Verify exception tracebacks containing secrets are redacted in log output."""
    buf = io.StringIO()
    handler = logging.StreamHandler(buf)
    handler.addFilter(SensitiveDataFilter())
    handler.setFormatter(logging.Formatter("%(message)s"))

    logger = logging.getLogger("test_traceback_logger")
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

    try:
        raise ValueError(
            "Connection failed: https://admin:leakypass@pikvm.local/api "
            "with Authorization: Basic YWRtaW46cGFzc3dvcmQ="
        )
    except ValueError:
        logger.exception("Operation failed")

    output = buf.getvalue()
    assert "leakypass" not in output
    assert "YWRtaW46cGFzc3dvcmQ=" not in output
    assert "[REDACTED]" in output
    assert "ValueError: Connection failed" in output


def test_sensitive_data_filter_pre_existing_exc_text() -> None:
    """Verify pre-existing exc_text is sanitized."""
    filt = SensitiveDataFilter()
    record = logging.LogRecord(
        name="test",
        level=logging.ERROR,
        pathname=__file__,
        lineno=35,
        msg="Error",
        args=(),
        exc_info=None,
    )
    record.exc_text = "Traceback...\nRuntimeError: X-KVMD-Passwd: secretvalue123"
    filt.filter(record)
    assert "secretvalue123" not in record.exc_text
    assert "X-KVMD-Passwd: [REDACTED]" in record.exc_text


def test_sensitive_data_filter_stack_info() -> None:
    """Verify stack_info string is sanitized."""
    filt = SensitiveDataFilter()
    record = logging.LogRecord(
        name="test",
        level=logging.ERROR,
        pathname=__file__,
        lineno=40,
        msg="Error",
        args=(),
        exc_info=None,
    )
    record.stack_info = "Stack frame: https://user:pass123@pikvm.local/api"
    filt.filter(record)
    assert "pass123" not in str(record.stack_info)
    assert "[REDACTED]" in str(record.stack_info)


def test_module_loggers_have_filter_attached() -> None:
    """Verify client and tls module loggers have SensitiveDataFilter attached out-of-the-box."""
    assert any(isinstance(f, SensitiveDataFilter) for f in client_logger.filters)
    assert any(isinstance(f, SensitiveDataFilter) for f in tls_logger.filters)


def test_attach_sensitive_data_filter_default() -> None:
    """Verify attach_sensitive_data_filter with None attaches to package loggers."""
    filt = attach_sensitive_data_filter()
    assert isinstance(filt, SensitiveDataFilter)
    pkg = logging.getLogger("pikvm_aio")
    assert filt in pkg.filters


def test_attach_sensitive_data_filter_logger_and_handlers() -> None:
    """Verify attach_sensitive_data_filter attaches filter to custom logger and handlers."""
    custom_logger = logging.getLogger("test_custom_pkg_unique")
    handler = logging.StreamHandler()
    custom_logger.addHandler(handler)

    filt = attach_sensitive_data_filter(custom_logger)
    assert filt in custom_logger.filters
    assert filt in handler.filters


def test_attach_sensitive_data_filter_handler_only() -> None:
    """Verify attach_sensitive_data_filter attaches filter directly to a handler."""
    handler = logging.StreamHandler()
    filt = attach_sensitive_data_filter(handler)
    assert filt in handler.filters


def test_configure_secure_logging_helper() -> None:
    """Verify configure_secure_logging sets up logger with filter."""
    logger = configure_secure_logging(level=logging.DEBUG)
    assert logger.level == logging.DEBUG
    assert any(isinstance(f, SensitiveDataFilter) for f in logger.filters)


def test_configure_secure_logging_str_level() -> None:
    """Verify configure_secure_logging with string level."""
    logger = configure_secure_logging(level="WARNING")
    assert logger.level == logging.WARNING


@pytest.mark.asyncio
async def test_cli_password_from_stdin() -> None:
    """Test reading password from stdin with -p -."""
    parser = build_parser()
    args = parser.parse_args(["-H", "pikvm.local", "-p", "-", "info"])

    mock_stdin = io.StringIO("secret_stdin_pass\n")
    with patch("sys.stdin", mock_stdin):
        with patch("pikvm_aio.cli.PiKVMClient") as mock_client:
            mock_inst = AsyncMock()
            mock_client.return_value.__aenter__.return_value = mock_inst
            mock_inst.get_info.return_value = AsyncMock()

            await async_main(args)
            assert args.password == "secret_stdin_pass"
            assert mock_client.call_args.kwargs["password"] == "secret_stdin_pass"


@pytest.mark.asyncio
async def test_cli_totp_from_stdin() -> None:
    """Test reading TOTP from stdin with -t -."""
    parser = build_parser()
    args = parser.parse_args(["-H", "pikvm.local", "-t", "-", "info"])

    mock_stdin = io.StringIO("123456\n")
    with patch("sys.stdin", mock_stdin):
        with patch("pikvm_aio.cli.PiKVMClient") as mock_client:
            mock_inst = AsyncMock()
            mock_client.return_value.__aenter__.return_value = mock_inst
            mock_inst.get_info.return_value = AsyncMock()

            await async_main(args)
            assert args.totp == "123456"
            assert mock_client.call_args.kwargs["totp_secret"] == "123456"


@pytest.mark.asyncio
async def test_cli_password_warning_emitted(capsys: pytest.CaptureFixture[str]) -> None:
    """Verify security warning printed to stderr when password passed on CLI."""
    original_argv = list(sys.argv)
    sys.argv = ["pikvm-cli", "-H", "pikvm.local", "-p", "plaintextpass", "info"]
    try:
        parser = build_parser()
        args = parser.parse_args(sys.argv[1:])
        with patch("pikvm_aio.cli.PiKVMClient") as mock_client:
            mock_inst = AsyncMock()
            mock_client.return_value.__aenter__.return_value = mock_inst
            mock_inst.get_info.return_value = AsyncMock()

            await async_main(args)
            captured = capsys.readouterr()
            assert (
                "Security Warning: Passing passwords via command-line flags is insecure"
                in captured.err
            )
    finally:
        sys.argv = original_argv
