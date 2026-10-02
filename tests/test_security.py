"""Unit tests for security filtering and credential protection."""

from __future__ import annotations

import logging
import sys

from pikvm_aio.security import SensitiveDataFilter, scrub_process_argv


def test_sensitive_data_filter() -> None:
    filt = SensitiveDataFilter()

    # Basic auth redaction
    record = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname=__file__,
        lineno=10,
        msg="Request headers: Authorization: Basic YWRtaW46cGFzc3dvcmQ=",
        args=(),
        exc_info=None,
    )
    filt.filter(record)
    assert "Authorization: Basic [REDACTED]" in record.msg

    # X-KVMD-Passwd redaction
    record2 = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname=__file__,
        lineno=15,
        msg="Header: X-KVMD-Passwd: mysecretpass",
        args=(),
        exc_info=None,
    )
    filt.filter(record2)
    assert "X-KVMD-Passwd: [REDACTED]" in record2.msg

    # URL credentials redaction
    record3 = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname=__file__,
        lineno=20,
        msg="Connecting to https://admin:supersecret@192.168.1.50/api",
        args=(),
        exc_info=None,
    )
    filt.filter(record3)
    assert "https://admin:[REDACTED]@192.168.1.50/api" in record3.msg

    # Record args redaction
    record4 = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname=__file__,
        lineno=25,
        msg="Connecting: %s, code: %d",
        args=("Authorization: Basic YWRtaW46cGFzc3dvcmQ=", 200),
        exc_info=None,
    )
    filt.filter(record4)
    assert record4.args == ("Authorization: Basic [REDACTED]", 200)


def test_scrub_process_argv() -> None:
    original_argv = list(sys.argv)
    try:
        sys.argv = ["pikvm-cli", "-H", "192.168.1.50", "-p", "secret123", "-t", "654321", "info"]
        scrub_process_argv()
        assert sys.argv[4] == "******"
        assert sys.argv[6] == "******"
        assert sys.argv[1] == "-H"
        assert sys.argv[2] == "192.168.1.50"

        # Equals format
        sys.argv = ["pikvm-cli", "--password=mysecret", "--totp=123456", "info"]
        scrub_process_argv()
        assert sys.argv[1] == "--password=******"
        assert sys.argv[2] == "--totp=******"
    finally:
        sys.argv = original_argv
