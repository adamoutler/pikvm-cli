"""Security logging filter and process memory scrubbing for PiKVM operations."""

from __future__ import annotations

import logging
import re
import sys
from typing import Any

BASIC_AUTH_REGEX = re.compile(r"(Authorization:\s*Basic\s+)[A-Za-z0-9+/=]+", re.IGNORECASE)
KVMD_AUTH_REGEX = re.compile(r"(X-KVMD-Passwd:\s*)[^\s]+", re.IGNORECASE)
URL_CREDENTIAL_REGEX = re.compile(r"(https?://)([^:]+):([^@]+)@", re.IGNORECASE)


class SensitiveDataFilter(logging.Filter):
    """Logging filter to prevent credentials and secrets from leaking into logs."""

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = BASIC_AUTH_REGEX.sub(r"\1[REDACTED]", record.msg)
            record.msg = KVMD_AUTH_REGEX.sub(r"\1[REDACTED]", record.msg)
            record.msg = URL_CREDENTIAL_REGEX.sub(r"\1\2:[REDACTED]@", record.msg)

        if record.args:
            cleaned_args: list[Any] = []
            for arg in record.args if isinstance(record.args, tuple) else [record.args]:
                if isinstance(arg, str):
                    arg = BASIC_AUTH_REGEX.sub(r"\1[REDACTED]", arg)
                    arg = KVMD_AUTH_REGEX.sub(r"\1[REDACTED]", arg)
                    arg = URL_CREDENTIAL_REGEX.sub(r"\1\2:[REDACTED]@", arg)
                cleaned_args.append(arg)
            record.args = tuple(cleaned_args)
        return True


def scrub_process_argv() -> None:
    """Wipe plaintext password and TOTP arguments from sys.argv in-place.

    Prevents credential leakage via /proc/<pid>/cmdline and ps aux.
    """
    for i, arg in enumerate(sys.argv):
        if arg in ("-p", "--password", "-t", "--totp") and i + 1 < len(sys.argv):
            sys.argv[i + 1] = "******"
        elif arg.startswith(("--password=", "--totp=")):
            flag, _ = arg.split("=", 1)
            sys.argv[i] = f"{flag}=******"
