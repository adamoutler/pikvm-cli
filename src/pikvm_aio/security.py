"""Security logging filter and process memory scrubbing for PiKVM operations."""

from __future__ import annotations

import collections.abc
import logging
import re
import sys
import traceback
from typing import Any

BASIC_AUTH_REGEX = re.compile(r"(Authorization:\s*Basic\s+)[A-Za-z0-9+/=]+", re.IGNORECASE)
KVMD_AUTH_REGEX = re.compile(r"(X-KVMD-Passwd:\s*)[^\s]+", re.IGNORECASE)
URL_CREDENTIAL_REGEX = re.compile(r"(https?://)([^:]+):([^@]+)@", re.IGNORECASE)
BEARER_AUTH_REGEX = re.compile(r"((?:Authorization:\s*)?Bearer\s+)[^\s]+", re.IGNORECASE)

SENSITIVE_KEY_SUBSTRINGS = frozenset(
    {"password", "passwd", "secret", "token", "totp", "auth", "key"}
)


def _sanitize_text(text: str) -> str:
    """Apply secret scrubbing regular expressions to a text string."""
    text = BASIC_AUTH_REGEX.sub(r"\1[REDACTED]", text)
    text = KVMD_AUTH_REGEX.sub(r"\1[REDACTED]", text)
    text = URL_CREDENTIAL_REGEX.sub(r"\1\2:[REDACTED]@", text)
    text = BEARER_AUTH_REGEX.sub(r"\1[REDACTED]", text)
    return text


def _sanitize_mapping(mapping: collections.abc.Mapping[Any, Any]) -> dict[str, Any]:
    """Recursively scrub strings and redact sensitive keys in a mapping."""
    cleaned: dict[str, Any] = {}
    for k, v in mapping.items():
        if isinstance(v, str):
            v = _sanitize_text(v)
        elif isinstance(v, collections.abc.Mapping):
            v = _sanitize_mapping(v)
        if isinstance(k, str) and any(sec in k.lower() for sec in SENSITIVE_KEY_SUBSTRINGS):
            v = "[REDACTED]"
        cleaned[str(k)] = v
    return cleaned


class SensitiveDataFilter(logging.Filter):
    """Logging filter to prevent credentials and secrets from leaking into logs."""

    def filter(self, record: logging.LogRecord) -> bool:
        # 1. Sanitize primary log message
        if isinstance(record.msg, str):
            record.msg = _sanitize_text(record.msg)
        elif record.msg is not None:
            record.msg = _sanitize_text(str(record.msg))

        # 2. Sanitize formatting arguments (dict, tuple, or single arg)
        if record.args:
            if isinstance(record.args, collections.abc.Mapping):
                record.args = _sanitize_mapping(record.args)
            elif isinstance(record.args, tuple):
                cleaned_tuple: list[Any] = []
                for arg in record.args:
                    if isinstance(arg, str):
                        cleaned_tuple.append(_sanitize_text(arg))
                    elif isinstance(arg, collections.abc.Mapping):
                        cleaned_tuple.append(_sanitize_mapping(arg))
                    else:
                        cleaned_tuple.append(arg)
                record.args = tuple(cleaned_tuple)
            elif isinstance(record.args, str):
                record.args = _sanitize_text(record.args)

        # 3. Sanitize exception traceback (exc_info / exc_text)
        if record.exc_info and record.exc_info[0] is not None:
            # Pre-format exc_text if not already created, ensuring secrets in tracebacks
            # are scrubbed before any handler formatter emits the record.
            if not record.exc_text:
                formatted_exc = "".join(traceback.format_exception(*record.exc_info)).rstrip("\n")
                record.exc_text = _sanitize_text(formatted_exc)
            else:
                record.exc_text = _sanitize_text(record.exc_text)
        elif record.exc_text:
            record.exc_text = _sanitize_text(record.exc_text)

        # 4. Sanitize stack_info if present
        if record.stack_info and isinstance(record.stack_info, str):
            record.stack_info = _sanitize_text(record.stack_info)

        return True


def scrub_process_argv(argv: list[str] | None = None) -> None:
    """Wipe plaintext password and TOTP arguments from sys.argv or provided argv in-place.

    Args:
        argv: Target argument list to scrub. If None, mutates sys.argv.

    """
    target = sys.argv if argv is None else argv
    for i, arg in enumerate(target):
        if arg in ("-p", "--password", "-t", "--totp") and i + 1 < len(target):
            target[i + 1] = "******"
        elif arg.startswith(("--password=", "--totp=")):
            flag, _ = arg.split("=", 1)
            target[i] = f"{flag}=******"


def attach_sensitive_data_filter(
    target: logging.Logger | logging.Handler | None = None,
) -> SensitiveDataFilter:
    """Attach a SensitiveDataFilter instance to a logger, handler, or package loggers.

    If target is None, the filter is attached to:
      1. Top-level package logger ('pikvm_aio')
      2. Known subloggers ('pikvm_aio.client', 'pikvm_aio.tls', 'pikvm_aio.cli')
      3. Any handlers attached to root logger

    If target is a Logger:
      The filter is attached to the logger and all its existing handlers.

    If target is a Handler:
      The filter is attached directly to the handler.

    Returns:
        The active SensitiveDataFilter instance.

    """
    filt = SensitiveDataFilter()
    if target is None:
        package_logger = logging.getLogger("pikvm_aio")
        package_logger.addFilter(filt)
        for mod in ("client", "tls", "cli", "security", "validators"):
            logging.getLogger(f"pikvm_aio.{mod}").addFilter(filt)
        root_logger = logging.getLogger()
        for h in root_logger.handlers:
            if filt not in h.filters:
                h.addFilter(filt)
    elif isinstance(target, logging.Logger):
        target.addFilter(filt)
        for h in target.handlers:
            if filt not in h.filters:
                h.addFilter(filt)
    elif isinstance(target, logging.Handler):
        target.addFilter(filt)
    return filt


def configure_secure_logging(
    level: int | str = logging.INFO,
    handler: logging.Handler | None = None,
) -> logging.Logger:
    """Configure secure logging for pikvm_aio with SensitiveDataFilter pre-installed.

    Args:
        level: Logging level (e.g. logging.INFO or 'INFO').
        handler: Optional custom logging handler. Defaults to StreamHandler.

    Returns:
        The configured 'pikvm_aio' Logger instance.

    """
    logger = logging.getLogger("pikvm_aio")
    if isinstance(level, str):
        level = getattr(logging, level.upper(), logging.INFO)
    logger.setLevel(level)
    if handler is None:
        handler = logging.StreamHandler()
        formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
        handler.setFormatter(formatter)
    attach_sensitive_data_filter(handler)
    if handler not in logger.handlers:
        logger.addHandler(handler)
    attach_sensitive_data_filter(logger)
    return logger
