"""Validation and input sanitization routines for PiKVM operations."""

from __future__ import annotations

import os
import re
from collections.abc import Sequence
from pathlib import Path

from .exceptions import (
    PiKVMInvalidKeyError,
    PiKVMInvalidTextError,
    PiKVMValidationError,
)

# MSD: Alphanumeric, dot, underscore, hyphen; 5-128 chars; ends with .iso or .img
MSD_IMAGE_NAME_REGEX = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,126}\.(iso|img)$", re.IGNORECASE)

# Canonical Web / EVDEV key names supported by PiKVM KVMD daemon
VALID_HID_KEYS: frozenset[str] = frozenset(
    {
        # Alphabetic
        *(f"Key{chr(c)}" for c in range(ord("A"), ord("Z") + 1)),
        # Digits
        *(f"Digit{i}" for i in range(10)),
        # Function Keys
        *(f"F{i}" for i in range(1, 25)),
        # Standard Controls & Navigation
        "Enter",
        "Escape",
        "Backspace",
        "Tab",
        "Space",
        "Minus",
        "Equal",
        "BracketLeft",
        "BracketRight",
        "Backslash",
        "Semicolon",
        "Quote",
        "Backquote",
        "Comma",
        "Period",
        "Slash",
        "CapsLock",
        "PrintScreen",
        "ScrollLock",
        "Pause",
        "Insert",
        "Delete",
        "Home",
        "End",
        "PageUp",
        "PageDown",
        "ArrowUp",
        "ArrowDown",
        "ArrowLeft",
        "ArrowRight",
        # Modifiers
        "ControlLeft",
        "ControlRight",
        "ShiftLeft",
        "ShiftRight",
        "AltLeft",
        "AltRight",
        "MetaLeft",
        "MetaRight",
        "ContextMenu",
        # Numpad
        "NumLock",
        "NumpadDivide",
        "NumpadMultiply",
        "NumpadSubtract",
        "NumpadAdd",
        "NumpadEnter",
        "NumpadDecimal",
        *(f"Numpad{i}" for i in range(10)),
    }
)

# Aliases for common user-friendly shortcut names
KEY_ALIASES: dict[str, str] = {
    "ctrl": "ControlLeft",
    "ctrlleft": "ControlLeft",
    "ctrlright": "ControlRight",
    "control": "ControlLeft",
    "alt": "AltLeft",
    "altleft": "AltLeft",
    "altright": "AltRight",
    "shift": "ShiftLeft",
    "shiftleft": "ShiftLeft",
    "shiftright": "ShiftRight",
    "meta": "MetaLeft",
    "win": "MetaLeft",
    "cmd": "MetaLeft",
    "super": "MetaLeft",
    "esc": "Escape",
    "del": "Delete",
    "ins": "Insert",
    "pgup": "PageUp",
    "pgdn": "PageDown",
    "enter": "Enter",
    "return": "Enter",
    "space": "Space",
    "tab": "Tab",
    "backspace": "Backspace",
    "prtscr": "PrintScreen",
    "printscreen": "PrintScreen",
    "sysrq": "PrintScreen",
}


def validate_iso_filename(name: str) -> str:
    """Validate and sanitize an MSD ISO or IMG image filename.

    Args:
        name: Filename to validate.

    Returns:
        Cleaned, validated filename.

    Raises:
        PiKVMValidationError: If name is invalid or contains traversal characters.

    """
    raw = name.strip()
    if ".." in raw or "\x00" in raw:
        raise PiKVMValidationError(f"Path traversal characters detected in image name: {name!r}")
    clean_name = os.path.basename(raw)
    if not clean_name or len(clean_name) > 128:
        raise PiKVMValidationError(
            f"Image filename length must be between 5 and 128 characters, got {len(clean_name)}"
        )
    if not MSD_IMAGE_NAME_REGEX.match(clean_name):
        raise PiKVMValidationError(
            f"Image name {clean_name!r} contains invalid characters or extension. "
            "Must be alphanumeric with . _ - and end in .iso or .img"
        )
    return clean_name


def validate_local_iso_file(path: Path | str, max_size_bytes: int = 68_719_476_736) -> Path:
    """Validate that local ISO source file exists, is regular, non-empty, and readable.

    Args:
        path: Path to local file.
        max_size_bytes: Maximum allowed file size (default: 64 GiB).

    Returns:
        Resolved Path object.

    Raises:
        PiKVMValidationError: If file does not exist, is not a regular file, or is empty.

    """
    p = Path(path).resolve()
    if not p.exists():
        raise PiKVMValidationError(f"Source file does not exist: {p}")
    if not p.is_file():
        raise PiKVMValidationError(
            f"Source is not a regular file (directories and special devices disallowed): {p}"
        )
    file_stat = p.stat()
    if file_stat.st_size == 0:
        raise PiKVMValidationError(f"Source file is empty (0 bytes): {p}")
    if file_stat.st_size > max_size_bytes:
        raise PiKVMValidationError(
            f"File size {file_stat.st_size} exceeds maximum allowable size {max_size_bytes} bytes"
        )
    return p


def validate_hid_key(key: str) -> str:
    """Validate a single HID key identifier against canonical whitelist.

    Args:
        key: Key name or alias (e.g. 'KeyA', 'Enter', 'ctrl').

    Returns:
        Canonical key string.

    Raises:
        PiKVMInvalidKeyError: If key is unrecognized.

    """
    clean = key.strip()
    lower = clean.lower()
    if lower in KEY_ALIASES:
        return KEY_ALIASES[lower]

    if clean in VALID_HID_KEYS:
        return clean

    # Check case-insensitive match for single letter (e.g. 'a' -> 'KeyA')
    if len(clean) == 1 and clean.isalpha():
        candidate = f"Key{clean.upper()}"
        if candidate in VALID_HID_KEYS:
            return candidate

    # Check single digit (e.g. '1' -> 'Digit1')
    if len(clean) == 1 and clean.isdigit():
        candidate = f"Digit{clean}"
        if candidate in VALID_HID_KEYS:
            return candidate

    # Check case-insensitive match across all valid keys
    for valid_key in VALID_HID_KEYS:
        if valid_key.lower() == lower:
            return valid_key

    raise PiKVMInvalidKeyError(
        f"Key {clean!r} is not a valid Web/EVDEV HID symbol recognized by PiKVM."
    )


def validate_hid_shortcut(keys: str | Sequence[str]) -> list[str]:
    """Validate a keyboard shortcut combination (e.g. 'ControlLeft+AltLeft+Delete').

    Args:
        keys: Shortcut string or list of key names.

    Returns:
        List of validated canonical key names.

    Raises:
        PiKVMInvalidKeyError: If shortcut is empty, too deep (>5), or contains invalid keys.

    """
    if isinstance(keys, str):
        key_list = [k.strip() for k in re.split(r"[,+\s]+", keys) if k.strip()]
    else:
        key_list = [str(k).strip() for k in keys if str(k).strip()]

    if not key_list:
        raise PiKVMInvalidKeyError("Shortcut cannot be empty.")
    if len(key_list) > 5:
        raise PiKVMInvalidKeyError(
            f"Shortcut exceeds maximum allowed depth of 5 keys: {len(key_list)}"
        )
    return [validate_hid_key(k) for k in key_list]


def sanitize_hid_text(text: str, max_length: int = 4096) -> str:
    """Validate printable ASCII and standard whitespace; reject control characters.

    Args:
        text: String to type.
        max_length: Maximum allowed length.

    Returns:
        Sanitized text.

    Raises:
        PiKVMInvalidTextError: If text is too long or contains invalid control characters.

    """
    if len(text) > max_length:
        raise PiKVMInvalidTextError(
            f"Text length {len(text)} exceeds maximum limit of {max_length} characters."
        )

    for char in text:
        code = ord(char)
        # Allow standard printable ASCII (0x20 - 0x7E) and standard whitespace
        if char in ("\n", "\r", "\t") or (32 <= code <= 126):
            continue
        raise PiKVMInvalidTextError(
            f"Invalid character in text: {char!r} (U+{code:04X}). "
            "Only printable ASCII and standard whitespace are permitted."
        )
    return text


def validate_ocr_box(
    left: int = -1,
    top: int = -1,
    right: int = -1,
    bottom: int = -1,
) -> tuple[int, int, int, int]:
    """Validate OCR bounding box coordinates.

    Coordinates must either be -1 (full frame) or valid non-negative pixels where
    right >= left and bottom >= top.

    Returns:
        Tuple of (left, top, right, bottom).

    Raises:
        PiKVMValidationError: If coordinates are negative (other than -1) or inverted.

    """
    coords = (left, top, right, bottom)
    if all(c == -1 for c in coords):
        return coords

    for name, val in zip(("left", "top", "right", "bottom"), coords, strict=True):
        if val < 0:
            raise PiKVMValidationError(
                f"OCR coordinate {name} must be non-negative or -1, got {val}"
            )

    if right < left:
        raise PiKVMValidationError(
            f"OCR box right ({right}) must be greater than or equal to left ({left})"
        )
    if bottom < top:
        raise PiKVMValidationError(
            f"OCR box bottom ({bottom}) must be greater than or equal to top ({top})"
        )

    return coords
