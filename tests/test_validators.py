"""Unit tests for validators and input sanitization routines."""

from __future__ import annotations

from pathlib import Path

import pytest

from pikvm_aio.exceptions import (
    PiKVMInvalidKeyError,
    PiKVMInvalidTextError,
    PiKVMValidationError,
)
from pikvm_aio.validators import (
    sanitize_hid_text,
    validate_hid_key,
    validate_hid_shortcut,
    validate_iso_filename,
    validate_local_iso_file,
    validate_ocr_box,
)


def test_validate_iso_filename_valid() -> None:
    assert validate_iso_filename("ubuntu-22.04.iso") == "ubuntu-22.04.iso"
    assert validate_iso_filename("disk_image.img") == "disk_image.img"
    assert validate_iso_filename("ArchLinux-x86_64.ISO") == "ArchLinux-x86_64.ISO"


def test_validate_iso_filename_traversal_and_invalid() -> None:
    with pytest.raises(PiKVMValidationError, match="Path traversal"):
        validate_iso_filename("/path/to/my_image.iso")
    with pytest.raises(PiKVMValidationError, match="Path traversal"):
        validate_iso_filename(r"C:\path\to\my_image.iso")
    with pytest.raises(PiKVMValidationError, match="Path traversal"):
        validate_iso_filename("../etc/shadow.iso")
    with pytest.raises(PiKVMValidationError, match="Path traversal"):
        validate_iso_filename("image..iso")
    with pytest.raises(PiKVMValidationError, match="invalid characters"):
        validate_iso_filename("invalid!@#.iso")
    with pytest.raises(PiKVMValidationError, match="invalid characters"):
        validate_iso_filename("test.tar.gz")
    with pytest.raises(PiKVMValidationError, match="between 5 and 128"):
        validate_iso_filename("")
    with pytest.raises(PiKVMValidationError, match="between 5 and 128"):
        validate_iso_filename("x" * 130 + ".iso")


def test_validate_local_iso_file(tmp_path: Path) -> None:
    iso_file = tmp_path / "test.iso"
    iso_file.write_bytes(b"\x00" * 1024)

    assert validate_local_iso_file(iso_file) == iso_file.resolve()

    # Non-existent
    with pytest.raises(PiKVMValidationError, match="does not exist"):
        validate_local_iso_file(tmp_path / "nonexistent.iso")

    # Directory
    with pytest.raises(PiKVMValidationError, match="not a regular file"):
        validate_local_iso_file(tmp_path)

    # Empty file
    empty_file = tmp_path / "empty.iso"
    empty_file.write_bytes(b"")
    with pytest.raises(PiKVMValidationError, match="empty"):
        validate_local_iso_file(empty_file)

    # Size limit
    with pytest.raises(PiKVMValidationError, match="exceeds maximum"):
        validate_local_iso_file(iso_file, max_size_bytes=512)


def test_validate_hid_key() -> None:
    assert validate_hid_key("Enter") == "Enter"
    assert validate_hid_key("KeyA") == "KeyA"
    assert validate_hid_key("a") == "KeyA"
    assert validate_hid_key("1") == "Digit1"
    assert validate_hid_key("f5") == "F5"
    assert validate_hid_key("ctrl") == "ControlLeft"
    assert validate_hid_key("alt") == "AltLeft"
    assert validate_hid_key("meta") == "MetaLeft"
    assert validate_hid_key("esc") == "Escape"

    with pytest.raises(PiKVMInvalidKeyError, match="not a valid Web/EVDEV HID symbol"):
        validate_hid_key("NonExistentKey123")


def test_validate_hid_shortcut() -> None:
    assert validate_hid_shortcut("ControlLeft+AltLeft+Delete") == [
        "ControlLeft",
        "AltLeft",
        "Delete",
    ]
    assert validate_hid_shortcut("ctrl+alt+del") == [
        "ControlLeft",
        "AltLeft",
        "Delete",
    ]
    assert validate_hid_shortcut(["ctrl", "c"]) == ["ControlLeft", "KeyC"]

    with pytest.raises(PiKVMInvalidKeyError, match="cannot be empty"):
        validate_hid_shortcut("")

    with pytest.raises(PiKVMInvalidKeyError, match="exceeds maximum allowed depth"):
        validate_hid_shortcut("ctrl+alt+shift+win+f1+f2")


def test_sanitize_hid_text() -> None:
    assert sanitize_hid_text("Hello World! 123\n\t") == "Hello World! 123\n\t"

    with pytest.raises(PiKVMInvalidTextError, match="exceeds maximum limit"):
        sanitize_hid_text("a" * 50, max_length=10)

    with pytest.raises(PiKVMInvalidTextError, match="Invalid character"):
        sanitize_hid_text("Hello\x00World")

    with pytest.raises(PiKVMInvalidTextError, match="Invalid character"):
        sanitize_hid_text("Esc\x1b[31mRed")


def test_validate_ocr_box() -> None:
    assert validate_ocr_box(-1, -1, -1, -1) == (-1, -1, -1, -1)
    assert validate_ocr_box(0, 0, 100, 100) == (0, 0, 100, 100)

    with pytest.raises(PiKVMValidationError, match="must be non-negative"):
        validate_ocr_box(0, -2, 100, 100)

    with pytest.raises(PiKVMValidationError, match="must be greater than or equal to left"):
        validate_ocr_box(100, 0, 50, 100)

    with pytest.raises(PiKVMValidationError, match="must be greater than or equal to top"):
        validate_ocr_box(0, 100, 100, 50)
