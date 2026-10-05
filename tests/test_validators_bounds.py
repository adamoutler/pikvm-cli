"""Unit tests for input whitelisting and hardware bounds validation."""

from __future__ import annotations

from pathlib import Path

import pytest

from pikvm_aio.exceptions import PiKVMValidationError
from pikvm_aio.validators import (
    validate_gpio_channel,
    validate_gpio_delay,
    validate_iso_filename,
    validate_local_iso_file,
    validate_mouse_button,
    validate_mouse_coords,
    validate_mouse_delay,
)


def test_validate_mouse_coords_valid() -> None:
    """Test valid mouse coordinates within default and custom bounds."""
    assert validate_mouse_coords(0, 0) == (0, 0)
    assert validate_mouse_coords(1920, 1080) == (1920, 1080)
    assert validate_mouse_coords(4096, 4096) == (4096, 4096)
    assert validate_mouse_coords(50, 50, min_x=10, max_x=100, min_y=10, max_y=100) == (50, 50)


def test_validate_mouse_coords_invalid_types() -> None:
    """Test rejecting non-integer and bool coordinate types."""
    with pytest.raises(PiKVMValidationError, match="must be an integer"):
        validate_mouse_coords(True, 100)  # type: ignore[arg-type]

    with pytest.raises(PiKVMValidationError, match="must be an integer"):
        validate_mouse_coords(100, False)  # type: ignore[arg-type]

    with pytest.raises(PiKVMValidationError, match="must be an integer"):
        validate_mouse_coords(10.5, 100)  # type: ignore[arg-type]

    with pytest.raises(PiKVMValidationError, match="must be an integer"):
        validate_mouse_coords("100", 200)  # type: ignore[arg-type]


def test_validate_mouse_coords_out_of_bounds() -> None:
    """Test rejecting coordinates outside bounds."""
    with pytest.raises(PiKVMValidationError, match="to_x .* out of safe bounds"):
        validate_mouse_coords(-1, 500)

    with pytest.raises(PiKVMValidationError, match="to_x .* out of safe bounds"):
        validate_mouse_coords(4097, 500)

    with pytest.raises(PiKVMValidationError, match="to_y .* out of safe bounds"):
        validate_mouse_coords(500, -1)

    with pytest.raises(PiKVMValidationError, match="to_y .* out of safe bounds"):
        validate_mouse_coords(500, 4097)


def test_validate_mouse_button_valid_and_case() -> None:
    """Test valid canonical mouse buttons with case and whitespace trimming."""
    assert validate_mouse_button("left") == "left"
    assert validate_mouse_button("RIGHT") == "right"
    assert validate_mouse_button("  middle  ") == "middle"
    assert validate_mouse_button("up") == "up"
    assert validate_mouse_button("Down") == "down"


def test_validate_mouse_button_invalid() -> None:
    """Test rejecting invalid mouse button identifiers."""
    with pytest.raises(PiKVMValidationError, match="Invalid mouse button"):
        validate_mouse_button("invalid_btn")

    with pytest.raises(PiKVMValidationError, match="Invalid mouse button"):
        validate_mouse_button("side")


def test_validate_mouse_delay_valid() -> None:
    """Test valid mouse delay bounds."""
    assert validate_mouse_delay(0.0) == 0.0
    assert validate_mouse_delay(0.05) == 0.05
    assert validate_mouse_delay(10.0) == 10.0
    assert validate_mouse_delay(1) == 1.0


def test_validate_mouse_delay_invalid() -> None:
    """Test rejecting invalid or dangerous mouse delay durations."""
    with pytest.raises(PiKVMValidationError, match="must be numeric"):
        validate_mouse_delay("0.5")  # type: ignore[arg-type]

    with pytest.raises(PiKVMValidationError, match="must be numeric"):
        validate_mouse_delay(True)  # type: ignore[arg-type]

    with pytest.raises(PiKVMValidationError, match="finite number"):
        validate_mouse_delay(float("nan"))

    with pytest.raises(PiKVMValidationError, match="finite number"):
        validate_mouse_delay(float("inf"))

    with pytest.raises(PiKVMValidationError, match="out of safe bounds"):
        validate_mouse_delay(-0.01)

    with pytest.raises(PiKVMValidationError, match="out of safe bounds"):
        validate_mouse_delay(10.1)


def test_validate_gpio_channel_valid() -> None:
    """Test valid GPIO channel identifiers."""
    assert validate_gpio_channel("relay1") == "relay1"
    assert validate_gpio_channel("power_btn") == "power_btn"
    assert validate_gpio_channel("PIN-22") == "PIN-22"
    assert validate_gpio_channel("a" * 64) == "a" * 64


def test_validate_gpio_channel_invalid() -> None:
    """Test rejecting illegal characters and bounds in GPIO channel names."""
    with pytest.raises(PiKVMValidationError, match="Invalid GPIO channel"):
        validate_gpio_channel("")

    with pytest.raises(PiKVMValidationError, match="Invalid GPIO channel"):
        validate_gpio_channel("   ")

    with pytest.raises(PiKVMValidationError, match="Invalid GPIO channel"):
        validate_gpio_channel("relay; rm -rf /")

    with pytest.raises(PiKVMValidationError, match="Invalid GPIO channel"):
        validate_gpio_channel("pin$1")

    with pytest.raises(PiKVMValidationError, match="Invalid GPIO channel"):
        validate_gpio_channel("a" * 65)


def test_validate_gpio_delay_valid() -> None:
    """Test valid GPIO pulse delays."""
    assert validate_gpio_delay(0.01) == 0.01
    assert validate_gpio_delay(0.5) == 0.5
    assert validate_gpio_delay(10.0) == 10.0


def test_validate_gpio_delay_invalid() -> None:
    """Test rejecting invalid or damaging GPIO timing bounds."""
    with pytest.raises(PiKVMValidationError, match="must be numeric"):
        validate_gpio_delay("0.1")  # type: ignore[arg-type]

    with pytest.raises(PiKVMValidationError, match="must be numeric"):
        validate_gpio_delay(False)  # type: ignore[arg-type]

    with pytest.raises(PiKVMValidationError, match="finite number"):
        validate_gpio_delay(float("nan"))

    with pytest.raises(PiKVMValidationError, match="finite number"):
        validate_gpio_delay(float("inf"))

    with pytest.raises(PiKVMValidationError, match="out of safe range"):
        validate_gpio_delay(0.005)

    with pytest.raises(PiKVMValidationError, match="out of safe range"):
        validate_gpio_delay(10.5)


def test_validate_local_iso_file_extensions(tmp_path: Path) -> None:
    """Test that only allowed media extensions are accepted for local upload files."""
    for ext in (".iso", ".img", ".bin", ".raw"):
        f = tmp_path / f"valid{ext}"
        f.write_bytes(b"DATA123")
        assert validate_local_iso_file(f) == f.resolve()

    # Reject non-whitelisted extensions
    for bad_ext in (".txt", ".sh", ".exe", ".iso.bak", ".tar.gz"):
        bad_f = tmp_path / f"malicious{bad_ext}"
        bad_f.write_bytes(b"SECRET_DATA")
        with pytest.raises(PiKVMValidationError, match="invalid extension"):
            validate_local_iso_file(bad_f)


def test_validate_iso_filename_strict_rejection() -> None:
    """Test that ISO filename rejects all directory traversal and path separators."""
    with pytest.raises(PiKVMValidationError, match="Path traversal.*or directory separators"):
        validate_iso_filename("/etc/shadow.iso")

    with pytest.raises(PiKVMValidationError, match="Path traversal.*or directory separators"):
        validate_iso_filename(r"subdir\image.iso")

    with pytest.raises(PiKVMValidationError, match="Path traversal.*or directory separators"):
        validate_iso_filename("../image.iso")

    with pytest.raises(PiKVMValidationError, match="Path traversal.*or directory separators"):
        validate_iso_filename("image\x00.iso")
