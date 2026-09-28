"""Unit tests for pikvm_aio data models."""

from __future__ import annotations

from pikvm_aio.models import (
    HardwareHealth,
    HardwareInfo,
    HardwarePerformance,
    MsdInfo,
    PiKVMDeviceInfo,
    PlatformInfo,
    ServerMeta,
    ThrottlingInfo,
)


def test_server_meta_parsing(sample_info_payload: dict) -> None:
    """Test parsing server metadata."""
    meta = ServerMeta.from_dict(sample_info_payload["result"]["meta"]["server"])
    assert meta.host == "pikvm.local"
    assert meta.name == "Lab PiKVM"
    assert meta.version == "3.240"

    empty_meta = ServerMeta.from_dict(None)
    assert empty_meta.host == ""
    assert empty_meta.name == ""


def test_platform_info_parsing(sample_info_payload: dict) -> None:
    """Test platform information parsing."""
    hw = sample_info_payload["result"]["hw"]["platform"]
    platform = PlatformInfo.from_dict(hw)
    assert platform.model == "v3-hdmi"
    assert platform.serial == "a1b2c3d4e5f6"
    assert platform.type == "v3"
    assert platform.base == "rpi4"


def test_throttling_info_parsing() -> None:
    """Test throttling info flag parsing and is_throttled logic."""
    data = {
        "raw_flags": 0x50005,
        "text_flags": ["arm_frequency_capped", "under_voltage"],
        "voltage": {
            "core": {
                "now": True,
                "past": True,
            }
        },
    }
    throttling = ThrottlingInfo.from_dict(data)
    assert throttling.is_throttled is True
    assert throttling.raw_flags == 0x50005
    assert throttling.undervoltage_now is True
    assert throttling.undervoltage_past is True
    assert "arm_frequency_capped" in throttling.text_flags

    clean_throttling = ThrottlingInfo.from_dict(None)
    assert clean_throttling.is_throttled is False
    assert clean_throttling.undervoltage_now is False


def test_hardware_health_and_performance(sample_info_payload: dict) -> None:
    """Test parsing health and performance metrics."""
    hw_data = sample_info_payload["result"]["hw"]
    health = HardwareHealth.from_dict(hw_data["health"])
    assert health.cpu_temp == 48.5
    assert health.throttling.is_throttled is False

    perf = HardwarePerformance.from_dict(hw_data["performance"])
    assert perf.cpu_utilization == 14.8
    assert perf.memory_utilization == 32.1
    assert perf.memory_total_bytes == 2147483648
    assert perf.memory_total_mb == 2048.0
    assert perf.memory_available_mb == 1391.34
    assert perf.fan_speed == 2400

    hw_info = HardwareInfo.from_dict(hw_data)
    assert hw_info.platform.serial == "a1b2c3d4e5f6"
    assert hw_info.health.cpu_temp == 48.5


def test_msd_info_parsing(sample_msd_payload: dict) -> None:
    """Test parsing Mass Storage Device payloads."""
    msd_data = sample_msd_payload["result"]
    msd = MsdInfo.from_dict(msd_data)
    assert msd.is_enabled is True
    assert msd.drive.is_mounted is True
    assert msd.drive.connected is True
    assert msd.storage.total_mb == 15360.0
    assert msd.storage.free_mb == 10240.0
    assert msd.storage.used_mb == 5120.0
    assert msd.storage.percent_used == 33.33
    assert "ubuntu.iso" in msd.storage.images
    assert msd.storage.images["ubuntu.iso"] == 2147483648

    # Edge cases
    empty_msd = MsdInfo.from_dict(None)
    assert empty_msd.is_enabled is False
    assert empty_msd.storage.percent_used is None


def test_device_info_combined(sample_info_payload: dict, sample_msd_payload: dict) -> None:
    """Test top-level PiKVMDeviceInfo combined snapshot."""
    raw = dict(sample_info_payload["result"])
    raw["msd"] = sample_msd_payload["result"]
    device = PiKVMDeviceInfo.from_dict(raw)

    assert device.name == "Lab PiKVM"
    assert device.model == "v3-hdmi"
    assert device.serial == "a1b2c3d4e5f6"
    assert device.cpu_temp == 48.5
    assert device.cpu_utilization == 14.8
    assert device.memory_utilization == 32.1
    assert device.fan_speed == 2400
    assert device.is_throttled is False
    assert device.kvmd_version == "3.240-1"
    assert device.extras.get("vnc") == {"is_running": True}
    assert device.msd.is_enabled is True
    assert device["hw"]["platform"]["model"] == "v3-hdmi"
    assert device.get("hw") is not None
    assert "hw" in device
    assert "nonexistent" not in device
