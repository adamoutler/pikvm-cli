"""Strongly typed data models for PiKVM API responses."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


def _bytes_to_mb(bytes_val: int | None) -> float | None:
    if bytes_val is None:
        return None
    return round(bytes_val / (1024 * 1024), 2)


@dataclass(slots=True, frozen=True)
class ServerMeta:
    """Metadata describing the PiKVM server."""

    host: str = ""
    name: str = ""
    version: str = ""

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> ServerMeta:
        data = data or {}
        return cls(
            host=str(data.get("host", "")),
            name=str(data.get("name", "")),
            version=str(data.get("version", "")),
        )


@dataclass(slots=True, frozen=True)
class PlatformInfo:
    """Hardware platform information for PiKVM."""

    model: str = ""
    serial: str = ""
    type: str = ""
    base: str = ""

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> PlatformInfo:
        data = data or {}
        serial = str(data.get("serial", "")).lower()
        return cls(
            model=str(data.get("model", "")),
            serial=serial,
            type=str(data.get("type", "")),
            base=str(data.get("base", "")),
        )


@dataclass(slots=True, frozen=True)
class ThrottlingInfo:
    """PiKVM / Raspberry Pi hardware throttling diagnostics."""

    raw_flags: int = 0
    text_flags: tuple[str, ...] = field(default_factory=tuple)
    undervoltage_now: bool = False
    undervoltage_past: bool = False

    @property
    def is_throttled(self) -> bool:
        """Return True if any throttling flags are set."""
        return self.raw_flags > 0

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> ThrottlingInfo:
        data = data or {}
        voltage = data.get("voltage", {})
        core = voltage.get("core", {}) if isinstance(voltage, dict) else {}
        flags = tuple(str(f) for f in data.get("text_flags", []))
        return cls(
            raw_flags=int(data.get("raw_flags", 0)),
            text_flags=flags,
            undervoltage_now=bool(core.get("now", False)),
            undervoltage_past=bool(core.get("past", False)),
        )


@dataclass(slots=True, frozen=True)
class HardwareHealth:
    """Health metrics reported by PiKVM."""

    cpu_temp: float | None = None
    throttling: ThrottlingInfo = field(default_factory=ThrottlingInfo)

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> HardwareHealth:
        data = data or {}
        temp_data = data.get("temp", {})
        cpu_temp = temp_data.get("cpu") if isinstance(temp_data, dict) else None
        if cpu_temp is not None:
            try:
                cpu_temp = float(cpu_temp)
            except (ValueError, TypeError):
                cpu_temp = None

        return cls(
            cpu_temp=cpu_temp,
            throttling=ThrottlingInfo.from_dict(data.get("throttling")),
        )


@dataclass(slots=True, frozen=True)
class HardwarePerformance:
    """Performance metrics (CPU, Memory, Fan) reported by PiKVM."""

    cpu_utilization: float | None = None
    memory_utilization: float | None = None
    memory_total_bytes: int | None = None
    memory_available_bytes: int | None = None
    fan_speed: int | None = None

    @property
    def memory_total_mb(self) -> float | None:
        """Total memory in megabytes."""
        return _bytes_to_mb(self.memory_total_bytes)

    @property
    def memory_available_mb(self) -> float | None:
        """Available memory in megabytes."""
        return _bytes_to_mb(self.memory_available_bytes)

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> HardwarePerformance:
        data = data or {}
        cpu = data.get("cpu", {})
        mem = data.get("memory", data.get("mem", {}))
        fan = data.get("fan", {})

        cpu_util = cpu.get("utilization", cpu.get("percent")) if isinstance(cpu, dict) else None
        mem_util = mem.get("utilization", mem.get("percent")) if isinstance(mem, dict) else None
        mem_tot = mem.get("total") if isinstance(mem, dict) else None
        mem_avail = mem.get("available") if isinstance(mem, dict) else None

        fan_speed: Any = None
        if isinstance(fan, dict):
            if "speed" in fan:
                fan_speed = fan.get("speed")
            elif "state" in fan and isinstance(fan["state"], dict):
                inner_fan = fan["state"].get("fan", {})
                if isinstance(inner_fan, dict):
                    fan_speed = inner_fan.get("speed")

        return cls(
            cpu_utilization=float(cpu_util) if cpu_util is not None else None,
            memory_utilization=float(mem_util) if mem_util is not None else None,
            memory_total_bytes=int(mem_tot) if mem_tot is not None else None,
            memory_available_bytes=int(mem_avail) if mem_avail is not None else None,
            fan_speed=round(float(fan_speed)) if fan_speed is not None else None,
        )


@dataclass(slots=True, frozen=True)
class HardwareInfo:
    """Consolidated hardware information."""

    platform: PlatformInfo = field(default_factory=PlatformInfo)
    health: HardwareHealth = field(default_factory=HardwareHealth)
    performance: HardwarePerformance = field(default_factory=HardwarePerformance)

    @classmethod
    def from_dict(
        cls,
        data: dict[str, Any] | None,
        root_data: dict[str, Any] | None = None,
    ) -> HardwareInfo:
        data = data or {}
        root = root_data or {}
        platform = PlatformInfo.from_dict(data.get("platform"))
        health = HardwareHealth.from_dict(data.get("health"))

        perf_data = data.get("performance")
        if not perf_data:
            perf_dict: dict[str, Any] = {}
            health_dict = data.get("health", {})
            if isinstance(health_dict, dict):
                if "cpu" in health_dict:
                    perf_dict["cpu"] = health_dict["cpu"]
                if "mem" in health_dict:
                    perf_dict["memory"] = health_dict["mem"]
            fan_dict = root.get("fan", data.get("fan", {}))
            if fan_dict:
                perf_dict["fan"] = fan_dict
            perf_data = perf_dict

        performance = HardwarePerformance.from_dict(perf_data)
        return cls(
            platform=platform,
            health=health,
            performance=performance,
        )


@dataclass(slots=True, frozen=True)
class MsdDrive:
    """Mass Storage Drive connection status."""

    is_mounted: bool = False
    connected: bool = False

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> MsdDrive:
        data = data or {}
        is_mounted = bool(data.get("is_mounted", data.get("mounted", False)))
        connected = bool(data.get("connected", is_mounted))
        return cls(is_mounted=is_mounted, connected=connected)


@dataclass(slots=True, frozen=True)
class MsdStorage:
    """Mass Storage Device partition and image status."""

    available_bytes: int | None = None
    total_bytes: int | None = None
    images: dict[str, int] = field(default_factory=dict)

    @property
    def free_mb(self) -> float | None:
        return _bytes_to_mb(self.available_bytes)

    @property
    def total_mb(self) -> float | None:
        return _bytes_to_mb(self.total_bytes)

    @property
    def used_bytes(self) -> int | None:
        if self.total_bytes is not None and self.available_bytes is not None:
            return max(0, self.total_bytes - self.available_bytes)
        return None

    @property
    def used_mb(self) -> float | None:
        return _bytes_to_mb(self.used_bytes)

    @property
    def percent_used(self) -> float | None:
        if self.total_bytes is not None and self.total_bytes > 0 and self.used_bytes is not None:
            return round((self.used_bytes / self.total_bytes) * 100, 2)
        return None

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> MsdStorage:
        data = data or {}
        avail = data.get("available")
        tot = data.get("total")

        parts = data.get("parts")
        if isinstance(parts, dict):
            if avail is None:
                avail_sum = sum(
                    int(p.get("free", 0))
                    for p in parts.values()
                    if isinstance(p, dict) and "free" in p
                )
                if avail_sum > 0 or parts:
                    avail = avail_sum
            if tot is None:
                tot_sum = sum(
                    int(p.get("size", 0))
                    for p in parts.values()
                    if isinstance(p, dict) and "size" in p
                )
                if tot_sum > 0 or parts:
                    tot = tot_sum

        raw_images = data.get("images", {})
        images_dict: dict[str, int] = {}
        if isinstance(raw_images, dict):
            for k, v in raw_images.items():
                if isinstance(v, dict) and "size" in v:
                    images_dict[k] = int(v["size"])
                elif isinstance(v, (int, float)):
                    images_dict[k] = int(v)

        return cls(
            available_bytes=int(avail) if avail is not None else None,
            total_bytes=int(tot) if tot is not None else None,
            images=images_dict,
        )


@dataclass(slots=True, frozen=True)
class MsdInfo:
    """PiKVM Mass Storage Device (MSD) subsystem state."""

    is_enabled: bool = False
    drive: MsdDrive = field(default_factory=MsdDrive)
    storage: MsdStorage = field(default_factory=MsdStorage)

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> MsdInfo:
        data = data or {}
        is_enabled = bool(data.get("is_enabled", data.get("enabled", False)))
        return cls(
            is_enabled=is_enabled,
            drive=MsdDrive.from_dict(data.get("drive")),
            storage=MsdStorage.from_dict(data.get("storage")),
        )


@dataclass(slots=True, frozen=True)
class PiKVMDeviceInfo:
    """Complete PiKVM device snapshot."""

    server: ServerMeta
    hw: HardwareInfo
    msd: MsdInfo
    extras: dict[str, Any] = field(default_factory=dict)
    kvmd_version: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def serial(self) -> str:
        return self.hw.platform.serial

    @property
    def model(self) -> str:
        return self.hw.platform.model or self.hw.platform.type or "PiKVM"

    @property
    def name(self) -> str:
        return self.server.name or self.server.host or "PiKVM"

    @property
    def cpu_temp(self) -> float | None:
        return self.hw.health.cpu_temp

    @property
    def cpu_utilization(self) -> float | None:
        return self.hw.performance.cpu_utilization

    @property
    def memory_utilization(self) -> float | None:
        return self.hw.performance.memory_utilization

    @property
    def fan_speed(self) -> int | None:
        return self.hw.performance.fan_speed

    @property
    def is_throttled(self) -> bool:
        return self.hw.health.throttling.is_throttled

    def __getitem__(self, key: str) -> Any:
        return self.raw[key]

    def get(self, key: str, default: Any = None) -> Any:
        return self.raw.get(key, default)

    def __contains__(self, key: str) -> bool:
        return key in self.raw

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PiKVMDeviceInfo:
        meta = data.get("meta", {})
        server_dict = meta.get("server") if isinstance(meta, dict) else None
        system_dict = data.get("system", {})
        kvmd_dict = system_dict.get("kvmd") if isinstance(system_dict, dict) else None
        kvmd_ver = kvmd_dict.get("version") if isinstance(kvmd_dict, dict) else None

        hw_info = HardwareInfo.from_dict(data.get("hw"), root_data=data)
        msd_info = MsdInfo.from_dict(data.get("msd"))

        raw_copy = dict(data)
        hw_raw = dict(raw_copy.get("hw", {}) or {})
        if "performance" not in hw_raw and hw_info.performance:
            hw_raw["performance"] = {
                "cpu": {"utilization": hw_info.performance.cpu_utilization},
                "memory": {
                    "utilization": hw_info.performance.memory_utilization,
                    "total": hw_info.performance.memory_total_bytes,
                    "available": hw_info.performance.memory_available_bytes,
                },
                "fan": {"speed": hw_info.performance.fan_speed},
            }
            raw_copy["hw"] = hw_raw

        msd_raw = dict(raw_copy.get("msd", {}) or {})
        storage_raw = dict(msd_raw.get("storage", {}) or {})
        if msd_info.storage.total_bytes is not None and "total" not in storage_raw:
            storage_raw["total"] = msd_info.storage.total_bytes
            storage_raw["available"] = msd_info.storage.available_bytes
            msd_raw["storage"] = storage_raw
            raw_copy["msd"] = msd_raw

        return cls(
            server=ServerMeta.from_dict(server_dict),
            hw=hw_info,
            msd=msd_info,
            extras=dict(data.get("extras", {}) or {}),
            kvmd_version=str(kvmd_ver) if kvmd_ver is not None else None,
            raw=raw_copy,
        )
