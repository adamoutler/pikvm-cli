# pikvm-aio

[![CI / CD](https://git.adamoutler.com/aoutler/pikvm-aio/actions/workflows/ci.yml/badge.svg)](https://git.adamoutler.com/aoutler/pikvm-aio)
[![PyPI version](https://img.shields.io/pypi/v/pikvm-aio.svg)](https://pypi.org/project/pikvm-aio/)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

An asynchronous Python client library and system administration CLI (`pikvm-cli`) for interacting with PiKVM hardware running the `kvmd` HTTP/REST and WebSocket APIs.

Engineered for homelab automation, devops scripting, and integration into platforms such as Home Assistant Core.

---

## Architectural Scope & Boundaries

`pikvm-aio` operates with strict architectural separation of concerns. Network transport is non-blocking via `asyncio` and `aiohttp`, while data transformation, cryptographic token derivation, and certificate loading execute synchronously in memory.

### Scope Overview

| Capability | In-Scope (`pikvm-aio`) | Out-of-Scope (External Consumers) |
| :--- | :--- | :--- |
| **KVMD Telemetry** | Parsing CPU, RAM, Fan, Temp, and Throttling flags | Registering entity sensors or UI dashboards |
| **Virtual Media (MSD)** | ISO uploading/downloading, drive mounting, storage usage | Low-level flash partitioning or raw disk formatting |
| **HID Automation** | Keystrokes, typing text, shortcuts, mouse clicks & macros | OS-level input capture or local hardware emulation |
| **Screen OCR** | Server-side text recognition via bounding box coords | Local OCR model training or image processing |
| **GPIO Control** | Reading channel status, firing switch and pulse triggers | Direct electrical pin wiring or board-level design |
| **ATX Power Control** | Dispatching validated `click`, `long`, `reset`, `off` actions | Configuring BIOS/UEFI firmware settings |
| **TLS & Security** | In-memory CA validation, peer certificate extraction | Writing certs to disk, generating custom CA root keys |
| **Video Streams** | Discovering MJPEG/WebRTC streaming endpoints & tokens | Video frame decoding, FFmpeg transcoding, canvas rendering |
| **CLI Automation** | Formatted terminal output and JSON pipelines for shell scripts | Web GUI dashboards or long-running daemon supervisors |
| **Host Management** | Interacting exclusively with the KVMD HTTP/WS API boundary | Host OS administration, SSH execution, Arch Linux (`pacman`) |
| **Framework Independence** | Generic, standalone Python library | Zero dependencies on Home Assistant Core (`homeassistant.*`) |

---

## Core Features

- **Asynchronous Network Transport:** Non-blocking HTTP and TLS operations built on `aiohttp` and `asyncio.open_connection`.
- **In-Memory TLS Verification:** Self-signed certificates and custom CAs load directly into RAM via `ssl.SSLContext.load_verify_locations(cadata=...)`. Eliminates the insecure anti-pattern of writing sensitive certificates or secrets to `/tmp`.
- **Remote Peer Certificate Extraction:** Built-in `fetch_remote_cert` performs an async TLS handshake and extracts peer PEM certificates without requiring `pyOpenSSL` or external binaries.
- **Two-Factor Authentication (TOTP):** Native `pyotp` integration automatically calculates RFC 6238 time-based tokens for 2FA-protected endpoints.
- **Strongly Typed Models:** Slotted, immutable dataclasses (`@dataclass(slots=True, frozen=True)`) provide fast attribute access with minimal memory overhead, plus dictionary-style subscripting for backwards compatibility.
- **Unified Exception Hierarchy:** Deterministic error handling derived from a common `PiKVMError` base class.
- **CLI Utility (`pikvm-cli`):** Standalone command-line administration tool supporting human-readable output and JSON (`--json`) for scripting with `jq`.

---

## Installation

```bash
pip install pikvm-aio
```

---

## Python API Usage

### Basic Usage with Context Manager

```python
import asyncio
from pikvm_aio import PiKVMClient


async def main():
    async with PiKVMClient(
        host="https://pikvm.local",
        username="admin",
        password="secret_password",
        totp_secret="JBSWY3DPEHPK3PXP",  # Optional RFC 6238 base32 secret
        verify_ssl=True,
        ssl_cert=None,  # Optional in-memory PEM string or bytes
        check_hostname=True,  # Set False for IP / .local self-signed certs
        timeout=10.0,
    ) as client:
        # Fetch consolidated device snapshot (info + msd)
        device = await client.get_info()

        print(f"Device: {device.name} ({device.model})")
        print(f"Serial: {device.serial}")
        print(f"KVMD Version: {device.kvmd_version}")
        print(f"CPU Temp: {device.cpu_temp}°C")
        print(f"CPU Utilization: {device.cpu_utilization}%")
        print(f"Memory Utilization: {device.memory_utilization}%")

        # Hardware throttling diagnostics (Raspberry Pi vcgencmd equivalent)
        throttling = device.hw.health.throttling
        if throttling.raw_flags > 0:
            print(f"Throttling Active! Flags: {throttling.text_flags}")
            print(f"Undervoltage Now: {throttling.undervoltage_now}")

        # Mass Storage Device (MSD) virtual drive inspection
        msd = await client.get_msd()
        print(f"MSD Drive Mounted: {msd.drive.is_mounted}")
        print(f"MSD Free Storage: {msd.storage.free_mb} MB ({msd.storage.percent_used}% used)")

        # Send ATX power action: 'click', 'long', 'reset', or 'off'
        # await client.power_action("click")


asyncio.run(main())
```

### Shared `aiohttp.ClientSession` (e.g., Home Assistant)

When integrating into long-running frameworks, provide an existing session to participate in connection pooling:

```python
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from pikvm_aio import PiKVMClient

session = async_get_clientsession(hass)

client = PiKVMClient(
    host="https://pikvm.local",
    username="admin",
    password="secret_password",
    session=session,  # Client will not close this external session on exit
    ssl_cert=cert_pem,
)

data = await client.get_info()
```

### Fetching a Remote Certificate In-Memory

```python
from pikvm_aio import fetch_remote_cert

# Extracts the peer certificate directly over TLS
pem_cert = await fetch_remote_cert("pikvm.local", default_port=443, timeout=5.0)
print(pem_cert)
```

---

## Command-Line Interface (`pikvm-cli`)

`pikvm-cli` is included for shell scripting and operational tasks. Credentials can be passed via command-line flags or environment variables:

```bash
export PIKVM_HOST="pikvm.local"
export PIKVM_USERNAME="admin"
export PIKVM_PASSWORD="secret_password"
export PIKVM_TOTP="JBSWY3DPEHPK3PXP"     # Optional
export PIKVM_CERT="/path/to/cert.pem"     # Optional
```

### Fast & Simple Usage

`pikvm-cli` accepts the target host as a positional argument and defaults to the `info` command. Flags can be placed anywhere:

```bash
# 1. Quick overview of a device (accepting self-signed certs)
pikvm-cli 192.168.1.108 -k

# 2. Or using the self-documenting option:
pikvm-cli 192.168.1.108 --accept-any-cert

# 3. Subcommands (info, health, msd, collect, fetch-cert, power)
pikvm-cli 192.168.1.108 health -k
pikvm-cli 192.168.1.108 msd -k
pikvm-cli 192.168.1.108 collect -k

# 4. Virtual Media (ISO / MSD) Management
pikvm-cli 192.168.1.108 iso upload /path/to/ubuntu.iso -k
pikvm-cli 192.168.1.108 iso mount ubuntu.iso -k
pikvm-cli 192.168.1.108 iso unmount -k

# 5. Remote HID Automation (Keys, Text, Shortcuts, Mouse, Macros)
pikvm-cli 192.168.1.108 hid text "uname -a" -k
pikvm-cli 192.168.1.108 hid shortcut ControlLeft AltLeft Delete -k
pikvm-cli 192.168.1.108 hid click --button left --to 100,200 -k
pikvm-cli 192.168.1.108 hid macro run script.json -k

# 6. Screen OCR Text Extraction
pikvm-cli 192.168.1.108 ocr --xywh 0,2,281,79 -k

# 7. GPIO Control
pikvm-cli 192.168.1.108 gpio read -k
pikvm-cli 192.168.1.108 gpio pulse power_switch -k

# 8. Fetch the remote TLS certificate as structured JSON or raw PEM
pikvm-cli 192.168.1.108 fetch-cert --json
pikvm-cli 192.168.1.108 fetch-cert -o /etc/ssl/certs/pikvm.pem

# 9. ATX Power Actions (click, long, reset, off)
pikvm-cli 192.168.1.108 power click -k

# 10. JSON output mode for scripting and jq
pikvm-cli 192.168.1.108 -k --json | jq .
```

---

## Exception Hierarchy

All client errors derive from `PiKVMError`, allowing consumers to catch exceptions at any granularity:

```text
PiKVMError
├── PiKVMConnectionError          # Sockets, DNS, SSL handshake failures
│   ├── PiKVMTimeoutError         # Request or connection timeout
│   └── PiKVMCertificateError     # TLS verification or certificate parsing failure
├── PiKVMAuthenticationError      # HTTP 401, 403, bad password, invalid TOTP secret
├── PiKVMDeviceError              # HTTP 5xx, ok=false payload, malformed response
└── PiKVMValidationError          # Input validation, path traversal, out-of-bounds coords
    ├── PiKVMInvalidKeyError      # Unknown/unsupported keyboard key name
    ├── PiKVMInvalidTextError     # Malformed or out-of-range text payload
    └── PiKVMSafetyError          # High-consequence action attempted without required confirmation
```

---

## Development & Quality Standards

`pikvm-aio` enforces strict type safety and a minimum of 85% test coverage.

### Running Local Checks

```bash
# Install development dependencies
pip install -e '.[dev]'

# Run unit tests and generate coverage report
pytest -v --cov=pikvm_aio --cov-report=term-missing --cov-fail-under=85

# Static type checking
mypy src

# Linter and formatting validation
ruff check src tests
```

---

## License

MIT License. See [LICENSE](LICENSE) for details.
