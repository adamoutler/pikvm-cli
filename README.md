# pikvm-aio

[![CI / CD](https://git.adamoutler.com/aoutler/pikvm-aio/actions/workflows/ci.yml/badge.svg)](https://git.adamoutler.com/aoutler/pikvm-aio)
[![PyPI version](https://img.shields.io/pypi/v/pikvm-aio.svg)](https://pypi.org/project/pikvm-aio/)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Asynchronous Python client library and CLI (`pikvm-cli`) for interacting with PiKVM hardware running the `kvmd` REST API.

Specifically designed for enterprise-grade homelab automation, command-line administration, and direct inclusion in Home Assistant Core as the upstream device communication client.

---

## Features

- **100% Asynchronous:** Built on top of `aiohttp` for non-blocking I/O.
- **In-Memory TLS Verification:** Seamlessly supports self-signed certificates and custom CAs in-memory via `ssl.SSLContext` without writing temporary files to `/tmp`.
- **2FA / TOTP Support:** Integrated TOTP token generation directly appended to Basic Auth credentials.
- **Strongly Typed Models:** Native dataclasses for PiKVM server metadata, hardware health (temperature, throttling flags, undervoltages), performance (CPU, memory, fan speed), and MSD (Mass Storage Device) state.
- **Zero-Dependency CLI:** Includes `pikvm-cli` for shell administration, health checks, MSD partition management, ATX power operations, and certificate extraction.
- **Home Assistant Ready:** Adheres strictly to Home Assistant Core architecture rules (ADR-0010, Integration Quality Scale Silver/Gold).

---

## Installation

```bash
pip install pikvm-aio
```

---

## Quickstart: Python API

```python
import asyncio
from pikvm_aio import PiKVMClient

async def main():
    async with PiKVMClient(
        host="https://pikvm.local",
        username="admin",
        password="admin_password",
        totp_secret="JBSWY3DPEHPK3PXP",  # Optional 2FA seed
        verify_ssl=True,
        ssl_cert=None,  # Or pass raw PEM string
    ) as client:
        # Fetch device status and hardware metrics
        info = await client.get_info()
        print(f"Device: {info.name} ({info.model}), Serial: {info.serial}")
        print(f"CPU Temp: {info.cpu_temp}°C, Fan: {info.fan_speed} RPM")
        print(f"Throttled: {info.is_throttled}")

        # Check Mass Storage Device
        msd = await client.get_msd()
        print(f"MSD Mounted: {msd.drive.is_mounted}, Storage Free: {msd.storage.free_mb} MB")

        # ATX Power Action (click, long, reset, off)
        # await client.power_action("click")

asyncio.run(main())
```

---

## Quickstart: `pikvm-cli` Command-Line Tool

The package includes a full-featured CLI:

```bash
# Export credentials (or pass via flags)
export PIKVM_HOST="pikvm.local"
export PIKVM_USERNAME="admin"
export PIKVM_PASSWORD="admin_password"
export PIKVM_TOTP="JBSWY3DPEHPK3PXP"

# 1. Fetch system info
pikvm-cli info

# 2. Check hardware health, temperatures, and throttling
pikvm-cli health

# 3. Check Mass Storage status and images
pikvm-cli msd

# 4. Trigger ATX power button click
pikvm-cli power click

# 5. Extract self-signed certificate directly to a PEM file
pikvm-cli fetch-cert -o pikvm.pem

# 6. JSON output mode for jq / scripting
pikvm-cli --json info | jq .
```

---

## Testing & Quality

Run the test suite locally:

```bash
pip install -e '.[dev]'
pytest -v --cov=pikvm_aio
ruff check src tests
mypy src
```

---

## License

MIT License. See [LICENSE](LICENSE) for details.
