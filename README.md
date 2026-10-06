# PiKVM-Client & CLI

[![CI / CD](https://github.com/adamoutler/pikvm-cli/actions/workflows/ci.yml/badge.svg)](https://github.com/adamoutler/pikvm-cli)
[![PyPI version](https://img.shields.io/pypi/v/pikvm-client.svg)](https://pypi.org/project/pikvm-client/)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**PiKVM-Client** is a fast, versatile out-of-band Command-Line Interface (`pikvm-cli`) and asynchronous Python client library for [PiKVM](https://pikvm.org/) devices.

Manage hardware health, stream and mount virtual ISOs, send keystrokes and mouse events, extract text from the screen with OCR, trigger GPIOs, and execute ATX power actions directly from your terminal or shell scripts.

---

## Installation

Install via `pip`, `pipx`, or `uv`:

```bash
# Recommended for CLI and Python library usage
pip install pikvm-client

# Or as an isolated standalone tool
pipx install pikvm-client
# or: uv tool install pikvm-client
```

This installs both the `pikvm-cli` command and the `pikvm` shortcut command.


---

## Quick Start

`pikvm-cli` is designed to be frictionless. Pass your device's hostname or IP as a positional argument. If using self-signed certificates, add `-k` or `--accept-any-cert`:

```bash
# Get an immediate hardware and system overview
pikvm-cli 192.168.1.108 -k

# Check detailed thermal and throttling diagnostics
pikvm-cli 192.168.1.108 health -k
```

### Credentials & Environment Configuration

Avoid typing credentials repeatedly by setting environment variables in your shell (`~/.bashrc` or `~/.zshrc`):

```bash
export PIKVM_HOST="192.168.1.108"
export PIKVM_USERNAME="admin"
export PIKVM_PASSWORD="secret_password"
# Optional:
export PIKVM_TOTP="JBSWY3DPEHPK3PXP"     # Base32 TOTP secret or 6-digit code
export PIKVM_ACCEPT_ANY_CERT="1"         # Trust local / self-signed TLS certs
```

With environment variables set, simply run:

```bash
pikvm-cli info
pikvm-cli health
```

---

## CLI Capabilities in Action

### 1. Virtual Media (ISO / MSD) Management

Upload images, trigger remote downloads directly onto the PiKVM, and control the virtual drive:

```bash
# Stream a local ISO directly to PiKVM flash storage
pikvm-cli iso upload ubuntu-24.04-live-server.iso

# Or instruct PiKVM to download an ISO directly from a remote URL
pikvm-cli iso download https://releases.ubuntu.com/noble/ubuntu-24.04.1-live-server-amd64.iso

# Mount an ISO as a virtual CD-ROM drive and connect it to the target
pikvm-cli iso mount ubuntu-24.04-live-server.iso

# Mount as a read/write virtual flash drive
pikvm-cli iso mount custom-firmware.img --flash --rw

# Eject and unmount the virtual media drive
pikvm-cli iso unmount

# List or delete images from storage
pikvm-cli msd
pikvm-cli iso remove old-installer.iso
```

### 2. Remote Keyboard & Mouse Automation

Control the target machine's inputs via the virtual HID subsystem:

```bash
# Type arbitrary text remotely into the active terminal / prompt
pikvm-cli hid text "sudo systemctl restart nginx\n"

# Send a specific key press or tap
pikvm-cli hid tap Return
pikvm-cli hid tap F12

# Send simultaneous hotkey shortcuts
pikvm-cli hid shortcut ControlLeft AltLeft Delete

# Move the cursor and click
pikvm-cli hid click --button left --to 100,200
pikvm-cli hid click --button right --to 500,400 --double

# Replay a recorded JSON macro script
pikvm-cli hid macro run boot_setup.json
```

### 3. Screen OCR Text Extraction

Read what's on the screen even when the target OS has no network connection or SSH access:

```bash
# Extract text using bounding box (left, top, right, bottom)
pikvm-cli ocr --box 0,2,281,81

# Extract text using x, y, width, height format
pikvm-cli ocr --xywh 0,2,281,79

# Use a specific OCR language
pikvm-cli ocr --xywh 0,0,800,600 --langs eng
```

### 4. ATX Power & Reset Control

Control host power states without physical buttons:

```bash
# Press the power button momentarily
pikvm-cli power click

# Hold the power button for 5 seconds (hard power off)
pikvm-cli power long

# Momentary reset button
pikvm-cli power reset

# Force off immediately
pikvm-cli power off_hard
```

### 5. GPIO Channel Inspection & Triggering

Inspect hardware relays, indicators, and send digital pulses:

```bash
# Read current GPIO channel scheme and state
pikvm-cli gpio read

# Toggle a digital switch or relay
pikvm-cli gpio switch relay1 on
pikvm-cli gpio switch relay1 off

# Send a momentary pulse to a channel (e.g. 500ms)
pikvm-cli gpio pulse power_switch --delay 0.5
```

### 6. Scripting & CI Automation with JSON

Every command supports `--json` for effortless piping into `jq` or CI/CD pipelines:

```bash
# Query CPU temperature as a raw float
pikvm-cli health --json | jq .hw.health.temperatures.cpu.temp

# Check whether virtual media is currently mounted
pikvm-cli msd --json | jq .drive.is_mounted

# Extract screen text as structured JSON
pikvm-cli ocr --xywh 0,0,500,200 --json | jq -r .text
```

---

## Subcommand Reference

| Command | Description |
| :--- | :--- |
| `pikvm-cli info` | Consolidated system, model, hardware, and OS overview |
| `pikvm-cli health` | Real-time thermal stats, fan speeds, and undervoltage/throttling flags |
| `pikvm-cli msd` | Virtual drive mount status and storage partition space |
| `pikvm-cli iso` | Virtual ISO management (`upload`, `download`, `mount`, `unmount`, `remove`, `reset`) |
| `pikvm-cli hid` | Remote HID automation (`key`, `tap`, `text`, `shortcut`, `click`, `macro`) |
| `pikvm-cli ocr` | Screen text recognition via coordinate bounding boxes |
| `pikvm-cli gpio` | User GPIO inspection (`read`) and actuation (`switch`, `pulse`) |
| `pikvm-cli power` | ATX button click and power action dispatch |
| `pikvm-cli fetch-cert` | Extract remote TLS certificate in PEM format or JSON |
| `pikvm-cli collect` | Dump comprehensive operational and diagnostic snapshot |

---

## Built-In Security Invariants

PiKVM-CLI is engineered for zero-trust and security-sensitive out-of-band environments:

- **Process Memory Protection (`sys.argv` Scrubbing):** Passwords and TOTP secrets passed via flags (`-p`, `--password`, `-t`, `--totp`) are scrubbed in-place from process memory upon execution, preventing credential exposure in `/proc/<pid>/cmdline` or `ps aux`.
- **Log Leakage Defense:** Built-in sanitization filters strip Basic Auth headers, session tokens, passwords, and URL credentials from all log outputs and tracebacks.
- **In-Memory TLS Verification:** Custom and self-signed certificates load directly into RAM via `ssl.SSLContext.load_verify_locations(cadata=...)`—eliminating the insecure anti-pattern of writing sensitive keys or certificates to `/tmp`.
- **Path-Traversal Protections:** Strict validation on all ISO names and file paths prevents path manipulation or directory escape.

---

## Python Developer Library Usage

For developers building custom automation, bots, or integrations (such as Home Assistant), `pikvm-client` includes a full-featured, asynchronous Python library.

`import pikvm_client`, `import pikvm_cli`, and backwards-compatible `import pikvm_aio` are all supported:

```python
import asyncio
from pikvm_client import PiKVMClient



async def main():
    async with PiKVMClient(
        host="192.168.1.108",
        username="admin",
        password="secret_password",
        verify_ssl=False,  # Or provide ssl_cert PEM string
    ) as client:
        # Fetch device telemetry
        device = await client.get_info()
        print(f"Connected to {device.name} (CPU Temp: {device.cpu_temp}°C)")

        # Mount virtual installation media
        await client.mount_msd_image("ubuntu.iso", cdrom=True)

        # Type boot instructions into the console
        await client.print_text("e")
        await asyncio.sleep(1.0)
        await client.send_shortcut(["ControlLeft", "KeyX"])

        # Extract on-screen confirmation via OCR
        screen_text = await client.get_ocr_text(left=0, top=0, right=800, bottom=600)
        print("Screen output:\n", screen_text)


asyncio.run(main())
```

---

## Development & Quality Standards

`pikvm-cli` enforces strict type safety and a minimum of 85% test coverage:

```bash
# Install development dependencies
pip install -e '.[dev]'

# Run the 160+ unit test suite
pytest

# Static type checking
mypy src

# Linter and formatting validation
ruff check src tests
```

---

## License

MIT License. See [LICENSE](LICENSE) for details.
