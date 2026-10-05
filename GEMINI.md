# Module Manifest: `pikvm-cli`

## Description
`pikvm-cli` is a standalone, high-performance, asynchronous Python client library and system administration CLI for interacting with PiKVM devices (v2, v3, v4, Mini, Plus) running the `kvmd` REST API.

It is specifically engineered to meet and exceed Home Assistant Core architectural standards (ADR-0010, Integration Quality Scale Silver/Gold), featuring zero-disk TLS certificate trust, connection pooling via `aiohttp`, Basic + TOTP 2FA authentication, strongly typed data models, virtual media (ISO/MSD) streaming, HID automation (keys, typing, mouse, macros), screen OCR text recognition, GPIO control, and a unified CLI. It provides dual import support under both `pikvm_cli` and `pikvm_aio` for complete backwards compatibility.

## Dependencies
- **Runtime:**
  - `python >= 3.11`
  - `aiohttp >= 3.9.0` (Asynchronous HTTP networking)
  - `pyotp >= 2.9.0` (TOTP generation for PiKVM 2FA)
- **Development & Testing:**
  - `pytest`, `pytest-asyncio`, `pytest-cov`, `aioresponses`
  - `ruff`, `mypy`, `build`, `twine`

## Dependent Systems
- **Home Assistant Core Integration (`homeassistant.components.pikvm` / `custom_components.pikvm_ha`):** Uses the library as its upstream client for device communication and polling coordinators.
- **Standalone CLI Users:** System administrators using `pikvm-cli` for automated health reporting, MSD ISO management, HID remote scripting, screen OCR, and GPIO/ATX power control in scripts and shell automation.
- **CI/CD Automation:** Automated Forgejo / GitHub Actions pipeline for linting, testing, packaging, and publishing to PyPI.

## Security Invariants
- **Hostile Wire:** All outbound HTTPS connections use strict timeout controls and configurable TLS verification.
- **In-Memory TLS Verification:** In-memory certificate trust using `ssl.SSLContext.load_verify_locations(cadata=...)` without temporary disk files or permission leaks.
- **Volatile State Sanitization & Memory Scrubbing:** Secrets (passwords, TOTP seeds) are actively scrubbed in-place from `sys.argv` to protect `/proc/<pid>/cmdline` and `ps aux`.
- **Log Data Sanitization:** `SensitiveDataFilter` actively strips Basic Auth headers, `X-KVMD-Passwd` headers, and URL credentials from all log outputs.
- **Strict Input Validation & Whitelisting:** Path traversal prevention for ISO filenames, strict enum/regex validation for HID key codes, bounding box coordinate bounds checking for OCR, and bounds checking for GPIO pulse timings.
- **High-Consequence Action Safeguards:** Destructive operations (hardware resets, flashing) require explicit confirmation flags or safety overrides.
