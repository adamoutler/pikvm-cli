# Module Manifest: `pikvm-aio`

## Description
`pikvm-aio` is a standalone, high-performance, asynchronous Python client library and CLI tool (`pikvm-cli`) for interacting with PiKVM devices (v2, v3, v4, Mini, Plus) running the `kvmd` REST API.

It is specifically engineered to meet and exceed Home Assistant Core architectural standards (ADR-0010, Integration Quality Scale Silver/Gold), featuring zero-disk TLS certificate trust, connection pooling via `aiohttp`, Basic + TOTP 2FA authentication, strongly typed data models, and a unified CLI.

## Dependencies
- **Runtime:**
  - `python >= 3.11`
  - `aiohttp >= 3.9.0` (Asynchronous HTTP networking)
  - `pyotp >= 2.9.0` (TOTP generation for PiKVM 2FA)
- **Development & Testing:**
  - `pytest`, `pytest-asyncio`, `pytest-cov`, `aioresponses`
  - `ruff`, `mypy`, `build`, `twine`

## Dependent Systems
- **Home Assistant Core Integration (`homeassistant.components.pikvm`):** Uses `pikvm-aio` as its upstream PyPI client for device communication and polling coordinators.
- **Standalone CLI Users:** System administrators using `pikvm-cli` for automated health reporting, MSD image inspection, and ATX power control in scripts and shell automation.
- **CI/CD Automation:** Automated Forgejo / GitHub Actions pipeline for linting, testing, packaging, and publishing to PyPI.

## Security Invariants
- **Hostile Wire:** All outbound HTTPS connections use strict timeout controls and configurable TLS verification.
- **In-Memory TLS Verification:** In-memory certificate trust using `ssl.SSLContext.load_verify_locations(cadata=...)` without temporary disk files or permission leaks.
- **Volatile State Sanitization:** Secrets (passwords, TOTP seeds) are never serialized into `__repr__` strings or exported logs.
