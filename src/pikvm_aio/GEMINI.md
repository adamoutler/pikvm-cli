# Module Manifest: `src/pikvm_aio`

## Overview
`src/pikvm_aio` is an asynchronous, zero-disk-leakage Python 3.11+ client library and command-line automation toolkit for PiKVM hardware running the `kvmd` HTTP/REST and WebSocket APIs.

## Component Architecture

| Module | Purpose | Public Contracts | Dependencies |
| :--- | :--- | :--- | :--- |
| [`__init__.py`](file:///home/adamoutler/git/pikvm-aio/src/pikvm_aio/__init__.py) | Package root & exports | Re-exports `PiKVMClient`, models, exceptions, and validators in `__all__` | Internal modules |
| [`client.py`](file:///home/adamoutler/git/pikvm-aio/src/pikvm_aio/client.py) | Main asynchronous client | `PiKVMClient` context manager; telemetry, ATX, MSD, HID, OCR, GPIO | `aiohttp`, `models`, `validators`, `security`, `tls` |
| [`models.py`](file:///home/adamoutler/git/pikvm-aio/src/pikvm_aio/models.py) | Slotted domain entities | Immutable, slotted dataclasses (`PiKVMDevice`, `MsdState`, `OcrResult`, etc.) | Standard library `dataclasses` |
| [`validators.py`](file:///home/adamoutler/git/pikvm-aio/src/pikvm_aio/validators.py) | Defense-in-depth sanitization | Input validation: ISO names, local files, HID keys, coordinates, GPIO channels & delays | `exceptions.PiKVMValidationError` |
| [`security.py`](file:///home/adamoutler/git/pikvm-aio/src/pikvm_aio/security.py) | Memory & log sanitization | `scrub_process_argv`, `SensitiveDataFilter` (scrubs headers, URLs, tracebacks) | Standard library `logging`, `sys`, `re` |
| [`tls.py`](file:///home/adamoutler/git/pikvm-aio/src/pikvm_aio/tls.py) | In-memory TLS transport | `create_ssl_context`, `fetch_remote_cert` (binary DER & PEM, SHA-256 fingerprinting) | Standard library `ssl`, `asyncio`, `hashlib` |
| [`exceptions.py`](file:///home/adamoutler/git/pikvm-aio/src/pikvm_aio/exceptions.py) | Exception hierarchy | `PiKVMError` root; connection, auth, device, and validation subclasses | Built-in `Exception` |
| [`cli.py`](file:///home/adamoutler/git/pikvm-aio/src/pikvm_aio/cli.py) | Standalone CLI (`pikvm-cli`) | Shell entrypoints, subcommands (`info`, `msd`, `power`, `iso`, `hid`, `ocr`, `gpio`) | `client`, `security`, `validators` |

## Semantic Context & Behavioral Contracts

### 1. Performance Expectations
- **Zero-Buffering Streams**: File transfers (`upload_msd_image`) stream binary data chunk-by-chunk directly from disk to socket, maintaining a strict $O(1)$ memory footprint regardless of ISO size (tested with multi-gigabyte virtual images).
- **In-Memory TLS**: Certificate loading and validation execute entirely in volatile memory via `ssl.SSLContext.load_verify_locations(cadata=...)` with zero temporary disk writes.
- **Slotted Dataclasses**: All models use `@dataclass(slots=True, frozen=True)` to minimize memory allocation and provide attribute access speeds significantly faster than plain dictionaries.

### 2. Failure Modes & Exception Guarantees
- **Unified Hierarchy**: All library exceptions inherit from `PiKVMError`. Consumers can safely catch `PiKVMError` to trap all library failures.
- **Pre-Flight Validation**: Malformed inputs (path traversal sequences `..`, `/`, `\`, out-of-range mouse coordinates, invalid HID keys, excessive GPIO pulse times) raise `PiKVMValidationError` locally *before* any HTTP request is dispatched.
- **Predictable Network Failures**: Sockets, timeouts, and TLS handshake failures map strictly to `PiKVMConnectionError`, `PiKVMTimeoutError`, or `PiKVMCertificateError`.

### 3. Security & Isolation Invariants
- **Hostile Wire Invariant**: Trust nothing from the network; bounds-check all incoming responses and enforce timeout controls on every HTTP call.
- **Volatile State Protection**: Authentication tokens and TOTP seeds in `sys.argv` are scrubbed in-place immediately upon parsing to prevent exposure in `/proc/<pid>/cmdline` and `ps aux`.
- **Log Leakage Protection**: `SensitiveDataFilter` actively strips Basic Auth headers, `X-KVMD-Passwd` tokens, URL credentials, and sensitive traceback contents from all active log handlers.
- **Offline Test Hermeticity**: Unit tests run with an autouse loopback socket guard in `tests/conftest.py`, deterministically intercepting and blocking any non-loopback network calls to physical devices.
