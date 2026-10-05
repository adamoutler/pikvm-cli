"""Asynchronous client for interacting with PiKVM."""

from __future__ import annotations

import asyncio
import base64
import binascii
import json
import logging
from collections.abc import AsyncIterator, Awaitable, Callable, Sequence
from pathlib import Path
from types import TracebackType
from typing import Any
from urllib.parse import unquote, urlparse

import aiohttp
import pyotp

from .exceptions import (
    PiKVMAuthenticationError,
    PiKVMConnectionError,
    PiKVMDeviceError,
    PiKVMSafetyError,
    PiKVMTimeoutError,
    PiKVMValidationError,
)
from .models import (
    HidDeviceState,
    HidMacro,
    KeyboardKeymaps,
    MsdInfo,
    MsdRemoteProgress,
    MsdUploadProgress,
    PiKVMDeviceInfo,
)
from .security import SensitiveDataFilter
from .tls import create_ssl_context
from .validators import (
    sanitize_hid_text,
    validate_gpio_channel,
    validate_gpio_delay,
    validate_hid_key,
    validate_hid_shortcut,
    validate_iso_filename,
    validate_local_iso_file,
    validate_mouse_button,
    validate_mouse_coords,
    validate_mouse_delay,
    validate_ocr_box,
)

_LOGGER = logging.getLogger(__name__)
_LOGGER.addFilter(SensitiveDataFilter())


def format_url(url: str) -> str:
    """Format and normalize a host or URL string, stripping embedded credentials."""
    clean = url.strip()
    if not clean.startswith("http://") and not clean.startswith("https://"):
        clean = f"https://{clean}"
    parsed = urlparse(clean)
    netloc = parsed.hostname or "localhost"
    if parsed.port:
        netloc = f"{netloc}:{parsed.port}"
    return f"{parsed.scheme}://{netloc}".rstrip("/")


class PiKVMClient:
    """Asynchronous client for PiKVM REST API."""

    def __init__(
        self,
        host: str,
        username: str = "admin",
        password: str = "admin",
        totp_secret: str | None = None,
        session: aiohttp.ClientSession | None = None,
        verify_ssl: bool = True,
        ssl_cert: str | bytes | None = None,
        check_hostname: bool | None = None,
        timeout: float = 10.0,
        ssl_context: Any | None = None,
    ) -> None:
        """Initialize the PiKVM client.

        Args:
            host: IP address, hostname, or full URL to PiKVM.
            username: HTTP Basic Auth username.
            password: HTTP Basic Auth password.
            totp_secret: Optional base32 TOTP secret for 2FA.
            session: Optional existing aiohttp ClientSession.
            verify_ssl: Whether to verify SSL certificates.
            ssl_cert: In-memory PEM certificate string or bytes to trust.
            check_hostname: Whether to verify server hostname matches cert.
            timeout: Request timeout in seconds.
            ssl_context: Optional pre-configured ssl.SSLContext.

        """
        raw_host = host.strip()
        parsed_url = urlparse(raw_host if "://" in raw_host else f"https://{raw_host}")
        if parsed_url.username and (username == "admin" or not username):
            username = unquote(parsed_url.username)
        if parsed_url.password and (password == "admin" or not password):
            password = unquote(parsed_url.password)

        self.base_url = format_url(host)
        self.username = username
        self.password = password
        self.totp_secret = totp_secret.strip().replace(" ", "") if totp_secret else None
        self._totp: pyotp.TOTP | None = None
        self._static_totp: str | None = None

        if self.totp_secret:
            # Support either a static numeric OTP code (6 or 8 digits) or a base32 seed secret
            if len(self.totp_secret) in (6, 8) and self.totp_secret.isdigit():
                self._static_totp = self.totp_secret
            else:
                try:
                    self._totp = pyotp.TOTP(self.totp_secret)
                    # Verify that it generates a token without error
                    self._totp.now()
                except (binascii.Error, ValueError) as err:
                    raise PiKVMAuthenticationError(f"Invalid TOTP base32 secret: {err}") from err

        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.ssl_cert = ssl_cert
        if check_hostname is not None:
            self.check_hostname = check_hostname
        elif ssl_cert is not None:
            self.check_hostname = False
        else:
            self.check_hostname = True

        self._session = session
        self._owns_session = session is None
        if ssl_context is not None:
            self._ssl_context = ssl_context
        else:
            self._ssl_context = create_ssl_context(
                verify_ssl=self.verify_ssl,
                ssl_cert=self.ssl_cert,
                check_hostname=self.check_hostname,
            )

    def _get_auth_header(self) -> str:
        """Calculate the Authorization header (Basic auth + optional TOTP)."""
        auth_pass = self.password
        if self._totp:
            auth_pass = f"{self.password}{self._totp.now()}"
        elif self._static_totp:
            auth_pass = f"{self.password}{self._static_totp}"

        credentials = f"{self.username}:{auth_pass}"
        encoded = base64.b64encode(credentials.encode("utf-8")).decode("utf-8")
        return f"Basic {encoded}"

    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or lazily create an aiohttp session."""
        if self._session is None or self._session.closed:
            connector = aiohttp.TCPConnector(ssl=self._ssl_context)
            client_timeout = aiohttp.ClientTimeout(total=self.timeout)
            self._session = aiohttp.ClientSession(
                connector=connector,
                timeout=client_timeout,
            )
            self._owns_session = True
        return self._session

    async def _request(
        self,
        method: str,
        endpoint: str,
        params: dict[str, Any] | None = None,
        data: Any = None,
    ) -> dict[str, Any]:
        """Perform an HTTP request with error handling and authentication."""
        session = await self._get_session()
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        headers = {
            "Authorization": self._get_auth_header(),
            "Accept": "application/json",
        }

        try:
            async with session.request(
                method=method,
                url=url,
                params=params,
                json=data,
                headers=headers,
                ssl=self._ssl_context,
            ) as response:
                if response.status in (401, 403):
                    body = await response.text()
                    raise PiKVMAuthenticationError(
                        f"Authentication failed (HTTP {response.status}): {body}"
                    )

                if response.status >= 500:
                    body = await response.text()
                    raise PiKVMDeviceError(f"PiKVM server error (HTTP {response.status}): {body}")

                response.raise_for_status()
                payload = await response.json()

                if not isinstance(payload, dict):
                    raise PiKVMDeviceError(f"Unexpected non-dict response from PiKVM: {payload!r}")

                if not payload.get("ok", True):
                    raise PiKVMDeviceError(
                        f"PiKVM API returned failure: {payload.get('error', 'Unknown error')}"
                    )

                result = payload.get("result", payload)
                if isinstance(result, dict):
                    return result
                return payload

        except TimeoutError as err:
            raise PiKVMTimeoutError(f"Request to {url} timed out after {self.timeout}s") from err
        except aiohttp.ClientSSLError as err:
            raise PiKVMConnectionError(f"SSL error communicating with {url}: {err}") from err
        except aiohttp.ClientConnectorError as err:
            raise PiKVMConnectionError(f"Cannot connect to {url}: {err}") from err
        except aiohttp.ClientResponseError as err:
            raise PiKVMDeviceError(f"HTTP error {err.status} for {url}: {err.message}") from err
        except aiohttp.ClientError as err:
            raise PiKVMConnectionError(f"Network error communicating with {url}: {err}") from err

    async def get_raw_info(self) -> dict[str, Any]:
        """Fetch raw /api/info dictionary."""
        return await self._request("GET", "/api/info")

    async def get_raw_msd(self) -> dict[str, Any]:
        """Fetch raw /api/msd dictionary."""
        try:
            return await self._request("GET", "/api/msd")
        except (PiKVMDeviceError, PiKVMConnectionError) as err:
            _LOGGER.debug("MSD endpoint returned error or not supported: %s", err)
            return {}

    async def get_info(self) -> PiKVMDeviceInfo:
        """Fetch complete device status (info + msd)."""
        info_dict = await self.get_raw_info()
        msd_dict = await self.get_raw_msd()
        combined = dict(info_dict)
        combined["msd"] = msd_dict
        return PiKVMDeviceInfo.from_dict(combined)

    async def get_msd(self) -> MsdInfo:
        """Fetch Mass Storage Device (MSD) status."""
        msd_dict = await self.get_raw_msd()
        return MsdInfo.from_dict(msd_dict)

    async def get_raw_atx(self) -> dict[str, Any]:
        """Fetch raw /api/atx status dictionary."""
        try:
            return await self._request("GET", "/api/atx")
        except (PiKVMDeviceError, PiKVMConnectionError) as err:
            _LOGGER.debug("ATX endpoint returned error or not supported: %s", err)
            return {}

    async def get_raw_gpio(self) -> dict[str, Any]:
        """Fetch raw /api/gpio dictionary."""
        try:
            return await self._request("GET", "/api/gpio")
        except (PiKVMDeviceError, PiKVMConnectionError) as err:
            _LOGGER.debug("GPIO endpoint returned error or not supported: %s", err)
            return {}

    async def get_raw_hid(self) -> dict[str, Any]:
        """Fetch raw /api/hid dictionary."""
        try:
            return await self._request("GET", "/api/hid")
        except (PiKVMDeviceError, PiKVMConnectionError) as err:
            _LOGGER.debug("HID endpoint returned error or not supported: %s", err)
            return {}

    async def get_raw_streamer(self) -> dict[str, Any]:
        """Fetch raw /api/streamer dictionary."""
        try:
            return await self._request("GET", "/api/streamer")
        except (PiKVMDeviceError, PiKVMConnectionError) as err:
            _LOGGER.debug("Streamer endpoint returned error or not supported: %s", err)
            return {}

    async def get_raw_auth_check(self) -> dict[str, Any]:
        """Verify authentication via /api/auth/check."""
        return await self._request("GET", "/api/auth/check")

    async def get_all_diagnostics(self) -> dict[str, Any]:
        """Fetch consolidated diagnostics from all standard KVMD endpoints."""
        info = await self.get_raw_info()
        msd = await self.get_raw_msd()
        atx = await self.get_raw_atx()
        gpio = await self.get_raw_gpio()
        hid = await self.get_raw_hid()
        streamer = await self.get_raw_streamer()
        return {
            "info": info,
            "msd": msd,
            "atx": atx,
            "gpio": gpio,
            "hid": hid,
            "streamer": streamer,
        }

    # -------------------------------------------------------------------------
    # ATX Power Operations
    # -------------------------------------------------------------------------

    async def power_action(self, action: str, force: bool = False) -> bool:
        """Send an ATX power command or button click.

        Supports button clicks ('click', 'long', 'reset', 'power', 'power_long') and
        power states ('on', 'off', 'off_hard', 'reset_hard').

        High-consequence actions ('off_hard', 'reset_hard') require force=True confirmation.

        Raises:
            PiKVMValidationError: If action name is invalid.
            PiKVMSafetyError: If high-consequence action is attempted without force=True.

        """
        valid_actions = {
            "click",
            "long",
            "reset",
            "power",
            "power_long",
            "on",
            "off",
            "off_hard",
            "reset_hard",
        }
        if action not in valid_actions:
            raise PiKVMValidationError(
                f"Invalid ATX power action '{action}'. Must be one of {valid_actions}"
            )

        if action in ("off_hard", "reset_hard") and not force:
            raise PiKVMSafetyError(
                f"High-consequence ATX power action '{action}' requires "
                "explicit force=True confirmation."
            )

        if action in ("click", "power"):
            result = await self._request("POST", "/api/atx/click", params={"button": "power"})
        elif action in ("long", "power_long"):
            result = await self._request("POST", "/api/atx/click", params={"button": "power_long"})
        elif action == "reset":
            result = await self._request("POST", "/api/atx/click", params={"button": "reset"})
        else:
            result = await self._request("POST", "/api/atx/power", params={"action": action})
        return bool(result is not None)

    # -------------------------------------------------------------------------
    # MSD / ISO Operations
    # -------------------------------------------------------------------------

    async def upload_msd_image(
        self,
        file_path: str | Path,
        image_name: str | None = None,
        remove_incomplete: bool = True,
        chunk_size: int = 1048576,
        progress_callback: Callable[[MsdUploadProgress], None | Awaitable[None]] | None = None,
        timeout: float | None = None,
    ) -> bool:
        """Stream an ISO image to PiKVM MSD storage without loading it fully into RAM.

        Endpoint: POST /api/msd/write?image=<name>&remove_incomplete=1
        """
        resolved_path = validate_local_iso_file(file_path)
        file_size = resolved_path.stat().st_size
        target_name = validate_iso_filename(image_name or resolved_path.name)

        # Check if image pre-existed on remote storage to prevent destructive rollback
        target_preexisted = False
        if remove_incomplete:
            try:
                msd_info = await self.get_msd()
                target_preexisted = target_name in msd_info.storage.images
            except Exception as check_err:
                _LOGGER.debug("Could not verify pre-existing MSD images: %s", check_err)
                target_preexisted = False

        session = await self._get_session()
        params = {
            "image": target_name,
            "remove_incomplete": "1" if remove_incomplete else "0",
        }
        headers = {
            "Authorization": self._get_auth_header(),
            "Content-Type": "application/octet-stream",
            "Content-Length": str(file_size),
        }

        async def _file_chunk_generator() -> AsyncIterator[bytes]:
            sent = 0
            start_time = asyncio.get_running_loop().time()
            with open(resolved_path, "rb") as f:
                while chunk := f.read(chunk_size):
                    yield chunk
                    sent += len(chunk)
                    if progress_callback:
                        now = asyncio.get_running_loop().time()
                        elapsed = max(0.001, now - start_time)
                        speed = sent / elapsed
                        pct = round((sent / file_size) * 100, 2) if file_size > 0 else 0.0
                        res = progress_callback(
                            MsdUploadProgress(
                                bytes_sent=sent,
                                total_bytes=file_size,
                                percent=pct,
                                speed_bps=speed,
                                elapsed_seconds=elapsed,
                            )
                        )
                        if asyncio.iscoroutine(res):
                            await res

        url = f"{self.base_url}/api/msd/write"
        client_timeout = aiohttp.ClientTimeout(
            total=timeout, sock_read=timeout or 300.0, sock_connect=15.0
        )

        try:
            async with session.post(
                url,
                params=params,
                data=_file_chunk_generator(),
                headers=headers,
                ssl=self._ssl_context,
                timeout=client_timeout,
            ) as resp:
                if resp.status in (401, 403):
                    body = await resp.text()
                    raise PiKVMAuthenticationError(
                        f"Authentication failed (HTTP {resp.status}): {body}"
                    )
                if resp.status >= 400:
                    body = await resp.text()
                    raise PiKVMDeviceError(f"MSD upload failed (HTTP {resp.status}): {body}")
                payload = await resp.json()
                return bool(payload.get("ok", True))
        except (Exception, asyncio.CancelledError) as err:
            _LOGGER.warning(
                "MSD upload of %s interrupted: %s. Initiating compensating rollback...",
                target_name,
                err,
            )
            if remove_incomplete and not target_preexisted:
                try:
                    await self.remove_msd_image(target_name)
                except Exception as cleanup_err:
                    _LOGGER.debug("Compensating rollback failed: %s", cleanup_err)
            elif target_preexisted:
                _LOGGER.info(
                    "Image %s pre-existed on remote storage; skipping compensating "
                    "removal to prevent data loss.",
                    target_name,
                )
            raise

    async def download_msd_remote(
        self,
        url: str,
        image_name: str | None = None,
        timeout: float | None = None,
        progress_callback: Callable[[MsdRemoteProgress], None | Awaitable[None]] | None = None,
    ) -> AsyncIterator[MsdRemoteProgress]:
        """Trigger PiKVM to download an ISO from a remote URL with live NDJSON progress."""
        session = await self._get_session()
        target_url = f"{self.base_url}/api/msd/write_remote"
        params: dict[str, Any] = {"url": url}
        if image_name:
            params["image"] = validate_iso_filename(image_name)

        client_timeout = aiohttp.ClientTimeout(
            total=timeout, sock_read=timeout or 300.0, sock_connect=15.0
        )
        headers = {
            "Authorization": self._get_auth_header(),
            "Accept": "application/x-ndjson, application/json",
        }

        async with session.post(
            target_url,
            params=params,
            headers=headers,
            ssl=self._ssl_context,
            timeout=client_timeout,
        ) as resp:
            resp.raise_for_status()
            async for raw_line in resp.content:
                line = raw_line.strip()
                if not line:
                    continue
                data = json.loads(line.decode("utf-8"))
                progress = MsdRemoteProgress.from_dict(data)
                if progress_callback:
                    res = progress_callback(progress)
                    if asyncio.iscoroutine(res):
                        await res
                yield progress

    async def remove_msd_image(self, image: str) -> bool:
        """Remove a disk image from MSD storage. POST /api/msd/remove?image=<name>."""
        clean_name = validate_iso_filename(image)
        res = await self._request("POST", "/api/msd/remove", params={"image": clean_name})
        return bool(res is not None)

    async def set_msd_params(
        self,
        image: str | None = None,
        cdrom: bool | None = None,
        rw: bool | None = None,
    ) -> bool:
        """Configure MSD drive parameters. POST /api/msd/set_params."""
        params: dict[str, Any] = {}
        if image is not None:
            params["image"] = validate_iso_filename(image) if image else ""
        if cdrom is not None:
            params["cdrom"] = "1" if cdrom else "0"
        if rw is not None:
            params["rw"] = "1" if rw else "0"
        res = await self._request("POST", "/api/msd/set_params", params=params)
        return bool(res is not None)

    async def set_msd_connected(self, connected: bool) -> bool:
        """Connect or disconnect virtual USB drive. POST /api/msd/set_connected."""
        res = await self._request(
            "POST",
            "/api/msd/set_connected",
            params={"connected": "1" if connected else "0"},
        )
        return bool(res is not None)

    async def reset_msd(self, force: bool = False) -> bool:
        """Reset MSD to factory default configuration. POST /api/msd/reset.

        High-consequence action requiring explicit confirmation.

        Raises:
            PiKVMSafetyError: If attempted without force=True.

        """
        if not force:
            raise PiKVMSafetyError(
                "Resetting MSD to factory configuration is high-consequence and "
                "requires explicit force=True confirmation."
            )
        res = await self._request("POST", "/api/msd/reset")
        return bool(res is not None)

    async def mount_msd_image(
        self,
        image: str,
        cdrom: bool = True,
        rw: bool = False,
        connect: bool = True,
    ) -> bool:
        """High-level helper: select image and connect the drive."""
        ok = await self.set_msd_params(image=image, cdrom=cdrom, rw=rw)
        if ok and connect:
            return await self.set_msd_connected(True)
        return ok

    async def unmount_msd_image(self, disconnect: bool = True) -> bool:
        """High-level helper: disconnect drive and clear selected image."""
        if disconnect:
            await self.set_msd_connected(False)
        return await self.set_msd_params(image="")

    # -------------------------------------------------------------------------
    # HID Automation Operations
    # -------------------------------------------------------------------------

    async def get_hid_state(self) -> HidDeviceState:
        """Fetch current HID state. GET /api/hid."""
        raw = await self._request("GET", "/api/hid")
        return HidDeviceState.from_dict(raw)

    async def get_keymaps(self) -> KeyboardKeymaps:
        """Fetch available typing layouts. GET /api/hid/keymaps."""
        raw = await self._request("GET", "/api/hid/keymaps")
        return KeyboardKeymaps.from_dict(raw)

    async def send_key(
        self,
        key: str,
        state: bool | None = None,
        finish: bool = False,
    ) -> bool:
        """Send a single key event. POST /api/hid/events/send_key."""
        canonical_key = validate_hid_key(key)
        params: dict[str, Any] = {"key": canonical_key}
        if state is not None:
            params["state"] = "1" if state else "0"
            if finish:
                params["finish"] = "1"
        res = await self._request("POST", "/api/hid/events/send_key", params=params)
        return bool(res is not None)

    async def tap_key(self, key: str, delay: float = 0.05) -> bool:
        """Tap a key: press, sleep, release with finish."""
        canonical_key = validate_hid_key(key)
        await self.send_key(canonical_key, state=True, finish=False)
        if delay > 0:
            await asyncio.sleep(delay)
        return await self.send_key(canonical_key, state=False, finish=True)

    async def send_shortcut(self, keys: str | Sequence[str]) -> bool:
        """Send a key combination shortcut (e.g. 'ControlLeft,AltLeft,Delete')."""
        valid_keys = validate_hid_shortcut(keys)
        keys_str = ",".join(valid_keys)
        res = await self._request(
            "POST", "/api/hid/events/send_shortcut", params={"keys": keys_str}
        )
        return bool(res is not None)

    async def print_text(
        self,
        text: str,
        keymap: str | None = None,
        delay: float | None = None,
        slow: bool = False,
    ) -> bool:
        """Send raw text string to type. POST /api/hid/print."""
        sanitized = sanitize_hid_text(text)
        params: dict[str, Any] = {}
        if keymap:
            params["keymap"] = keymap
        if delay is not None:
            params["delay"] = str(delay)
        if slow:
            params["slow"] = "1"

        session = await self._get_session()
        url = f"{self.base_url}/api/hid/print"
        headers = {
            "Authorization": self._get_auth_header(),
            "Content-Type": "text/plain; charset=utf-8",
        }
        async with session.post(
            url,
            params=params,
            data=sanitized.encode("utf-8"),
            headers=headers,
            ssl=self._ssl_context,
        ) as resp:
            resp.raise_for_status()
            payload = await resp.json()
            return bool(payload.get("ok", True))

    async def send_mouse_button(
        self,
        button: str = "left",
        state: bool | None = None,
    ) -> bool:
        """Send mouse button event. POST /api/hid/events/send_mouse_button."""
        clean_button = validate_mouse_button(button)
        params: dict[str, Any] = {"button": clean_button}
        if state is not None:
            params["state"] = "1" if state else "0"
        res = await self._request("POST", "/api/hid/events/send_mouse_button", params=params)
        return bool(res is not None)

    async def move_mouse(self, to_x: int, to_y: int) -> bool:
        """Move cursor to absolute coordinates. POST /api/hid/events/send_mouse_move."""
        valid_x, valid_y = validate_mouse_coords(to_x, to_y)
        params = {"to_x": str(valid_x), "to_y": str(valid_y)}
        res = await self._request("POST", "/api/hid/events/send_mouse_move", params=params)
        return bool(res is not None)

    async def click_mouse(
        self,
        button: str = "left",
        to_x: int | None = None,
        to_y: int | None = None,
        delay: float = 0.05,
        double_click: bool = False,
    ) -> bool:
        """Tap mouse button with optional coordinate target and double-click support."""
        clean_button = validate_mouse_button(button)
        clean_delay = validate_mouse_delay(delay)

        if to_x is not None or to_y is not None:
            if to_x is None or to_y is None:
                raise PiKVMValidationError(
                    "Both to_x and to_y must be provided for mouse click, "
                    f"got to_x={to_x}, to_y={to_y}"
                )
            await self.move_mouse(to_x=to_x, to_y=to_y)

        clicks = 2 if double_click else 1
        for i in range(clicks):
            await self.send_mouse_button(button=clean_button, state=True)
            if clean_delay > 0:
                await asyncio.sleep(clean_delay)
            await self.send_mouse_button(button=clean_button, state=False)
            if double_click and i == 0:
                await asyncio.sleep(0.08)
        return True

    async def play_macro(
        self,
        macro: HidMacro | Sequence[dict[str, Any]],
        abort_on_error: bool = True,
        max_steps: int = 1000,
        timeout: float | None = 60.0,
        allow_hardware_control: bool = False,
    ) -> list[bool]:
        """Execute a recorded PiKVM recorder script JSON sequence.

        Args:
            macro: HidMacro object or sequence of macro event step dictionaries.
            abort_on_error: If True, halts macro execution upon encountering any step failure.
            max_steps: Maximum allowable step count (default: 1000).
            timeout: Maximum execution timeout in seconds (default: 60.0s).
            allow_hardware_control: If True, allows GPIO switching, pulsing, and ATX actions.
                If False, attempting hardware actions raises PiKVMSafetyError.

        Returns:
            List of boolean results for each executed step.

        Raises:
            PiKVMValidationError: If macro exceeds max_steps or has unsupported type.
            PiKVMSafetyError: If macro attempts hardware actions without authorization.
            PiKVMTimeoutError: If execution exceeds timeout duration.

        """
        if isinstance(macro, HidMacro):
            compiled = macro
        elif isinstance(macro, (list, tuple)):
            compiled = HidMacro.from_list(list(macro))
        else:
            raise PiKVMValidationError(f"Unsupported macro input type: {type(macro)}")

        if len(compiled.steps) > max_steps:
            raise PiKVMValidationError(
                f"Macro step count {len(compiled.steps)} exceeds maximum allowed limit "
                f"of {max_steps} steps."
            )

        async def _execute_macro() -> list[bool]:
            results: list[bool] = []
            for step in compiled.steps:
                try:
                    ok = True
                    etype = step.event_type
                    ev = step.event

                    if (
                        etype in ("gpio_switch", "gpio_pulse", "atx_button")
                        and not allow_hardware_control
                    ):
                        raise PiKVMSafetyError(
                            f"Macro step '{etype}' requires allow_hardware_control=True "
                            "confirmation."
                        )

                    if etype == "delay":
                        delay_sec = step.delay_ms / 1000.0 if step.delay_ms > 0 else 0.05
                        await asyncio.sleep(delay_sec)
                    elif etype == "key":
                        key_val = str(ev.get("key", ""))
                        st = ev.get("state")
                        ok = await self.send_key(key_val, state=st)
                    elif etype in ("print", "text"):
                        ok = await self.print_text(
                            text=str(ev.get("text", "")),
                            keymap=ev.get("keymap"),
                            delay=ev.get("delay"),
                            slow=bool(ev.get("slow", False)),
                        )
                    elif etype == "mouse_button":
                        btn = str(ev.get("button", "left"))
                        st = ev.get("state")
                        ok = await self.send_mouse_button(btn, state=st)
                    elif etype == "mouse_move":
                        target_to = ev.get("to", {})
                        x = int(target_to.get("x", 0))
                        y = int(target_to.get("y", 0))
                        ok = await self.move_mouse(x, y)
                    elif etype == "gpio_switch":
                        ch = str(ev.get("channel", ""))
                        to_st = bool(ev.get("state", False))
                        ok = await self.switch_gpio(ch, to_st)
                    elif etype == "gpio_pulse":
                        ch = str(ev.get("channel", ""))
                        ok = await self.pulse_gpio(ch)
                    elif etype == "atx_button":
                        btn = str(ev.get("button", "power"))
                        ok = await self.power_action(btn, force=True)

                    results.append(ok)
                    if not ok and abort_on_error:
                        break
                except Exception:
                    results.append(False)
                    if abort_on_error:
                        raise

            return results

        if timeout is not None:
            try:
                async with asyncio.timeout(timeout):
                    return await _execute_macro()
            except TimeoutError as err:
                raise PiKVMTimeoutError(
                    f"Macro execution timed out after {timeout} seconds."
                ) from err
        else:
            return await _execute_macro()

    # -------------------------------------------------------------------------
    # Screen OCR Operations
    # -------------------------------------------------------------------------

    async def get_ocr_text(
        self,
        left: int = -1,
        top: int = -1,
        right: int = -1,
        bottom: int = -1,
        langs: str = "eng",
        allow_offline: bool = True,
    ) -> str:
        """Extract text from the screen or specific region using PiKVM OCR.

        Endpoint: GET /api/streamer/snapshot?ocr=1&ocr_langs=<langs>&...
        """
        valid_left, valid_top, valid_right, valid_bottom = validate_ocr_box(
            left, top, right, bottom
        )
        params: dict[str, Any] = {
            "ocr": "1",
            "ocr_langs": langs,
            "allow_offline": "1" if allow_offline else "0",
        }
        if valid_left >= 0 and valid_top >= 0 and valid_right >= 0 and valid_bottom >= 0:
            params["ocr_left"] = str(valid_left)
            params["ocr_top"] = str(valid_top)
            params["ocr_right"] = str(valid_right)
            params["ocr_bottom"] = str(valid_bottom)

        session = await self._get_session()
        url = f"{self.base_url}/api/streamer/snapshot"
        headers = {
            "Authorization": self._get_auth_header(),
            "Accept": "text/plain",
        }
        async with session.get(
            url,
            params=params,
            headers=headers,
            ssl=self._ssl_context,
        ) as resp:
            resp.raise_for_status()
            return await resp.text()

    # -------------------------------------------------------------------------
    # GPIO Subsystem Operations
    # -------------------------------------------------------------------------

    async def read_gpio(self) -> dict[str, Any]:
        """Fetch raw GPIO status and scheme dictionary. GET /api/gpio."""
        return await self.get_raw_gpio()

    async def switch_gpio(
        self,
        channel: str,
        state: bool,
        wait: bool = False,
    ) -> bool:
        """Switch an output GPIO channel on or off. POST /api/gpio/switch."""
        clean_channel = validate_gpio_channel(channel)
        params = {
            "channel": clean_channel,
            "state": "1" if state else "0",
            "wait": "1" if wait else "0",
        }
        res = await self._request("POST", "/api/gpio/switch", params=params)
        return bool(res is not None)

    async def pulse_gpio(
        self,
        channel: str,
        delay: float | None = None,
        wait: bool = False,
    ) -> bool:
        """Trigger a momentary pulse on an output GPIO channel. POST /api/gpio/pulse."""
        clean_channel = validate_gpio_channel(channel)
        params: dict[str, Any] = {
            "channel": clean_channel,
            "wait": "1" if wait else "0",
        }
        if delay is not None:
            valid_delay = validate_gpio_delay(delay)
            params["delay"] = str(valid_delay)
        res = await self._request("POST", "/api/gpio/pulse", params=params)
        return bool(res is not None)

    async def close(self) -> None:
        """Close the underlying session if owned by this client."""
        if self._owns_session and self._session is not None and not self._session.closed:
            await self._session.close()

    async def __aenter__(self) -> PiKVMClient:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        await self.close()
