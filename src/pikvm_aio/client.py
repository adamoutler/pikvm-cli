"""Asynchronous client for interacting with PiKVM."""

from __future__ import annotations

import base64
import binascii
import logging
from types import TracebackType
from typing import Any
from urllib.parse import unquote, urlparse

import aiohttp
import pyotp

from .exceptions import (
    PiKVMAuthenticationError,
    PiKVMConnectionError,
    PiKVMDeviceError,
    PiKVMTimeoutError,
)
from .models import MsdInfo, PiKVMDeviceInfo
from .tls import create_ssl_context

_LOGGER = logging.getLogger(__name__)


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
        check_hostname: bool = True,
        timeout: float = 10.0,
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
        self.check_hostname = check_hostname

        self._session = session
        self._owns_session = session is None
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

    async def power_action(self, action: str) -> bool:
        """Send an ATX power command (e.g. 'click', 'long', 'reset', 'off')."""
        valid_actions = {"click", "long", "reset", "off"}
        if action not in valid_actions:
            raise ValueError(f"Invalid ATX power action '{action}'. Must be one of {valid_actions}")

        result = await self._request("POST", "/api/atx/power", params={"action": action})
        return bool(result)

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
