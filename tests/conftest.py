from __future__ import annotations

import _socket
import ipaddress
import os
import socket
import struct
import sys
from collections.abc import Generator
from typing import Any

import pytest

_ORIG_RAW_SOCKET = _socket.socket

# Pre-initialize pycares Channel daemon thread to avoid verify_cleanup thread check failure
try:
    import pycares  # type: ignore[import-not-found]

    _channel = pycares.Channel()
except Exception:
    pass


def _is_loopback_address(address: Any) -> bool:
    """Determine whether a socket address targets local loopback or local IPC.

    Allows IPv4 loopback (127.0.0.0/8), IPv6 loopback (::1), 'localhost',
    and UNIX domain sockets (paths/bytes). All other destinations are blocked.
    """
    if isinstance(address, (str, bytes)):
        return True
    if not isinstance(address, (tuple, list)) or not address:
        return False

    host = address[0]
    if host in ("localhost", "127.0.0.1", "::1", None, ""):
        return True

    if isinstance(host, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
        return host.is_loopback

    try:
        ip = ipaddress.ip_address(host)
        return ip.is_loopback
    except (ValueError, TypeError):
        return False


_LOOPBACK_HOSTNAMES: frozenset[str] = frozenset(
    {
        "localhost",
        "localhost.localdomain",
        "ip6-localhost",
        "ip6-loopback",
    }
)


def _is_loopback_dns_host(host: Any) -> bool:
    """Determine whether a hostname or IP address targets local loopback for DNS operations.

    Permits 'localhost', '127.0.0.1', '::1', IPv4 loopback (127.0.0.0/8), IPv6 loopback (::1),
    standard loopback aliases, and None / empty strings for local binding/connects.
    Blocks all non-loopback domain names and non-loopback IP addresses.
    """
    if host is None or host == "" or host == b"":
        return True
    if isinstance(host, (bytes, bytearray)):
        try:
            host = host.decode("utf-8", errors="replace")
        except Exception:
            return False
    if not isinstance(host, str):
        if isinstance(host, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
            return host.is_loopback
        return False

    host_lower = host.lower().strip().rstrip(".")
    if host_lower in _LOOPBACK_HOSTNAMES:
        return True

    try:
        ip = ipaddress.ip_address(host_lower)
        if ip.is_loopback:
            return True
        mapped = getattr(ip, "ipv4_mapped", None)
        return mapped is not None and mapped.is_loopback
    except (ValueError, TypeError):
        return False


def _check_ancdata_destinations(ancdata: Any) -> None:
    """Inspect ancillary data (control messages) for non-loopback IP destinations."""
    if not ancdata:
        return
    try:
        for item in ancdata:
            if isinstance(item, (tuple, list)) and len(item) >= 3:
                cmsg_level, cmsg_type, cmsg_data = item[0], item[1], item[2]
                if isinstance(cmsg_data, (bytes, bytearray, memoryview)):
                    raw_bytes = bytes(cmsg_data)
                    # IP_PKTINFO (IPv4): struct in_pktinfo (ifindex 4B, spec_dst 4B, addr 4B)
                    if cmsg_level in (
                        socket.IPPROTO_IP,
                        getattr(socket, "SOL_IP", 0),
                    ) and cmsg_type == getattr(socket, "IP_PKTINFO", 8):
                        if len(raw_bytes) >= 12:
                            _, spec_dst_b, addr_b = struct.unpack_from("=I4s4s", raw_bytes)
                            for b_ip in (spec_dst_b, addr_b):
                                if b_ip != b"\x00\x00\x00\x00":
                                    ip_obj = ipaddress.IPv4Address(b_ip)
                                    if not ip_obj.is_loopback:
                                        msg = (
                                            "Outbound network call blocked during "
                                            f"offline testing: {ip_obj}"
                                        )
                                        raise RuntimeError(msg)
                    # IPV6_PKTINFO (IPv6): struct in6_pktinfo (ipi6_addr 16B, ipi6_ifindex 4B)
                    elif cmsg_level == getattr(socket, "IPPROTO_IPV6", 41) and cmsg_type == getattr(
                        socket, "IPV6_PKTINFO", 50
                    ):
                        if len(raw_bytes) >= 16:
                            addr6_b = struct.unpack_from("=16s", raw_bytes)[0]
                            if addr6_b != b"\x00" * 16:
                                ip6_obj = ipaddress.IPv6Address(addr6_b)
                                if not ip6_obj.is_loopback:
                                    msg = (
                                        "Outbound network call blocked during "
                                        f"offline testing: {ip6_obj}"
                                    )
                                    raise RuntimeError(msg)
    except RuntimeError:
        raise
    except Exception:
        pass


@pytest.fixture(autouse=True)
def socket_guard(
    monkeypatch: pytest.MonkeyPatch, request: pytest.FixtureRequest
) -> Generator[None, None, None]:
    """Autouse fixture enforcing strict offline isolation across all tests.

    Intercepts socket creation and connection attempts:
    - Immediately raises RuntimeError on any outbound connection to a non-loopback address.
    - Permits local loopback connections (127.0.0.0/8, ::1, localhost, UNIX sockets).
    - Unblocks sockets for tests marked '@pytest.mark.live' ONLY if
      PIKVM_ENABLE_LIVE_TESTS=='1' is explicitly set in the environment.
    - Neutralizes bypass attempts via pytest-socket enable_socket() or _remove_restrictions().
    """
    if request.node.get_closest_marker("live"):
        if os.environ.get("PIKVM_ENABLE_LIVE_TESTS") == "1":
            yield
            return

    orig_connect = socket.socket.connect
    orig_connect_ex = socket.socket.connect_ex
    orig_create_conn = socket.create_connection
    orig_sendto = socket.socket.sendto
    orig_sendmsg = getattr(socket.socket, "sendmsg", None)

    orig_getaddrinfo = socket.getaddrinfo
    orig_gethostbyname = socket.gethostbyname
    orig_gethostbyname_ex = socket.gethostbyname_ex
    orig_gethostbyaddr = socket.gethostbyaddr
    orig_getnameinfo = socket.getnameinfo
    orig_getfqdn = getattr(socket, "getfqdn", None)

    orig_raw_getaddrinfo = getattr(_socket, "getaddrinfo", None)
    orig_raw_gethostbyname = getattr(_socket, "gethostbyname", None)
    orig_raw_gethostbyname_ex = getattr(_socket, "gethostbyname_ex", None)
    orig_raw_gethostbyaddr = getattr(_socket, "gethostbyaddr", None)
    orig_raw_getnameinfo = getattr(_socket, "getnameinfo", None)

    def _guarded_connect(self: Any, *args: Any, **kwargs: Any) -> None:
        address = args[0] if args else kwargs.get("address")
        if not _is_loopback_address(address):
            raise RuntimeError(f"Outbound network call blocked during offline testing: {address}")
        orig_connect(self, *args, **kwargs)

    def _guarded_connect_ex(self: Any, *args: Any, **kwargs: Any) -> int:
        address = args[0] if args else kwargs.get("address")
        if not _is_loopback_address(address):
            raise RuntimeError(f"Outbound network call blocked during offline testing: {address}")
        return int(orig_connect_ex(self, *args, **kwargs))

    def _guarded_create_connection(*args: Any, **kwargs: Any) -> socket.socket:
        address = args[0] if args else kwargs.get("address")
        if not _is_loopback_address(address):
            raise RuntimeError(f"Outbound network call blocked during offline testing: {address}")
        return orig_create_conn(*args, **kwargs)

    def _guarded_sendto(self: Any, data: bytes, *args: Any, **kwargs: Any) -> int:
        # Extract destination address by distinguishing flags (int) from address
        address = kwargs.get("address")
        if address is None:
            if len(args) == 1:
                # Signature: sendto(data, address) OR sendto(data, flags)
                if not isinstance(args[0], int):
                    address = args[0]
            elif len(args) >= 2:
                # Signature: sendto(data, flags, address)
                if not isinstance(args[1], int):
                    address = args[1]
                elif not isinstance(args[0], int):
                    address = args[0]

        # Explicit destination address provided
        if address is not None:
            if not _is_loopback_address(address):
                raise RuntimeError(
                    f"Outbound network call blocked during offline testing: {address}"
                )
            return int(orig_sendto(self, data, *args, **kwargs))

        # Destination address is omitted; verify connected peer destination
        try:
            peer = self.getpeername()
        except OSError:
            peer = None

        if peer is not None:
            if not _is_loopback_address(peer):
                raise RuntimeError(f"Outbound network call blocked during offline testing: {peer}")
            # Delegate to send() to support POSIX sendto(data, flags) on connected sockets
            return int(self.send(data, *args, **kwargs))

        return int(orig_sendto(self, data, *args, **kwargs))

    def _guarded_sendmsg(self: Any, *args: Any, **kwargs: Any) -> int:
        address = kwargs.get("address")
        if address is None and len(args) >= 4:
            address = args[3]

        if address is not None:
            if not _is_loopback_address(address):
                raise RuntimeError(
                    f"Outbound network call blocked during offline testing: {address}"
                )
        else:
            try:
                peer = self.getpeername()
            except OSError:
                peer = None
            if peer is not None and not _is_loopback_address(peer):
                raise RuntimeError(f"Outbound network call blocked during offline testing: {peer}")

        ancdata = kwargs.get("ancdata")
        if ancdata is None and len(args) >= 2:
            ancdata = args[1]
        if ancdata:
            _check_ancdata_destinations(ancdata)

        if orig_sendmsg is None:
            raise NotImplementedError("socket.sendmsg is not available on this platform")
        return int(orig_sendmsg(self, *args, **kwargs))

    def _guarded_getaddrinfo(*args: Any, **kwargs: Any) -> list[tuple[Any, ...]]:
        host = args[0] if args else kwargs.get("host")
        if not _is_loopback_dns_host(host):
            raise RuntimeError(f"Outbound network call blocked during offline testing: {host}")
        return orig_getaddrinfo(*args, **kwargs)

    def _guarded_raw_getaddrinfo(*args: Any, **kwargs: Any) -> Any:
        host = args[0] if args else kwargs.get("host")
        if not _is_loopback_dns_host(host):
            raise RuntimeError(f"Outbound network call blocked during offline testing: {host}")
        if orig_raw_getaddrinfo is None:
            raise NotImplementedError("_socket.getaddrinfo is unavailable")
        return orig_raw_getaddrinfo(*args, **kwargs)

    def _guarded_gethostbyname(*args: Any, **kwargs: Any) -> str:
        host = (
            args[0] if args else kwargs.get("hostname") or kwargs.get("host") or kwargs.get("name")
        )
        if not _is_loopback_dns_host(host):
            raise RuntimeError(f"Outbound network call blocked during offline testing: {host}")
        return orig_gethostbyname(*args, **kwargs)

    def _guarded_raw_gethostbyname(*args: Any, **kwargs: Any) -> Any:
        host = (
            args[0] if args else kwargs.get("hostname") or kwargs.get("host") or kwargs.get("name")
        )
        if not _is_loopback_dns_host(host):
            raise RuntimeError(f"Outbound network call blocked during offline testing: {host}")
        if orig_raw_gethostbyname is None:
            raise NotImplementedError("_socket.gethostbyname is unavailable")
        return orig_raw_gethostbyname(*args, **kwargs)

    def _guarded_gethostbyname_ex(*args: Any, **kwargs: Any) -> tuple[str, list[str], list[str]]:
        host = (
            args[0] if args else kwargs.get("hostname") or kwargs.get("host") or kwargs.get("name")
        )
        if not _is_loopback_dns_host(host):
            raise RuntimeError(f"Outbound network call blocked during offline testing: {host}")
        return orig_gethostbyname_ex(*args, **kwargs)

    def _guarded_raw_gethostbyname_ex(*args: Any, **kwargs: Any) -> Any:
        host = (
            args[0] if args else kwargs.get("hostname") or kwargs.get("host") or kwargs.get("name")
        )
        if not _is_loopback_dns_host(host):
            raise RuntimeError(f"Outbound network call blocked during offline testing: {host}")
        if orig_raw_gethostbyname_ex is None:
            raise NotImplementedError("_socket.gethostbyname_ex is unavailable")
        return orig_raw_gethostbyname_ex(*args, **kwargs)

    def _guarded_gethostbyaddr(*args: Any, **kwargs: Any) -> tuple[str, list[str], list[str]]:
        host = (
            args[0] if args else kwargs.get("ip_address") or kwargs.get("host") or kwargs.get("ip")
        )
        if not _is_loopback_dns_host(host):
            raise RuntimeError(f"Outbound network call blocked during offline testing: {host}")
        return orig_gethostbyaddr(*args, **kwargs)

    def _guarded_raw_gethostbyaddr(*args: Any, **kwargs: Any) -> Any:
        host = (
            args[0] if args else kwargs.get("ip_address") or kwargs.get("host") or kwargs.get("ip")
        )
        if not _is_loopback_dns_host(host):
            raise RuntimeError(f"Outbound network call blocked during offline testing: {host}")
        if orig_raw_gethostbyaddr is None:
            raise NotImplementedError("_socket.gethostbyaddr is unavailable")
        return orig_raw_gethostbyaddr(*args, **kwargs)

    def _guarded_getnameinfo(*args: Any, **kwargs: Any) -> tuple[str, str]:
        sockaddr = args[0] if args else kwargs.get("sockaddr")
        host = sockaddr[0] if isinstance(sockaddr, (tuple, list)) and sockaddr else sockaddr
        if not _is_loopback_dns_host(host):
            raise RuntimeError(f"Outbound network call blocked during offline testing: {host}")
        return orig_getnameinfo(*args, **kwargs)

    def _guarded_raw_getnameinfo(*args: Any, **kwargs: Any) -> Any:
        sockaddr = args[0] if args else kwargs.get("sockaddr")
        host = sockaddr[0] if isinstance(sockaddr, (tuple, list)) and sockaddr else sockaddr
        if not _is_loopback_dns_host(host):
            raise RuntimeError(f"Outbound network call blocked during offline testing: {host}")
        if orig_raw_getnameinfo is None:
            raise NotImplementedError("_socket.getnameinfo is unavailable")
        return orig_raw_getnameinfo(*args, **kwargs)

    def _guarded_getfqdn(name: str = "") -> Any:
        if not name:
            return "localhost"
        if not _is_loopback_dns_host(name):
            raise RuntimeError(f"Outbound network call blocked during offline testing: {name}")
        if orig_getfqdn is not None:
            try:
                return orig_getfqdn(name)
            except Exception:
                return name
        return name

    # Patch socket.socket methods
    monkeypatch.setattr(socket.socket, "connect", _guarded_connect)
    monkeypatch.setattr(socket.socket, "connect_ex", _guarded_connect_ex)
    monkeypatch.setattr(socket, "create_connection", _guarded_create_connection)
    monkeypatch.setattr(socket.socket, "sendto", _guarded_sendto)
    if hasattr(socket.socket, "sendmsg"):
        monkeypatch.setattr(socket.socket, "sendmsg", _guarded_sendmsg)

    # Patch DNS functions on socket and _socket
    monkeypatch.setattr(socket, "getaddrinfo", _guarded_getaddrinfo)
    if hasattr(_socket, "getaddrinfo"):
        monkeypatch.setattr(_socket, "getaddrinfo", _guarded_raw_getaddrinfo)
    monkeypatch.setattr(socket, "gethostbyname", _guarded_gethostbyname)
    if hasattr(_socket, "gethostbyname"):
        monkeypatch.setattr(_socket, "gethostbyname", _guarded_raw_gethostbyname)
    monkeypatch.setattr(socket, "gethostbyname_ex", _guarded_gethostbyname_ex)
    if hasattr(_socket, "gethostbyname_ex"):
        monkeypatch.setattr(_socket, "gethostbyname_ex", _guarded_raw_gethostbyname_ex)
    monkeypatch.setattr(socket, "gethostbyaddr", _guarded_gethostbyaddr)
    if hasattr(_socket, "gethostbyaddr"):
        monkeypatch.setattr(_socket, "gethostbyaddr", _guarded_raw_gethostbyaddr)
    monkeypatch.setattr(socket, "getnameinfo", _guarded_getnameinfo)
    if hasattr(_socket, "getnameinfo"):
        monkeypatch.setattr(_socket, "getnameinfo", _guarded_raw_getnameinfo)
    if hasattr(socket, "getfqdn"):
        monkeypatch.setattr(socket, "getfqdn", _guarded_getfqdn)

    # Patch pycares Channel methods if present
    if "pycares" in sys.modules:
        pc = sys.modules["pycares"]
        if hasattr(pc, "Channel"):
            orig_pc_query = getattr(pc.Channel, "query", None)
            orig_pc_gai = getattr(pc.Channel, "getaddrinfo", None)
            orig_pc_ghba = getattr(pc.Channel, "gethostbyaddr", None)
            orig_pc_gni = getattr(pc.Channel, "getnameinfo", None)

            def _guarded_pc_query(self: Any, name: Any, *args: Any, **kwargs: Any) -> Any:
                if not _is_loopback_dns_host(name):
                    raise RuntimeError(
                        f"Outbound network call blocked during offline testing: {name}"
                    )
                if orig_pc_query is not None:
                    return orig_pc_query(self, name, *args, **kwargs)

            def _guarded_pc_gai(self: Any, host: Any, *args: Any, **kwargs: Any) -> Any:
                if not _is_loopback_dns_host(host):
                    raise RuntimeError(
                        f"Outbound network call blocked during offline testing: {host}"
                    )
                if orig_pc_gai is not None:
                    return orig_pc_gai(self, host, *args, **kwargs)

            def _guarded_pc_ghba(self: Any, ip: Any, *args: Any, **kwargs: Any) -> Any:
                if not _is_loopback_dns_host(ip):
                    raise RuntimeError(
                        f"Outbound network call blocked during offline testing: {ip}"
                    )
                if orig_pc_ghba is not None:
                    return orig_pc_ghba(self, ip, *args, **kwargs)

            def _guarded_pc_gni(self: Any, sockaddr: Any, *args: Any, **kwargs: Any) -> Any:
                host = sockaddr[0] if isinstance(sockaddr, (tuple, list)) and sockaddr else sockaddr
                if not _is_loopback_dns_host(host):
                    raise RuntimeError(
                        f"Outbound network call blocked during offline testing: {host}"
                    )
                if orig_pc_gni is not None:
                    return orig_pc_gni(self, sockaddr, *args, **kwargs)

            if orig_pc_query:
                monkeypatch.setattr(pc.Channel, "query", _guarded_pc_query)
            if orig_pc_gai:
                monkeypatch.setattr(pc.Channel, "getaddrinfo", _guarded_pc_gai)
            if orig_pc_ghba:
                monkeypatch.setattr(pc.Channel, "gethostbyaddr", _guarded_pc_ghba)
            if orig_pc_gni:
                monkeypatch.setattr(pc.Channel, "getnameinfo", _guarded_pc_gni)

    # Metaclass ensuring isinstance/issubclass checks succeed for all socket instances
    class _GuardedSocketMeta(type):
        def __instancecheck__(cls, instance: Any) -> bool:
            return isinstance(instance, (socket.socket, _ORIG_RAW_SOCKET))

        def __subclasscheck__(cls, subclass: type) -> bool:
            try:
                return issubclass(subclass, (socket.socket, _ORIG_RAW_SOCKET))
            except TypeError:
                return False

    # Guarded C-extension socket subclass
    class _GuardedRawSocket(_ORIG_RAW_SOCKET, metaclass=_GuardedSocketMeta):
        connect = _guarded_connect
        connect_ex = _guarded_connect_ex
        sendto = _guarded_sendto  # type: ignore[assignment]
        if hasattr(_ORIG_RAW_SOCKET, "sendmsg"):
            sendmsg = _guarded_sendmsg

    # Patch SocketType and socket in socket and _socket modules
    monkeypatch.setattr(socket, "SocketType", _GuardedRawSocket)
    if hasattr(_socket, "SocketType"):
        monkeypatch.setattr(_socket, "SocketType", _GuardedRawSocket)
    monkeypatch.setattr(_socket, "socket", _GuardedRawSocket)

    # Patch pre-imported references across sys.modules
    dns_replace_map = {
        orig_getaddrinfo: _guarded_getaddrinfo,
        orig_raw_getaddrinfo: _guarded_raw_getaddrinfo,
        orig_gethostbyname: _guarded_gethostbyname,
        orig_raw_gethostbyname: _guarded_raw_gethostbyname,
        orig_gethostbyname_ex: _guarded_gethostbyname_ex,
        orig_raw_gethostbyname_ex: _guarded_raw_gethostbyname_ex,
        orig_gethostbyaddr: _guarded_gethostbyaddr,
        orig_raw_gethostbyaddr: _guarded_raw_gethostbyaddr,
        orig_getnameinfo: _guarded_getnameinfo,
        orig_raw_getnameinfo: _guarded_raw_getnameinfo,
    }

    for mod in list(sys.modules.values()):
        if mod is None or not hasattr(mod, "__dict__"):
            continue
        if getattr(mod, "__name__", "") in ("tests.conftest", "builtins"):
            continue
        for attr, val in list(mod.__dict__.items()):
            if val is _ORIG_RAW_SOCKET:
                try:
                    monkeypatch.setattr(mod, attr, _GuardedRawSocket)
                except Exception:
                    pass
            else:
                try:
                    if val in dns_replace_map and dns_replace_map[val] is not None:
                        monkeypatch.setattr(mod, attr, dns_replace_map[val])
                except Exception:
                    pass

    # Countermeasure against pytest-socket unpatching
    if "pytest_socket" in sys.modules:
        ps = sys.modules["pytest_socket"]
        if hasattr(ps, "_true_connect"):
            monkeypatch.setattr(ps, "_true_connect", _guarded_connect)

    yield


@pytest.fixture
def sample_cert_pem() -> str:
    """Return a valid self-signed PEM certificate for testing."""
    return (
        "-----BEGIN CERTIFICATE-----\n"
        "MIIDDTCCAfWgAwIBAgIUGx8y2YXwDl3sygVGL+lRTjVxdGgwDQYJKoZIhvcNAQEL\n"
        "BQAwFjEUMBIGA1UEAwwLcGlrdm0ubG9jYWwwHhcNMjYwOTI4MTYxNzM5WhcNMjcw\n"
        "OTI4MTYxNzM5WjAWMRQwEgYDVQQDDAtwaWt2bS5sb2NhbDCCASIwDQYJKoZIhvcN\n"
        "AQEBBQADggEPADCCAQoCggEBAIbc2qrsotAn9o22/erkh8MhYA4iPe4neeK8NB8G\n"
        "MwTHMsrPC4jmkyGVGk1HozdlvVi8fewbUD1NTtFmdKlwKMzHdGdTtlvdsi12I6AG\n"
        "1sB3iSsCBMxsR+E/7mlAE/+VLH9KKFLwTDfGKe3iJKdCocKVnBTQWoSYm3rHV0ZM\n"
        "ebUQ/SN90quCSlsNafchCCqDe7J+eJYxhDLQ/YVLoNkPUhEPSJ166pp5sf4qSgEn\n"
        "eXAKT2/n2Koq5C1c/STLDa+3LOWdQWn6fFUoIJuPQ7qiAt9LZI3VeYeU5XlzIBZT\n"
        "DdPdaDoEoOhaBxXAZG7gxywcRwyWA9Yl8HwsXqwft6XrfdMCAwEAAaNTMFEwHQYD\n"
        "VR0OBBYEFEjDBIlmFCuf4mLzea3C37DtBGYtMB8GA1UdIwQYMBaAFEjDBIlmFCuf\n"
        "4mLzea3C37DtBGYtMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEB\n"
        "AIAZjCHKFbouCwgEla1/nimBoFbfuFdls7DpRugTbxyALjgNi8QtL12WpOuFhryi\n"
        "UcVEBJJyM0rtSgkC++FxHJgSbIw1iQRKp5C6ErTlt7JPF3hS7Iur4GZ0jIspyrok\n"
        "9XCSogNlhE1ir5PYgTBvG8uMCIfzU0mSmLt93bfybYC+/kEO7IC+8pvtHx7Ybqww\n"
        "0s9T2FnzYSDsCPO+T0T20SPktgrO5N835jc+G5VCG9KNhIXuFUQRNgDA27FdFLH6\n"
        "TCvMc3K/uBo3Yt/1RRiuwS1YBl6jFNFkamdCs7+dwwTd2GuNgXlQPwOMpQAUwTzA\n"
        "d94+v71gOPoa9mV8f46e47Y=\n"
        "-----END CERTIFICATE-----"
    )


@pytest.fixture
def sample_info_payload() -> dict[str, Any]:
    """Return a representative PiKVM /api/info response dictionary."""
    return {
        "ok": True,
        "result": {
            "hw": {
                "platform": {
                    "type": "v3",
                    "model": "v3-hdmi",
                    "base": "rpi4",
                    "serial": "A1B2C3D4E5F6",
                },
                "health": {
                    "temp": {"cpu": 48.5},
                    "throttling": {
                        "raw_flags": 0,
                        "text_flags": [],
                        "voltage": {
                            "core": {
                                "now": False,
                                "past": False,
                            }
                        },
                    },
                },
                "performance": {
                    "cpu": {"utilization": 14.8},
                    "memory": {
                        "utilization": 32.1,
                        "total": 2147483648,
                        "available": 1458925568,
                    },
                    "fan": {"speed": 2400},
                },
            },
            "meta": {
                "server": {
                    "host": "pikvm.local",
                    "name": "Lab PiKVM",
                    "version": "3.240",
                }
            },
            "system": {
                "kvmd": {
                    "version": "3.240-1",
                }
            },
            "extras": {
                "vnc": {"is_running": True},
            },
        },
    }


@pytest.fixture
def sample_msd_payload() -> dict[str, Any]:
    """Return a representative PiKVM /api/msd response dictionary."""
    return {
        "ok": True,
        "result": {
            "is_enabled": True,
            "drive": {
                "is_mounted": True,
                "connected": True,
            },
            "storage": {
                "total": 16106127360,
                "available": 10737418240,
                "images": {
                    "ubuntu.iso": {"size": 2147483648},
                    "debian.iso": {"size": 1073741824},
                },
            },
        },
    }
