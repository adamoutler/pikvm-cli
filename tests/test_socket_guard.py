"""Verification tests for offline socket guard fixture.

Ensures that outbound network calls to physical/remote hardware are intercepted
and blocked, while loopback and local IPC remain functional.
"""

from __future__ import annotations

import asyncio
import socket
import sys
import threading
from typing import Any
from unittest.mock import patch

import aiohttp
import pytest


def test_socket_guard_blocks_sync_connect() -> None:
    """Verify synchronous socket.connect to external IP is blocked."""
    sock = socket.socket()
    with pytest.raises(RuntimeError, match="Outbound network call blocked"):
        sock.connect(("192.168.1.108", 80))
    sock.close()


def test_socket_guard_blocks_create_connection() -> None:
    """Verify socket.create_connection to external IP is blocked."""
    with pytest.raises(RuntimeError, match="Outbound network call blocked"):
        socket.create_connection(("192.168.1.108", 443))


def test_socket_guard_blocks_connect_ex() -> None:
    """Verify socket.connect_ex to external IP raises RuntimeError instead of returning errno."""
    sock = socket.socket()
    with pytest.raises(RuntimeError, match="Outbound network call blocked"):
        sock.connect_ex(("192.168.1.108", 80))
    sock.close()


def test_socket_guard_blocks_udp_sendto() -> None:
    """Verify UDP sendto to external IP is blocked."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    with pytest.raises(RuntimeError, match="Outbound network call blocked"):
        sock.sendto(b"ping", ("192.168.1.108", 9999))
    sock.close()


@pytest.mark.asyncio
async def test_socket_guard_blocks_asyncio_open_connection() -> None:
    """Verify asyncio.open_connection to external IP is blocked."""
    with pytest.raises(RuntimeError, match="Outbound network call blocked"):
        await asyncio.open_connection("192.168.1.108", 443)


@pytest.mark.asyncio
async def test_socket_guard_blocks_aiohttp_unmocked() -> None:
    """Verify aiohttp unmocked requests to external IP are blocked."""
    with pytest.raises(RuntimeError, match="Outbound network call blocked"):
        async with aiohttp.ClientSession() as session:
            await session.get("http://192.168.1.108/api/info")


def test_socket_guard_allows_loopback_ipv4() -> None:
    """Verify local loopback TCP connection is permitted."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    def srv_handler() -> None:
        conn, _ = srv.accept()
        conn.sendall(b"ECHO")
        conn.close()
        srv.close()

    t = threading.Thread(target=srv_handler)
    t.start()

    client = socket.create_connection(("127.0.0.1", port))
    data = client.recv(1024)
    client.close()
    t.join()

    assert data == b"ECHO"


def test_socket_guard_allows_loopback_localhost() -> None:
    """Verify local loopback connection using 'localhost' is permitted."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    def srv_handler() -> None:
        conn, _ = srv.accept()
        conn.sendall(b"LOCALHOST_OK")
        conn.close()
        srv.close()

    t = threading.Thread(target=srv_handler)
    t.start()

    client = socket.create_connection(("localhost", port))
    data = client.recv(1024)
    client.close()
    t.join()

    assert data == b"LOCALHOST_OK"


@pytest.mark.skipif(
    not hasattr(socket, "AF_UNIX"),
    reason="AF_UNIX sockets are not supported on this platform",
)
def test_socket_guard_allows_unix_domain_socket(tmp_path: Any) -> None:
    """Verify UNIX domain socket IPC is permitted."""
    sock_path = str(tmp_path / "test.sock")
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(sock_path)
    srv.listen(1)

    def srv_handler() -> None:
        conn, _ = srv.accept()
        conn.sendall(b"UNIX_OK")
        conn.close()
        srv.close()

    t = threading.Thread(target=srv_handler)
    t.start()

    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.connect(sock_path)
    data = client.recv(1024)
    client.close()
    t.join()

    assert data == b"UNIX_OK"


def test_socket_guard_prevents_pytest_socket_bypass() -> None:
    """Verify that calling enable_socket() cannot bypass the guard."""
    import types

    ps = types.ModuleType("pytest_socket")
    ps._true_connect = socket.socket.connect  # type: ignore[attr-defined]

    def fake_enable() -> None:
        socket.socket.connect = ps._true_connect  # type: ignore[method-assign]

    ps.enable_socket = fake_enable  # type: ignore[attr-defined]
    with patch.dict(sys.modules, {"pytest_socket": ps}):
        ps.enable_socket()
        sock = socket.socket()
        with pytest.raises(RuntimeError, match="Outbound network call blocked"):
            sock.connect(("192.168.1.108", 80))
        sock.close()


@pytest.mark.skipif(
    not hasattr(socket.socket, "sendmsg"),
    reason="socket.sendmsg is not supported on this platform",
)
def test_socket_guard_blocks_udp_sendmsg() -> None:
    """Verify UDP sendmsg to external IP is blocked."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    with pytest.raises(RuntimeError, match="Outbound network call blocked"):
        sock.sendmsg([b"ping"], [], 0, ("192.168.1.108", 9999))
    sock.close()


@pytest.mark.skipif(
    not hasattr(socket.socket, "sendmsg"),
    reason="socket.sendmsg is not supported on this platform",
)
def test_socket_guard_allows_udp_sendmsg_loopback(tmp_path: Any) -> None:
    """Verify UDP sendmsg to local loopback is permitted."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.bind(("127.0.0.1", 0))
    port = srv.getsockname()[1]

    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sent = client.sendmsg([b"ECHO_UDP"], [], 0, ("127.0.0.1", port))
    client.close()

    data, _ = srv.recvfrom(1024)
    srv.close()

    assert sent == len(b"ECHO_UDP")
    assert data == b"ECHO_UDP"

    if hasattr(socket, "AF_UNIX"):
        sock_path = str(tmp_path / "sendmsg_test.sock")
        srv_unix = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        srv_unix.bind(sock_path)

        cl_unix = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        sent_unix = cl_unix.sendmsg([b"UNIX_SENDMSG_OK"], [], 0, sock_path)
        data_unix, _ = srv_unix.recvfrom(1024)
        cl_unix.close()
        srv_unix.close()

        assert sent_unix == len(b"UNIX_SENDMSG_OK")
        assert data_unix == b"UNIX_SENDMSG_OK"


test_socket_guard_allows_loopback_sendmsg = test_socket_guard_allows_udp_sendmsg_loopback


@pytest.mark.skipif(
    not hasattr(socket.socket, "sendmsg") or not hasattr(socket, "IP_PKTINFO"),
    reason="socket.sendmsg or IP_PKTINFO is not supported on this platform",
)
def test_socket_guard_blocks_sendmsg_with_external_pktinfo() -> None:
    """Verify sendmsg with external IP in IP_PKTINFO ancillary data is blocked."""
    import struct

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    pktinfo = struct.pack(
        "=I4s4s",
        0,
        socket.inet_aton("127.0.0.1"),
        socket.inet_aton("192.168.1.108"),
    )
    ancdata = [(socket.IPPROTO_IP, getattr(socket, "IP_PKTINFO", 8), pktinfo)]
    with pytest.raises(RuntimeError, match="Outbound network call blocked"):
        sock.sendmsg([b"ping"], ancdata, 0, ("127.0.0.1", 9999))
    sock.close()


def test_socket_guard_blocks_direct_socket_module_connect() -> None:
    """Verify direct _socket module socket instantiation is blocked from external connect."""
    import _socket

    raw_sock = _socket.socket()
    with pytest.raises(RuntimeError, match="Outbound network call blocked"):
        raw_sock.connect(("192.168.1.108", 80))
    raw_sock.close()


def test_socket_guard_blocks_socket_sockettype_connect() -> None:
    """Verify socket.SocketType().connect to external IP is blocked."""
    sock = socket.SocketType(socket.AF_INET, socket.SOCK_STREAM)
    try:
        with pytest.raises(RuntimeError, match="Outbound network call blocked"):
            sock.connect(("192.168.1.108", 80))
    finally:
        sock.close()


def test_socket_guard_blocks_socket_sockettype_connect_ex() -> None:
    """Verify socket.SocketType().connect_ex to external IP raises RuntimeError."""
    sock = socket.SocketType(socket.AF_INET, socket.SOCK_STREAM)
    try:
        with pytest.raises(RuntimeError, match="Outbound network call blocked"):
            sock.connect_ex(("192.168.1.108", 80))
    finally:
        sock.close()


def test_socket_guard_blocks_socket_sockettype_sendto() -> None:
    """Verify socket.SocketType UDP sendto to external IP is blocked."""
    sock = socket.SocketType(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        with pytest.raises(RuntimeError, match="Outbound network call blocked"):
            sock.sendto(b"ping", ("192.168.1.108", 9999))
    finally:
        sock.close()


@pytest.mark.skipif(
    not hasattr(socket.SocketType, "sendmsg"),
    reason="socket.sendmsg is not supported on this platform",
)
def test_socket_guard_blocks_socket_sockettype_sendmsg() -> None:
    """Verify socket.SocketType UDP sendmsg to external IP is blocked."""
    sock = socket.SocketType(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        with pytest.raises(RuntimeError, match="Outbound network call blocked"):
            sock.sendmsg([b"ping"], [], 0, ("192.168.1.108", 9999))
    finally:
        sock.close()


def test_socket_guard_blocks_c_socket_sockettype_connect() -> None:
    """Verify _socket.SocketType().connect to external IP is blocked."""
    import _socket

    sock = _socket.SocketType(socket.AF_INET, socket.SOCK_STREAM)
    try:
        with pytest.raises(RuntimeError, match="Outbound network call blocked"):
            sock.connect(("192.168.1.108", 80))
    finally:
        sock.close()


def test_socket_guard_blocks_c_socket_sockettype_sendto() -> None:
    """Verify _socket.SocketType UDP sendto to external IP is blocked."""
    import _socket

    sock = _socket.SocketType(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        with pytest.raises(RuntimeError, match="Outbound network call blocked"):
            sock.sendto(b"ping", ("192.168.1.108", 9999))
    finally:
        sock.close()


def test_socket_guard_allows_socket_sockettype_loopback() -> None:
    """Verify socket.SocketType can connect to local loopback."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    def srv_handler() -> None:
        conn, _ = srv.accept()
        conn.sendall(b"SOCKETTYPE_OK")
        conn.close()
        srv.close()

    t = threading.Thread(target=srv_handler)
    t.start()

    client = socket.SocketType(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client.connect(("127.0.0.1", port))
        data = client.recv(1024)
        assert data == b"SOCKETTYPE_OK"
    finally:
        client.close()
        t.join()


def test_socket_guard_blocks_getaddrinfo_external_domain() -> None:
    """Verify socket.getaddrinfo for external domain is blocked."""
    with pytest.raises(RuntimeError, match="Outbound network call blocked"):
        socket.getaddrinfo("example.com", 80)


def test_socket_guard_blocks_getaddrinfo_external_ip() -> None:
    """Verify socket.getaddrinfo for non-loopback IP address is blocked."""
    with pytest.raises(RuntimeError, match="Outbound network call blocked"):
        socket.getaddrinfo("192.168.1.108", 80)


def test_socket_guard_allows_getaddrinfo_localhost() -> None:
    """Verify socket.getaddrinfo for 'localhost' succeeds with loopback addresses."""
    res = socket.getaddrinfo("localhost", 80)
    assert len(res) > 0
    # Every resolved sockaddr must be loopback
    for item in res:
        sockaddr = item[4]
        ip = sockaddr[0]
        assert ip in ("127.0.0.1", "::1") or (isinstance(ip, str) and ip.startswith("127."))


def test_socket_guard_allows_getaddrinfo_loopback_ip() -> None:
    """Verify socket.getaddrinfo for '127.0.0.1' and '::1' succeeds."""
    res_v4 = socket.getaddrinfo("127.0.0.1", 80)
    assert len(res_v4) > 0
    assert res_v4[0][4][0] == "127.0.0.1"

    if socket.has_ipv6:
        res_v6 = socket.getaddrinfo("::1", 80)
        assert len(res_v6) > 0
        assert res_v6[0][4][0] == "::1"


def test_socket_guard_blocks_gethostbyname_external() -> None:
    """Verify socket.gethostbyname for external domain is blocked."""
    with pytest.raises(RuntimeError, match="Outbound network call blocked"):
        socket.gethostbyname("example.com")


def test_socket_guard_allows_gethostbyname_localhost() -> None:
    """Verify socket.gethostbyname for 'localhost' returns 127.0.0.1."""
    ip = socket.gethostbyname("localhost")
    assert ip in ("127.0.0.1", "::1") or ip.startswith("127.")


def test_socket_guard_blocks_c_socket_getaddrinfo_external() -> None:
    """Verify _socket.getaddrinfo for external domain is blocked."""
    import _socket

    with pytest.raises(RuntimeError, match="Outbound network call blocked"):
        _socket.getaddrinfo("example.com", 80)


def test_socket_guard_allows_connected_udp_sendto_with_flags() -> None:
    """Verify connected UDP socket calling sendto(data, 0) to loopback is permitted."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.bind(("127.0.0.1", 0))
    srv_port = srv.getsockname()[1]

    cl = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        cl.connect(("127.0.0.1", srv_port))
        bytes_sent = cl.sendto(b"LOOPBACK_SENDTO_FLAGS", 0)  # type: ignore[call-overload]
        assert bytes_sent == len(b"LOOPBACK_SENDTO_FLAGS")

        data, _ = srv.recvfrom(1024)
        assert data == b"LOOPBACK_SENDTO_FLAGS"
    finally:
        cl.close()
        srv.close()


def test_socket_guard_allows_connected_udp_sendto_without_address() -> None:
    """Verify connected UDP socket calling sendto(data) without address is permitted."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.bind(("127.0.0.1", 0))
    srv_port = srv.getsockname()[1]

    cl = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        cl.connect(("127.0.0.1", srv_port))
        bytes_sent = cl.sendto(b"LOOPBACK_SENDTO_NO_ADDR")  # type: ignore[call-overload]
        assert bytes_sent == len(b"LOOPBACK_SENDTO_NO_ADDR")

        data, _ = srv.recvfrom(1024)
        assert data == b"LOOPBACK_SENDTO_NO_ADDR"
    finally:
        cl.close()
        srv.close()


def test_socket_guard_allows_udp_sendto_with_flags_and_address() -> None:
    """Verify UDP sendto(data, flags, address) to loopback is permitted."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.bind(("127.0.0.1", 0))
    srv_port = srv.getsockname()[1]

    cl = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        bytes_sent = cl.sendto(b"FLAGS_AND_ADDR", 0, ("127.0.0.1", srv_port))
        assert bytes_sent == len(b"FLAGS_AND_ADDR")

        data, _ = srv.recvfrom(1024)
        assert data == b"FLAGS_AND_ADDR"
    finally:
        cl.close()
        srv.close()


def test_socket_guard_blocks_udp_sendto_with_flags_external_address() -> None:
    """Verify UDP sendto(data, flags, address) to external address is blocked."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        with pytest.raises(RuntimeError, match="Outbound network call blocked"):
            sock.sendto(b"payload", 0, ("192.168.1.108", 9999))
    finally:
        sock.close()


def test_socket_guard_blocks_connected_sendto_to_external_peer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify sendto on socket connected to external peer raises RuntimeError via getpeername."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        monkeypatch.setattr(socket.socket, "getpeername", lambda self: ("192.168.1.108", 9999))
        with pytest.raises(RuntimeError, match="Outbound network call blocked"):
            sock.sendto(b"leak_payload", 0)  # type: ignore[call-overload]
    finally:
        sock.close()
