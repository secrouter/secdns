"""End-to-end server tests over real localhost sockets (ephemeral ports, no root)."""

from __future__ import annotations

import socket
import struct

from secdns import message
from secdns.config import Config
from secdns.resolver import Resolver
from secdns.server import DNSServer
from secdns.zone import Zone


def _server(tmp_path) -> DNSServer:
    zf = tmp_path / "z.zone"
    zf.write_text("secrouter A 10.0.0.9\n")
    resolver = Resolver(Config(domain="sec.internal", zone_file=zf))
    dns = DNSServer(resolver, bind="127.0.0.1", port=0)  # port 0 → OS-assigned
    dns.start()
    return dns


def test_udp_resolve(tmp_path, make_query):
    dns = _server(tmp_path)
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(3)
        sock.sendto(make_query("secrouter.sec.internal"), ("127.0.0.1", dns.udp_port))
        data, _ = sock.recvfrom(4096)
        sock.close()
        assert struct.unpack("!H", data[6:8])[0] == 1     # one answer
        assert b"\x0a\x00\x00\x09" in data                # 10.0.0.9
    finally:
        dns.stop()


def test_tcp_resolve(tmp_path, make_query):
    dns = _server(tmp_path)
    try:
        query = make_query("secrouter.sec.internal")
        sock = socket.create_connection(("127.0.0.1", dns.tcp_port), timeout=3)
        sock.sendall(struct.pack("!H", len(query)) + query)
        length = struct.unpack("!H", _recv(sock, 2))[0]
        resp = _recv(sock, length)
        sock.close()
        assert struct.unpack("!H", resp[6:8])[0] == 1
        assert b"\x0a\x00\x00\x09" in resp
    finally:
        dns.stop()


def _recv(sock, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        assert chunk, "connection closed early"
        buf += chunk
    return buf
