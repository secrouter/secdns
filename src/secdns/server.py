"""UDP + TCP listeners on port 53, backed by a shared :class:`Resolver`.

Both transports share one resolver (and therefore one zone + one stats counter). TCP frames
each message with a 2-byte length prefix (RFC 1035 §4.2.2); UDP is a single datagram.
"""

from __future__ import annotations

import socketserver
import struct
import threading

from .resolver import Resolver


class _UDPHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        data, sock = self.request
        response = self.server.resolver.handle_query(data)
        if response:
            sock.sendto(response, self.client_address)


class _TCPHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        header = self._recv_exactly(2)
        if not header:
            return
        (length,) = struct.unpack("!H", header)
        data = self._recv_exactly(length)
        if not data:
            return
        response = self.server.resolver.handle_query(data)
        if response:
            self.request.sendall(struct.pack("!H", len(response)) + response)

    def _recv_exactly(self, n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            chunk = self.request.recv(n - len(buf))
            if not chunk:
                return b""
            buf += chunk
        return buf


class _ThreadingUDPServer(socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = True


class _ThreadingTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class DNSServer:
    """Owns the UDP and TCP listeners; ``start`` runs them in daemon threads."""

    def __init__(self, resolver: Resolver, bind: str = "0.0.0.0", port: int = 53) -> None:
        self.resolver = resolver
        self.udp = _ThreadingUDPServer((bind, port), _UDPHandler)
        self.tcp = _ThreadingTCPServer((bind, port), _TCPHandler)
        self.udp.resolver = resolver
        self.tcp.resolver = resolver
        self._threads: list[threading.Thread] = []

    @property
    def udp_port(self) -> int:
        return self.udp.server_address[1]

    @property
    def tcp_port(self) -> int:
        return self.tcp.server_address[1]

    def start(self) -> None:
        for srv in (self.udp, self.tcp):
            t = threading.Thread(target=srv.serve_forever, daemon=True)
            t.start()
            self._threads.append(t)

    def stop(self) -> None:
        for srv in (self.udp, self.tcp):
            srv.shutdown()
            srv.server_close()
