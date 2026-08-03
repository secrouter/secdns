"""Forward non-authoritative queries to upstream resolvers.

Closed-network default: if no upstream is configured the resolver REFUSEs anything outside
the internal zone rather than leaking lookups. When upstreams are set, the raw query is
relayed (transaction ID preserved) and the first upstream to answer wins.
"""

from __future__ import annotations

import socket


def forward(query: bytes, upstreams: list[str], timeout: float = 2.0,
            port: int = 53) -> bytes | None:
    """Relay ``query`` to each upstream in turn; return the first response, or None."""
    for host in upstreams:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            sock.sendto(query, (host, port))
            data, _ = sock.recvfrom(65535)
            return data
        except OSError:
            continue
        finally:
            sock.close()
    return None
