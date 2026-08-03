"""Shared test helpers."""

from __future__ import annotations

import struct

import pytest

from secdns import message


@pytest.fixture
def make_query():
    """Build a raw DNS query packet for one question."""

    def _q(name: str, qtype: int = message.TYPE_A, ident: int = 0x1234, rd: bool = True) -> bytes:
        flags = message.FLAG_RD if rd else 0
        header = struct.pack("!HHHHHH", ident, flags, 1, 0, 0, 0)
        return header + message.encode_name(name) + struct.pack("!HH", qtype, message.CLASS_IN)

    return _q
