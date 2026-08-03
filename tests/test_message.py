"""Wire-format codec tests."""

from __future__ import annotations

import struct

from secdns import message


def test_name_roundtrip():
    for name in ("secrouter.sec.internal", "a.b.c.d", "sec.internal", "x"):
        encoded = message.encode_name(name)
        assert encoded.endswith(b"\x00")
        decoded, end = message.decode_name(encoded, 0)
        assert decoded == name
        assert end == len(encoded)


def test_decode_compression_pointer():
    # "sec.internal" at offset 0, then a name that is just a pointer back to it.
    base = message.encode_name("sec.internal")
    packet = base + struct.pack("!H", 0xC000)  # pointer to offset 0
    name, end = message.decode_name(packet, len(base))
    assert name == "sec.internal"
    assert end == len(packet)


def test_parse_query(make_query):
    pkt = make_query("secllm.sec.internal", qtype=message.TYPE_A, ident=0xABCD)
    msg = message.parse(pkt)
    assert msg.ident == 0xABCD
    assert msg.recursion_desired
    assert len(msg.questions) == 1
    assert msg.questions[0].name == "secllm.sec.internal"
    assert msg.questions[0].qtype == message.TYPE_A


def test_parse_rejects_short_packet():
    import pytest

    with pytest.raises(message.DNSFormatError):
        message.parse(b"\x00\x01\x02")


def test_build_response_sets_flags_and_answer(make_query):
    query = message.parse(make_query("secrouter.sec.internal"))
    rec = message.Record("secrouter.sec.internal", message.TYPE_A, message.a_rdata("10.0.0.5"))
    resp = message.build_response(query, [rec])
    ident, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", resp[:12])
    assert ident == query.ident
    assert flags & message.FLAG_QR  # is a response
    assert flags & message.FLAG_AA  # authoritative
    assert flags & message.FLAG_RD  # RD copied from query
    assert qd == 1 and an == 1
    assert b"\x0a\x00\x00\x05" in resp  # 10.0.0.5 rdata


def test_a_and_txt_rdata():
    assert message.a_rdata("1.2.3.4") == b"\x01\x02\x03\x04"
    txt = message.txt_rdata("hello")
    assert txt == b"\x05hello"
