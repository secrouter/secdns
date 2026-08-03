"""Resolver decision + answer tests."""

from __future__ import annotations

import struct

from secdns import message
from secdns.config import Config
from secdns.resolver import Resolver
from secdns.zone import Zone


def _rcode(resp: bytes) -> int:
    return struct.unpack("!H", resp[2:4])[0] & 0x0F


def _ancount(resp: bytes) -> int:
    return struct.unpack("!H", resp[6:8])[0]


def _zone() -> Zone:
    z = Zone("sec.internal")
    z.add("secrouter", "A", "10.0.0.5")
    z.add("secchat", "TXT", "chat")  # exists but no A → NODATA
    return z


def test_authoritative_answer(make_query):
    r = Resolver(Config(domain="sec.internal"), zone=_zone())
    resp = r.handle_query(make_query("secrouter.sec.internal"))
    assert _rcode(resp) == message.RCODE_OK
    assert _ancount(resp) == 1
    assert b"\x0a\x00\x00\x05" in resp  # 10.0.0.5
    assert r.stats["authoritative"] == 1


def test_nodata(make_query):
    r = Resolver(Config(domain="sec.internal"), zone=_zone())
    resp = r.handle_query(make_query("secchat.sec.internal", qtype=message.TYPE_A))
    assert _rcode(resp) == message.RCODE_OK
    assert _ancount(resp) == 0
    assert r.stats["nodata"] == 1


def test_nxdomain(make_query):
    r = Resolver(Config(domain="sec.internal"), zone=_zone())
    resp = r.handle_query(make_query("ghost.sec.internal"))
    assert _rcode(resp) == message.RCODE_NXDOMAIN
    assert r.stats["nxdomain"] == 1


def test_refuse_without_upstream(make_query):
    r = Resolver(Config(domain="sec.internal", upstream=[]), zone=_zone())
    resp = r.handle_query(make_query("example.com"))
    assert _rcode(resp) == message.RCODE_REFUSED
    assert r.stats["refused"] == 1


def test_forward_when_upstream_set(make_query, monkeypatch):
    canned = b"\xff" * 20
    monkeypatch.setattr("secdns.forwarder.forward", lambda *a, **k: canned)
    r = Resolver(Config(domain="sec.internal", upstream=["1.1.1.1"]), zone=_zone())
    resp = r.handle_query(make_query("example.com"))
    assert resp == canned
    assert r.stats["forwarded"] == 1


def test_reload(tmp_path, make_query):
    zf = tmp_path / "z.zone"
    zf.write_text("secrouter A 10.0.0.5\n")
    r = Resolver(Config(domain="sec.internal", zone_file=zf))
    assert r.zone.count == 1
    zf.write_text("secrouter A 10.0.0.5\nsecllm A 10.0.0.6\n")
    assert r.reload() == 2
    resp = r.handle_query(make_query("secllm.sec.internal"))
    assert _ancount(resp) == 1
