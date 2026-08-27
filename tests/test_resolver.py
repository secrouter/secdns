"""Resolver decision + answer tests."""

from __future__ import annotations

import json
import struct

from secdns import message
from secdns.audit import verify
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


def test_construction_and_reload_emit_lifecycle_audit_events(tmp_path):
    """Loading the zone at startup, and reloading it, are lifecycle events — the
    resolver's audit log must record both (chained), with the reload's principal
    honored (defaults to "system" for e.g. SIGHUP)."""
    zf = tmp_path / "z.zone"
    zf.write_text("secrouter A 10.0.0.5\n")
    r = Resolver(Config(domain="sec.internal", zone_file=zf))

    audit_path = r.audit._path
    assert audit_path is not None and audit_path.exists()
    lines = audit_path.read_text().splitlines()
    assert len(lines) == 1
    first = json.loads(lines[0])
    assert first["type"] == "zone.load"
    assert first["principal"] == "system"
    assert first["outcome"] == "ok"
    assert first["detail"]["records"] == 1

    zf.write_text("secrouter A 10.0.0.5\nsecllm A 10.0.0.6\n")
    r.reload(principal="console:10.0.0.9", source_ip="10.0.0.9")

    lines = audit_path.read_text().splitlines()
    assert len(lines) == 2
    second = json.loads(lines[1])
    assert second["type"] == "zone.reload"
    assert second["principal"] == "console:10.0.0.9"
    assert second["sourceIp"] == "10.0.0.9"
    assert second["detail"]["records"] == 2
    assert second["prevHash"] == first["hash"]

    ok, checked, broken = verify(audit_path)
    assert ok is True and checked == 2 and broken is None


def test_reload_failure_is_audited_as_error(tmp_path):
    zf = tmp_path / "z.zone"
    zf.write_text("secrouter A 10.0.0.5\n")
    r = Resolver(Config(domain="sec.internal", zone_file=zf))

    zf.write_text("secrouter A\n")  # malformed: missing value
    try:
        r.reload()
        raised = False
    except ValueError:
        raised = True
    assert raised

    lines = r.audit._path.read_text().splitlines()
    last = json.loads(lines[-1])
    assert last["type"] == "zone.reload"
    assert last["outcome"] == "error"


def test_query_path_never_writes_audit(tmp_path, make_query, monkeypatch):
    """Hard rule: secdns is a hot-path resolver — a query, however answered, must
    never trigger a synchronous audit write. Only lifecycle events (load/reload/
    start/stop) do."""
    zf = tmp_path / "z.zone"
    zf.write_text("secrouter A 10.0.0.5\n")
    monkeypatch.setattr("secdns.forwarder.forward", lambda *a, **k: b"\xff" * 20)
    r = Resolver(Config(domain="sec.internal", zone_file=zf, upstream=["1.1.1.1"]))

    audit_path = r.audit._path
    before = audit_path.read_text()  # the one zone.load event from construction

    for _ in range(25):
        r.handle_query(make_query("secrouter.sec.internal"))          # authoritative
        r.handle_query(make_query("ghost.sec.internal"))              # nxdomain
        r.handle_query(make_query("secrouter.sec.internal", qtype=message.TYPE_AAAA))  # nodata
        r.handle_query(make_query("example.com"))                     # forwarded/refused
        r.handle_query(b"\x00\x00garbage")                            # malformed

    after = audit_path.read_text()
    assert after == before, "a DNS query must never produce an audit write"
