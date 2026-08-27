"""Lifecycle audit log tests: chained append, verify, and tamper detection."""

from __future__ import annotations

import json

from secdns.audit import AuditLogger, verify


def test_no_log_verifies_ok(tmp_path):
    ok, checked, broken = verify(tmp_path / "nope.jsonl")
    assert ok is True and checked == 0 and broken is None


def test_append_and_verify_chain(tmp_path):
    path = tmp_path / "audit.jsonl"
    logger = AuditLogger(path)

    r1 = logger.record("server.start", detail={"records": 3})
    r2 = logger.record("zone.reload", principal="console:127.0.0.1", detail={"records": 4})
    r3 = logger.record("server.stop", detail={"records": 4})

    assert r1["prevHash"] == "GENESIS"
    assert r2["prevHash"] == r1["hash"]
    assert r3["prevHash"] == r2["hash"]

    lines = path.read_text().splitlines()
    assert len(lines) == 3

    ok, checked, broken = verify(path)
    assert ok is True
    assert checked == 3
    assert broken is None


def test_verify_detects_tampered_record(tmp_path):
    path = tmp_path / "audit.jsonl"
    logger = AuditLogger(path)
    logger.record("server.start", detail={"records": 1})
    logger.record("zone.reload", detail={"records": 2})
    logger.record("zone.reload", detail={"records": 3})

    lines = path.read_text().splitlines()
    tampered = json.loads(lines[1])
    tampered["detail"] = {"records": 999}  # edit metadata without recomputing the hash
    lines[1] = json.dumps(tampered)
    path.write_text("\n".join(lines) + "\n")

    ok, checked, broken_at = verify(path)
    assert ok is False
    assert broken_at == 2  # 1-based line number of the tampered record


def test_verify_detects_broken_linkage(tmp_path):
    path = tmp_path / "audit.jsonl"
    logger = AuditLogger(path)
    logger.record("server.start", detail={"records": 1})
    logger.record("zone.reload", detail={"records": 2})

    lines = path.read_text().splitlines()
    rec = json.loads(lines[1])
    rec["prevHash"] = "deadbeef" * 8  # snip the chain — doesn't match record 1's hash
    lines[1] = json.dumps(rec)
    path.write_text("\n".join(lines) + "\n")

    ok, checked, broken_at = verify(path)
    assert ok is False
    assert broken_at == 2


def test_disabled_logger_writes_nothing(tmp_path):
    path = tmp_path / "audit.jsonl"
    logger = AuditLogger(path, enabled=False)
    assert logger.record("server.start") is None
    assert not path.exists()


def test_new_logger_continues_existing_chain(tmp_path):
    path = tmp_path / "audit.jsonl"
    first = AuditLogger(path)
    r1 = first.record("server.start", detail={"records": 1})

    second = AuditLogger(path)  # simulates a process restart
    r2 = second.record("server.start", detail={"records": 1})
    assert r2["prevHash"] == r1["hash"]

    ok, checked, broken = verify(path)
    assert ok is True and checked == 2 and broken is None
