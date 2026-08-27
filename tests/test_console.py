"""Status console tests (health, records, reload, index page)."""

from __future__ import annotations

import json
import urllib.request

from secdns.audit import verify
from secdns.config import Config
from secdns.console import Console
from secdns.resolver import Resolver


def _get(url: str):
    with urllib.request.urlopen(url, timeout=3) as r:
        return r.status, r.read()


def _post(url: str):
    req = urllib.request.Request(url, method="POST")
    with urllib.request.urlopen(req, timeout=3) as r:
        return r.status, r.read()


def test_health_records_reload_and_index(tmp_path):
    zf = tmp_path / "z.zone"
    zf.write_text("secrouter A 10.0.0.5\n")
    resolver = Resolver(Config(domain="sec.internal", zone_file=zf))
    console = Console(resolver, bind="127.0.0.1", port=0)
    console.start()
    try:
        base = f"http://127.0.0.1:{console.port}"

        status, body = _get(base + "/health")
        health = json.loads(body)
        assert status == 200 and health["status"] == "ok" and health["records"] == 1

        status, body = _get(base + "/records")
        recs = json.loads(body)["records"]
        assert {"name": "secrouter.sec.internal", "type": "A", "value": "10.0.0.5"} in recs

        # grow the zone on disk, then reload via the console
        zf.write_text("secrouter A 10.0.0.5\nsecllm A 10.0.0.6\n")
        status, body = _post(base + "/reload")
        assert status == 200 and json.loads(body)["records"] == 2

        status, body = _get(base + "/")
        html = body.decode()
        assert status == 200 and "secdns" in html and "secrouter" in html
    finally:
        console.stop()


def test_render_escapes_record_values(tmp_path):
    """A record value/name/type containing HTML must render escaped, not raw — the
    console interpolates zone data (and resolver.config.domain) into the page, and
    an attacker-influenced string there must not be able to inject markup/script."""
    zf = tmp_path / "z.zone"
    zf.write_text('xss TXT "<script>alert(1)</script>"\n')
    resolver = Resolver(Config(domain="<b>sec</b>.internal", zone_file=zf))
    console = Console(resolver, bind="127.0.0.1", port=0)
    console.start()
    try:
        base = f"http://127.0.0.1:{console.port}"
        status, body = _get(base + "/")
        html_out = body.decode()
        assert status == 200
        assert "<script>alert(1)</script>" not in html_out
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html_out
        assert "<b>sec</b>.internal" not in html_out
        assert "&lt;b&gt;sec&lt;/b&gt;.internal" in html_out
    finally:
        console.stop()


def test_console_reload_is_audited_with_console_principal(tmp_path):
    """POST /reload is a lifecycle event triggered through the console, not the
    daemon itself — the audit record's principal must reflect the requesting
    client's IP as "console:<ip>", per the suite audit spec (B.7 secdns entry)."""
    zf = tmp_path / "z.zone"
    zf.write_text("secrouter A 10.0.0.5\n")
    resolver = Resolver(Config(domain="sec.internal", zone_file=zf))
    console = Console(resolver, bind="127.0.0.1", port=0)
    console.start()
    try:
        base = f"http://127.0.0.1:{console.port}"
        zf.write_text("secrouter A 10.0.0.5\nsecllm A 10.0.0.6\n")
        status, body = _post(base + "/reload")
        assert status == 200 and json.loads(body)["records"] == 2
    finally:
        console.stop()

    audit_path = resolver.audit._path
    lines = audit_path.read_text().splitlines()
    events = [json.loads(line) for line in lines]
    reload_events = [e for e in events if e["type"] == "zone.reload"]
    assert len(reload_events) == 1
    assert reload_events[0]["principal"] == "console:127.0.0.1"
    assert reload_events[0]["sourceIp"] == "127.0.0.1"
    assert reload_events[0]["outcome"] == "ok"

    ok, checked, broken = verify(audit_path)
    assert ok is True and broken is None
