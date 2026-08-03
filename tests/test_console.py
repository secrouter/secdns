"""Status console tests (health, records, reload, index page)."""

from __future__ import annotations

import json
import urllib.request

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
