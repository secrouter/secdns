"""Zone loading + lookup tests."""

from __future__ import annotations

import pytest

from secdns import message
from secdns.zone import Zone


def test_load_and_lookup(tmp_path):
    zf = tmp_path / "z.zone"
    zf.write_text(
        "# comment\n"
        "secrouter        A     10.0.0.5\n"
        "secllm.sec.internal   A   10.0.0.6   # inline comment\n"
        "\n"
    )
    zone = Zone.load(zf, "sec.internal")
    assert zone.count == 2
    # short and FQDN names normalize to the same key
    assert zone.lookup("secrouter", message.TYPE_A) == [message.a_rdata("10.0.0.5")]
    assert zone.lookup("secrouter.sec.internal", message.TYPE_A) == [message.a_rdata("10.0.0.5")]
    assert zone.lookup("secllm", message.TYPE_A) == [message.a_rdata("10.0.0.6")]


def test_nodata_vs_nxdomain():
    zone = Zone("sec.internal")
    zone.add("secchat", "TXT", "hello")
    assert zone.has("secchat")           # exists…
    assert zone.lookup("secchat", message.TYPE_A) == []  # …but not as A → NODATA
    assert not zone.has("ghost")         # doesn't exist → NXDOMAIN


def test_missing_file_is_empty_zone(tmp_path):
    zone = Zone.load(tmp_path / "nope.zone", "sec.internal")
    assert zone.count == 0


def test_bad_line_rejected(tmp_path):
    zf = tmp_path / "bad.zone"
    zf.write_text("secrouter A\n")  # missing value
    with pytest.raises(ValueError):
        Zone.load(zf, "sec.internal")


def test_entries_render():
    zone = Zone("sec.internal")
    zone.add("secrouter", "A", "10.0.0.5")
    zone.add("note", "TXT", "hello world")
    entries = dict((n, (t, v)) for n, t, v in zone.entries())
    assert entries["secrouter.sec.internal"] == ("A", "10.0.0.5")
    assert entries["note.sec.internal"] == ("TXT", "hello world")
