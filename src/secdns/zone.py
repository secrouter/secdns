"""The authoritative zone — the small set of names secdns answers for.

SecDeploy generates the zone file from the site topology (one record per component,
``<component>.<domain> → hosting-resource address``). The format is deliberately trivial so
it is easy to generate and easy to read::

    # name            type  value
    secrouter         A     10.0.0.5
    secllm            A     10.0.0.6
    _acme-challenge   TXT   "token…"     # (future: DNS-01)

Names may be written short (relative to the zone ``domain``) or as full FQDNs; both normalize
to the same key. Blank lines and ``#`` comments are ignored.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from . import message

_TYPES = {"A": message.TYPE_A, "AAAA": message.TYPE_AAAA, "TXT": message.TYPE_TXT}
_RDATA = {
    message.TYPE_A: message.a_rdata,
    message.TYPE_AAAA: message.aaaa_rdata,
    message.TYPE_TXT: message.txt_rdata,
}


@dataclass
class Zone:
    domain: str
    ttl: int = 60
    # fqdn -> list of (rtype, rdata)
    records: dict[str, list[tuple[int, bytes]]] = field(default_factory=dict)

    def _fqdn(self, name: str) -> str:
        name = name.rstrip(".").lower()
        if name == self.domain or name.endswith("." + self.domain):
            return name
        return f"{name}.{self.domain}"

    def add(self, name: str, type_name: str, value: str) -> None:
        rtype = _TYPES.get(type_name.upper())
        if rtype is None:
            raise ValueError(f"unsupported record type {type_name!r} (A, AAAA, TXT)")
        rdata = _RDATA[rtype](value.strip().strip('"'))
        self.records.setdefault(self._fqdn(name), []).append((rtype, rdata))

    def has(self, name: str) -> bool:
        """Whether the name exists at all (any type) — distinguishes NXDOMAIN from NODATA."""
        return self._fqdn(name) in self.records

    def lookup(self, name: str, qtype: int) -> list[bytes]:
        """rdata for records at ``name`` matching ``qtype`` (empty list = none of that type)."""
        return [rd for rt, rd in self.records.get(self._fqdn(name), []) if rt == qtype]

    @staticmethod
    def load(path: str | Path, domain: str, ttl: int = 60) -> "Zone":
        zone = Zone(domain=domain.rstrip(".").lower(), ttl=ttl)
        text = Path(path).read_text() if Path(path).exists() else ""
        for lineno, raw in enumerate(text.splitlines(), 1):
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            parts = line.split(None, 2)
            if len(parts) < 3:
                raise ValueError(f"{path}:{lineno}: expected '<name> <type> <value>', got {raw!r}")
            name, type_name, value = parts
            zone.add(name, type_name, value)
        return zone

    @property
    def count(self) -> int:
        return sum(len(v) for v in self.records.values())

    def entries(self) -> list[tuple[str, str, str]]:
        """Human-readable view: sorted list of (fqdn, type-name, value) for the console/CLI."""
        import socket

        rev = {message.TYPE_A: "A", message.TYPE_AAAA: "AAAA", message.TYPE_TXT: "TXT"}
        out: list[tuple[str, str, str]] = []
        for name, recs in sorted(self.records.items()):
            for rtype, rdata in recs:
                if rtype == message.TYPE_A:
                    value = socket.inet_ntoa(rdata)
                elif rtype == message.TYPE_AAAA:
                    value = socket.inet_ntop(socket.AF_INET6, rdata)
                elif rtype == message.TYPE_TXT:
                    value, i = "", 0
                    while i < len(rdata):
                        n = rdata[i]
                        value += rdata[i + 1:i + 1 + n].decode("utf-8", "replace")
                        i += 1 + n
                else:
                    value = rdata.hex()
                out.append((name, rev.get(rtype, str(rtype)), value))
        return out
