"""Resolver — decide authoritative vs. forward, and answer.

For a query the resolver either (a) answers from the zone when the name is inside our
``domain``, (b) forwards to upstream when it isn't, or (c) REFUSEs when it isn't and we have
no upstream (closed-network default). Inside the zone, a name that exists but lacks the asked
type is NODATA (RCODE 0, no answers); a name that doesn't exist is NXDOMAIN.
"""

from __future__ import annotations

import threading

from . import forwarder, message
from .config import Config
from .zone import Zone


class Resolver:
    def __init__(self, config: Config, zone: Zone | None = None) -> None:
        self.config = config
        self.zone = zone if zone is not None else Zone.load(config.zone_file, config.domain, config.ttl)
        self._lock = threading.Lock()
        self.stats = {
            "queries": 0, "authoritative": 0, "nodata": 0, "nxdomain": 0,
            "forwarded": 0, "refused": 0, "malformed": 0,
        }

    def reload(self) -> int:
        """Re-read the zone file (called on SIGHUP / the admin console). Returns record count."""
        zone = Zone.load(self.config.zone_file, self.config.domain, self.config.ttl)
        with self._lock:
            self.zone = zone
        return zone.count

    def _authoritative_for(self, name: str) -> bool:
        d = self.config.domain
        return name == d or name.endswith("." + d)

    def _bump(self, key: str) -> None:
        with self._lock:
            self.stats[key] += 1

    def handle_query(self, data: bytes) -> bytes | None:
        """Turn a raw query packet into a raw response packet (or None to drop)."""
        self._bump("queries")
        try:
            query = message.parse(data)
        except message.DNSFormatError:
            self._bump("malformed")
            return None
        if not query.questions:
            return message.error_response(query, message.RCODE_FORMERR)
        q = query.questions[0]
        name = q.name

        if self._authoritative_for(name):
            self._bump("authoritative")
            with self._lock:
                rdatas = self.zone.lookup(name, q.qtype)
                exists = self.zone.has(name)
            if rdatas:
                answers = [message.Record(name, q.qtype, rd, ttl=self.config.ttl) for rd in rdatas]
                return message.build_response(query, answers, rcode=message.RCODE_OK)
            # in-zone name: NODATA if it exists with another type, else NXDOMAIN
            if exists:
                self._bump("nodata")
                return message.build_response(query, [], rcode=message.RCODE_OK)
            self._bump("nxdomain")
            return message.build_response(query, [], rcode=message.RCODE_NXDOMAIN)

        # outside the zone
        if self.config.forward and self.config.upstream:
            self._bump("forwarded")
            resp = forwarder.forward(data, self.config.upstream)
            if resp is not None:
                return resp
            return message.error_response(query, message.RCODE_SERVFAIL)
        self._bump("refused")
        return message.error_response(query, message.RCODE_REFUSED)
