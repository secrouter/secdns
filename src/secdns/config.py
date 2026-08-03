"""Runtime configuration — CLI flags over environment variables over defaults.

Env vars (all optional): ``SECDNS_DOMAIN``, ``SECDNS_ZONE``, ``SECDNS_UPSTREAM`` (comma-
separated), ``SECDNS_BIND``, ``SECDNS_PORT``, ``SECDNS_ADMIN_BIND``, ``SECDNS_ADMIN_PORT``,
``SECDNS_TTL``, ``SECDNS_NO_FORWARD``.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_DOMAIN = "sec.internal"
DEFAULT_PORT = 53
DEFAULT_ADMIN_PORT = 47053  # HTTP status/health/reload console


def _split(value: str) -> list[str]:
    return [s.strip() for s in value.split(",") if s.strip()]


@dataclass
class Config:
    domain: str = DEFAULT_DOMAIN
    zone_file: Path = Path("zones/secdns.zone")
    upstream: list[str] = field(default_factory=list)
    bind: str = "0.0.0.0"
    port: int = DEFAULT_PORT
    admin_bind: str = "127.0.0.1"
    admin_port: int = DEFAULT_ADMIN_PORT
    ttl: int = 60
    forward: bool = True

    @staticmethod
    def from_env(env: dict[str, str] | None = None) -> "Config":
        e = os.environ if env is None else env
        return Config(
            domain=e.get("SECDNS_DOMAIN", DEFAULT_DOMAIN).rstrip(".").lower(),
            zone_file=Path(e.get("SECDNS_ZONE", "zones/secdns.zone")),
            upstream=_split(e.get("SECDNS_UPSTREAM", "")),
            bind=e.get("SECDNS_BIND", "0.0.0.0"),
            port=int(e.get("SECDNS_PORT", DEFAULT_PORT)),
            admin_bind=e.get("SECDNS_ADMIN_BIND", "127.0.0.1"),
            admin_port=int(e.get("SECDNS_ADMIN_PORT", DEFAULT_ADMIN_PORT)),
            ttl=int(e.get("SECDNS_TTL", "60")),
            forward=e.get("SECDNS_NO_FORWARD", "") == "",
        )
