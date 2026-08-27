"""Lifecycle audit logging — append-only, hash-chained JSONL (CMMC AU-3.3.1 / AU-3.3.8).

secdns is a hot-path UDP/TCP resolver: audit covers **lifecycle** events only (server
start/stop, zone load/reload) — never per-query logging. A query answered/refused/forwarded
never touches this module; see ``docs/control-validation.md`` for the control mapping and the
explicit query-log posture (environment-owned, not implemented here, by design).

Because writes happen only on rare lifecycle events (server start, a zone reload once in a
while, server stop) rather than per query, a plain synchronous file append is fine here — it
would NOT be fine on the query path.

Canonical fields (suite audit spec, section B.1): ``ts``, ``type`` (dotted lowercase, e.g.
``zone.reload``), ``principal`` (``"system"`` for daemon-initiated lifecycle events, or
``"console:<client-ip>"`` for an action triggered through the status console), ``sourceIp``,
``target``, ``outcome``, ``detail`` (object, METADATA ONLY — never zone/record *content*,
just counts/paths/outcomes), ``prevHash``, ``hash``.
"""

from __future__ import annotations

import json
import os
import sys
import threading
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Any

GENESIS = "GENESIS"
SCHEMA_VERSION = 1


def _now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _canonical(record: dict[str, Any]) -> str:
    """Stable serialization for hashing (sorted keys, no incidental whitespace)."""
    return json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)


def _harden(path: Path, mode: int) -> None:
    """Best-effort at-rest permission tightening. No-op on platforms without chmod."""
    try:
        os.chmod(path, mode)
    except OSError:
        pass


def _last_hash(path: Path) -> str | None:
    """The ``hash`` of the last record in an existing log, to continue the chain."""
    if not path.exists():
        return None
    last = None
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    last = line
    except OSError:
        return None
    if not last:
        return None
    try:
        value = json.loads(last).get("hash")
    except json.JSONDecodeError:
        return None
    return value if isinstance(value, str) else None


class AuditLogger:
    """Append-only, hash-chained JSONL logger for secdns lifecycle events.

    Deliberately lazy: no file or directory is touched until the first :meth:`record`
    call, so constructing a :class:`~secdns.resolver.Resolver` that never reloads its
    zone (e.g. most unit tests, which inject a :class:`~secdns.zone.Zone` directly)
    never creates an audit log. A disabled logger (``enabled=False`` or ``path=None``)
    is a safe no-op.
    """

    def __init__(self, path: str | Path | None, *, enabled: bool = True) -> None:
        self.enabled = enabled and path is not None
        self._path = Path(path) if path is not None else None
        self._lock = threading.Lock()
        self._prev = GENESIS
        self._initialized = False

    def _ensure_init(self) -> None:
        if self._initialized:
            return
        assert self._path is not None
        self._path.parent.mkdir(parents=True, exist_ok=True)
        _harden(self._path.parent, 0o700)  # at-rest hardening (CMMC-2)
        self._prev = _last_hash(self._path) or GENESIS
        self._initialized = True

    def record(
        self,
        event_type: str,
        *,
        principal: str = "system",
        source_ip: str | None = None,
        target: dict[str, Any] | None = None,
        outcome: str = "ok",
        detail: dict[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        """Append one lifecycle audit record. Returns it, or ``None`` if disabled."""
        if not self.enabled or self._path is None:
            return None
        with self._lock:
            self._ensure_init()
            record: dict[str, Any] = {
                "v": SCHEMA_VERSION,
                "ts": _now_iso(),
                "type": event_type,
                "principal": principal,
                "sourceIp": source_ip,
                "target": target or {},
                "outcome": outcome,
                "detail": detail or {},
                "prevHash": self._prev,
            }
            digest = sha256(_canonical(record).encode("utf-8")).hexdigest()
            record["hash"] = digest
            self._prev = digest
            self._write(record)
            return record

    def _write(self, record: dict[str, Any]) -> None:
        assert self._path is not None
        line = json.dumps(record, default=str)
        try:
            with open(self._path, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
            _harden(self._path, 0o600)  # owner-only audit log (CMMC-2)
        except OSError as exc:  # never break the daemon on a logging failure
            print(f"secdns: audit write failed: {exc}", file=sys.stderr)


def verify(path: str | Path) -> tuple[bool, int, int | None]:
    """Validate a JSONL audit log's hash chain.

    Returns ``(ok, checked, brokenAtSeq)`` — ``brokenAtSeq`` is the 1-based line number
    of the first record that fails verification (bad JSON, broken ``prevHash`` linkage,
    or a recomputed hash that doesn't match the stored one), or ``None`` if the whole
    chain verifies (including the case of no log / an empty log, which trivially verifies).
    """
    p = Path(path)
    if not p.exists():
        return True, 0, None
    prev = GENESIS
    checked = 0
    with open(p, encoding="utf-8") as fh:
        for lineno, raw in enumerate(fh, start=1):
            raw = raw.strip()
            if not raw:
                continue
            try:
                record = json.loads(raw)
            except json.JSONDecodeError:
                return False, checked, lineno
            checked += 1
            stored = record.get("hash")
            if stored is None:
                return False, checked, lineno
            if record.get("prevHash") != prev:
                return False, checked, lineno
            recomputed = sha256(
                _canonical({k: v for k, v in record.items() if k != "hash"}).encode("utf-8")
            ).hexdigest()
            if recomputed != stored:
                return False, checked, lineno
            prev = str(stored)
    return True, checked, None
