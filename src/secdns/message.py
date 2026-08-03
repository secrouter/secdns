"""DNS wire-format codec (RFC 1035) — just enough to be authoritative and to forward.

secdns parses an incoming query's header + question, then either builds an answer from the
zone or relays an upstream response verbatim. So this module needs to *parse* a query and
*build* a response; it deliberately does not fully decode arbitrary resource records (the
forward path relays upstream bytes untouched). Names are encoded uncompressed in responses —
always valid, and our zone names are short.

Zero dependencies: standard library only.
"""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass, field

# Record / query types
TYPE_A = 1
TYPE_NS = 2
TYPE_CNAME = 5
TYPE_TXT = 16
TYPE_AAAA = 28
CLASS_IN = 1

# Response codes
RCODE_OK = 0
RCODE_FORMERR = 1
RCODE_SERVFAIL = 2
RCODE_NXDOMAIN = 3
RCODE_NOTIMP = 4
RCODE_REFUSED = 5

# Header flag bits (within the 16-bit flags field)
FLAG_QR = 0x8000  # response
FLAG_AA = 0x0400  # authoritative answer
FLAG_TC = 0x0200  # truncated
FLAG_RD = 0x0100  # recursion desired (copied from query)
FLAG_RA = 0x0080  # recursion available
OPCODE_MASK = 0x7800


class DNSFormatError(ValueError):
    """Raised when an inbound packet cannot be parsed as a DNS message."""


@dataclass
class Question:
    name: str  # dotted, lower-cased, no trailing dot
    qtype: int
    qclass: int = CLASS_IN


@dataclass
class Record:
    name: str
    rtype: int
    rdata: bytes
    ttl: int = 60
    rclass: int = CLASS_IN


@dataclass
class Message:
    ident: int
    flags: int
    questions: list[Question] = field(default_factory=list)
    answers: list[Record] = field(default_factory=list)

    @property
    def recursion_desired(self) -> bool:
        return bool(self.flags & FLAG_RD)

    @property
    def opcode(self) -> int:
        return self.flags & OPCODE_MASK


# ── names ────────────────────────────────────────────────────────────────────────────
def encode_name(name: str) -> bytes:
    """Encode a dotted name as length-prefixed labels terminated by a zero octet."""
    out = bytearray()
    for label in name.rstrip(".").split("."):
        if not label:
            continue
        raw = label.encode("idna") if any(ord(c) > 127 for c in label) else label.encode("ascii")
        if len(raw) > 63:
            raise DNSFormatError(f"label too long: {label!r}")
        out.append(len(raw))
        out += raw
    out.append(0)
    return bytes(out)


def decode_name(data: bytes, offset: int) -> tuple[str, int]:
    """Decode a (possibly compressed) name. Returns (name, offset-past-the-name-in-stream)."""
    labels: list[str] = []
    jumped = False
    end = offset
    seen = 0
    while True:
        if offset >= len(data):
            raise DNSFormatError("name runs past end of packet")
        length = data[offset]
        if length & 0xC0 == 0xC0:  # compression pointer
            if offset + 1 >= len(data):
                raise DNSFormatError("truncated compression pointer")
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                end = offset + 2
            offset = pointer
            jumped = True
            seen += 1
            if seen > 128:
                raise DNSFormatError("compression pointer loop")
            continue
        offset += 1
        if length == 0:
            if not jumped:
                end = offset
            break
        labels.append(data[offset:offset + length].decode("ascii", "replace"))
        offset += length
    return ".".join(labels), end


# ── parse (query) ────────────────────────────────────────────────────────────────────
def parse(data: bytes) -> Message:
    """Parse an inbound message's header + question section (answers are not decoded)."""
    if len(data) < 12:
        raise DNSFormatError("packet shorter than DNS header")
    ident, flags, qd, _an, _ns, _ar = struct.unpack("!HHHHHH", data[:12])
    offset = 12
    questions: list[Question] = []
    for _ in range(qd):
        name, offset = decode_name(data, offset)
        if offset + 4 > len(data):
            raise DNSFormatError("truncated question")
        qtype, qclass = struct.unpack("!HH", data[offset:offset + 4])
        offset += 4
        questions.append(Question(name.rstrip(".").lower(), qtype, qclass))
    return Message(ident=ident, flags=flags, questions=questions)


# ── build (response) ─────────────────────────────────────────────────────────────────
def build_response(query: Message, answers: list[Record], rcode: int = RCODE_OK,
                   authoritative: bool = True, recursion_available: bool = False) -> bytes:
    """Build a response packet echoing the query's question and carrying ``answers``."""
    flags = FLAG_QR | (query.flags & OPCODE_MASK) | (rcode & 0x0F)
    if authoritative:
        flags |= FLAG_AA
    if query.recursion_desired:
        flags |= FLAG_RD
    if recursion_available:
        flags |= FLAG_RA
    out = bytearray(struct.pack("!HHHHHH", query.ident, flags, len(query.questions),
                                len(answers), 0, 0))
    for q in query.questions:
        out += encode_name(q.name)
        out += struct.pack("!HH", q.qtype, q.qclass)
    for r in answers:
        out += encode_name(r.name)
        out += struct.pack("!HHIH", r.rtype, r.rclass, r.ttl, len(r.rdata))
        out += r.rdata
    return bytes(out)


def error_response(query: Message, rcode: int) -> bytes:
    return build_response(query, [], rcode=rcode, authoritative=False)


# ── rdata helpers ────────────────────────────────────────────────────────────────────
def a_rdata(address: str) -> bytes:
    """IPv4 dotted-quad → 4-byte A rdata."""
    return socket.inet_aton(address)


def aaaa_rdata(address: str) -> bytes:
    """IPv6 → 16-byte AAAA rdata."""
    return socket.inet_pton(socket.AF_INET6, address)


def txt_rdata(text: str) -> bytes:
    """TXT rdata — one or more length-prefixed character-strings (≤255 bytes each)."""
    raw = text.encode("utf-8")
    out = bytearray()
    for i in range(0, len(raw), 255) or [0]:
        chunk = raw[i:i + 255]
        out.append(len(chunk))
        out += chunk
    if not raw:  # empty string is a single zero-length character-string
        out = bytearray(b"\x00")
    return bytes(out)
