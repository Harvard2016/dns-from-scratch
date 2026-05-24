#!/usr/bin/env python3
"""
DNS resolver built from scratch — no external libraries, no system resolver.

Constructs DNS query packets in binary wire format using struct.pack, sends
them over raw UDP sockets, parses the binary responses, and walks the full
delegation chain from IANA root nameservers to the authoritative answer.

Usage:
    python resolver.py <domain> [--type TYPE] [--trace] [--stub]
"""

from __future__ import annotations

import argparse
import random
import socket
import struct
import sys
from typing import Any

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

STUB_SERVER = "8.8.8.8"   # used only with --stub flag
DNS_PORT    = 53
TIMEOUT_SEC = 3

# Root nameservers — hardcoded IANA roots, the universal starting point
ROOT_NAMESERVERS = [
    "198.41.0.4",    # a.root-servers.net
    "199.9.14.201",  # b.root-servers.net
    "192.112.36.4",  # g.root-servers.net
]

MAX_HOPS = 20  # guard against infinite delegation loops

# DNS record type codes (QTYPE / TYPE field in wire format)
TYPE_A     = 1
TYPE_NS    = 2
TYPE_CNAME = 5
TYPE_MX    = 15
TYPE_TXT   = 16
TYPE_AAAA  = 28

TYPE_NAMES: dict[str, int] = {
    "A":     TYPE_A,
    "NS":    TYPE_NS,
    "CNAME": TYPE_CNAME,
    "MX":    TYPE_MX,
    "TXT":   TYPE_TXT,
    "AAAA":  TYPE_AAAA,
}
TYPE_LABELS: dict[int, str] = {v: k for k, v in TYPE_NAMES.items()}

CLASS_IN = 1

# Header flags: QR=0 (query), Opcode=0, AA=0, TC=0, RD=1, RA=0, Z=0, RCODE=0
# Only the Recursion Desired bit is set — 0x0100
FLAGS_RD = 0x0100

RCODE_OK       = 0
RCODE_NXDOMAIN = 3


# ---------------------------------------------------------------------------
# Build query
# ---------------------------------------------------------------------------

def encode_name(domain: str) -> bytes:
    """
    Encode a domain name into DNS wire format (RFC 1035 §3.1).

    Each dot-separated label is prefixed by its length as a single byte.
    The name ends with a zero-length label (0x00 = the DNS root).

        "google.com"  →  b'\\x06google\\x03com\\x00'
        "www.x.io"    →  b'\\x03www\\x01x\\x02io\\x00'
    """
    encoded = b""
    for label in domain.rstrip(".").split("."):
        if len(label) > 63:
            raise ValueError(f"DNS label too long: {label!r}")
        encoded += bytes([len(label)]) + label.encode("ascii")
    encoded += b"\x00"  # root label terminator
    return encoded


def build_query(domain: str, qtype: int = TYPE_A) -> tuple[bytes, int]:
    """
    Build a complete DNS query packet. Returns (packet_bytes, transaction_id).

    Wire layout:
    ┌────────────────────────────────────────────────────┐
    │  Header (12 bytes)                                 │
    │    ID       2 bytes — random transaction ID        │
    │    Flags    2 bytes — 0x0100 (RD bit only)         │
    │    QDCOUNT  2 bytes — 1                            │
    │    ANCOUNT  2 bytes — 0  (this is a query)         │
    │    NSCOUNT  2 bytes — 0                            │
    │    ARCOUNT  2 bytes — 0                            │
    ├────────────────────────────────────────────────────┤
    │  Question (variable)                               │
    │    QNAME   length-prefixed labels + 0x00           │
    │    QTYPE   2 bytes — record type                   │
    │    QCLASS  2 bytes — 1 (IN = Internet)             │
    └────────────────────────────────────────────────────┘
    """
    txid     = random.randint(0, 0xFFFF)
    header   = struct.pack(">HHHHHH", txid, FLAGS_RD, 1, 0, 0, 0)
    question = encode_name(domain) + struct.pack(">HH", qtype, CLASS_IN)
    return header + question, txid


# ---------------------------------------------------------------------------
# Name decoder (with compression)
# ---------------------------------------------------------------------------

def decode_name(data: bytes, offset: int) -> tuple[str, int]:
    """
    Decode a DNS name from `data` starting at `offset`.

    DNS name compression (RFC 1035 §4.1.4) allows any name to be replaced by
    a 2-byte pointer to an earlier occurrence in the same packet:

        ┌──────┬────────────────────────┐
        │  11  │  14-bit target offset  │  ← top 2 bits are 1, byte >= 0xC0
        └──────┴────────────────────────┘

    Pointer-following is transparent to callers — the returned offset always
    points to the byte *after* the name in the *original* stream (i.e., after
    the 2-byte pointer, not after its target). This is critical: if you use the
    target offset to advance, you silently skip all subsequent records.
    """
    labels:     list[str] = []
    end_offset: int       = -1  # set once, the first time we follow a pointer

    while True:
        if offset >= len(data):
            raise ValueError("Malformed DNS name: read past end of packet")

        length = data[offset]

        if length == 0:
            # Null byte = root label = end of name
            if end_offset == -1:
                end_offset = offset + 1
            break

        elif (length & 0xC0) == 0xC0:
            # Compression pointer: save resume position, jump to target
            if end_offset == -1:
                end_offset = offset + 2        # caller resumes after these 2 bytes
            ptr    = struct.unpack(">H", data[offset: offset + 2])[0]
            offset = ptr & 0x3FFF              # strip the 0xC0 marker bits

        else:
            # Normal label: read `length` ASCII bytes
            offset += 1
            labels.append(data[offset: offset + length].decode("ascii"))
            offset += length

    return ".".join(labels), end_offset


# ---------------------------------------------------------------------------
# Parse header, questions, records
# ---------------------------------------------------------------------------

def parse_header(data: bytes) -> dict[str, int]:
    """Parse the 12-byte DNS response header."""
    id_, flags, qdcount, ancount, nscount, arcount = struct.unpack(">HHHHHH", data[:12])
    return {
        "id":      id_,
        "flags":   flags,
        "rcode":   flags & 0x000F,    # response code: 0=OK, 3=NXDOMAIN
        "tc":      (flags >> 9) & 1,  # truncated: response exceeded 512-byte UDP limit
        "qdcount": qdcount,
        "ancount": ancount,
        "nscount": nscount,
        "arcount": arcount,
    }


def skip_question(data: bytes, offset: int) -> int:
    """Advance past one question entry (QNAME + QTYPE 2 + QCLASS 2)."""
    _, offset = decode_name(data, offset)
    return offset + 4


def parse_record(data: bytes, offset: int) -> tuple[dict[str, Any], int]:
    """
    Parse one resource record (RFC 1035 §3.2.1).

    Wire format per record:
        NAME      variable  — owner name, may use pointer compression
        TYPE      2 bytes
        CLASS     2 bytes
        TTL       4 bytes   — unsigned 32-bit seconds
        RDLENGTH  2 bytes
        RDATA     RDLENGTH bytes — record-specific payload

    `rdata_offset` (absolute byte position in the full packet) is stored so
    RDATA decoders for CNAME / NS / MX — which contain encoded names — can
    follow compression pointers relative to the full packet, not a slice.
    """
    name, offset = decode_name(data, offset)
    rtype, rclass, ttl, rdlength = struct.unpack(">HHIH", data[offset: offset + 10])
    offset += 10

    rdata_offset = offset
    rdata        = data[offset: offset + rdlength]
    offset      += rdlength

    return {
        "name":         name,
        "type":         rtype,
        "class":        rclass,
        "ttl":          ttl,
        "rdata":        rdata,
        "rdata_offset": rdata_offset,
    }, offset


def parse_section(data: bytes, offset: int, count: int) -> tuple[list[dict], int]:
    """Parse `count` consecutive resource records starting at `offset`."""
    records = []
    for _ in range(count):
        record, offset = parse_record(data, offset)
        records.append(record)
    return records, offset


# ---------------------------------------------------------------------------
# RDATA decoders — one per supported record type
# ---------------------------------------------------------------------------

def decode_a(rdata: bytes) -> str:
    """4-byte IPv4 address → dotted-quad string (e.g. '142.251.32.14')."""
    if len(rdata) != 4:
        raise ValueError(f"A RDATA must be 4 bytes, got {len(rdata)}")
    return ".".join(str(b) for b in rdata)


def decode_aaaa(rdata: bytes) -> str:
    """16-byte IPv6 address → colon-hex string with :: compression."""
    if len(rdata) != 16:
        raise ValueError(f"AAAA RDATA must be 16 bytes, got {len(rdata)}")
    return socket.inet_ntop(socket.AF_INET6, rdata)


def decode_cname_ns(data: bytes, rdata_offset: int) -> str:
    """
    CNAME and NS RDATA is a single encoded domain name.
    Must decode from the full packet buffer (not a RDATA slice) so compression
    pointers that reference positions before the RDATA resolve correctly.
    """
    name, _ = decode_name(data, rdata_offset)
    return name


def decode_mx(rdata: bytes, data: bytes, rdata_offset: int) -> str:
    """
    MX RDATA: 2-byte preference (big-endian uint16) + encoded mail exchange.
    Returns a string like '10 smtp.google.com'.
    """
    preference = struct.unpack(">H", rdata[:2])[0]
    exchange, _ = decode_name(data, rdata_offset + 2)
    return f"{preference} {exchange}"


def decode_txt(rdata: bytes) -> str:
    """
    TXT RDATA: one or more length-prefixed character strings (RFC 1035 §3.3.14).

    Format: [1-byte length][string bytes] repeated until RDATA is exhausted.
    Multiple strings are joined with a space (rare but valid per spec).
    """
    parts: list[str] = []
    i = 0
    while i < len(rdata):
        slen = rdata[i]
        i   += 1
        parts.append(rdata[i: i + slen].decode("utf-8", errors="replace"))
        i   += slen
    return " ".join(parts)


def decode_rdata(record: dict[str, Any], data: bytes) -> str:
    """Dispatch RDATA decoding by record type. Unknown types → hex dump."""
    rtype        = record["type"]
    rdata        = record["rdata"]
    rdata_offset = record["rdata_offset"]

    if   rtype == TYPE_A:     return decode_a(rdata)
    elif rtype == TYPE_AAAA:  return decode_aaaa(rdata)
    elif rtype == TYPE_CNAME: return decode_cname_ns(data, rdata_offset)
    elif rtype == TYPE_NS:    return decode_cname_ns(data, rdata_offset)
    elif rtype == TYPE_MX:    return decode_mx(rdata, data, rdata_offset)
    elif rtype == TYPE_TXT:   return decode_txt(rdata)
    else:                     return rdata.hex()


# ---------------------------------------------------------------------------
# Network — send query, parse full response
# ---------------------------------------------------------------------------

def send_query(domain: str, qtype: int, server: str) -> tuple[bytes, int]:
    """Send a UDP DNS query to `server:53`. Returns (raw_response, txid)."""
    query, txid = build_query(domain, qtype)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(TIMEOUT_SEC)
    try:
        sock.sendto(query, (server, DNS_PORT))
        response, _ = sock.recvfrom(512)
    except socket.timeout:
        raise RuntimeError(f"Timed out waiting for response from {server}")
    finally:
        sock.close()
    return response, txid


def parse_response(data: bytes) -> dict[str, Any]:
    """
    Parse a full DNS response packet into structured sections.

    Returns a dict with keys: header, answers, authority, additional, raw.
    `raw` is kept so RDATA decoders can resolve compression pointers.
    """
    header = parse_header(data)
    offset = 12
    for _ in range(header["qdcount"]):
        offset = skip_question(data, offset)

    answers,    offset = parse_section(data, offset, header["ancount"])
    authority,  offset = parse_section(data, offset, header["nscount"])
    additional, offset = parse_section(data, offset, header["arcount"])

    return {
        "header":     header,
        "answers":    answers,
        "authority":  authority,
        "additional": additional,
        "raw":        data,
    }


def _decode_section(records: list[dict], raw: bytes) -> None:
    """Decode RDATA for every record in a section in-place."""
    for r in records:
        if "value" not in r:
            r["value"] = decode_rdata(r, raw)


# ---------------------------------------------------------------------------
# Stub resolver — single query to 8.8.8.8 (--stub mode)
# ---------------------------------------------------------------------------

def resolve_stub(domain: str, qtype: int = TYPE_A) -> list[dict]:
    """
    Send one query to STUB_SERVER and return decoded answers.
    Fast, but delegates all recursion to an external resolver.
    """
    raw, txid = send_query(domain, qtype, STUB_SERVER)
    parsed    = parse_response(raw)
    header    = parsed["header"]

    if header["id"] != txid:
        raise RuntimeError("Transaction ID mismatch — possible spoofed response")
    if header["rcode"] == RCODE_NXDOMAIN:
        raise RuntimeError(f"NXDOMAIN: {domain!r} does not exist")
    if header["rcode"] != RCODE_OK:
        raise RuntimeError(f"DNS error RCODE={header['rcode']} for {domain!r}")

    _decode_section(parsed["answers"], raw)
    return parsed["answers"]


# ---------------------------------------------------------------------------
# Recursive resolver — walks the full delegation chain from root
# ---------------------------------------------------------------------------

def _get_glue(ns_name: str, additional: list[dict], raw: bytes) -> str | None:
    """
    Look for an A record for `ns_name` in the additional section.

    Glue records break the chicken-and-egg problem: to reach ns1.example.com,
    you would normally need to query example.com's nameserver — which is
    ns1.example.com. The parent zone pre-emptively includes the IP address
    in the additional section of its referral response.
    """
    target = ns_name.rstrip(".").lower()
    for record in additional:
        if (record["type"] == TYPE_A
                and record["name"].rstrip(".").lower() == target):
            return decode_rdata(record, raw)
    return None


def resolve_recursive(
    domain:  str,
    qtype:   int = TYPE_A,
    _start:  str | None       = None,
    _trace:  list[str] | None = None,
) -> list[dict]:
    """
    Resolve `domain` / `qtype` by walking the DNS delegation chain from root.
    Makes no use of external resolvers — all answers come from authoritative
    nameservers reached by starting at the IANA root.

    Delegation walk (example: google.com A):
        1. Query root (198.41.0.4)
             → referral: a.gtld-servers.net (glue IP in additional)
        2. Query .com TLD (192.5.6.30)
             → referral: ns1.google.com (glue IP in additional)
        3. Query authoritative (216.239.32.10)
             → answer: 142.251.32.14  ✓

    CNAME handling:
        If the answer section contains a CNAME (and qtype != CNAME),
        update domain to the canonical name and restart from root.
        A seen-set detects and breaks loops.

    Glue vs. no-glue:
        Referrals include NS hostnames (e.g. ns1.example.com). Often the
        additional section also contains their A records (glue). When no glue
        is present, we call resolve_recursive(ns_hostname, A) from root first.

    `_trace` (optional):
        Pass an empty list to collect human-readable hop descriptions.
        The caller prints them; the list is populated in-place.
    """
    server      = _start or ROOT_NAMESERVERS[0]
    cname_seen: set[str] = {domain.lower()}

    for hop in range(MAX_HOPS):

        # Try the current server; on hop 0 fall back to alternate roots on timeout
        try:
            raw, txid = send_query(domain, qtype, server)
        except RuntimeError:
            if hop == 0 and _start is None:
                for fallback in ROOT_NAMESERVERS[1:]:
                    try:
                        raw, txid = send_query(domain, qtype, fallback)
                        server    = fallback
                        break
                    except RuntimeError:
                        continue
                else:
                    raise
            else:
                raise

        type_name = TYPE_LABELS.get(qtype, str(qtype))
        if _trace is not None:
            _trace.append(f"\n[{hop + 1}]  querying   {server:<18} for {domain} ({type_name})")

        parsed    = parse_response(raw)
        header    = parsed["header"]
        answers   = parsed["answers"]
        authority = parsed["authority"]
        additional= parsed["additional"]

        if header["id"] != txid:
            raise RuntimeError("Transaction ID mismatch — possible spoofed response")
        if header["rcode"] == RCODE_NXDOMAIN:
            raise RuntimeError(f"NXDOMAIN: {domain!r} does not exist")
        if header["rcode"] != RCODE_OK:
            raise RuntimeError(f"DNS error RCODE={header['rcode']} for {domain!r}")

        for section in (answers, authority, additional):
            _decode_section(section, raw)

        # ── Case 1: Direct answer ──────────────────────────────────────────
        matching = [r for r in answers if r["type"] == qtype]
        if matching:
            if _trace is not None:
                values = ", ".join(r["value"] for r in matching)
                _trace.append(f"     answer   → {values}")
            return matching

        # ── Case 2: CNAME redirect ────────────────────────────────────────
        cnames = [r for r in answers if r["type"] == TYPE_CNAME]
        if cnames and qtype != TYPE_CNAME:
            target = cnames[0]["value"].rstrip(".").lower()
            if target in cname_seen:
                raise RuntimeError(
                    f"CNAME loop: {' → '.join(cname_seen)} → {target}"
                )
            if _trace is not None:
                _trace.append(
                    f"     cname    → {cnames[0]['value']}  (restarting from root)"
                )
            cname_seen.add(target)
            domain = target
            server = ROOT_NAMESERVERS[0]
            continue

        # ── Case 3: NS delegation ─────────────────────────────────────────
        ns_records = [r for r in authority if r["type"] == TYPE_NS]
        if not ns_records:
            raise RuntimeError(
                f"No answer and no NS delegation for {domain!r} from {server}"
            )

        # Prefer glue records (NS IPs already in the additional section)
        ns_ip:  str | None = None
        ns_used: str       = ""
        glue_used          = False

        for ns in ns_records:
            ns_ip = _get_glue(ns["value"], additional, raw)
            if ns_ip:
                ns_used   = ns["value"]
                glue_used = True
                break

        # No glue — resolve the NS hostname recursively from root
        if not ns_ip:
            for ns in ns_records:
                try:
                    # Don't propagate _trace into sub-lookups (too noisy)
                    glue_results = resolve_recursive(ns["value"], TYPE_A)
                    if glue_results:
                        ns_ip   = glue_results[0]["value"]
                        ns_used = ns["value"]
                        break
                except RuntimeError:
                    continue

        if not ns_ip:
            tried = [r["value"] for r in ns_records]
            raise RuntimeError(
                f"Could not resolve any nameserver for {domain!r} "
                f"(tried: {tried})"
            )

        if _trace is not None:
            source = "[glue]" if glue_used else "[resolved]"
            _trace.append(f"     referral → {ns_used} ({ns_ip}) {source}")

        server = ns_ip

    raise RuntimeError(f"Exceeded {MAX_HOPS} delegation hops resolving {domain!r}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="resolver.py",
        description=(
            "DNS resolver built from scratch — no external libraries.\n"
            "Walks the full delegation chain from IANA root nameservers."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  python resolver.py google.com
  python resolver.py google.com  --type AAAA
  python resolver.py gmail.com   --type MX
  python resolver.py google.com  --trace
  python resolver.py google.com  --stub
""",
    )
    parser.add_argument("domain", help="Domain name to resolve")
    parser.add_argument(
        "--type",
        default="A",
        choices=list(TYPE_NAMES),
        metavar="TYPE",
        help="Record type: A, AAAA, CNAME, MX, NS, TXT  (default: A)",
    )
    parser.add_argument(
        "--trace",
        action="store_true",
        help="Show each delegation hop in the resolution chain",
    )
    parser.add_argument(
        "--stub",
        action="store_true",
        help="Skip recursive resolution; query 8.8.8.8 directly",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args   = parser.parse_args()

    qtype  = TYPE_NAMES[args.type.upper()]
    trace: list[str] | None = [] if args.trace else None

    try:
        if args.stub:
            records = resolve_stub(args.domain, qtype)
        else:
            records = resolve_recursive(args.domain, qtype, _trace=trace)
    except RuntimeError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)

    # Print trace before results
    if trace:
        for line in trace:
            print(line)
        print()

    type_label = TYPE_LABELS.get(qtype, str(qtype))
    if not records:
        print(f"No {type_label} records found for {args.domain}")
        return

    for r in records:
        label = TYPE_LABELS.get(r["type"], str(r["type"]))
        print(f"{r['name']:<30}  {r['ttl']:<6}  {label:<6}  {r['value']}")


if __name__ == "__main__":
    main()
