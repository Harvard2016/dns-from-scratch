# dns-from-scratch

![Python](https://img.shields.io/badge/Python-3.9+-3776AB?logo=python&logoColor=white)
![Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen)
![License](https://img.shields.io/badge/license-MIT-green)

A DNS resolver built from scratch in Python using only the standard library.

Constructs query packets in binary wire format with `struct.pack`, sends them over raw UDP sockets, parses the binary responses, and walks the full delegation chain from IANA root nameservers — no `dig`, no `resolv.conf`, no external resolvers.

---

## Demo

```
$ python resolver.py google.com --trace

[1]  querying   198.41.0.4         for google.com (A)
     referral → l.gtld-servers.net (192.41.162.30) [glue]

[2]  querying   192.41.162.30      for google.com (A)
     referral → ns2.google.com (216.239.34.10) [glue]

[3]  querying   216.239.34.10      for google.com (A)
     answer   → 142.251.211.14

google.com                      300     A       142.251.211.14
```

```
$ python resolver.py gmail.com --type MX

gmail.com                       3600    MX      5 gmail-smtp-in.l.google.com
gmail.com                       3600    MX      10 alt1.gmail-smtp-in.l.google.com
gmail.com                       3600    MX      20 alt2.gmail-smtp-in.l.google.com
gmail.com                       3600    MX      30 alt3.gmail-smtp-in.l.google.com
gmail.com                       3600    MX      40 alt4.gmail-smtp-in.l.google.com
```

---

## Features

- **Full recursive resolution** — starts at IANA root nameservers, follows the delegation chain to the authoritative nameserver, no external resolver required
- **Binary wire format** — queries built byte-by-byte with `struct.pack`; responses parsed the same way
- **DNS name compression** — correctly follows pointer chains (RFC 1035 §4.1.4)
- **Record types**: A, AAAA, CNAME, MX, NS, TXT
- **Glue record handling** — uses IPs from the additional section when available; resolves NS hostnames from root when not
- **CNAME following** — chases aliases automatically, detects loops
- **`--trace` flag** — shows every delegation hop: server queried, referral or answer, glue vs. resolved

---

## Requirements

- Python 3.9 or later
- No third-party packages

---

## Usage

```
python resolver.py <domain> [--type TYPE] [--trace] [--stub]
```

| Flag | Description |
|------|-------------|
| `--type TYPE` | Record type to query: `A`, `AAAA`, `CNAME`, `MX`, `NS`, `TXT` (default: `A`) |
| `--trace` | Print each delegation hop as the chain is walked |
| `--stub` | Skip recursive resolution; send directly to `8.8.8.8` |

### Examples

```bash
# A record (default)
python resolver.py github.com

# IPv6
python resolver.py google.com --type AAAA

# Mail exchangers
python resolver.py gmail.com --type MX

# TXT (SPF, DMARC, etc.)
python resolver.py _dmarc.google.com --type TXT

# Show delegation chain
python resolver.py cloudflare.com --trace

# Fast mode (skip recursive walk, use 8.8.8.8)
python resolver.py google.com --stub
```

---

## How it works

### DNS in one paragraph

Every domain name is served by an *authoritative nameserver*. To find it, you start at the root — 13 sets of root servers managed by IANA. The root doesn't know where `google.com` lives, but it knows who runs `.com`. The `.com` TLD nameserver doesn't know `google.com`'s IPs, but it knows which nameservers are authoritative for `google.com`. Those authoritative nameservers return the actual answer. This three-step chain (root → TLD → authoritative) is how every DNS query works.

### Wire format

DNS packets are binary. A query is a 12-byte header followed by a question section:

```
Header (12 bytes):
  ID       2 bytes  — random transaction identifier
  Flags    2 bytes  — 0x0100: recursion desired, all else zero
  QDCOUNT  2 bytes  — number of questions (1)
  ANCOUNT  2 bytes  — answer records (0 in a query)
  NSCOUNT  2 bytes  — authority records (0 in a query)
  ARCOUNT  2 bytes  — additional records (0 in a query)

Question (variable):
  QNAME    encoded domain labels + 0x00 terminator
  QTYPE    2 bytes  — record type (1=A, 28=AAAA, 15=MX, ...)
  QCLASS   2 bytes  — 1 (IN = Internet)
```

Domain names are encoded as length-prefixed labels: `google.com` → `\x06google\x03com\x00`.

### Name compression

Responses reuse domain names via 2-byte pointers (RFC 1035 §4.1.4). Any name can be replaced by a pointer to an earlier occurrence in the same packet:

```
  ┌──────┬────────────────────────┐
  │  11  │  14-bit target offset  │  ← byte >= 0xC0
  └──────┴────────────────────────┘
```

Correctly returning the offset *after the pointer bytes* (not after the pointer's target) is critical — getting this wrong silently drops all subsequent records.

### Glue records

When the `.com` TLD refers you to `ns1.google.com`, resolving `ns1.google.com` would normally require querying `google.com`'s nameserver — which is `ns1.google.com`. This circular dependency is broken by *glue records*: the parent zone pre-emptively includes `ns1.google.com`'s A record in the additional section of its referral response.

When no glue is present (common for cross-zone NS names), this resolver recursively resolves the NS hostname from root before continuing.

### Resolution loop

```
server = root nameserver

loop (up to MAX_HOPS times):
  response = UDP query to server

  if response has matching answer records:
      return them

  if response has CNAME (and we're not querying for CNAME):
      domain = CNAME target
      server = root nameserver  # restart for the canonical name
      continue

  if response has NS delegation:
      ns_ip = glue record from additional section
              OR resolve_recursive(ns_hostname)
      server = ns_ip
      continue
```

---

## Limitations

- **No TCP fallback** — DNS falls back to TCP when a response exceeds 512 bytes (server sets the TC bit). This resolver only uses UDP; oversized responses are truncated. Affects domains with many TXT records.
- **No DNSSEC** — responses are not cryptographically validated.
- **IPv4 transport only** — queries are sent over IPv4 UDP even when resolving AAAA records.
- **Single-threaded** — no concurrent queries or query pipelining.

---

## License

MIT
