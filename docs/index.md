# secdns

A small, **zero-dependency** authoritative DNS server for closed networks — the naming layer
of the [SecRouter](https://github.com/secrouter) suite. It answers for one internal zone so
components on different hosts resolve each other by name, and forwards everything else
upstream (or refuses it, on a fully closed network).

```{toctree}
:maxdepth: 2
:caption: Contents

configuration
zone
console
deployment
```

## Why it exists

A single-host deploy can get away with `localhost` and a couple of `/etc/hosts` lines. The
moment the suite spans more than one machine — say inference on a GPU box and the gateway on
a core host — components need to *resolve* each other, and the CA needs stable names to issue
certificates for. secdns provides that resolution from data SecDeploy already has: the site
topology. SecDeploy writes one `A` record per component (→ the address of the resource
hosting it) into the zone file, and secdns serves it.

## How it answers

For each query secdns decides:

1. **Inside the zone** (`*.sec.internal`) → answer from the zone file. A name that exists but
   lacks the requested type is `NODATA`; a name that doesn't exist is `NXDOMAIN`.
2. **Outside the zone**, with upstreams configured → **forward** and relay the first answer.
3. **Outside the zone**, with no upstreams → **REFUSE**. On a closed network this is the safe
   default: internal lookups resolve, and nothing leaks outward.

It listens on **UDP and TCP** port 53 (TCP is length-framed per RFC 1035), and ships a small
[status console](console.md) with live query stats and a reload button.

## Design notes

- **Standard library only.** The DNS wire format (header, question, resource records, name
  compression) is implemented directly in {mod}`secdns.message` — auditable, no third-party
  parser in the trust boundary. This mirrors SecCert's build-our-own approach.
- **Authoritative-only.** secdns does not recurse; it answers from its zone or forwards. That
  keeps the attack surface small and the behavior easy to reason about in an enclave.
- **Reload without downtime.** The zone reloads on `SIGHUP` (or the console), so SecDeploy can
  regenerate it after a topology change and signal a refresh.
