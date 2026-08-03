# Deployment

secdns is part of the SecRouter suite's `identity` tier and is normally stood up by
**SecDeploy**, which generates the zone from `topology.toml`, runs secdns, and points the
other hosts' resolvers at it. This page covers running it directly.

## As a service (port 53)

Port 53 is privileged, so secdns runs as a dedicated system service. A minimal hardened
systemd unit:

```ini
[Unit]
Description=secdns internal DNS
After=network-online.target
Wants=network-online.target

[Service]
Environment=SECDNS_DOMAIN=sec.internal
Environment=SECDNS_ZONE=/var/lib/secdns/secdns.zone
Environment=SECDNS_UPSTREAM=
ExecStart=/usr/bin/secdns serve
ExecReload=/bin/kill -HUP $MAINPID
DynamicUser=yes
StateDirectory=secdns
AmbientCapabilities=CAP_NET_BIND_SERVICE   # bind :53 without full root
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
RestrictAddressFamilies=AF_INET AF_INET6

[Install]
WantedBy=multi-user.target
```

`CAP_NET_BIND_SERVICE` lets an unprivileged user bind port 53; `ExecReload` wires
`systemctl reload secdns` to the zone hot-reload. Leave `SECDNS_UPSTREAM` empty for a closed
network, or set it to your site resolvers to forward external names.

## Pointing clients at it

Hosts that should resolve the internal zone must use secdns as (one of) their resolvers.
Depending on the OS that means a `nameserver` line in `/etc/resolv.conf` /
`systemd-resolved`, or a per-domain resolver entry (e.g. macOS `/etc/resolver/<domain>`).
SecDeploy configures this for each resource as part of a deploy.

## Air-gapped

secdns has zero third-party dependencies, so it needs nothing from a package index at
runtime — it ships and runs entirely from the standard library. The zone is a plain file
carried with the rest of the release bundle.

## Health

Point your monitoring at the console's `/health` endpoint (default
`http://127.0.0.1:47053/health`); `secdeploy status` reads the same endpoint.
