# Ladon on OPNsense

The engine runs on FreeBSD (pf tables via `pfctl`, DNS observed through an Unbound
dynlib over a unix socket). On OPNsense it ships as the `os-ladon` plugin (GUI,
service, auto-wiring).

## How it works

- **Set backend** (`internal/ipset`): auto-selects `pfctl` on FreeBSD, `ipset` on Linux.
- **DNS mediator** (`internal/dnssrc`): `auto` → unbound (unix socket) on FreeBSD,
  dnsmasq (log tail) elsewhere. Socket defaults to `/var/unbound/var/run/ladon-dns.sock`
  (inside the unbound chroot) on FreeBSD — no config needed.
- **Unbound dynlib** (`ladon-unbound.c`): on each reply emits `domain<TAB>client<TAB>ips`
  to the socket. Coexists with the DNSBL python module (`module-config: "python dynlib iterator"`).
- The `.so` is ABI-bound to the unbound version, so it is **built on the box** by
  `plugin/.../build_unbound_module.sh` (reuses `unbound -V` flags, ~10s, idempotent),
  not shipped prebuilt. This is what keeps the port working across unbound bumps.

## OPNsense (os-ladon plugin)

Install the plugin; everything is automatic on enable: builds the `.so`, injects the
dynlib into unbound (`unbound.opnsense.d/`), declares the three pf tables as
**External (advanced)** firewall aliases, starts the service. Configure under
**Services ▸ Ladon ▸ Settings**, observe under **Diagnostics**.
