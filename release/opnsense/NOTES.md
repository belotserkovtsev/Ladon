# Ladon on FreeBSD / OPNsense

The engine runs on FreeBSD (pf tables via `pfctl`, DNS observed through an Unbound
dynlib over a unix socket). On OPNsense it ships as the `os-ladon` plugin (GUI,
service, auto-wiring). On bare FreeBSD it runs headless — see below.

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

## Bare FreeBSD (no GUI)

Assumes a chrooted unbound at `/var/unbound` (FreeBSD base `local_unbound`). No
installer — wire it by hand (all pieces are in this repo):

1. **Binary**: `CGO_ENABLED=0 GOOS=freebsd GOARCH=amd64 go build -o ladon ./cmd/ladon`,
   then `install -m755 ladon /usr/local/bin/ladon`.
2. **Service**: copy `plugin/src/etc/rc.d/ladon` → `/usr/local/etc/rc.d/ladon`,
   then `sysrc ladon_enable=YES`.
3. **Dynlib**: `install -m644 release/opnsense/plugin/src/share/ladon/ladon-unbound.c /usr/local/share/ladon/`,
   run `plugin/src/opnsense/scripts/OPNsense/Ladon/build_unbound_module.sh`
   → `/usr/local/lib/ladon_unbound.so`. Copy it into the chroot:
   `cp /usr/local/lib/ladon_unbound.so /var/unbound/ladon_unbound.so`.
4. **Unbound**: add to `unbound.conf` (keep your existing modules):
   ```
   server:
       module-config: "dynlib iterator"
   dynlib:
       dynlib-file: "/ladon_unbound.so"   # chroot-relative
   ```
   then `mkdir -p /var/unbound/var/run` and restart unbound.
5. **pf** (`/etc/pf.conf`) — ladon creates/fills these tables; declare + route them:
   ```
   table <ladon_engine> persist
   table <ladon_manual> persist
   table <ladon_cidr>   persist
   # send matched destinations out the tunnel (adapt iface/gateway):
   pass out route-to (tun0 <TUNNEL_GW>) from <lan> to <ladon_engine>
   ```
6. **Start**: `service ladon start`. It auto-configures (Unbound source + pf backend);
   `ladon -db /var/db/ladon/engine.db doctor` should be green.

Tuning is optional via `/usr/local/etc/ladon/config.yaml` (see `release/config.yaml.example`).
A non-chrooted unbound is not currently supported (the socket paths won't align).
