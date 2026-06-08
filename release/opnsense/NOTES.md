# Ladon on OPNsense — status & build notes

Work-in-progress port of Ladon to OPNsense (FreeBSD / pf / Unbound). The engine
core already runs on FreeBSD; this directory holds the OPNsense-specific glue.

## What works (validated on OPNsense 26.1.6 / unbound 1.24.2, amd64)

- **Engine on FreeBSD**: cross-compiles `CGO_ENABLED=0 GOOS=freebsd` (pure-Go
  sqlite), runs, `ladon doctor` green.
- **Set backend** (`internal/ipset`): auto-selects `pfctl` (pf tables) on
  FreeBSD, `ipset` on Linux. `Manager` API unchanged.
- **DNS mediator** (`internal/dnssrc`): neutral `Record` protocol; adapters for
  dnsmasq (tail log) and unbound (unix socket). Engine is source-agnostic.
- **unbound dynlib module** (`ladon-unbound.c`): observes domain+resolved-IP at
  reply time, emits to `/var/run/ladon-dns.sock`. **Coexists with the DNSBL
  python module** via `module-config: "python dynlib iterator"` (both run).
- Full cycle proven live: query → dynlib → socket → engine → probe → `pfctl`
  fills `ladon_engine` (e.g. rutracker.org → hot → IPs in the pf table).

## Routing (operator-side, same boundary as Linux)

Ladon fills the pf tables; the operator wires routing. On OPNsense:
3 **External (advanced)** aliases `ladon_engine` / `ladon_manual` / `ladon_cidr`,
then a firewall rule: Destination = alias, Advanced → Gateway = your VPN gw,
with RFC1918 excluded (Destination invert) so LAN-local traffic isn't tunneled.

## Building the dynlib `.so`

See the header comment in `ladon-unbound.c`. Summary: fetch the unbound source
matching the running version, `./configure` with the same ABI flags as
`unbound -V` (minus `--with-pythonmodule`/swig — they don't affect the structs
the module touches), drop `ladon-unbound.c` into `dynlibmod/examples/ladon.c`,
`cc -I../.. -shared -fpic -o ladon.so ladon.c`. The `.so` must be ABI-matched to
the running unbound.

## Not done yet (boilerplate, no technical unknowns left)

- `os-ladon` OPNsense plugin: rc.d service, configd actions, `config.xml` model,
  MVC GUI (model after `cloudflared-opnsense`).
- Inject the dynlib into OPNsense's unbound config (module-config + dynlib-file
  via unbound custom options) from the plugin.
- Reproducible `.so` build/delivery per unbound version.
- Optional: manual-allow enforce inside the dynlib (pf) + real per-client IP.
- Resolver-aware install (Linux dnsmasq / OPNsense unbound-dynlib).
