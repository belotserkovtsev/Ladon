#!/usr/bin/env bash
# ladon uninstaller — undoes everything install.sh did.
#
# Routing rules (iptables / ip rule) are NOT touched — install.sh didn't
# add them either. If you wired ladon_engine / ladon_manual into your
# routing setup, remove those rules manually.
#
# Usage:
#   sudo bash uninstall.sh

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
log()  { printf "%b==>%b %s\n" "$GREEN" "$NC" "$*"; }
warn() { printf "%b==>%b %s\n" "$YELLOW" "$NC" "$*"; }
die()  { printf "%b==>%b %s\n" "$RED" "$NC" "$*" >&2; exit 1; }

IPSET_ENGINE="${IPSET_ENGINE:-ladon_engine}"
IPSET_MANUAL="${IPSET_MANUAL:-ladon_manual}"
LADON_PREFIX="${LADON_PREFIX:-/opt/ladon}"
LADON_CONFIG_DIR="${LADON_CONFIG_DIR:-/etc/ladon}"

[[ $EUID -eq 0 ]] || die "must run as root (sudo)"

log "stopping ladon"
systemctl disable --now ladon 2>/dev/null || true
rm -f /etc/systemd/system/ladon.service

log "removing dnsmasq drop-in"
rm -f /etc/systemd/system/dnsmasq.service.d/ladon-ipset.conf
rmdir /etc/systemd/system/dnsmasq.service.d 2>/dev/null || true

log "destroying ipsets (will fail if still referenced by iptables — clean those first)"
ipset destroy "$IPSET_ENGINE" 2>/dev/null || \
  warn "$IPSET_ENGINE still in use; remove iptables rules referencing it first"
ipset destroy "$IPSET_MANUAL" 2>/dev/null || \
  warn "$IPSET_MANUAL still in use; remove iptables rules referencing it first"

log "persisting netfilter state (ipset save)"
mkdir -p /etc/iptables
ipset save > /etc/iptables/ipsets 2>/dev/null || true

log "removing ladon-manual.conf"
rm -f /etc/dnsmasq.d/ladon-manual.conf

log "removing $LADON_PREFIX and $LADON_CONFIG_DIR"
rm -rf "$LADON_PREFIX" "$LADON_CONFIG_DIR"

log "reloading systemd, restarting dnsmasq"
systemctl daemon-reload
systemctl restart dnsmasq 2>/dev/null || true

cat <<EOF

${GREEN}==> ladon uninstalled${NC}

What was NOT removed (do this by hand if needed):
  - any iptables rules YOU added that reference $IPSET_ENGINE / $IPSET_MANUAL
  - any ip rule fwmark / routing tables you set up for the tunnel
  - dnsmasq + ipset packages (still installed)
EOF
