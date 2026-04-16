#!/usr/bin/env bash
# ladon installer — Debian/Ubuntu only.
#
# Scope: ladon's job is to keep two kernel ipsets populated:
#   ladon_engine — IPs of probe-discovered blocked domains (hot/cache)
#   ladon_manual — IPs of domains in manual-allow + extensions (via dnsmasq)
#
# Wiring those ipsets into actual routing (iptables MARK + ip rule fwmark
# + custom routing table → tunnel interface) is the OPERATOR'S responsibility:
# only you know your tunnel interface, peer subnet, fwmark scheme, etc.
# This script DOES NOT touch iptables — it prints an example at the end so
# you can copy-paste-adjust.
#
# Re-running this script upgrades to the latest version: existing config
# files are preserved (manual-allow.txt, manual-deny.txt, config.yaml),
# binary + unit + extensions are replaced, ladon is restarted.
#
# Usage:
#   sudo bash install.sh
#
# Or:
#   curl -fsSL https://github.com/belotserkovtsev/ladon/releases/latest/download/install.sh \
#     | sudo bash
#
# Optional env:
#   TAG=v0.4.0-rc1          install a specific release tag instead of latest
#                           (useful for testing pre-releases — `releases/latest`
#                           in the GH API skips prereleases by default)
#   IPSET_ENGINE=ladon_engine, IPSET_MANUAL=ladon_manual
#   LADON_PREFIX=/opt/ladon, LADON_CONFIG_DIR=/etc/ladon

set -euo pipefail

# --- pretty logging ---
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
log()  { printf "%b==>%b %s\n" "$GREEN" "$NC" "$*"; }
warn() { printf "%b==>%b %s\n" "$YELLOW" "$NC" "$*"; }
die()  { printf "%b==>%b %s\n" "$RED" "$NC" "$*" >&2; exit 1; }

# --- env ---
IPSET_ENGINE="${IPSET_ENGINE:-ladon_engine}"
IPSET_MANUAL="${IPSET_MANUAL:-ladon_manual}"
LADON_PREFIX="${LADON_PREFIX:-/opt/ladon}"
LADON_CONFIG_DIR="${LADON_CONFIG_DIR:-/etc/ladon}"
GH_REPO="belotserkovtsev/ladon"

# --- preflight ---
[[ $EUID -eq 0 ]] || die "must run as root (sudo)"
[[ -f /etc/os-release ]] || die "no /etc/os-release — only Debian/Ubuntu supported"
. /etc/os-release
case "${ID:-}${ID_LIKE:-}" in
  *debian*|*ubuntu*) ;;
  *) die "only Debian/Ubuntu supported (got ID=${ID:-?})" ;;
esac
command -v systemctl >/dev/null || die "systemd required"
command -v curl       >/dev/null || die "curl required"

# --- arch detection ---
case "$(uname -m)" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) die "unsupported architecture: $(uname -m)" ;;
esac
log "architecture: $ARCH"

# --- step 1: deps ---
log "installing deps (apt)"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq ipset sqlite3 dnsmasq >/dev/null

# --- step 2: fetch release tag ---
TAG="${TAG:-}"
if [[ -z "$TAG" ]]; then
  log "querying latest stable release"
  TAG=$(curl -fsSL "https://api.github.com/repos/${GH_REPO}/releases/latest" \
    | grep '"tag_name":' | head -1 | cut -d'"' -f4)
  [[ -n "$TAG" ]] || die "couldn't determine latest tag from GitHub API"
  log "latest version: $TAG"
else
  log "using TAG override: $TAG"
fi

WORKDIR=$(mktemp -d)
trap "rm -rf '$WORKDIR'" EXIT
cd "$WORKDIR"

URL="https://github.com/${GH_REPO}/releases/download/${TAG}/ladon-linux-${ARCH}.tar.gz"
log "downloading ${URL##*/}"
curl -fsSL -O "$URL"
curl -fsSL -O "${URL}.sha256"
log "verifying sha256"
sha256sum -c "ladon-linux-${ARCH}.tar.gz.sha256"

tar xzf "ladon-linux-${ARCH}.tar.gz"
SRC="ladon-linux-${ARCH}-${TAG}"

# --- step 3: install binary + units + extensions ---
log "installing files into $LADON_PREFIX"
install -d "$LADON_PREFIX/state" "$LADON_CONFIG_DIR" "$LADON_PREFIX/extensions"
install -m 0755 "$SRC/ladon"             "$LADON_PREFIX/ladon"
install -m 0644 "$SRC/ladon.service"     /etc/systemd/system/ladon.service
[[ ! -f "$LADON_CONFIG_DIR/manual-allow.txt" ]] && \
  install -m 0644 "$SRC/manual-allow.txt.example" "$LADON_CONFIG_DIR/manual-allow.txt"
[[ ! -f "$LADON_CONFIG_DIR/manual-deny.txt" ]] && \
  install -m 0644 "$SRC/manual-deny.txt.example"  "$LADON_CONFIG_DIR/manual-deny.txt"
[[ ! -f "$LADON_CONFIG_DIR/config.yaml" ]] && \
  install -m 0644 "$SRC/config.yaml.example"      "$LADON_CONFIG_DIR/config.yaml"
install -m 0644 "$SRC/extensions/"*.txt  "$LADON_PREFIX/extensions/"
install -m 0644 "$SRC/extensions/README.md" "$LADON_PREFIX/extensions/"

# --- step 4: ipsets (idempotent) ---
log "creating ipsets ($IPSET_ENGINE, $IPSET_MANUAL)"
ipset list "$IPSET_ENGINE" -t >/dev/null 2>&1 || \
  ipset create "$IPSET_ENGINE" hash:ip family inet maxelem 65536
ipset list "$IPSET_MANUAL" -t >/dev/null 2>&1 || \
  ipset create "$IPSET_MANUAL" hash:ip family inet maxelem 65536 timeout 86400

# Persist ipsets across reboot. iptables-persistent's `ipsets` file is the
# Debian/Ubuntu standard location; works whether or not netfilter-persistent
# is installed (operator's choice).
mkdir -p /etc/iptables
ipset save > /etc/iptables/ipsets

# --- step 6: dnsmasq CAP_NET_ADMIN drop-in ---
log "granting dnsmasq CAP_NET_ADMIN (needed for ipset= directives)"
install -d /etc/systemd/system/dnsmasq.service.d
cat > /etc/systemd/system/dnsmasq.service.d/ladon-ipset.conf <<EOF
# Installed by ladon: dnsmasq drops privileges to user 'dnsmasq', it needs
# CAP_NET_ADMIN to manipulate kernel ipsets via the ipset= directive
# ladon writes into /etc/dnsmasq.d/ladon-manual.conf.
[Service]
AmbientCapabilities=CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW CAP_SETUID CAP_SETGID CAP_CHOWN CAP_DAC_OVERRIDE CAP_FOWNER CAP_SETFCAP CAP_SETPCAP CAP_SYS_CHROOT CAP_KILL
EOF

# --- step 7: ladon systemd unit — point at config.yaml ---
if ! grep -q -- '-config' /etc/systemd/system/ladon.service; then
  log "wiring -config /etc/ladon/config.yaml into ladon.service"
  sed -i "s|^  -db ${LADON_PREFIX//\//\\/}/state/engine.db|  -db ${LADON_PREFIX}/state/engine.db -config ${LADON_CONFIG_DIR}/config.yaml|" \
    /etc/systemd/system/ladon.service
fi

# --- step 8: init db ---
log "initializing database"
"$LADON_PREFIX/ladon" -db "$LADON_PREFIX/state/engine.db" init-db >/dev/null

# --- step 9: reload + start ---
# `restart` instead of `start` so re-running this script serves as an
# upgrade: a fresh install starts, an existing one is replaced — picking
# up the new binary and any unit / drop-in changes in one shot.
log "reloading systemd, restarting dnsmasq, starting/restarting ladon"
systemctl daemon-reload
systemctl restart dnsmasq
systemctl enable ladon >/dev/null
systemctl restart ladon

sleep 1
if ! systemctl is-active --quiet ladon; then
  warn "ladon failed to start — check: journalctl -u ladon -n 50 --no-pager"
  exit 1
fi

# --- post-install message ---
cat <<EOF

${GREEN}==> ladon $TAG installed${NC}

What's running:
  service:  systemctl status ladon
  logs:     journalctl -u ladon -f
  config:   $LADON_CONFIG_DIR/config.yaml
  ipsets:   $IPSET_ENGINE (probe-driven), $IPSET_MANUAL (dnsmasq-driven)

${YELLOW}==> ROUTING IS YOUR JOB${NC}

ladon only fills the ipsets — wiring traffic from peers through your tunnel
when the destination IP matches one of those sets is up to you. A typical
WireGuard split-tunnel setup looks like (adjust subnet/fwmark/iface):

  iptables -t mangle -A WG_ROUTE -s 10.10.0.0/16 \\
    -m set --match-set $IPSET_ENGINE dst -j MARK --set-mark 0x1
  iptables -t mangle -A WG_ROUTE -s 10.10.0.0/16 \\
    -m set --match-set $IPSET_MANUAL dst -j MARK --set-mark 0x1

  ip rule add fwmark 0x1 table ladon priority 1000
  echo '666 ladon' >> /etc/iproute2/rt_tables
  ip route replace default dev tun0 table ladon

  iptables-save > /etc/iptables/rules.v4   # persist across reboot

Next steps:
  1. Wire the iptables / ip rule above (or whatever your routing setup needs).
  2. Add domains to $LADON_CONFIG_DIR/manual-allow.txt and restart ladon.
  3. Or enable bundled extensions in $LADON_CONFIG_DIR/config.yaml:
       extensions: [ai, twitch]
  4. (Optional) For exit-compare validator, set probe.mode: exit-compare
     in config.yaml. See $LADON_PREFIX/README.md.

To uninstall: download and run release/uninstall.sh from the same release.
EOF
