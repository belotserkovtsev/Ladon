#!/bin/sh
# ladon uninstaller — Debian/Ubuntu + OpenWRT.
#
# Mirrors install.sh: detects OS and runs the matching teardown.
# Routing rules (iptables / ip rule / firewall4 nft / routing tables)
# are NOT touched — install.sh didn't add them. If you wired the ipsets
# into your firewall, remove those rules manually.
#
# Usage:
#   sh uninstall.sh

set -eu

if [ -t 1 ]; then
	RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
else
	RED=''; GREEN=''; YELLOW=''; NC=''
fi
log()  { printf '%s==>%s %s\n' "$GREEN" "$NC" "$*"; }
warn() { printf '%s==>%s %s\n' "$YELLOW" "$NC" "$*"; }
die()  { printf '%s==>%s %s\n' "$RED" "$NC" "$*" >&2; exit 1; }

IPSET_ENGINE="${IPSET_ENGINE:-ladon_engine}"
IPSET_MANUAL="${IPSET_MANUAL:-ladon_manual}"
IPSET_CIDR="${IPSET_CIDR:-ladon_cidr}"

[ "$(id -u)" -eq 0 ] || die "must run as root (sudo)"

if [ -f /etc/openwrt_release ]; then
	OS=openwrt
elif [ -f /etc/os-release ]; then
	# shellcheck disable=SC1091
	. /etc/os-release
	case "${ID:-}${ID_LIKE:-}" in
		*debian*|*ubuntu*) OS=debian ;;
		*) die "unsupported OS: ID=${ID:-?}" ;;
	esac
else
	die "no /etc/openwrt_release or /etc/os-release — can't identify OS"
fi
log "detected OS: $OS"

# ============================================================
# Debian/Ubuntu path
# ============================================================
uninstall_debian() {
	LADON_PREFIX="${LADON_PREFIX:-/opt/ladon}"
	LADON_CONFIG_DIR="${LADON_CONFIG_DIR:-/etc/ladon}"

	log "stopping ladon"
	systemctl disable --now ladon 2>/dev/null || true
	rm -f /etc/systemd/system/ladon.service

	log "removing dnsmasq drop-in"
	rm -f /etc/systemd/system/dnsmasq.service.d/ladon-ipset.conf
	rmdir /etc/systemd/system/dnsmasq.service.d 2>/dev/null || true

	log "destroying ipsets (will warn if still referenced by iptables)"
	for set in "$IPSET_ENGINE" "$IPSET_MANUAL" "$IPSET_CIDR"; do
		ipset destroy "$set" 2>/dev/null || \
			warn "$set still in use; remove iptables rules referencing it first"
	done

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

${GREEN}==> ladon uninstalled (Debian/Ubuntu)${NC}

What was NOT removed (do this by hand if needed):
  - iptables rules YOU added that reference $IPSET_ENGINE / $IPSET_MANUAL / $IPSET_CIDR
  - ip rule fwmark / routing tables you set up for the tunnel
  - dnsmasq + ipset packages (still installed)
EOF
}

# ============================================================
# OpenWRT path
# ============================================================
uninstall_openwrt() {
	PREFIX_BIN=/usr/bin
	PREFIX_SHARE=/usr/share/ladon
	CONFIG_DIR=/etc/ladon
	STATE_DIR=/var/lib/ladon
	INITD=/etc/init.d/ladon

	log "stopping and disabling ladon"
	if [ -x "$INITD" ]; then
		"$INITD" stop 2>/dev/null || true
		"$INITD" disable 2>/dev/null || true
	fi
	rm -f "$INITD"

	log "destroying ipsets (will warn if still referenced by firewall)"
	for set in "$IPSET_ENGINE" "$IPSET_MANUAL" "$IPSET_CIDR"; do
		if ipset list "$set" -t >/dev/null 2>&1; then
			ipset destroy "$set" 2>/dev/null || \
				warn "$set still in use — remove referencing firewall rules first"
		fi
	done

	log "removing ladon-manual.conf dnsmasq snippet"
	rm -f /tmp/dnsmasq.d/ladon-manual.conf /etc/dnsmasq.d/ladon-manual.conf

	# --- restore UCI from backup ---
	BACKUP="$CONFIG_DIR/.uci-backup"
	if [ -f "$BACKUP" ]; then
		log "restoring /etc/config/dhcp from $BACKUP"
		while IFS='=' read -r key val; do
			case "$key" in
				'#'*|'') continue ;;
			esac
			if [ "$val" = "__unset" ]; then
				uci -q delete "dhcp.@dnsmasq[0].$key" || true
			else
				uci set "dhcp.@dnsmasq[0].$key=$val"
			fi
		done < "$BACKUP"
		uci commit dhcp
		/etc/init.d/dnsmasq reload
	else
		warn "no UCI backup at $BACKUP — leaving /etc/config/dhcp as-is"
		warn "you may want to remove dhcp.@dnsmasq[0].logqueries / .logfacility manually"
	fi

	log "removing $PREFIX_BIN/ladon, $PREFIX_SHARE, $CONFIG_DIR, $STATE_DIR"
	rm -f "$PREFIX_BIN/ladon"
	rm -rf "$PREFIX_SHARE" "$CONFIG_DIR" "$STATE_DIR"

	cat <<EOF

${GREEN}==> ladon uninstalled (OpenWRT)${NC}

What was NOT removed (do this by hand if needed):
  - firewall4 / nftables / iptables rules YOU added that reference
    $IPSET_ENGINE / $IPSET_MANUAL / $IPSET_CIDR
  - ip rule fwmark / routing tables you set up for the tunnel
  - the dnsmasq → dnsmasq-full package swap (now baseline on this router)
  - /var/log/dnsmasq.log (truncate or remove if you want)
EOF
}

case "$OS" in
	debian)  uninstall_debian ;;
	openwrt) uninstall_openwrt ;;
esac
