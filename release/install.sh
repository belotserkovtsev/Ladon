#!/bin/sh
# ladon installer — Debian/Ubuntu + OpenWRT.
#
# This is a unified entry point: it sniffs /etc/openwrt_release vs
# /etc/os-release and dispatches into the appropriate OS-specific
# routine. Both paths keep the same boundary: ladon's job is to keep
# three kernel ipsets populated; wiring those ipsets into routing
# (iptables MARK / firewall4 nft / ip rule fwmark + custom routing
# table → tunnel interface) is the OPERATOR'S responsibility.
#
# Re-run = upgrade. config.yaml / manual-allow.txt / manual-deny.txt
# are preserved; binary + unit/init + extensions are replaced.
#
# Usage:
#   sh install.sh
#
# Or via one-liner:
#   wget -O- https://github.com/belotserkovtsev/ladon/releases/latest/download/install.sh | sh
#   curl -fsSL https://github.com/belotserkovtsev/ladon/releases/latest/download/install.sh | sh
#
# Optional env:
#   TAG=v1.4.0-rc1          install a specific release tag instead of latest
#   IPSET_ENGINE=ladon_engine, IPSET_MANUAL=ladon_manual, IPSET_CIDR=ladon_cidr
#   ASSUME_YES=1            skip OpenWRT's dnsmasq-full swap countdown (CI/scripts)
#   LADON_PREFIX=/opt/ladon, LADON_CONFIG_DIR=/etc/ladon  (Debian only)

set -eu

# --- pretty logging ---
if [ -t 1 ]; then
	RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
else
	RED=''; GREEN=''; YELLOW=''; NC=''
fi
log()  { printf '%s==>%s %s\n' "$GREEN" "$NC" "$*"; }
warn() { printf '%s==>%s %s\n' "$YELLOW" "$NC" "$*"; }
die()  { printf '%s==>%s %s\n' "$RED" "$NC" "$*" >&2; exit 1; }

# --- common env ---
IPSET_ENGINE="${IPSET_ENGINE:-ladon_engine}"
IPSET_MANUAL="${IPSET_MANUAL:-ladon_manual}"
IPSET_CIDR="${IPSET_CIDR:-ladon_cidr}"
GH_REPO="belotserkovtsev/ladon"
ASSUME_YES="${ASSUME_YES:-0}"
TAG="${TAG:-}"

# --- preflight ---
[ "$(id -u)" -eq 0 ] || die "must run as root (sudo)"

# --- OS detection ---
if [ -f /etc/openwrt_release ]; then
	OS=openwrt
elif [ -f /etc/os-release ]; then
	# shellcheck disable=SC1091
	. /etc/os-release
	case "${ID:-}${ID_LIKE:-}" in
		*debian*|*ubuntu*) OS=debian ;;
		*) die "unsupported OS: ID=${ID:-?} (only Debian/Ubuntu and OpenWRT are supported)" ;;
	esac
else
	die "no /etc/openwrt_release or /etc/os-release — can't identify OS"
fi
log "detected OS: $OS"

# ============================================================
# Debian/Ubuntu path
# ============================================================
install_debian() {
	LADON_PREFIX="${LADON_PREFIX:-/opt/ladon}"
	LADON_CONFIG_DIR="${LADON_CONFIG_DIR:-/etc/ladon}"

	command -v systemctl >/dev/null || die "systemd required"
	command -v curl       >/dev/null || die "curl required"

	# --- arch detection ---
	case "$(uname -m)" in
		x86_64|amd64)   ARCH=amd64 ;;
		aarch64|arm64)  ARCH=arm64 ;;
		*) die "unsupported architecture: $(uname -m) (need amd64 or arm64)" ;;
	esac
	log "architecture: $ARCH"

	# --- deps ---
	log "installing deps (apt)"
	export DEBIAN_FRONTEND=noninteractive
	apt-get update -qq
	apt-get install -y -qq ipset sqlite3 dnsmasq >/dev/null

	# --- fetch release tag ---
	if [ -z "$TAG" ]; then
		log "querying latest stable release"
		TAG=$(curl -fsSL "https://api.github.com/repos/${GH_REPO}/releases/latest" \
			| grep '"tag_name":' | head -1 | cut -d'"' -f4)
		[ -n "$TAG" ] || die "couldn't determine latest tag from GitHub API"
		log "latest version: $TAG"
	else
		log "using TAG override: $TAG"
	fi

	WORKDIR=$(mktemp -d)
	trap 'rm -rf "$WORKDIR"' EXIT
	cd "$WORKDIR"

	URL="https://github.com/${GH_REPO}/releases/download/${TAG}/ladon-linux-${ARCH}.tar.gz"
	log "downloading ${URL##*/}"
	curl -fsSL -O "$URL"
	curl -fsSL -O "${URL}.sha256"
	log "verifying sha256"
	sha256sum -c "ladon-linux-${ARCH}.tar.gz.sha256"

	tar xzf "ladon-linux-${ARCH}.tar.gz"
	SRC="ladon-linux-${ARCH}-${TAG}"

	# --- install files ---
	log "installing files into $LADON_PREFIX"
	install -d "$LADON_PREFIX/state" "$LADON_CONFIG_DIR" "$LADON_PREFIX/extensions"
	install -m 0755 "$SRC/ladon"             "$LADON_PREFIX/ladon"
	install -m 0644 "$SRC/ladon.service"     /etc/systemd/system/ladon.service
	[ -f "$LADON_CONFIG_DIR/manual-allow.txt" ] || \
		install -m 0644 "$SRC/manual-allow.txt.example" "$LADON_CONFIG_DIR/manual-allow.txt"
	[ -f "$LADON_CONFIG_DIR/manual-deny.txt" ] || \
		install -m 0644 "$SRC/manual-deny.txt.example"  "$LADON_CONFIG_DIR/manual-deny.txt"
	[ -f "$LADON_CONFIG_DIR/config.yaml" ] || \
		install -m 0644 "$SRC/config.yaml.example"      "$LADON_CONFIG_DIR/config.yaml"
	install -m 0644 "$SRC/extensions/"*.txt  "$LADON_PREFIX/extensions/"

	# --- ipsets (idempotent) ---
	log "creating ipsets ($IPSET_ENGINE, $IPSET_MANUAL, $IPSET_CIDR)"
	ipset list "$IPSET_ENGINE" -t >/dev/null 2>&1 || \
		ipset create "$IPSET_ENGINE" hash:ip family inet maxelem 65536
	ipset list "$IPSET_MANUAL" -t >/dev/null 2>&1 || \
		ipset create "$IPSET_MANUAL" hash:ip family inet maxelem 65536 timeout 86400
	ipset list "$IPSET_CIDR" -t >/dev/null 2>&1 || \
		ipset create "$IPSET_CIDR" hash:net family inet maxelem 65536

	# Persist ipsets across reboot via iptables-persistent's `ipsets` file.
	mkdir -p /etc/iptables
	ipset save > /etc/iptables/ipsets

	# --- dnsmasq CAP_NET_ADMIN drop-in ---
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

	# --- wire -config into the unit (idempotent) ---
	if ! grep -q -- '-config' /etc/systemd/system/ladon.service; then
		log "wiring -config $LADON_CONFIG_DIR/config.yaml into ladon.service"
		sed -i "s|^  -db ${LADON_PREFIX}/state/engine.db|  -db ${LADON_PREFIX}/state/engine.db -config ${LADON_CONFIG_DIR}/config.yaml|" \
			/etc/systemd/system/ladon.service
	fi

	# --- init db, reload, start ---
	log "initializing database"
	"$LADON_PREFIX/ladon" -db "$LADON_PREFIX/state/engine.db" init-db >/dev/null
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

	cat <<EOF

${GREEN}==> ladon $TAG installed (Debian/Ubuntu)${NC}

What's running:
  service:  systemctl status ladon
  logs:     journalctl -u ladon -f
  config:   $LADON_CONFIG_DIR/config.yaml
  ipsets:   $IPSET_ENGINE (probe-driven), $IPSET_MANUAL (dnsmasq-driven),
            $IPSET_CIDR (extension CIDR blocks, hash:net)

${YELLOW}==> ROUTING IS YOUR JOB${NC}

ladon only fills the ipsets — wiring traffic from peers through your
tunnel when the destination IP matches one of those sets is up to you.
A typical WireGuard split-tunnel setup (adjust subnet/fwmark/iface):

  iptables -t mangle -A WG_ROUTE -s 10.10.0.0/16 \\
    -m set --match-set $IPSET_ENGINE dst -j MARK --set-mark 0x1
  iptables -t mangle -A WG_ROUTE -s 10.10.0.0/16 \\
    -m set --match-set $IPSET_MANUAL dst -j MARK --set-mark 0x1
  iptables -t mangle -A WG_ROUTE -s 10.10.0.0/16 \\
    -m set --match-set $IPSET_CIDR dst -j MARK --set-mark 0x1

  ip rule add fwmark 0x1 table ladon priority 1000
  echo '666 ladon' >> /etc/iproute2/rt_tables
  ip route replace default dev tun0 table ladon

  iptables-save > /etc/iptables/rules.v4   # persist across reboot

Next steps:
  1. Wire the iptables / ip rule above for your routing setup.
  2. Edit $LADON_CONFIG_DIR/manual-allow.txt / manual-deny.txt and restart.
  3. Or enable bundled allow presets in $LADON_CONFIG_DIR/config.yaml:
       allow_extensions: [ai, twitch, tiktok]
     Catalogue: https://github.com/belotserkovtsev/ladon/blob/main/docs/extensions.md

To uninstall: re-run uninstall.sh from the same release.
EOF
}

# ============================================================
# OpenWRT path
# ============================================================
install_openwrt() {
	command -v opkg >/dev/null || die "opkg required (you're not on OpenWRT?)"
	command -v uci  >/dev/null || die "uci required"

	# OpenWRT layout: binary under /usr/bin, ephemeral state under /var/lib
	# (writable on overlayfs), config under /etc, bundled assets under /usr/share.
	PREFIX_BIN=/usr/bin
	PREFIX_SHARE=/usr/share/ladon
	CONFIG_DIR=/etc/ladon
	STATE_DIR=/var/lib/ladon/state
	INITD=/etc/init.d/ladon

	# --- detect arch via opkg print-architecture ---
	# opkg lists supported archs with priority (arch all 1, arch noarch 1,
	# arch arm_cortex-a7_neon-vfpv4 10). Pick the highest-priority entry and
	# map to our tarball naming scheme.
	opkg_arch=$(opkg print-architecture 2>/dev/null \
		| awk '$1 == "arch" { print $3, $2 }' \
		| sort -rn \
		| awk 'NR == 1 { print $2 }')
	[ -n "$opkg_arch" ] || die "couldn't read architecture from opkg print-architecture"
	case "$opkg_arch" in
		aarch64_*|arm64*)                          TARBALL_ARCH=aarch64 ;;
		arm_cortex-a*|arm_*_neon*|arm_*_vfp*|armv7*) TARBALL_ARCH=armv7  ;;
		x86_64)                                    TARBALL_ARCH=x86_64  ;;
		mipsel_*|mips_*|mips64_*)
			die "MIPS not supported in v1.4.0 (modernc.org/libc has no linux/mipsle build files) — see docs/install-openwrt.md" ;;
		*) die "unsupported OpenWRT architecture: $opkg_arch" ;;
	esac
	log "OpenWRT arch: $opkg_arch → tarball: ladon-openwrt-$TARBALL_ARCH.tar.gz"

	# --- dnsmasq-full check & swap-with-confirm ---
	# Stock 'dnsmasq' is built without ipset support; only 'dnsmasq-full' has
	# the ipset= directive ladon relies on. If plain dnsmasq is installed, we
	# swap — but DNS goes dark for a few seconds, so give the operator a
	# window to abort.
	if opkg list-installed 2>/dev/null | awk '{ print $1 }' | grep -qx 'dnsmasq-full'; then
		log "dnsmasq-full already installed"
	elif ! opkg list-installed 2>/dev/null | awk '{ print $1 }' | grep -qx 'dnsmasq'; then
		log "no dnsmasq package present — installing dnsmasq-full"
		opkg update >/dev/null
		opkg install dnsmasq-full
	else
		cat <<EOF

${YELLOW}====================================================================${NC}
${YELLOW}  WARNING — about to swap dnsmasq for dnsmasq-full${NC}
${YELLOW}====================================================================${NC}

ladon needs dnsmasq's ipset= directive support, which lives only in
dnsmasq-full. The plain 'dnsmasq' currently installed will be replaced.

Effects:
  * DNS resolution will be briefly unavailable (~5s) on this router
    while opkg removes the old package and installs the new one.
  * Existing /etc/config/dhcp UCI config is preserved by the swap.
  * dnsmasq-full pulls in extra deps (DNSSEC, ipset, conntrack support).
    Expect ~200KB more flash usage.

EOF
		if [ "$ASSUME_YES" = "1" ]; then
			log "ASSUME_YES=1 — skipping countdown"
		else
			printf "Press Ctrl-C in the next 10 seconds to abort, or wait to continue.\n\n"
			i=10
			while [ "$i" -gt 0 ]; do
				printf "\r  continuing in %2d seconds (Ctrl-C to abort)... " "$i"
				sleep 1
				i=$((i - 1))
			done
			printf "\r%-60s\n" " "
		fi
		log "removing dnsmasq, installing dnsmasq-full"
		opkg update >/dev/null
		opkg remove dnsmasq --force-removal-of-dependent-packages
		opkg install dnsmasq-full
		/etc/init.d/dnsmasq restart || warn "dnsmasq restart returned non-zero — check logread"
	fi

	log "installing runtime deps (ipset, ca-bundles, wget-ssl)"
	opkg update >/dev/null
	opkg install ipset ca-bundles wget-ssl >/dev/null

	# --- fetch release tag ---
	if [ -z "$TAG" ]; then
		log "querying latest stable release"
		TAG=$(wget -qO- "https://api.github.com/repos/${GH_REPO}/releases/latest" \
			| jsonfilter -e '@.tag_name' 2>/dev/null || true)
		[ -n "$TAG" ] || die "couldn't determine latest tag from GitHub API"
		log "latest version: $TAG"
	else
		log "using TAG override: $TAG"
	fi

	WORKDIR=$(mktemp -d)
	trap 'rm -rf "$WORKDIR"' EXIT
	cd "$WORKDIR"

	URL="https://github.com/${GH_REPO}/releases/download/${TAG}/ladon-openwrt-${TARBALL_ARCH}.tar.gz"
	log "downloading ${URL##*/}"
	wget -q "$URL" "${URL}.sha256"
	log "verifying sha256"
	sha256sum -c "ladon-openwrt-${TARBALL_ARCH}.tar.gz.sha256"
	tar xzf "ladon-openwrt-${TARBALL_ARCH}.tar.gz"
	SRC="ladon-openwrt-${TARBALL_ARCH}-${TAG}"

	# --- install files ---
	log "installing files"
	mkdir -p "$PREFIX_SHARE/extensions" "$STATE_DIR" "$CONFIG_DIR"
	install -m 0755 "$SRC/ladon"              "$PREFIX_BIN/ladon"
	install -m 0755 "$SRC/ladon.init"         "$INITD"
	[ -f "$CONFIG_DIR/manual-allow.txt" ] || \
		install -m 0644 "$SRC/manual-allow.txt.example" "$CONFIG_DIR/manual-allow.txt"
	[ -f "$CONFIG_DIR/manual-deny.txt" ] || \
		install -m 0644 "$SRC/manual-deny.txt.example" "$CONFIG_DIR/manual-deny.txt"
	[ -f "$CONFIG_DIR/config.yaml" ] || \
		install -m 0644 "$SRC/config.yaml.openwrt.example" "$CONFIG_DIR/config.yaml"
	for ext in "$SRC/extensions/"*.txt; do
		[ -f "$ext" ] && install -m 0644 "$ext" "$PREFIX_SHARE/extensions/"
	done

	# --- UCI patch — dnsmasq query logging, with rollback backup ---
	BACKUP="$CONFIG_DIR/.uci-backup"
	{
		echo "# ladon UCI backup — generated $(date -u +%Y-%m-%dT%H:%M:%SZ)"
		echo "# format: KEY=VALUE  ('__unset' means the field was not set)"
		for key in logqueries logfacility; do
			val=$(uci -q get "dhcp.@dnsmasq[0].$key" 2>/dev/null || true)
			[ -n "$val" ] || val="__unset"
			echo "$key=$val"
		done
	} > "$BACKUP"
	chmod 0600 "$BACKUP"

	log "enabling dnsmasq query logging (UCI: dhcp.@dnsmasq[0])"
	uci set dhcp.@dnsmasq[0].logqueries='1'
	existing_logfacility=$(uci -q get dhcp.@dnsmasq[0].logfacility 2>/dev/null || true)
	if [ -z "$existing_logfacility" ]; then
		uci set dhcp.@dnsmasq[0].logfacility='/var/log/dnsmasq.log'
	elif [ "$existing_logfacility" != "/var/log/dnsmasq.log" ]; then
		warn "logfacility already set to '$existing_logfacility' — keeping it"
		warn "you'll need to edit $CONFIG_DIR/config.yaml so ladon tails the right file"
	fi
	uci commit dhcp
	/etc/init.d/dnsmasq reload

	# --- init db + enable + start ---
	log "initializing database"
	"$PREFIX_BIN/ladon" -db "$STATE_DIR/engine.db" init-db >/dev/null
	log "enabling and starting ladon"
	"$INITD" enable
	"$INITD" restart

	sleep 2
	if ! pgrep -f '^/usr/bin/ladon' >/dev/null 2>&1; then
		warn "ladon doesn't appear to be running — check: logread -e ladon"
	fi

	cat <<EOF

${GREEN}==> ladon $TAG installed (OpenWRT beta)${NC}

What's running:
  status:   /etc/init.d/ladon status; pgrep -af ladon
  logs:     logread -f -e ladon
  config:   $CONFIG_DIR/config.yaml
  ipsets:   $IPSET_ENGINE (probe-driven), $IPSET_MANUAL (dnsmasq-driven),
            $IPSET_CIDR (extension CIDR blocks, hash:net)

${YELLOW}==> ROUTING IS YOUR JOB${NC}

ladon only fills the ipsets — wiring traffic from clients through your
tunnel when the destination IP matches one of those sets is up to you.
A minimal firewall4 (nftables) wiring example, assuming WireGuard 'wg0'
and clients on br-lan:

  # /etc/nftables.d/30-ladon.nft  (loaded automatically by firewall4)
  table inet ladon {
    chain mangle_prerouting {
      type filter hook prerouting priority mangle; policy accept;
      iifname "br-lan" ip daddr @ladon_engine meta mark set 0x1
      iifname "br-lan" ip daddr @ladon_manual meta mark set 0x1
      iifname "br-lan" ip daddr @ladon_cidr   meta mark set 0x1
    }
  }

  ip rule add fwmark 0x1 table 100 priority 1000
  echo '100 ladon' >> /etc/iproute2/rt_tables
  ip route replace default dev wg0 table 100

(Adjust iifname/interface/mark/table to your setup. Legacy ipsets are
visible to nftables on OpenWRT 22.03+ via the kernel shim.)

Next steps:
  1. Wire routing as above (or whatever your VPN setup needs).
  2. Edit $CONFIG_DIR/manual-allow.txt / manual-deny.txt and restart:
     /etc/init.d/ladon restart
  3. Or enable bundled allow presets in $CONFIG_DIR/config.yaml:
       allow_extensions: [ai, twitch, tiktok]
     Catalogue: https://github.com/belotserkovtsev/ladon/blob/main/docs/extensions.md

To uninstall: re-run uninstall.sh from the same release. UCI rollback is
automatic via $BACKUP.
EOF
}

# --- dispatch ---
case "$OS" in
	debian)  install_debian ;;
	openwrt) install_openwrt ;;
esac
