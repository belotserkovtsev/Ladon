#!/bin/sh
# Ladon as a router in its own network namespace.
#
# Everything the split needs lives in here: the resolver, the sets, the rules
# that act on them. The container carries the traffic instead of reaching into
# the host's namespace, which is what lets it keep a namespace of its own —
# sets are per-namespace, so the decision and the enforcement have to share one.
#
# What the host does is send traffic in. Where the split traffic goes out is
# EGRESS_GW: point it at a router that already has a tunnel and this container
# never needs one of its own.
#
#   LADON_ADDR   address clients reach us on      (default: the container's own)
#   EGRESS_GW    next hop for split traffic       (unset: leave by the default route)
#   UPSTREAM_DNS resolver dnsmasq forwards to     (default 1.1.1.1)

set -eu

LADON_ADDR="${LADON_ADDR:-$(ip -4 -o addr show scope global | awk 'NR==1{sub(/\/.*/,"",$4); print $4}')}"
UPSTREAM_DNS="${UPSTREAM_DNS:-1.1.1.1}"
EGRESS_GW="${EGRESS_GW:-}"
SNIPPET=/etc/dnsmasq.d/ladon-manual.conf
LOG=/var/log/dnsmasq.log

log() { echo "[entrypoint] $*"; }

# --- sets ---------------------------------------------------------------
# Ours alone: nothing outside this namespace can see or collide with them.
for s in ladon_engine ladon_manual; do ipset create "$s" hash:ip family inet -exist; done
ipset create ladon_cidr hash:net family inet -exist
log "sets ready in this namespace"

# --- resolver -----------------------------------------------------------
mkdir -p /etc/dnsmasq.d
: > "$LOG"
cat > /etc/dnsmasq.conf <<CONF
listen-address=127.0.0.1,${LADON_ADDR}
bind-interfaces
no-resolv
server=${UPSTREAM_DNS}
log-queries=extra
log-facility=${LOG}
conf-dir=/etc/dnsmasq.d,*.conf
CONF

# --- routing ------------------------------------------------------------
# /proc/sys is read-only in here, so forwarding is the caller's to grant:
#   docker run --sysctl net.ipv4.ip_forward=1
# Check rather than set, and say so plainly if it is missing — without it this
# container accepts traffic and quietly drops it.
if [ "$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo 0)" != "1" ]; then
    log "ERROR: ip_forward is off — start with --sysctl net.ipv4.ip_forward=1"
    exit 1
fi

iptables -t nat -C POSTROUTING -j MASQUERADE 2>/dev/null \
    || iptables -t nat -A POSTROUTING -j MASQUERADE

if [ -n "$EGRESS_GW" ]; then
    # Split traffic leaves by a different door than everything else: mark what
    # the sets match, and let a routing rule send just those packets to the
    # router that carries the tunnel.
    iptables -t mangle -N LADON_MARK 2>/dev/null || iptables -t mangle -F LADON_MARK
    for net in 10.0.0.0/8 127.0.0.0/8 172.16.0.0/12 192.168.0.0/16 224.0.0.0/4; do
        iptables -t mangle -A LADON_MARK -d "$net" -j RETURN
    done
    for s in ladon_engine ladon_manual ladon_cidr; do
        iptables -t mangle -A LADON_MARK -m set --match-set "$s" dst -j MARK --set-mark 0x1
    done
    iptables -t mangle -C PREROUTING -j LADON_MARK 2>/dev/null \
        || iptables -t mangle -A PREROUTING -j LADON_MARK

    ip rule show | grep -q "fwmark 0x1" || ip rule add fwmark 0x1 table 100 priority 100
    ip route replace default via "$EGRESS_GW" table 100
    log "split traffic leaves via $EGRESS_GW"
else
    log "no EGRESS_GW set — split traffic leaves the normal way (plumbing test only)"
fi

# --- engine, then resolver ---------------------------------------------
# Order matters and it buys something: ladon writes dnsmasq's snippet on start,
# and dnsmasq is started afterwards, so it comes up already knowing the manual
# domains. No restart to arrange, and the address lands in the set while the
# answer is being written — the one thing the engine-owned path gives up.
log "starting engine"
/opt/ladon/ladon -config /etc/ladon/config.yaml run "$LOG" &
ENGINE=$!

i=0
while [ ! -s "$SNIPPET" ] && [ $i -lt 50 ]; do sleep 0.2; i=$((i + 1)); done
[ -s "$SNIPPET" ] && log "manual snippet ready ($(grep -c '^ipset=' "$SNIPPET") domains)" \
                  || log "no manual snippet — continuing without one"

log "starting resolver on ${LADON_ADDR}:53"
dnsmasq --keep-in-foreground &
RESOLVER=$!

# Either one dying is fatal: half of this is not a working router, and a
# container that keeps running while it cannot resolve or cannot classify is
# worse than one that restarts. Polled rather than `wait -n`, which busybox's
# shell does not have.
trap 'kill $ENGINE $RESOLVER 2>/dev/null' TERM INT
while kill -0 $ENGINE 2>/dev/null && kill -0 $RESOLVER 2>/dev/null; do
    sleep 2
done
kill -0 $ENGINE 2>/dev/null || log "engine exited"
kill -0 $RESOLVER 2>/dev/null || log "resolver exited"
kill $ENGINE $RESOLVER 2>/dev/null || true
exit 1
