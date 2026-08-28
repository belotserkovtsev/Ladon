#!/bin/sh
# Ladon in a container, keeping the split inside its own network namespace.
#
# Sets are per-namespace: a container that only programs them has to borrow the
# host's, which is no isolation at all. This one carries the resolver and
# forwards the traffic instead, so the namespace it decides in is the one the
# packets actually cross.
#
# Given arguments, it runs the CLI instead and exits — `docker exec ladon doctor`
# and friends work exactly as they do on a host install.
#
#   LADON_LISTEN        address clients reach us on   (default: the container's own)
#   LADON_UPSTREAM_DNS  where the resolver forwards   (default 1.1.1.1)
#   LADON_EGRESS_GW     next hop for split traffic    (unset: leave the normal way)
#
# Point LADON_EGRESS_GW at a router that already has a tunnel and this container
# never needs one of its own: it decides, the router carries.

set -eu

BIN=/opt/ladon/ladon
CONFIG=/etc/ladon/config.yaml
SNIPPET=/etc/dnsmasq.d/ladon-manual.conf
LOG=/var/log/dnsmasq.log

log() { echo "[ladon] $*"; }

# Operator commands: doctor, status, why, version, prune…
if [ "$#" -gt 0 ]; then
    exec "$BIN" "$@"
fi

LADON_LISTEN="${LADON_LISTEN:-$(ip -4 -o addr show scope global | awk 'NR==1{sub(/\/.*/,"",$4); print $4}')}"
LADON_UPSTREAM_DNS="${LADON_UPSTREAM_DNS:-1.1.1.1}"
LADON_EGRESS_GW="${LADON_EGRESS_GW:-}"

# Autodetection takes the first global address there is. With none it would
# leave a trailing comma in listen-address and dnsmasq would fail on a line the
# operator never wrote; with several it would pick by whatever order the kernel
# lists them. Both are worth saying out loud rather than discovering later.
if [ -z "$LADON_LISTEN" ]; then
    log "no global IPv4 address in this namespace — set LADON_LISTEN to the one clients reach"
    exit 1
fi
if [ "$(ip -4 -o addr show scope global | wc -l)" -gt 1 ]; then
    log "several addresses here, using $LADON_LISTEN — set LADON_LISTEN to choose"
fi

# /proc/sys is read-only in here, so forwarding is the caller's to grant:
#   docker run --sysctl net.ipv4.ip_forward=1
# Check rather than set, and say so plainly if it is missing — without it this
# container accepts traffic and quietly drops it.
if [ "$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo 0)" != "1" ]; then
    log "ip_forward is off — start with --sysctl net.ipv4.ip_forward=1"
    exit 1
fi

# --- sets: ours alone, nothing outside can see or collide with them ------
for s in ladon_engine ladon_manual; do ipset create "$s" hash:ip family inet -exist; done
ipset create ladon_cidr hash:net family inet -exist
log "sets ready in this namespace"

# --- resolver -----------------------------------------------------------
mkdir -p /etc/dnsmasq.d
: > "$LOG"
cat > /etc/dnsmasq.conf <<CONF
listen-address=127.0.0.1,${LADON_LISTEN}
bind-interfaces
no-resolv
server=${LADON_UPSTREAM_DNS}
log-queries=extra
log-facility=${LOG}
conf-dir=/etc/dnsmasq.d,*.conf
CONF

# --- routing ------------------------------------------------------------
iptables -t nat -C POSTROUTING -j MASQUERADE 2>/dev/null \
    || iptables -t nat -A POSTROUTING -j MASQUERADE

if [ -n "$LADON_EGRESS_GW" ]; then
    # Split traffic leaves by a different door than everything else: mark what
    # the sets match, and let a routing rule send just those packets on.
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
    ip route replace default via "$LADON_EGRESS_GW" table 100
    log "split traffic leaves via $LADON_EGRESS_GW"
else
    log "LADON_EGRESS_GW unset — split traffic leaves the normal way"
fi

# --- engine, then resolver ---------------------------------------------
# Order matters and it buys something: ladon writes dnsmasq's snippet on start,
# and dnsmasq is started afterwards, so it comes up already knowing the manual
# domains. Nothing to restart, and the address lands in the set while the answer
# is being written — the one thing an engine-filled set gives up.
log "starting engine"
# The engine refuses to start on a -config naming a file that is not there, and
# it is right to: a config someone asked for and that is missing is a mistake
# worth stopping on. Here, though, the path is the image's own default, and an
# empty /etc/ladon is the ordinary state of a machine nobody has configured yet
# — the defaults are already a working router. So the flag is passed only when
# there is something to pass, and otherwise this says so and carries on.
if [ -f "$CONFIG" ]; then
    set -- -config "$CONFIG"
else
    log "no $CONFIG — running on defaults"
    set --
fi
"$BIN" "$@" run "$LOG" &
ENGINE=$!

i=0
while [ ! -s "$SNIPPET" ] && [ $i -lt 50 ]; do sleep 0.2; i=$((i + 1)); done
[ -s "$SNIPPET" ] && log "manual list ready ($(grep -c '^ipset=' "$SNIPPET") domains)" \
                  || log "no manual list — continuing without one"

log "starting resolver on ${LADON_LISTEN}:53"
dnsmasq --keep-in-foreground &
RESOLVER=$!

# Either one dying is fatal: half of this is not a working router, and a
# container that runs on while it cannot resolve or cannot classify is worse
# than one that restarts. Polled rather than `wait -n`, which busybox lacks.
STOPPING=0
trap 'STOPPING=1; kill $ENGINE $RESOLVER 2>/dev/null' TERM INT
while kill -0 $ENGINE 2>/dev/null && kill -0 $RESOLVER 2>/dev/null; do
    sleep 2
done

# A `docker stop` is not a crash, and reporting it as one makes every ordinary
# restart look like an incident in whatever watches the exit codes.
if [ "$STOPPING" = 1 ]; then
    log "stopping"
    kill $ENGINE $RESOLVER 2>/dev/null || true
    exit 0
fi

kill -0 $ENGINE 2>/dev/null || log "engine exited"
kill -0 $RESOLVER 2>/dev/null || log "resolver exited"
kill $ENGINE $RESOLVER 2>/dev/null || true
exit 1
