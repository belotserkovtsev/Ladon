#!/bin/sh
# Routing for a single machine — ladon splitting this host's own traffic.
#
# The gateway recipe in docs/install.md marks packets in mangle PREROUTING,
# which only ever sees traffic being forwarded on behalf of someone else. A
# machine's own connections leave through OUTPUT and never pass that chain, so
# on a desktop none of it applies.
#
# TPROXY is also out: it works in PREROUTING only. What replaces it here is a
# REDIRECT in nat OUTPUT to a local port where the tunnel client listens in
# "redirect" mode.
#
#   ./setup-routing.sh up     [PORT]   default 12345
#   ./setup-routing.sh down   [PORT]
#   ./setup-routing.sh status
#
# The sets have to exist first; ladon fills them but never creates them:
#   ipset create ladon_engine hash:ip  family inet -exist
#   ipset create ladon_manual hash:ip  family inet -exist
#   ipset create ladon_cidr   hash:net family inet -exist
#
# Two limits worth knowing before you rely on this:
#
#   TCP only. REDIRECT has nothing to offer UDP here, so QUIC (HTTP/3) is left
#   to leave directly — and a browser that reaches a listed site over QUIC gets
#   the blocked path, not the tunnel. Browsers do fall back to TCP, but not
#   always quickly. Turn QUIC off in the client, or block UDP/443 to listed
#   destinations so the fallback happens at once.
#
#   The tunnel client needs its own user. Its connection to its own server is
#   to a public address like any other, so without an exception it matches the
#   sets and gets redirected into itself. LADON_TUNNEL_USER names that user:
#
#     LADON_TUNNEL_USER=sing-box ./setup-routing.sh up
#
#   Running the client as root leaves nothing to distinguish it by — give it a
#   dedicated user instead.

set -eu

CHAIN=LADON_OUT
PORT="${2:-12345}"
LADON_TUNNEL_USER="${LADON_TUNNEL_USER:-xray}"

need() {
    command -v "$1" >/dev/null 2>&1 || { echo "missing: $1" >&2; exit 1; }
}

up() {
    need iptables
    need ipset

    for s in ladon_engine ladon_manual ladon_cidr; do
        ipset list -n "$s" >/dev/null 2>&1 || {
            echo "set $s does not exist — create it first (see the header of this script)" >&2
            exit 1
        }
    done

    iptables -t nat -N "$CHAIN" 2>/dev/null || iptables -t nat -F "$CHAIN"

    # Anything that isn't a public destination has no business in the tunnel,
    # and sending the tunnel's own packets into it would loop.
    for net in 0.0.0.0/8 10.0.0.0/8 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 \
               192.168.0.0/16 224.0.0.0/4 240.0.0.0/4; do
        iptables -t nat -A "$CHAIN" -d "$net" -j RETURN
    done

    # The tunnel client runs as its own user; without this its outbound
    # connection would match the sets and be redirected back into itself.
    if id -u "$LADON_TUNNEL_USER" >/dev/null 2>&1; then
        iptables -t nat -A "$CHAIN" -m owner --uid-owner "$LADON_TUNNEL_USER" -j RETURN
    else
        echo "warning: no user '$LADON_TUNNEL_USER' — the tunnel's own traffic is NOT excluded" >&2
        echo "         set LADON_TUNNEL_USER to the user your client runs as, or it will loop" >&2
    fi

    for s in ladon_engine ladon_manual ladon_cidr; do
        iptables -t nat -A "$CHAIN" -p tcp -m set --match-set "$s" dst \
            -j REDIRECT --to-ports "$PORT"
    done

    iptables -t nat -C OUTPUT -p tcp -j "$CHAIN" 2>/dev/null \
        || iptables -t nat -A OUTPUT -p tcp -j "$CHAIN"

    echo "up: OUTPUT -> $CHAIN -> REDIRECT :$PORT"
}

down() {
    iptables -t nat -D OUTPUT -p tcp -j "$CHAIN" 2>/dev/null || true
    iptables -t nat -F "$CHAIN" 2>/dev/null || true
    iptables -t nat -X "$CHAIN" 2>/dev/null || true
    echo "down: rules removed"
}

status() {
    echo "--- nat OUTPUT ---"
    iptables -t nat -S OUTPUT 2>/dev/null | grep -- "$CHAIN" || echo "  (not hooked up)"
    echo "--- $CHAIN ---"
    iptables -t nat -S "$CHAIN" 2>/dev/null || echo "  (chain absent)"
    echo "--- sets ---"
    for s in ladon_engine ladon_manual ladon_cidr; do
        n=$(ipset list "$s" 2>/dev/null | sed -n '/Members/,$p' | tail -n +2 | grep -c .) || n=0
        printf '  %-14s %s members\n' "$s" "$n"
    done
}

case "${1:-}" in
    up)     up ;;
    down)   down ;;
    status) status ;;
    *)      echo "usage: $0 {up|down|status} [port]" >&2; exit 2 ;;
esac
