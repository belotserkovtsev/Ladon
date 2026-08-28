#!/bin/sh
# Is ladon itself healthy — the answer docker's healthcheck wants.
#
# `doctor` exits 0 when everything is fine, 1 when it has remarks, and 2 when a
# stage is actually broken. Docker treats anything non-zero as unhealthy, so
# used directly it would condemn a container over a remark — something worth
# reading, not worth restarting for. Only a 2 fails here.
#
# The config flag is passed only when there is a file to pass, for the same
# reason the entrypoint does it: doctor stops on a named config that is not
# there, and by exit code that stop is indistinguishable from a remark. Passing
# it blindly would report a container as healthy on the strength of a check that
# never ran, which is worse than no check at all.
#
# Judges ladon and nothing under it: the tunnel and the exit node are not its to
# vouch for, so an unhealthy answer here means ladon.

set -u

BIN=/opt/ladon/ladon
DB=/opt/ladon/state/engine.db
CONFIG=/etc/ladon/config.yaml

set --
[ -f "$CONFIG" ] && set -- -config "$CONFIG"

"$BIN" -db "$DB" "$@" doctor -json >/dev/null
rc=$?

[ "$rc" -lt 2 ]
