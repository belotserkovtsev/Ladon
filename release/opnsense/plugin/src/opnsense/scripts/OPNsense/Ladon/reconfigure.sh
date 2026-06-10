#!/bin/sh
# Regenerate config + enable flag + Unbound dynlib include, (un)load the hook, sync the daemon.
#
# DNS-safety invariant: never restart unbound while its dynlib include points at a
# /ladon_unbound.so that isn't in the chroot — that takes DNS down box-wide. So the
# include is kept only after the .so is built+staged; a failed build strips it (DNS
# keeps resolving, just unobserved) and exits non-zero so the Apply shows the error.

DYNLIB_INC=/usr/local/etc/unbound.opnsense.d/ladon-dynlib.conf
CHROOT_SO=/var/unbound/ladon_unbound.so
BUILD_LOG=/var/log/ladon/dynlib-build.log

mkdir -p /usr/local/etc/ladon /var/db/ladon /var/log/ladon /var/unbound/var/run

configctl template reload OPNsense/Ladon

build_failed=0
if grep -q 'ladon_enable="YES"' /etc/rc.conf.d/ladon 2>/dev/null; then
    # Build the Unbound dynlib against the running unbound (idempotent — only the
    # first enable compiles; later runs skip via the version stamp). The .so is
    # ABI-bound to the unbound version, so we build on the box, not ship one.
    #
    # Stage it into the chroot ATOMICALLY: copy to a temp path, chown, then mv —
    # a same-fs rename is atomic, so a concurrent unbound restart never sees a
    # half-written /ladon_unbound.so. The copy runs every reconfigure (keyed off
    # the lib copy, not "did a build run"), so a chroot .so deleted out from under
    # us is restored. Any failure of build OR staging falls to the strip path.
    if sh /usr/local/opnsense/scripts/OPNsense/Ladon/build_unbound_module.sh >"$BUILD_LOG" 2>&1 \
       && [ -f /usr/local/lib/ladon_unbound.so ] \
       && cp /usr/local/lib/ladon_unbound.so "$CHROOT_SO.new" \
       && chown unbound:unbound "$CHROOT_SO.new" \
       && mv -f "$CHROOT_SO.new" "$CHROOT_SO"; then
        :
    else
        # Build/stage failed: drop the include the template just rendered (and any
        # stale/partial .so) so the unbound restart below stays clean and DNS keeps
        # resolving — degraded (no observation) beats no DNS.
        build_failed=1
        rm -f "$DYNLIB_INC" "$CHROOT_SO" "$CHROOT_SO.new"
    fi
    # Declare the pf tables as External firewall aliases (idempotent, create-if-missing).
    /usr/local/bin/php /usr/local/opnsense/scripts/OPNsense/Ladon/ensure_aliases.php
else
    # Disabled: the template renders an empty include; drop the staged .so too so
    # nothing dangles in the chroot.
    rm -f "$CHROOT_SO"
fi

configctl unbound restart

if grep -q 'ladon_enable="YES"' /etc/rc.conf.d/ladon 2>/dev/null; then
    /usr/local/etc/rc.d/ladon restart
else
    /usr/local/etc/rc.d/ladon stop
fi

if [ "$build_failed" = 1 ]; then
    echo "Unbound-модуль ladon (.so) не собрался — DNS-наблюдение выключено, маршрутизация работать не будет." >&2
    echo "Лог сборки: $BUILD_LOG (нужен выход в интернет к nlnetlabs.nl и базовый cc)." >&2
    exit 1
fi
exit 0
