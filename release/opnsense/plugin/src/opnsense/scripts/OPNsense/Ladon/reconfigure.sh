#!/bin/sh
# Regenerate config + enable flag + Unbound dynlib include, (un)load the hook, sync the daemon.

# Template targets land in these dirs; make sure they exist before rendering.
mkdir -p /usr/local/etc/ladon /var/db/ladon /var/log/ladon /var/unbound/var/run

configctl template reload OPNsense/Ladon

# Unbound is chrooted in /var/unbound and dlopen's dynlib-file from there, so
# the .so must live inside the chroot (referenced as /ladon_unbound.so).
if grep -q 'ladon_enable="YES"' /etc/rc.conf.d/ladon 2>/dev/null; then
    # Build the Unbound dynlib against the running unbound (idempotent — only the
    # first enable actually compiles; later runs skip via the version stamp). The
    # .so is ABI-bound to the unbound version, so we build on the box, not ship one.
    sh /usr/local/opnsense/scripts/OPNsense/Ladon/build_unbound_module.sh || true
    if [ -f /usr/local/lib/ladon_unbound.so ]; then
        cp /usr/local/lib/ladon_unbound.so /var/unbound/ladon_unbound.so
        chown unbound:unbound /var/unbound/ladon_unbound.so
    fi
    # Declare the pf tables as External firewall aliases (idempotent, create-if-missing).
    /usr/local/bin/php /usr/local/opnsense/scripts/OPNsense/Ladon/ensure_aliases.php
fi

configctl unbound restart

if grep -q 'ladon_enable="YES"' /etc/rc.conf.d/ladon 2>/dev/null; then
    /usr/local/etc/rc.d/ladon restart
else
    /usr/local/etc/rc.d/ladon stop
fi

exit 0
