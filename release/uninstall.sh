#!/bin/sh
# ladon uninstaller — POSIX sh, undoes install.sh on Linux and FreeBSD/OPNsense.
#
# Routing rules (iptables / ip rule / pf route-to) are NOT touched — install.sh
# didn't add them. Firewall aliases still referenced by an operator rule are
# kept (removing them would break that rule); the script reports which.
#
# Plain run keeps operator state (config node + engine.db) so a reinstall
# resumes. Pass --purge to also wipe settings + DB + logs.
#
# Usage:
#   curl -fsSL …/uninstall.sh | sudo sh
#   fetch -o - …/uninstall.sh | sh   # FreeBSD
#   sh uninstall.sh [--purge]

set -eu

PURGE=0
for a in "$@"; do case "$a" in --purge) PURGE=1 ;; esac; done

IPSET_ENGINE="${IPSET_ENGINE:-ladon_engine}"
IPSET_MANUAL="${IPSET_MANUAL:-ladon_manual}"
IPSET_CIDR="${IPSET_CIDR:-ladon_cidr}"
LADON_PREFIX="${LADON_PREFIX:-/opt/ladon}"
LADON_CONFIG_DIR="${LADON_CONFIG_DIR:-/etc/ladon}"

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  GREEN=$(printf '\033[32m'); YELLOW=$(printf '\033[33m'); RED=$(printf '\033[31m'); NC=$(printf '\033[0m')
else GREEN=; YELLOW=; RED=; NC=; fi
log()  { printf '%s==>%s %s\n' "$GREEN" "$NC" "$*"; }
warn() { printf '%s==>%s %s\n' "$YELLOW" "$NC" "$*"; }
die()  { printf '%s==>%s %s\n' "$RED" "$NC" "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "must run as root (sudo)"

# ============================================================
#  LINUX
# ============================================================
uninstall_linux() {
  log "stopping ladon"
  systemctl disable --now ladon 2>/dev/null || true
  rm -f /etc/systemd/system/ladon.service

  log "removing dnsmasq drop-in"
  rm -f /etc/systemd/system/dnsmasq.service.d/ladon-ipset.conf
  rmdir /etc/systemd/system/dnsmasq.service.d 2>/dev/null || true

  log "destroying ipsets (skips any still referenced by iptables)"
  for s in "$IPSET_ENGINE" "$IPSET_MANUAL" "$IPSET_CIDR"; do
    ipset destroy "$s" 2>/dev/null || warn "$s still in use; remove iptables rules referencing it first"
  done
  mkdir -p /etc/iptables && ipset save > /etc/iptables/ipsets 2>/dev/null || true

  log "removing files"
  rm -f /etc/dnsmasq.d/ladon-manual.conf /usr/local/bin/ladon
  rm -rf "$LADON_PREFIX"
  if [ "$PURGE" = 1 ]; then rm -rf "$LADON_CONFIG_DIR"; log "purged config + state"; else log "kept $LADON_CONFIG_DIR (--purge to remove)"; fi

  systemctl daemon-reload
  systemctl restart dnsmasq 2>/dev/null || true
  log "ladon uninstalled (Linux)"
  warn "NOT removed: your iptables/ip-rule routing; the dnsmasq/ipset packages"
}

# ============================================================
#  FREEBSD / OPNsense
# ============================================================
is_opnsense() { [ -x /usr/local/sbin/opnsense-version ] || [ -d /usr/local/opnsense/mvc ]; }

# Reverse-of-ensure_aliases: remove the 3 external aliases (only if unreferenced)
# and, when --purge, the <OPNsense><ladon> config node. Prints:
#   removed:<space list>
#   skipped:<space list>
opnsense_config_teardown() {
  php_script=$(mktemp)
  cat > "$php_script" <<'PHP'
<?php
require_once 'config.inc';
require_once 'util.inc';
use OPNsense\Core\Config;
use OPNsense\Firewall\Alias;
$purge = (isset($argv[1]) && $argv[1] === '--purge');
$names = ['ladon_engine', 'ladon_manual', 'ladon_cidr'];
$removed = []; $skipped = [];
Config::getInstance()->lock();
try {
    $mdl = new Alias();
    $changed = false;
    foreach ($names as $n) {
        $node = $mdl->getByName($n);
        if ($node === null) { continue; }
        $used = $mdl->whereUsed($n);
        if (!empty($used)) { $skipped[] = $n; continue; }
        $mdl->aliases->alias->del($node->getAttribute('uuid'));
        $removed[] = $n; $changed = true;
    }
    // validateFullModel=false, disable_validation=true — same as ensure_aliases.php,
    // so an unrelated invalid alias elsewhere can't abort this delete-only teardown.
    if ($changed) { $mdl->serializeToConfig(false, true); }
    $cfg = Config::getInstance();
    if ($purge) {
        $x = $cfg->object();
        if (isset($x->OPNsense->ladon)) { unset($x->OPNsense->ladon); $changed = true; }
    }
    if ($changed) { $cfg->save(); }
} catch (\Throwable $e) {
    Config::getInstance()->unlock();
    fwrite(STDERR, 'ladon teardown: ' . $e->getMessage() . "\n");
    exit(1);
}
Config::getInstance()->unlock();
echo 'removed:' . implode(' ', $removed) . "\n";
echo 'skipped:' . implode(' ', $skipped) . "\n";
PHP
  if [ "$PURGE" = 1 ]; then php "$php_script" --purge; else php "$php_script"; fi
  rm -f "$php_script"
}

uninstall_opnsense() {
  # 1) stop + disable the service
  log "stopping ladon"
  /usr/local/etc/rc.d/ladon stop 2>/dev/null || true
  sysrc -x ladon_enable 2>/dev/null || true
  rm -f /etc/rc.conf.d/ladon

  # 2) CRITICAL: drop the unbound dynlib reference + restart unbound BEFORE
  #    deleting the .so (else unbound fails to start → DNS down box-wide).
  log "removing unbound dynlib + restarting unbound"
  rm -f /usr/local/etc/unbound.opnsense.d/ladon-dynlib.conf
  configctl unbound restart >/dev/null 2>&1 || warn "unbound restart reported an issue — check 'configctl unbound status'"
  rm -f /var/unbound/ladon_unbound.so /usr/local/lib/ladon_unbound.so /usr/local/lib/ladon_unbound.so.unbound-version

  # 3) remove firewall aliases (unreferenced only) + (--purge) the config node
  log "backing out config.xml (aliases + settings)"
  out=$(opnsense_config_teardown 2>/dev/null || true)
  removed=$(printf '%s\n' "$out" | sed -n 's/^removed://p')
  skipped=$(printf '%s\n' "$out" | sed -n 's/^skipped://p')
  [ -n "$removed" ] && { configctl filter reload >/dev/null 2>&1 || true; log "removed aliases:$removed"; }
  [ -n "$skipped" ] && warn "kept aliases (still used by a rule):$skipped — remove the rule and re-run to drop them"

  # 4) flush + kill pf tables, but only for aliases we actually removed
  for t in $removed; do
    pfctl -t "$t" -T flush 2>/dev/null || true
    pfctl -t "$t" -T kill  2>/dev/null || true
  done

  # 5) delete files (state behind --purge)
  log "removing plugin files"
  rm -f  /usr/local/bin/ladon \
         /usr/local/etc/rc.d/ladon \
         /usr/local/etc/inc/plugins.inc.d/ladon.inc \
         /usr/local/opnsense/service/conf/actions.d/actions_ladon.conf
  rm -rf /usr/local/share/ladon \
         /usr/local/opnsense/mvc/app/controllers/OPNsense/Ladon \
         /usr/local/opnsense/mvc/app/models/OPNsense/Ladon \
         /usr/local/opnsense/mvc/app/views/OPNsense/Ladon \
         /usr/local/opnsense/service/templates/OPNsense/Ladon \
         /usr/local/opnsense/scripts/OPNsense/Ladon
  rm -f  /usr/local/etc/ladon/config.yaml /usr/local/etc/ladon/manual-allow.txt /usr/local/etc/ladon/manual-deny.txt
  rm -f  /var/run/ladon.pid /var/run/ladon-dns.sock
  if [ "$PURGE" = 1 ]; then
    rm -rf /var/db/ladon /var/log/ladon /usr/local/etc/ladon
    log "purged settings + engine.db + logs"
  else
    log "kept /var/db/ladon (engine.db) + settings (--purge to remove)"
  fi

  # 6) deregister from the GUI (last)
  log "reloading configd + GUI"
  # Drop cached model metadata/templates/ACL AND the menu cache, or the dead
  # "Services ▸ Ladon" entry lingers (TTL ~1h) and errors when clicked. Current
  # OPNsense caches under /var/lib/php; the old mvc/app/cache path is kept for
  # older releases. Restrict to *.php so unrelated tempDir files are untouched.
  rm -f /usr/local/opnsense/mvc/app/cache/* 2>/dev/null || true
  rm -f /var/lib/php/cache/*.php /var/lib/php/tmp/*.php 2>/dev/null || true
  rm -f /var/lib/php/tmp/opnsense_menu_cache.xml /tmp/opnsense_menu_cache.xml 2>/dev/null || true
  [ -f /usr/local/etc/rc.d/configd ] && /usr/local/etc/rc.d/configd restart >/dev/null 2>&1 || true
  configctl webgui restart >/dev/null 2>&1 || true

  log "ladon uninstalled (OPNsense)"
  warn "NOT removed: firewall rules YOU added referencing the ladon aliases"
}

case "$(uname -s)" in
  Linux)   uninstall_linux ;;
  FreeBSD) if is_opnsense; then uninstall_opnsense; else die "на FreeBSD поддерживается только OPNsense"; fi ;;
  *) die "unsupported OS: $(uname -s)" ;;
esac
