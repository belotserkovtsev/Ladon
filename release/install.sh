#!/bin/sh
# ladon installer — POSIX sh, runs on Linux (curl … | sudo sh) and
# FreeBSD/OPNsense (fetch -o - … | sh). One script, OS-detected:
#
#   Linux            — dnsmasq + ipset + systemd unit (Debian/Ubuntu gateway).
#   OPNsense         — the os-ladon plugin (GUI/service/configd); Unbound + pf.
#   bare FreeBSD     — headless engine (binary + rc.d), wire Unbound/pf by hand.
#
# Re-running upgrades in place (config/state/aliases preserved). Routing is the
# operator's job — the script never touches firewall rules, only prints a hint.
#
# Usage:
#   curl -fsSL https://github.com/belotserkovtsev/ladon/releases/latest/download/install.sh | sudo sh
#   fetch -o - https://github.com/belotserkovtsev/ladon/releases/latest/download/install.sh | sh   # FreeBSD
#
# Optional env:
#   TAG=v1.4.0            install a specific tag (default: latest stable)
#   LADON_SRC=/path       use an already-extracted bundle dir (offline/testing)
#   LADON_DRY_RUN=1       run checks, change nothing
#   LADON_EXTENSIONS="discord telegram"   non-interactive preset list
#   LADON_PROBE_MODE=local|exit-compare   non-interactive probe mode
#   LADON_REMOTE_URL= / LADON_REMOTE_TOKEN=   exit-compare prober
#   NO_COLOR=1           disable color
#   IPSET_ENGINE / IPSET_MANUAL / IPSET_CIDR / LADON_PREFIX / LADON_CONFIG_DIR   (Linux)

set -eu

# Temp bundles are cleaned at process exit (after install finishes using $SRC,
# which points inside one of them — so cleanup must NOT happen any earlier).
_TMPDIRS=""
trap 'for _d in $_TMPDIRS; do rm -rf "$_d"; done' EXIT

# ===== env / defaults =====
GH_REPO="belotserkovtsev/ladon"
TAG="${TAG:-}"
DRY_RUN="${LADON_DRY_RUN:-0}"
LADON_SRC="${LADON_SRC:-}"
IPSET_ENGINE="${IPSET_ENGINE:-ladon_engine}"
IPSET_MANUAL="${IPSET_MANUAL:-ladon_manual}"
IPSET_CIDR="${IPSET_CIDR:-ladon_cidr}"
LADON_PREFIX="${LADON_PREFIX:-/opt/ladon}"
LADON_CONFIG_DIR="${LADON_CONFIG_DIR:-/etc/ladon}"
LADON_EXTENSIONS="${LADON_EXTENSIONS:-}"
LADON_PROBE_MODE="${LADON_PROBE_MODE:-}"
LADON_REMOTE_URL="${LADON_REMOTE_URL:-}"
LADON_REMOTE_TOKEN="${LADON_REMOTE_TOKEN:-}"
FORCE=0
for a in "$@"; do case "$a" in -f|--force) FORCE=1 ;; esac; done

# ===== style (color only on a terminal) =====
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  CYAN=$(printf '\033[36m'); GREEN=$(printf '\033[32m'); YELLOW=$(printf '\033[33m')
  RED=$(printf '\033[31m'); DIM=$(printf '\033[90m'); BOLD=$(printf '\033[1m'); NC=$(printf '\033[0m')
else
  CYAN=; GREEN=; YELLOW=; RED=; DIM=; BOLD=; NC=
fi
# All progress goes to stderr: stdout is reserved for captured values
# (obtain_bundle prints the source dir there via `SRC=$(obtain_bundle …)`),
# so a stray ok/info/warn can never pollute what the caller captures.
step() { printf '\n  %s%s%s%s\n' "$BOLD" "$CYAN" "$1" "$NC" >&2; }
ok()   { printf '   %s✔%s %s\n' "$GREEN" "$NC" "$*" >&2; }
info() { printf '   %s·%s %s\n' "$DIM" "$NC" "$*" >&2; }
warn() { printf '   %s▲%s %s\n' "$YELLOW" "$NC" "$*" >&2; }
die()  { printf '   %s✖%s %s\n' "$RED" "$NC" "$*" >&2; exit 1; }

banner() {
  printf '%s' "$CYAN"
  cat <<'ART'
  ██╗      █████╗ ██████╗  ██████╗ ███╗   ██╗
  ██║     ██╔══██╗██╔══██╗██╔═══██╗████╗  ██║
  ██║     ███████║██║  ██║██║   ██║██╔██╗ ██║
  ██║     ██╔══██║██║  ██║██║   ██║██║╚██╗██║
  ███████╗██║  ██║██████╔╝╚██████╔╝██║ ╚████║
  ╚══════╝╚═╝  ╚═╝╚═════╝  ╚═════╝ ╚═╝  ╚═══╝
ART
  printf '%s' "$NC"
  printf '  %santi-dpi engine · установка%s\n\n' "$DIM" "$NC"
}

# ===== shared helpers =====
need_root() { [ "$(id -u)" -eq 0 ] || die "запусти через sudo (нужен root)"; }
have() { command -v "$1" >/dev/null 2>&1; }

fetch_to() { # $1=dest $2=url  → 0 on success
  if have curl; then curl -fsSL -o "$1" "$2"
  elif have fetch; then fetch -q -o "$1" "$2"
  else return 1; fi
}

sha_verify() { # $1=file $2=sha256-file ("HASH  name") → 0 ok / 1 mismatch / 2 no-tool
  _want=$(awk '{print $1; exit}' "$2" 2>/dev/null)
  [ -n "$_want" ] || return 2
  if have sha256sum;   then _got=$(sha256sum   "$1" | awk '{print $1}')
  elif have sha256;    then _got=$(sha256 -q   "$1")
  elif have shasum;    then _got=$(shasum -a 256 "$1" | awk '{print $1}')
  else return 2; fi
  [ "$_got" = "$_want" ]
}

resolve_tag() {
  [ -n "$TAG" ] && return 0
  TAG=$(fetch_to /dev/stdout "https://api.github.com/repos/${GH_REPO}/releases/latest" 2>/dev/null \
        | grep '"tag_name":' | head -1 | cut -d'"' -f4) || true
  [ -n "$TAG" ] || die "не удалось узнать последнюю версию с GitHub (задай TAG=…)"
}

# obtain_bundle <asset-prefix>  → prints the extracted source dir.
obtain_bundle() {
  if [ -n "$LADON_SRC" ]; then printf '%s' "$LADON_SRC"; return 0; fi
  resolve_tag
  _work=$(mktemp -d); _TMPDIRS="$_TMPDIRS $_work"
  _base="$1-${TAG}.tar.gz"
  _url="https://github.com/${GH_REPO}/releases/download/${TAG}/${_base}"
  fetch_to "$_work/${_base}" "$_url" || die "не скачал $_url"
  if fetch_to "$_work/${_base}.sha256" "${_url}.sha256" 2>/dev/null; then
    # Capture sha_verify's status explicitly (0 ok / 1 mismatch / 2 no-tool);
    # set -e tolerates the failure here because it sits in an if-condition.
    if sha_verify "$_work/${_base}" "$_work/${_base}.sha256"; then _rc=0; else _rc=$?; fi
    if   [ "$_rc" = 0 ]; then :
    elif [ "$_rc" = 1 ]; then die "sha256 не сошёлся — скачивание битое"
    else warn "нет утилиты для проверки sha256 — пропускаю"; fi
  else
    warn "нет .sha256 у релиза — пропускаю проверку"
  fi
  tar -C "$_work" -xzf "$_work/${_base}"
  printf '%s' "$_work/$1-${TAG}"
}

# ============================================================
#  LINUX  (dnsmasq + ipset + systemd)
# ============================================================
DETECT_GUESS=""
detect_topology() {
  gw=0; dt=0
  if [ "$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null)" = "1" ]; then gw=$((gw+2)); else dt=$((dt+1)); fi
  if grep -rqsE '^[[:space:]]*dhcp-range=' /etc/dnsmasq.conf /etc/dnsmasq.d/ 2>/dev/null; then gw=$((gw+2)); fi
  if { iptables -t nat -S 2>/dev/null; nft list ruleset 2>/dev/null; } | grep -qi 'masquerade'; then gw=$((gw+1)); fi
  if ip -o link show type bridge 2>/dev/null | grep -q .; then gw=$((gw+1)); fi
  if systemctl is-active --quiet systemd-resolved 2>/dev/null; then dt=$((dt+1)); fi
  if [ "$(systemctl get-default 2>/dev/null)" = "graphical.target" ] || systemctl is-active --quiet display-manager 2>/dev/null; then dt=$((dt+2)); fi
  if [ "$gw" -gt "$dt" ]; then DETECT_GUESS="gateway"; else DETECT_GUESS="desktop"; fi
}

# numbered multi-select over $EXT_NAMES (space list) → CHOICE_MULTI (space list)
CHOICE_MULTI=""
ask_extensions() {
  printf '  %s?%s Какие расширения включить?  %sномера через пробел, Enter — ничего%s\n' "$CYAN" "$NC" "$DIM" "$NC"
  i=1
  for e in $EXT_NAMES; do printf '    %d) %s\n' "$i" "$e"; i=$((i+1)); done
  printf '    > '
  IFS= read -r sel <&3 || sel=""
  CHOICE_MULTI=""
  for num in $sel; do
    j=1
    for e in $EXT_NAMES; do [ "$j" = "$num" ] && CHOICE_MULTI="$CHOICE_MULTI $e"; j=$((j+1)); done
  done
  CHOICE_MULTI=$(printf '%s' "$CHOICE_MULTI" | sed 's/^ *//')
}

PROBE_MODE="local"; REMOTE_URL=""; REMOTE_TOKEN=""
ask_probe_mode() {
  printf '  %s?%s Режим проверки доменов?\n' "$CYAN" "$NC"
  printf '    1) local         %sтолько со шлюза (по умолчанию)%s\n' "$DIM" "$NC"
  printf '    2) exit-compare  %sсверять с выходным сервером (точнее)%s\n' "$DIM" "$NC"
  printf '    > '
  IFS= read -r m <&3 || m=""
  case "$m" in
    2|exit-compare)
      PROBE_MODE="exit-compare"
      printf '    URL probe-сервера: '; IFS= read -r REMOTE_URL <&3 || REMOTE_URL=""
      printf '    Токен (Enter — пусто): '; IFS= read -r REMOTE_TOKEN <&3 || REMOTE_TOKEN=""
      [ -n "$REMOTE_URL" ] || { warn "URL пуст — откатываюсь на local"; PROBE_MODE="local"; }
      ;;
    *) PROBE_MODE="local" ;;
  esac
}

write_config_linux() {
  cfg="$LADON_CONFIG_DIR/config.yaml"
  {
    echo "# ladon config — создан установщиком."
    echo "# Полный список опций: $LADON_CONFIG_DIR/config.yaml.example"
    echo
    echo "log:"
    echo "  level: info"
    echo
    if [ -n "$CHOICE_MULTI" ]; then
      printf 'allow_extensions: ['; _sep=""
      for e in $CHOICE_MULTI; do printf '%s%s' "$_sep" "$e"; _sep=", "; done
      printf ']\n\n'
    fi
    echo "probe:"
    echo "  mode: $PROBE_MODE"
    if [ "$PROBE_MODE" = "exit-compare" ]; then
      echo "  remote:"
      echo "    url: $REMOTE_URL"
      if [ -n "$REMOTE_TOKEN" ]; then
        echo "    auth_header: Authorization"
        echo "    auth_value: $REMOTE_TOKEN"
      fi
    fi
  } > "$cfg"
}

install_linux() {
  [ -f /etc/os-release ] || die "нет /etc/os-release — поддерживается только Debian/Ubuntu"
  . /etc/os-release
  case "${ID:-}${ID_LIKE:-}" in
    *debian*|*ubuntu*) ;;
    *) die "поддерживается только Debian/Ubuntu (ID=${ID:-?})" ;;
  esac
  have systemctl || die "нужен systemd"
  have curl || die "нужен curl"
  case "$(uname -m)" in
    x86_64|amd64) ARCH=amd64 ;;
    aarch64|arm64) ARCH=arm64 ;;
    *) die "архитектура не поддерживается: $(uname -m)" ;;
  esac

  step "Окружение"
  ok "Linux/$ARCH (${PRETTY_NAME:-$ID})"

  detect_topology
  if [ "$DETECT_GUESS" = "desktop" ] && [ "$FORCE" != 1 ]; then
    die "устройство определено как десктоп — установка остановлена (-f чтобы пропустить)"
  fi

  step "Загрузка"
  SRC=$(obtain_bundle "ladon-linux-${ARCH}")
  ok "версия: ${TAG:-$LADON_SRC}"

  EXT_NAMES=""
  for f in "$SRC"/extensions/*.txt; do [ -e "$f" ] && EXT_NAMES="$EXT_NAMES $(basename "$f" .txt)"; done
  EXT_NAMES=$(printf '%s' "$EXT_NAMES" | sed 's/^ *//')

  FRESH=1; [ -f "$LADON_CONFIG_DIR/config.yaml" ] && FRESH=0

  [ -n "$LADON_PROBE_MODE" ] && PROBE_MODE="$LADON_PROBE_MODE"
  [ -n "$LADON_EXTENSIONS" ] && CHOICE_MULTI="$LADON_EXTENSIONS"
  [ -n "$LADON_REMOTE_URL" ] && REMOTE_URL="$LADON_REMOTE_URL"
  [ -n "$LADON_REMOTE_TOKEN" ] && REMOTE_TOKEN="$LADON_REMOTE_TOKEN"

  # Interactive wizard, but only for dimensions not already preset via env.
  # A bare `exec 3</dev/tty` is FATAL in a non-interactive shell when /dev/tty
  # can't be opened (the curl|sh path) — `2>/dev/null` can't catch it. So probe
  # openability in a subshell first (the fatal exit is confined there); only
  # then commit the real `exec` in this shell.
  if [ "$FRESH" = 1 ] && { [ -z "$LADON_PROBE_MODE" ] || [ -z "$LADON_EXTENSIONS" ]; } \
     && ( exec 3</dev/tty ) 2>/dev/null && exec 3</dev/tty; then
    step "Настройка"
    [ -n "$EXT_NAMES" ] && [ -z "$LADON_EXTENSIONS" ] && ask_extensions
    [ -z "$LADON_PROBE_MODE" ] && ask_probe_mode
    exec 3<&-
  else
    [ "$FRESH" = 0 ] && info "обновление: config.yaml сохраняю, мастер пропускаю"
  fi

  if [ "$DRY_RUN" = 1 ]; then step "Dry-run"; info "пропущено: apt, файлы, ipset, служба"; exit 0; fi

  step "Установка"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq ipset sqlite3 dnsmasq >/dev/null
  ok "зависимости (ipset, sqlite3, dnsmasq)"

  install -d "$LADON_PREFIX/state" "$LADON_CONFIG_DIR" "$LADON_PREFIX/extensions"
  install -m 0755 "$SRC/ladon"               "$LADON_PREFIX/ladon"
  install -m 0644 "$SRC/ladon.service"       /etc/systemd/system/ladon.service
  install -m 0644 "$SRC/config.yaml.example" "$LADON_CONFIG_DIR/config.yaml.example"
  [ ! -f "$LADON_CONFIG_DIR/manual-allow.txt" ] && install -m 0644 "$SRC/manual-allow.txt.example" "$LADON_CONFIG_DIR/manual-allow.txt"
  [ ! -f "$LADON_CONFIG_DIR/manual-deny.txt" ]  && install -m 0644 "$SRC/manual-deny.txt.example"  "$LADON_CONFIG_DIR/manual-deny.txt"
  for f in "$SRC"/extensions/*.txt; do [ -e "$f" ] && install -m 0644 "$f" "$LADON_PREFIX/extensions/"; done
  ok "бинарь → $LADON_PREFIX/ladon"

  cat > /usr/local/bin/ladon <<EOF
#!/bin/sh
exec ${LADON_PREFIX}/ladon -db ${LADON_PREFIX}/state/engine.db -config ${LADON_CONFIG_DIR}/config.yaml "\$@"
EOF
  chmod +x /usr/local/bin/ladon
  ok "команда ladon → /usr/local/bin/ladon"

  if [ "$FRESH" = 1 ]; then write_config_linux; ok "конфиг → $LADON_CONFIG_DIR/config.yaml"; else ok "конфиг сохранён"; fi

  ipset list "$IPSET_ENGINE" -t >/dev/null 2>&1 || ipset create "$IPSET_ENGINE" hash:ip  family inet maxelem 65536
  ipset list "$IPSET_MANUAL" -t >/dev/null 2>&1 || ipset create "$IPSET_MANUAL" hash:ip  family inet maxelem 65536 timeout 86400
  ipset list "$IPSET_CIDR"   -t >/dev/null 2>&1 || ipset create "$IPSET_CIDR"   hash:net family inet maxelem 65536
  mkdir -p /etc/iptables && ipset save > /etc/iptables/ipsets
  ok "наборы ipset: $IPSET_ENGINE, $IPSET_MANUAL, $IPSET_CIDR"

  install -d /etc/systemd/system/dnsmasq.service.d
  cat > /etc/systemd/system/dnsmasq.service.d/ladon-ipset.conf <<'EOF'
# Installed by ladon: dnsmasq needs CAP_NET_ADMIN to fill kernel ipsets.
[Service]
AmbientCapabilities=CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW CAP_SETUID CAP_SETGID CAP_CHOWN CAP_DAC_OVERRIDE CAP_FOWNER CAP_SETFCAP CAP_SETPCAP CAP_SYS_CHROOT CAP_KILL
EOF
  ok "dnsmasq: выдан CAP_NET_ADMIN"

  if ! grep -q -- '-config' /etc/systemd/system/ladon.service; then
    esc=$(printf '%s' "$LADON_PREFIX" | sed 's/[\/&]/\\&/g')
    sed -i "s|^  -db ${esc}/state/engine.db|  -db ${LADON_PREFIX}/state/engine.db -config ${LADON_CONFIG_DIR}/config.yaml|" \
      /etc/systemd/system/ladon.service
  fi

  "$LADON_PREFIX/ladon" -db "$LADON_PREFIX/state/engine.db" init-db >/dev/null
  ok "база инициализирована"

  systemctl daemon-reload
  systemctl restart dnsmasq
  systemctl enable ladon >/dev/null 2>&1
  systemctl restart ladon
  sleep 1
  systemctl is-active --quiet ladon || die "ladon не стартанул — journalctl -u ladon -n 50 --no-pager"
  ok "служба ladon запущена"

  printf '\n  %s● ГОТОВО · ladon %s работает%s\n' "$GREEN" "${TAG:-}" "$NC"
  step "Что дальше"
  info "проверить:  sudo ladon doctor"
  info "маршрутизация — за тобой (ipset $IPSET_ENGINE → твой туннель), пример:"
  printf '%s    iptables -t mangle -A PREROUTING -m set --match-set %s dst -j MARK --set-mark 0x1\n' "$DIM" "$IPSET_ENGINE"
  printf '    ip rule add fwmark 0x1 table 100 priority 1000\n'
  printf '    ip route replace default dev <tunnel> table 100%s\n\n' "$NC"
}

# ============================================================
#  FREEBSD / OPNsense
# ============================================================
is_opnsense() { [ -x /usr/local/sbin/opnsense-version ] || [ -d /usr/local/opnsense/mvc ]; }

# FreeBSD release arch → FBARCH (amd64|arm64). Run as a statement, not in $(…),
# so `die` exits the real shell. The bundle ships both and the .so builds on-box,
# so either arch is fully supported (arm64 is for bare FreeBSD — OPNsense is amd64).
FBARCH=""
resolve_freebsd_arch() {
  case "$(uname -m)" in
    amd64|x86_64)  FBARCH=amd64 ;;
    arm64|aarch64) FBARCH=arm64 ;;
    *) die "архитектура FreeBSD не поддерживается: $(uname -m) (нужен amd64 или arm64)" ;;
  esac
}

install_opnsense() {
  resolve_freebsd_arch
  step "Окружение"
  ok "OPNsense $(/usr/local/sbin/opnsense-version 2>/dev/null || echo '') · $FBARCH"

  step "Загрузка"
  SRC=$(obtain_bundle "ladon-freebsd-${FBARCH}")
  ok "версия: ${TAG:-$LADON_SRC}"

  if [ "$DRY_RUN" = 1 ]; then step "Dry-run"; info "пропущено: копирование, сборка .so, регистрация"; exit 0; fi

  step "Установка плагина"
  cp -R "$SRC/plugin/." /usr/local/
  install -m 0755 "$SRC/ladon" /usr/local/bin/ladon
  chmod 0755 /usr/local/etc/rc.d/ladon /usr/local/opnsense/scripts/OPNsense/Ladon/*.sh 2>/dev/null || true
  mkdir -p /var/db/ladon /var/log/ladon /usr/local/etc/ladon /var/unbound/var/run
  ok "файлы плагина + бинарь → /usr/local"

  step "Сборка Unbound-модуля"
  if sh /usr/local/opnsense/scripts/OPNsense/Ladon/build_unbound_module.sh; then
    ok "ladon_unbound.so собран под текущий unbound"
  else
    warn "не собрал .so сейчас — соберётся при первом Apply (нужен интернет + cc)"
  fi

  step "Регистрация"
  [ -f /usr/local/etc/rc.d/configd ] && /usr/local/etc/rc.d/configd restart >/dev/null 2>&1 || true
  sleep 1
  [ -f /usr/local/opnsense/mvc/script/run_migrations.php ] && \
    /usr/local/opnsense/mvc/script/run_migrations.php OPNsense/Ladon >/dev/null 2>&1 || true
  configctl template reload OPNsense/Ladon >/dev/null 2>&1 || true
  ok "плагин зарегистрирован (configd + модель + шаблоны)"

  printf '\n  %s● ГОТОВО · плагин os-ladon установлен%s\n' "$GREEN" "$NC"
  step "Что дальше"
  info "включить:    Services ▸ Ladon ▸ Enable → Apply"
  info "диагностика: Services ▸ Ladon ▸ Diagnostics"
  info "роутинг:     Firewall ▸ Rules, dst = алиас ladon_engine → твой VPN gateway"
  printf '\n'
}

install_bsd_bare() {
  resolve_freebsd_arch
  step "Окружение"; ok "bare FreeBSD/$(uname -r) $FBARCH — без GUI"
  step "Загрузка"; SRC=$(obtain_bundle "ladon-freebsd-${FBARCH}"); ok "версия: ${TAG:-$LADON_SRC}"
  if [ "$DRY_RUN" = 1 ]; then step "Dry-run"; exit 0; fi

  step "Установка"
  install -m 0755 "$SRC/ladon" /usr/local/bin/ladon
  install -m 0755 "$SRC/plugin/etc/rc.d/ladon" /usr/local/etc/rc.d/ladon
  install -d /usr/local/share/ladon /var/db/ladon /var/log/ladon
  install -m 0644 "$SRC/plugin/share/ladon/ladon-unbound.c" /usr/local/share/ladon/ladon-unbound.c
  install -m 0755 "$SRC/plugin/opnsense/scripts/OPNsense/Ladon/build_unbound_module.sh" /usr/local/share/ladon/build_unbound_module.sh
  sysrc ladon_enable=YES >/dev/null
  ok "бинарь + rc.d"

  step "Сборка Unbound-модуля"
  if sh /usr/local/share/ladon/build_unbound_module.sh; then ok "ladon_unbound.so собран"; else warn "не собрал .so (нужен интернет + cc)"; fi

  printf '\n  %s● движок установлен%s — обвязку Unbound/pf сделать вручную:\n' "$GREEN" "$NC"
  printf '%s    unbound: server { module-config: "dynlib iterator" }  dynlib { dynlib-file: "/ladon_unbound.so" }\n' "$DIM"
  printf '             cp /usr/local/lib/ladon_unbound.so /var/unbound/ladon_unbound.so ; service unbound restart\n'
  printf '    pf:      table <ladon_engine> persist ; pass out route-to (<if> <gw>) from <lan> to <ladon_engine>\n'
  printf '    start:   service ladon start%s\n\n' "$NC"
}

# ============================================================
#  main
# ============================================================
[ -t 1 ] && printf '\033[H\033[2J\033[3J'
banner
need_root
case "$(uname -s)" in
  Linux)   install_linux ;;
  FreeBSD) if is_opnsense; then install_opnsense; else install_bsd_bare; fi ;;
  *) die "неподдерживаемая ОС: $(uname -s)" ;;
esac
