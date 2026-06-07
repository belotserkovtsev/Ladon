#!/usr/bin/env bash
# ladon installer — Debian/Ubuntu only.
#
# Interactive when run on a terminal (даже через `curl | sudo bash` — ввод
# читается из /dev/tty): спрашивает расширения и режим проверки, показывает
# сводку и просит подтверждение перед изменениями. Без терминала (cron, пайп)
# тихо ставит с дефолтами.
#
# Scope: ladon's job is to keep three kernel ipsets populated:
#   ladon_engine — IPs of probe-discovered blocked domains (hot/cache)
#   ladon_manual — IPs of domains in manual-allow + extensions (via dnsmasq)
#   ladon_cidr   — CIDR blocks from manual-allow + extensions (hash:net)
#
# Wiring those ipsets into routing (iptables MARK + ip rule + table → tunnel)
# is the OPERATOR'S job — this script does NOT touch iptables/routing; it prints
# a copy-paste example at the end.
#
# Re-running upgrades in place: config files (config.yaml, manual-*.txt) are
# preserved, binary/unit/extensions replaced, ladon restarted. On an upgrade the
# interactive wizard is skipped (your config stays as-is).
#
# Usage:
#   sudo bash install.sh
#   curl -fsSL https://github.com/belotserkovtsev/ladon/releases/latest/download/install.sh | sudo bash
#
# Optional env:
#   TAG=v1.4.0              install a specific tag (default: latest stable)
#   LADON_DRY_RUN=1         run the wizard, change nothing (for testing)
#   NO_COLOR=1              disable color
#   IPSET_ENGINE / IPSET_MANUAL / IPSET_CIDR / LADON_PREFIX / LADON_CONFIG_DIR

set -euo pipefail

# --- env / defaults ---
IPSET_ENGINE="${IPSET_ENGINE:-ladon_engine}"
IPSET_MANUAL="${IPSET_MANUAL:-ladon_manual}"
IPSET_CIDR="${IPSET_CIDR:-ladon_cidr}"
LADON_PREFIX="${LADON_PREFIX:-/opt/ladon}"
LADON_CONFIG_DIR="${LADON_CONFIG_DIR:-/etc/ladon}"
DRY_RUN="${LADON_DRY_RUN:-0}"
GH_REPO="belotserkovtsev/ladon"

# --- style (color only on a terminal) ---
if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
  CYAN=$'\033[36m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'; RED=$'\033[31m'
  DIM=$'\033[90m'; BOLD=$'\033[1m'; NC=$'\033[0m'
else
  CYAN=; GREEN=; YELLOW=; RED=; DIM=; BOLD=; NC=
fi

step() { printf "\n  ${BOLD}${CYAN}%s${NC}\n" "$1"; }
ok()   { printf "   ${GREEN}✔${NC} %s\n" "$*"; }
info() { printf "   ${DIM}·${NC} %s\n" "$*"; }
warn() { printf "   ${YELLOW}▲${NC} %s\n" "$*"; }
die()  { printf "   ${RED}✖${NC} %s\n" "$*" >&2; exit 1; }

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
  printf "  ${DIM}anti-dpi engine · установка${NC}\n\n"
}

# --- controlling terminal for interactive input (works under curl|bash) ---
HAS_TTY=0
if { exec 3</dev/tty; } 2>/dev/null; then HAS_TTY=1; fi

# read_key: one keypress from the tty, expanding arrow escape sequences.
read_key() {
  local k k2 k3
  IFS= read -rsn1 -u 3 k || true
  if [[ $k == $'\033' ]]; then
    IFS= read -rsn1 -u 3 -t 0.01 k2 || true
    IFS= read -rsn1 -u 3 -t 0.01 k3 || true
    k+="$k2$k3"
  fi
  printf '%s' "$k"
}

join_by() { local d="$1"; shift; [[ $# -eq 0 ]] && return; local out="$1"; shift; printf '%s' "$out"; for x in "$@"; do printf '%s%s' "$d" "$x"; done; }

# --- arrow-key menus (draw to stdout, read from fd 3) ---
# select_extensions: multi-select over $EXT_NAMES → sets CHOICE_MULTI[]
CHOICE_MULTI=()
select_extensions() {
  local n=${#EXT_NAMES[@]} cur=0 i key
  local -a chk; for ((i=0;i<n;i++)); do chk[i]=0; done
  printf "  ${CYAN}?${NC} Какие расширения включить?  ${DIM}↑/↓ · Space отметить · Enter дальше${NC}\n"
  _draw() {
    for ((i=0;i<n;i++)); do
      local box="[ ]"; [[ ${chk[i]} == 1 ]] && box="[${GREEN}x${NC}]"
      local ptr="  "; [[ $i == "$cur" ]] && ptr="${CYAN}▸${NC} "
      printf "    %s%s %s\033[K\n" "$ptr" "$box" "${EXT_NAMES[i]}"
    done
  }
  printf '\033[?25l'   # hide cursor
  _draw
  while true; do
    key=$(read_key)
    case "$key" in
      $'\033[A'|$'\033OA'|k) ((cur=(cur-1+n)%n)) ;;
      $'\033[B'|$'\033OB'|j) ((cur=(cur+1)%n)) ;;
      ' ') chk[cur]=$((1-chk[cur])) ;;
      ''|$'\n'|$'\r') break ;;
      q|Q) printf '\033[?25h'; die "установка отменена" ;;
    esac
    printf "\033[%dA" "$n"; _draw
  done
  printf '\033[?25h'   # show cursor
  CHOICE_MULTI=()
  for ((i=0;i<n;i++)); do [[ ${chk[i]} == 1 ]] && CHOICE_MULTI+=("${EXT_NAMES[i]}"); done
  return 0
}

# select_probe_mode: single-select → sets PROBE_MODE (+ REMOTE_URL/REMOTE_TOKEN)
PROBE_MODE="local"; REMOTE_URL=""; REMOTE_TOKEN=""
select_probe_mode() {
  local opts=("local" "exit-compare")
  local desc=("только со шлюза (по умолчанию)" "сверять с выходным сервером (точнее)")
  local n=2 cur=0 i key
  printf "  ${CYAN}?${NC} Режим проверки доменов?  ${DIM}↑/↓ · Enter${NC}\n"
  _draw() {
    for ((i=0;i<n;i++)); do
      local dot="${DIM}○${NC}"; [[ $i == "$cur" ]] && dot="${GREEN}●${NC}"
      local ptr="  "; [[ $i == "$cur" ]] && ptr="${CYAN}▸${NC} "
      printf "    %s%s %-13s ${DIM}%s${NC}\033[K\n" "$ptr" "$dot" "${opts[i]}" "${desc[i]}"
    done
  }
  printf '\033[?25l'; _draw
  while true; do
    key=$(read_key)
    case "$key" in
      $'\033[A'|$'\033OA'|k) ((cur=(cur-1+n)%n)) ;;
      $'\033[B'|$'\033OB'|j) ((cur=(cur+1)%n)) ;;
      ''|$'\n'|$'\r') break ;;
    esac
    printf "\033[%dA" "$n"; _draw
  done
  printf '\033[?25h'
  PROBE_MODE="${opts[cur]}"
  if [[ $PROBE_MODE == exit-compare ]]; then
    printf "    URL probe-сервера: "; IFS= read -r -u 3 REMOTE_URL || true
    printf "    Токен (Authorization, Enter — пусто): "; IFS= read -r -u 3 REMOTE_TOKEN || true
    [[ -n "$REMOTE_URL" ]] || { warn "URL пуст — откатываюсь на local"; PROBE_MODE="local"; }
  fi
  return 0
}

confirm() {
  local ans
  printf "\n  ${BOLD}Устанавливаем с этими настройками?${NC} ${DIM}[Y/n]${NC} "
  IFS= read -r -u 3 ans || ans=""
  case "$ans" in n|N|no|NO|нет|Нет) return 1 ;; *) return 0 ;; esac
}

write_config() {
  local cfg="$LADON_CONFIG_DIR/config.yaml"
  {
    echo "# ladon config — создан установщиком."
    echo "# Полный список опций: $LADON_CONFIG_DIR/config.yaml.example"
    echo
    echo "log:"
    echo "  level: info"
    echo
    if [[ ${#CHOICE_MULTI[@]} -gt 0 ]]; then
      echo "allow_extensions: [$(join_by ', ' "${CHOICE_MULTI[@]}")]"
      echo
    fi
    echo "probe:"
    echo "  mode: $PROBE_MODE"
    if [[ $PROBE_MODE == exit-compare ]]; then
      echo "  remote:"
      echo "    url: $REMOTE_URL"
      if [[ -n "$REMOTE_TOKEN" ]]; then
        echo "    auth_header: Authorization"
        echo "    auth_value: $REMOTE_TOKEN"
      fi
    fi
  } > "$cfg"
}

# ============================ flow ============================

# Clean start: clear screen + scrollback so the banner sits at the top (only on
# a real terminal — never emit escapes into a pipe/log).
[[ -t 1 ]] && printf '\033[H\033[2J\033[3J'
banner

# --- preflight ---
[[ $EUID -eq 0 ]] || die "запусти через sudo (нужен root)"
[[ -f /etc/os-release ]] || die "нет /etc/os-release — поддерживается только Debian/Ubuntu"
. /etc/os-release
case "${ID:-}${ID_LIKE:-}" in
  *debian*|*ubuntu*) ;;
  *) die "поддерживается только Debian/Ubuntu (ID=${ID:-?})" ;;
esac
command -v systemctl >/dev/null || die "нужен systemd"
command -v curl       >/dev/null || die "нужен curl"
case "$(uname -m)" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) die "архитектура не поддерживается: $(uname -m)" ;;
esac

step "Окружение"
ok "архитектура: $ARCH (${PRETTY_NAME:-$ID})"

# --- fetch + verify release (read-only, into tmp) ---
TAG="${TAG:-}"
if [[ -z "$TAG" ]]; then
  TAG=$(curl -fsSL "https://api.github.com/repos/${GH_REPO}/releases/latest" \
    | grep '"tag_name":' | head -1 | cut -d'"' -f4)
  [[ -n "$TAG" ]] || die "не удалось узнать последнюю версию с GitHub"
fi
ok "версия: $TAG"

WORKDIR=$(mktemp -d); trap 'rm -rf "$WORKDIR"' EXIT; cd "$WORKDIR"
URL="https://github.com/${GH_REPO}/releases/download/${TAG}/ladon-linux-${ARCH}.tar.gz"
curl -fsSL -O "$URL"
curl -fsSL -O "${URL}.sha256"
sha256sum -c "ladon-linux-${ARCH}.tar.gz.sha256" >/dev/null 2>&1 || die "sha256 не сошёлся — скачивание битое"
tar xzf "ladon-linux-${ARCH}.tar.gz"
SRC="ladon-linux-${ARCH}-${TAG}"
ok "загружено и проверено"

# available extensions from the tarball
EXT_NAMES=()
for f in "$SRC"/extensions/*.txt; do [[ -e "$f" ]] && EXT_NAMES+=("$(basename "$f" .txt)"); done

FRESH=1; [[ -f "$LADON_CONFIG_DIR/config.yaml" ]] && FRESH=0

# --- interactive wizard (fresh install on a terminal only) ---
if [[ $FRESH == 1 && $HAS_TTY == 1 ]]; then
  step "Настройка"
  if [[ ${#EXT_NAMES[@]} -gt 0 ]]; then select_extensions; fi
  select_probe_mode

  step "Сводка"
  if [[ ${#CHOICE_MULTI[@]} -gt 0 ]]; then info "расширения:  $(join_by ', ' "${CHOICE_MULTI[@]}")"; else info "расширения:  нет"; fi
  info "режим:       $PROBE_MODE"
  [[ $PROBE_MODE == exit-compare ]] && info "probe-сервер: $REMOTE_URL"
  info "путь:        $LADON_PREFIX  ·  конфиг: $LADON_CONFIG_DIR/config.yaml"
  confirm || { printf "\n  ${DIM}отменено — ничего не менял.${NC}\n\n"; exit 0; }
else
  [[ $FRESH == 0 ]] && info "обновление: существующий config.yaml сохраняю, мастер пропускаю"
  [[ $HAS_TTY == 0 ]] && info "неинтерактивный режим: ставлю с дефолтами (расширения — нет, режим — local)"
fi

if [[ $DRY_RUN == 1 ]]; then
  step "Установка (dry-run)"
  info "пропущено: apt, файлы, ipset, служба — это пробный прогон"
  printf "\n  ${GREEN}╭────────────────────────────────╮${NC}\n"
  printf "  ${GREEN}│${NC}  ${GREEN}●${NC}  ${BOLD}DRY-RUN · ничего не менял${NC}  ${GREEN}│${NC}\n"
  printf "  ${GREEN}╰────────────────────────────────╯${NC}\n\n"
  exit 0
fi

# ============================ apply ============================
step "Установка"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq ipset sqlite3 dnsmasq >/dev/null
ok "зависимости (ipset, sqlite3, dnsmasq)"

install -d "$LADON_PREFIX/state" "$LADON_CONFIG_DIR" "$LADON_PREFIX/extensions"
install -m 0755 "$SRC/ladon"         "$LADON_PREFIX/ladon"
install -m 0644 "$SRC/ladon.service" /etc/systemd/system/ladon.service
install -m 0644 "$SRC/config.yaml.example" "$LADON_CONFIG_DIR/config.yaml.example"
[[ ! -f "$LADON_CONFIG_DIR/manual-allow.txt" ]] && install -m 0644 "$SRC/manual-allow.txt.example" "$LADON_CONFIG_DIR/manual-allow.txt"
[[ ! -f "$LADON_CONFIG_DIR/manual-deny.txt"  ]] && install -m 0644 "$SRC/manual-deny.txt.example"  "$LADON_CONFIG_DIR/manual-deny.txt"
install -m 0644 "$SRC/extensions/"*.txt "$LADON_PREFIX/extensions/"
ok "бинарь → $LADON_PREFIX/ladon"

# CLI wrapper on PATH so `ladon doctor` / `status` / `why` work from anywhere
# against the installed db/config. systemd calls the binary directly; this is
# only for interactive operator use.
cat > /usr/local/bin/ladon <<EOF
#!/bin/sh
# ladon CLI wrapper (installed by install.sh) — points operator commands at the
# installed database and config. The systemd unit calls the binary directly.
exec ${LADON_PREFIX}/ladon -db ${LADON_PREFIX}/state/engine.db -config ${LADON_CONFIG_DIR}/config.yaml "\$@"
EOF
chmod +x /usr/local/bin/ladon
ok "команда ladon → /usr/local/bin/ladon"

if [[ $FRESH == 1 ]]; then
  write_config
  ok "конфиг → $LADON_CONFIG_DIR/config.yaml"
else
  ok "конфиг сохранён (без изменений)"
fi

ipset list "$IPSET_ENGINE" -t >/dev/null 2>&1 || ipset create "$IPSET_ENGINE" hash:ip  family inet maxelem 65536
ipset list "$IPSET_MANUAL" -t >/dev/null 2>&1 || ipset create "$IPSET_MANUAL" hash:ip  family inet maxelem 65536 timeout 86400
ipset list "$IPSET_CIDR"   -t >/dev/null 2>&1 || ipset create "$IPSET_CIDR"   hash:net family inet maxelem 65536
mkdir -p /etc/iptables && ipset save > /etc/iptables/ipsets
ok "наборы ipset: $IPSET_ENGINE, $IPSET_MANUAL, $IPSET_CIDR"

install -d /etc/systemd/system/dnsmasq.service.d
cat > /etc/systemd/system/dnsmasq.service.d/ladon-ipset.conf <<EOF
# Installed by ladon: dnsmasq needs CAP_NET_ADMIN to fill kernel ipsets via the
# ipset= directive ladon writes into /etc/dnsmasq.d/ladon-manual.conf.
[Service]
AmbientCapabilities=CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW CAP_SETUID CAP_SETGID CAP_CHOWN CAP_DAC_OVERRIDE CAP_FOWNER CAP_SETFCAP CAP_SETPCAP CAP_SYS_CHROOT CAP_KILL
EOF
ok "dnsmasq: выдан CAP_NET_ADMIN"

if ! grep -q -- '-config' /etc/systemd/system/ladon.service; then
  sed -i "s|^  -db ${LADON_PREFIX//\//\\/}/state/engine.db|  -db ${LADON_PREFIX}/state/engine.db -config ${LADON_CONFIG_DIR}/config.yaml|" \
    /etc/systemd/system/ladon.service
fi

"$LADON_PREFIX/ladon" -db "$LADON_PREFIX/state/engine.db" init-db >/dev/null
ok "база инициализирована"

systemctl daemon-reload
systemctl restart dnsmasq
systemctl enable ladon >/dev/null 2>&1
systemctl restart ladon
sleep 1
if systemctl is-active --quiet ladon; then
  ok "служба ladon запущена"
else
  die "ladon не стартанул — смотри: journalctl -u ladon -n 50 --no-pager"
fi

# --- done badge ---
printf "\n  ${GREEN}╭──────────────────────────────────╮${NC}\n"
printf "  ${GREEN}│${NC}  ${GREEN}●${NC}  ${BOLD}ГОТОВО · ladon %s работает${NC}\n" "$TAG"
printf "  ${GREEN}╰──────────────────────────────────╯${NC}\n"

step "Что дальше"
info "проверить:  ${BOLD}sudo ladon doctor${NC}"
info "логи:       journalctl -u ladon -f"
info "конфиг:     $LADON_CONFIG_DIR/config.yaml"

printf "\n  ${YELLOW}Маршрутизация — за тобой.${NC} ladon только наполняет ipset; направить\n"
printf "  трафик в твой туннель по совпадению с набором нужно самому. Пример\n"
printf "  (подставь свой fwmark / таблицу / интерфейс):\n\n"
printf "${DIM}    iptables -t mangle -A PREROUTING -m set --match-set %s dst -j MARK --set-mark 0x1\n" "$IPSET_ENGINE"
printf "    ip rule add fwmark 0x1 table 100 priority 1000\n"
printf "    ip route replace default dev <tunnel> table 100\n"
printf "    iptables-save > /etc/iptables/rules.v4${NC}\n\n"
printf "  Удалить:  release/uninstall.sh из того же релиза.\n\n"
