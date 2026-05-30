# Установка ladon на OpenWRT (beta)

← [README](../README.md) · [установка Debian/Ubuntu](install.md) · [конфигурация](configuration.md) · [extensions](extensions.md)

> **Статус:** beta. Сборки под OpenWRT появились в v1.4.0 и пока не проверены
> в продакшене на физическом железе. Если установишь — поделись опытом в issues.

## Поддерживаемые таргеты

| OpenWRT arch (`opkg print-architecture`) | tarball | типичные устройства |
| --- | --- | --- |
| `aarch64_*` | `ladon-openwrt-aarch64.tar.gz` | RPi 4, GL-AXT1800/MT3000, Banana Pi, modern ARM SoC |
| `arm_cortex-a*` / `arm_*_neon-vfpv4` | `ladon-openwrt-armv7.tar.gz` | ipq40xx, mt7621 ARM head, mvebu (Linksys WRT) |
| `x86_64` | `ladon-openwrt-x86_64.tar.gz` | mini-PC рутер, x86 OpenWRT |

**MIPS (любой) пока не поддерживается.** Корень проблемы — `modernc.org/libc`,
транзитивный dep `modernc.org/sqlite`, не имеет build-файлов под `linux/mipsle`
и `linux/mips`. Возврат MIPS требует либо другого pure-Go SQLite бэкенда
(`ncruces/go-sqlite3` через wazero — +5MB overhead, медленнее), либо CGO-сборки
с musl-mips toolchain'ом. Отложено в v1.5+ backlog.

Также не входят в release-matrix: ppc, riscv64, mips big-endian — собрать
вручную можно, готовых ассетов нет.

## TL;DR — установка одной командой

```sh
wget -O- https://github.com/belotserkovtsev/ladon/releases/latest/download/install.sh | sh
```

Тот же `install.sh`, что и для Debian — он сниффает `/etc/openwrt_release` и
переключается в OpenWRT-режим автоматически.

Скрипт:

- определит архитектуру через `opkg print-architecture`;
- проверит наличие `dnsmasq-full` (нужен для `ipset=` директив) — если стоит
  обычный `dnsmasq`, **предложит замену с 10-секундным countdown'ом**;
- поставит `ipset`, `ca-bundles`, `wget-ssl`;
- скачает бинарь под нужную арку + проверит sha256;
- разложит файлы:
  - `/usr/bin/ladon` — бинарь;
  - `/etc/init.d/ladon` — procd unit;
  - `/etc/ladon/{config.yaml,manual-allow.txt,manual-deny.txt}` — конфиги (сохраняются при upgrade);
  - `/usr/share/ladon/extensions/*.txt` — пресеты;
  - `/var/lib/ladon/state/engine.db` — БД;
- пропатчит UCI `dhcp.@dnsmasq[0]`:
  - `logqueries=1`
  - `logfacility=/var/log/dnsmasq.log` (если ещё не задан)
  - сохранит исходные значения в `/etc/ladon/.uci-backup` для отката;
- создаст ipset'ы и запустит ладон через procd;
- напечатает пример firewall4/nftables wiring'а.

**Что скрипт НЕ делает:** не трогает firewall4 / nftables / routing.
Это зона ответственности оператора — см. секцию ниже.

**Обновление:** тот же `install.sh` повторно. Скрипт идемпотентен:
подтянет latest, перезапишет бинарь / init / extensions, **сохранит**
`config.yaml` и manual-списки, перезапустит ладон.

## Wiring в firewall4 (nftables, OpenWRT 22.03+)

Положи в `/etc/nftables.d/30-ladon.nft` (firewall4 автоматически подхватит):

```nft
table inet ladon {
  chain mangle_prerouting {
    type filter hook prerouting priority mangle; policy accept;

    # Здесь меняй iifname и subnet под свой LAN.
    iifname "br-lan" ip daddr @ladon_engine meta mark set 0x1
    iifname "br-lan" ip daddr @ladon_manual meta mark set 0x1
    iifname "br-lan" ip daddr @ladon_cidr   meta mark set 0x1
  }
}
```

Затем routing table и rule для туннеля (тут `wg0` — пример имени WireGuard-интерфейса):

```sh
echo '100 ladon' >> /etc/iproute2/rt_tables
ip rule add fwmark 0x1 table ladon priority 1000
ip route replace default dev wg0 table ladon
```

Чтобы пережило ребут — положи команды в `/etc/rc.local` или сделай hotplug
скрипт под интерфейс.

**Почему ipset'ы видны nftables:** на OpenWRT 22.03+ kernel содержит
`xt_set` shim, который проксирует legacy ipset'ы в nftables-движок. Сеты
`@ladon_engine` / `@ladon_manual` / `@ladon_cidr` ссылаются на те же
kernel-объекты, которые создаёт ладон через `ipset create`.

Если предпочитаешь нативные nft set'ы — придётся форкнуть и переписать
`internal/ipset`. В backlog.

## Установка вручную (если хочешь понимать что делает скрипт)

```sh
# 1. Деп-стек
opkg update
opkg install ipset ca-bundles wget-ssl

# 2. dnsmasq-full (обязательно — обычный dnsmasq не умеет ipset= директивы)
opkg list-installed | grep -q '^dnsmasq-full ' || {
  opkg remove dnsmasq --force-removal-of-dependent-packages
  opkg install dnsmasq-full
  /etc/init.d/dnsmasq restart
}

# 3. Бинарь + ассеты
TAG=v1.4.0   # или latest, см. скрипт
ARCH=aarch64 # выбери под opkg print-architecture
cd /tmp
wget "https://github.com/belotserkovtsev/ladon/releases/download/${TAG}/ladon-openwrt-${ARCH}.tar.gz"
wget "https://github.com/belotserkovtsev/ladon/releases/download/${TAG}/ladon-openwrt-${ARCH}.tar.gz.sha256"
sha256sum -c "ladon-openwrt-${ARCH}.tar.gz.sha256"
tar xzf "ladon-openwrt-${ARCH}.tar.gz"
cd "ladon-openwrt-${ARCH}-${TAG}"

mkdir -p /etc/ladon /usr/share/ladon/extensions /var/lib/ladon/state
install -m 0755 ladon                          /usr/bin/ladon
install -m 0755 ladon.init                     /etc/init.d/ladon
install -m 0644 manual-allow.txt.example       /etc/ladon/manual-allow.txt
install -m 0644 manual-deny.txt.example        /etc/ladon/manual-deny.txt
install -m 0644 config.yaml.openwrt.example    /etc/ladon/config.yaml
install -m 0644 extensions/*.txt               /usr/share/ladon/extensions/

# 4. Включить query logging у dnsmasq
uci set dhcp.@dnsmasq[0].logqueries='1'
uci set dhcp.@dnsmasq[0].logfacility='/var/log/dnsmasq.log'
uci commit dhcp
/etc/init.d/dnsmasq reload

# 5. Создать ipset'ы
ipset create ladon_engine hash:ip  family inet maxelem 65536
ipset create ladon_manual hash:ip  family inet maxelem 65536 timeout 86400
ipset create ladon_cidr   hash:net family inet maxelem 65536

# 6. Init DB и запуск
/usr/bin/ladon -db /var/lib/ladon/state/engine.db init-db
/etc/init.d/ladon enable
/etc/init.d/ladon start
```

## Известные ограничения OpenWRT-версии

**1. `/var` — tmpfs.** На большинстве OpenWRT-устройств `/var` (где лежит
`/var/log/dnsmasq.log`) — RAM-диск. На устройствах с ≤128MB RAM активный
лог может разрастись и съесть память. Workarounds:

- Поднять `cachesize` у dnsmasq (`uci set dhcp.@dnsmasq[0].cachesize='1000'`) —
  меньше query'ев = меньше строк лога.
- Перенаправить лог на ext-fs (USB-флешка), переопределив `logfacility` в
  UCI и `dnsmasq.conf_path` в `/etc/ladon/config.yaml`.
- Периодически truncate'ить: `*/30 * * * * : > /var/log/dnsmasq.log` в cron.
  Ладон держит файловый дескриптор открытым через tail, truncate не ломает
  его — dnsmasq продолжит писать.

В backlog (v1.5+): встроенный лог-ротатор в самом ладоне с настраиваемым
threshold размера.

**2. nftables / firewall4 интеграция.** Ладон создаёт legacy ipset'ы,
firewall4 их видит через kernel shim. Это работает, но не идиоматично
для современного OpenWRT. Натинвый nft set'овый бекенд — отдельная работа.

**3. Замена `dnsmasq` → `dnsmasq-full`.** Установщик делает её
автоматически с alert + 10-секундным countdown'ом. Это даёт ~5 секунд
unavailability DNS на роутере. Для unattended-сценариев (CI, скрипты)
поставь `ASSUME_YES=1`. Откат уничтожен — uninstall не возвращает
обычный `dnsmasq` обратно (зависимости могли уже завязаться на ipset
support).

**4. Beta-статус.** На реальном железе с production-нагрузкой ladon
under OpenWRT пока не валидировался. Скорее всего работает; если найдёшь
edge case — открой issue с `logread -e ladon` и `uname -a`.

## Удаление

```sh
wget -O- https://github.com/belotserkovtsev/ladon/releases/latest/download/uninstall.sh | sh
```

Скрипт:

- остановит и удалит `/etc/init.d/ladon`;
- уничтожит ipset'ы (если не зареференсены firewall-правилами);
- удалит `/usr/bin/ladon`, `/etc/ladon`, `/usr/share/ladon`, `/var/lib/ladon`;
- **восстановит** оригинальные UCI-значения `dhcp.@dnsmasq[0].logqueries` и
  `logfacility` из `/etc/ladon/.uci-backup`;
- НЕ откатит `dnsmasq-full` обратно к `dnsmasq` — это разовая операция;
- НЕ трогает твои firewall4 / routing-правила.
