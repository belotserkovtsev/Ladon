# Установка ladon (Debian/Ubuntu)

← [README](../README.md) · [OpenWRT (beta)](install-openwrt.md) · [конфигурация](configuration.md) · [extensions](extensions.md)

> На OpenWRT — отдельный гайд: [install-openwrt.md](install-openwrt.md).

## TL;DR — установка одной командой (Debian/Ubuntu)

```bash
curl -fsSL https://github.com/belotserkovtsev/ladon/releases/latest/download/install.sh \
  | sudo bash
```

Скрипт сам:
- определит архитектуру (amd64/arm64) и скачает последнюю версию + проверит sha256;
- поставит зависимости (`ipset`, `sqlite3`, `dnsmasq`);
- разложит бинарь, systemd-unit, конфиги и extensions в `/opt/ladon` и `/etc/ladon`;
- создаст ipset'ы `ladon_engine` + `ladon_manual` + `ladon_cidr` с правильными опциями + сохранит ipset state в `/etc/iptables/ipsets`;
- установит CAP_NET_ADMIN drop-in для dnsmasq (нужно для нативных `ipset=` директив);
- инициализирует БД, перезапустит dnsmasq и запустит ladon;
- напечатает example iptables/routing-сетапа который **тебе нужно сделать руками**.

**Что скрипт НЕ делает:** не трогает iptables / ip rule / routing tables.
Это зона ответственности оператора — только ты знаешь какой у тебя tunnel-интерфейс, fwmark-схема, peer-subnet и т.д. Ладон просто наполняет ipset'ы; куда направлять трафик при попадании destination IP в эти ipset'ы — твой выбор. Скрипт в конце печатает example для типичного WireGuard split-tunnel сетапа.

**Обновление:** тот же `install.sh` повторно. Скрипт идемпотентен: подтянет latest-версию с GitHub, перезапишет бинарь / systemd-unit / extensions, **сохранит** `config.yaml` и `manual-{allow,deny}.txt`, перезапустит ladon. Подходит и для первой установки и для апгрейда. Схему БД мигрировать руками не нужно — `run` сам прогоняет миграции на старте (идемпотентно, по `PRAGMA user_version`): старая БД доводится до актуальной формы автоматически.

Удаление:

```bash
curl -fsSL https://github.com/belotserkovtsev/ladon/releases/latest/download/uninstall.sh \
  | sudo bash
```

Опциональные env-переменные (для нестандартных сетапов): `IPSET_ENGINE`,
`IPSET_MANUAL`, `LADON_PREFIX`, `LADON_CONFIG_DIR` — см. дефолты в
[`release/install.sh`](../release/install.sh).

---

## Установка вручную

Если хочешь понимать что происходит, или у тебя нестандартный сетап — ниже
пошаговая версия того же что делает `install.sh`. Поддерживается Debian/Ubuntu
с WireGuard, dnsmasq и fwmark-based routing через туннель наружу
(stun0 / wg1 / hysteria / etc.).

## 1. Зависимости

```bash
apt update
apt install ipset iptables-persistent sqlite3
```

Убедись что dnsmasq настроен с детальным логом. В `/etc/dnsmasq.d/gateway.conf`
должно быть что-то вроде:

```
log-queries=extra
log-facility=/var/log/dnsmasq.log
```

После изменения — `systemctl restart dnsmasq`, проверь `tail -f /var/log/dnsmasq.log`:
должны появляться строки вида `query[A] domain from peer_ip` и `reply domain is ip`.

## 2. Установка бинаря

```bash
ARCH=amd64    # или arm64 для Raspberry Pi / ARM-серверов
# Возьмём последнюю опубликованную версию.
# Можно зафиксировать конкретную — например, TAG=v0.2.0
TAG=$(curl -sSL "https://api.github.com/repos/belotserkovtsev/ladon/releases/latest" \
  | grep '"tag_name":' | head -1 | cut -d'"' -f4)
echo "installing $TAG for $ARCH"

mkdir -p /opt/ladon/state /etc/ladon
cd /tmp
curl -L -O "https://github.com/belotserkovtsev/ladon/releases/download/${TAG}/ladon-linux-${ARCH}.tar.gz"
tar xzf ladon-linux-${ARCH}.tar.gz

# Распаковался каталог ladon-linux-${ARCH}-${TAG}/
cd ladon-linux-${ARCH}-${TAG}

install -m 0755 ladon             /opt/ladon/ladon
install -m 0644 ladon.service     /etc/systemd/system/
install -m 0644 manual-allow.txt.example /etc/ladon/manual-allow.txt
install -m 0644 manual-deny.txt.example  /etc/ladon/manual-deny.txt

# Extensions — преднастроенные allow-списки (ai, twitch, ...). Опциональны,
# подключаются по имени через config.yaml. Полный справочник: docs/extensions.md.
install -d /opt/ladon/extensions
install -m 0644 extensions/*.txt /opt/ladon/extensions/
```

## 3. Подготовка netfilter

```bash
# Три ipset'а с разной ответственностью:
#   ladon_engine — управляется ладоном из probe-driven discovery (hot/cache)
#   ladon_manual — populates dnsmasq из ladon-manual.conf (manual-allow + extensions)
#   ladon_cidr   — статический hash:net для CIDR-блоков из extensions
#                  (Telegram MTProto, Discord voice, etc.) — нужен только если
#                  включаете extensions, объявляющие CIDR-диапазоны
ipset create ladon_engine hash:ip  family inet maxelem 65536
ipset create ladon_manual hash:ip  family inet maxelem 65536 timeout 86400
ipset create ladon_cidr   hash:net family inet maxelem 65536

# Три iptables-правила в WG_ROUTE — все три ведут в один и тот же fwmark 0x1.
# Пример для pipeline, где peer 10.10.0.2 → fwmark 0x1 → tunnel:
for SET in ladon_engine ladon_manual ladon_cidr; do
  iptables -t mangle -A WG_ROUTE \
    -s 10.10.0.2/32 \
    -m set --match-set "$SET" dst \
    -j MARK --set-mark 0x1
done

# Сохранить для переживания ребута
mkdir -p /etc/iptables
iptables-save > /etc/iptables/rules.v4
ipset save    > /etc/iptables/ipsets
systemctl enable netfilter-persistent
```

**Почему разные ipset'ы:**

- `ladon_engine` — динамический, ладон периодически пересоздаёт его на основе hot/cache → reconcile удаляет лишнее.
- `ladon_manual` — populated dnsmasq'ом синхронно при резолве через `ipset=/domain/ladon_manual` директивы, которые ладон записывает в `/etc/dnsmasq.d/ladon-manual.conf`. Если бы он был одним ipset'ом с `ladon_engine`, ладон при reconcile удалял бы IP-шки которые добавил dnsmasq и про которые ладон не знает. Timeout=86400 — естественная эвикция стейл-IP'шек, dnsmasq refresh'ит timeout при каждом резолве.
- `ladon_cidr` — `hash:net` для CIDR-диапазонов из extensions (например, Telegram MTProto data-plane на `91.108.0.0/16`). Заполняется ладоном при старте из extension-файлов; матчится iptables на уровне dst IP, минуя DNS.

### Capability для dnsmasq (обязательно)

Стандартный пакетный dnsmasq запускается под пользователем `dnsmasq` (а не root) и **по умолчанию не имеет `CAP_NET_ADMIN`** — без этой capability он не может добавлять записи в kernel ipset, даже если `ipset=/domain/set` директивы прописаны. Симптом: dnsmasq резолвит, отвечает клиенту, но `ladon_manual` остаётся пустым, и трафик идёт direct.

Лечится systemd drop-in'ом:

```bash
sudo install -d /etc/systemd/system/dnsmasq.service.d
sudo tee /etc/systemd/system/dnsmasq.service.d/ladon-ipset.conf > /dev/null <<'EOF'
[Service]
AmbientCapabilities=CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW CAP_SETUID CAP_SETGID CAP_CHOWN CAP_DAC_OVERRIDE CAP_FOWNER CAP_SETFCAP CAP_SETPCAP CAP_SYS_CHROOT CAP_KILL
EOF
sudo systemctl daemon-reload
sudo systemctl restart dnsmasq
```

Проверить что заработало:
```bash
dig @127.0.0.1 +short openai.com
sudo ipset list ladon_manual | tail -10
# ↳ должны появиться IP-шки CloudFlare с timeout
```

Подробная схема iptables/ip-rule для cascading gateway (замени `tun0` на
имя твоего upstream-интерфейса):

```
ip rule add fwmark 0x1 table ladon priority 1000
echo '666 ladon' >> /etc/iproute2/rt_tables
ip route replace default dev tun0 table ladon
```

Эта часть обычно настраивается на стороне твоего VPN-стека — ladon
предполагает что routing-таблица и fwmark → интерфейс уже готовы, и просто
наполняет ipset'ы `ladon_engine` / `ladon_manual` / `ladon_cidr`.

## 4. Инициализация и запуск

> **`run` сам разворачивает и мигрирует схему на старте** (`store.Init`,
> идемпотентно по `PRAGMA user_version`): на пустой БД создаст таблицы, на
> существующей догонит до актуальной. `init-db` ниже — явный шаг создать БД
> заранее (рекомендуется в установке, чтобы поймать ошибки до запуска сервиса).

```bash
# Создать схему БД
/opt/ladon/ladon \
  -db /opt/ladon/state/engine.db \
  init-db

# Включить сервис
systemctl daemon-reload
systemctl enable --now ladon

# Проверить
systemctl status ladon
journalctl -u ladon -f
```

Через минуту в логе должны начать появляться строки вида:

```
probe example.com → HOT (tcp_connect_failed, 800ms)
ipset ladon_engine: +5 -0 (total 5, etlds expanded 1)
```

## 5. Проверка работы

```bash
# Сколько доменов собрал
sqlite3 /opt/ladon/state/engine.db \
  "SELECT state, COUNT(*) FROM domains GROUP BY state"

# Сколько IP в каждом ipset
for SET in ladon_engine ladon_manual ladon_cidr; do
  echo -n "$SET: "; ipset list "$SET" -t 2>/dev/null | grep '^Number'
done

# Последние 10 blocked-вердиктов. verdict штампуется только на batch-пути;
# inline-проба оставляет verdict NULL, поэтому WHERE verdict='blocked' их не
# покажет — пустой результат на свежей БД это нормально.
sqlite3 -column /opt/ladon/state/engine.db \
  "SELECT domain, verdict, failure_reason, created_at
   FROM probes
   WHERE verdict = 'blocked'
   ORDER BY created_at DESC LIMIT 10"
```

## 6. Обновление manual-списков

```bash
# Добавить домен в always-tunnel list
echo "myblocked.com" >> /etc/ladon/manual-allow.txt

# Добавить в never-touch list
echo "mybank.ru" >> /etc/ladon/manual-deny.txt

# Перечитать (engine читает только при старте)
systemctl restart ladon
```

## 7. Удаление

```bash
systemctl disable --now ladon
rm /etc/systemd/system/ladon.service
rm -rf /opt/ladon /etc/ladon

# Снести iptables-правила и ipset'ы (зеркало Step 3)
for SET in ladon_engine ladon_manual ladon_cidr; do
  iptables -t mangle -D WG_ROUTE -s 10.10.0.2/32 \
    -m set --match-set "$SET" dst -j MARK --set-mark 0x1
  ipset destroy "$SET"
done
iptables-save > /etc/iptables/rules.v4
ipset save    > /etc/iptables/ipsets
```

## Troubleshooting

**Engine запустился, но ipset пустой после часа**

Проверь что dnsmasq реально пишет лог:
```bash
tail -f /var/log/dnsmasq.log
```
Если молчит — убедись что `log-queries=extra` применён, `systemctl restart dnsmasq`.

**Логи показывают `ipset "ladon_engine" not found — skipping`**

Ты не создал ipset до старта engine (или они не пережили ребут — `netfilter-persistent` не включён, см. Step 3). Создай и перезапусти сервис:
```bash
ipset create ladon_engine hash:ip  family inet maxelem 65536
ipset create ladon_manual hash:ip  family inet maxelem 65536 timeout 86400
ipset create ladon_cidr   hash:net family inet maxelem 65536
systemctl restart ladon
```

**Все домены уходят в `hot` хотя direct работает**

Скорее всего на гейте отключён IPv6, но dns_cache забит v6-адресами. Engine в v0.1.0+
сам фильтрует v6 на ingest, но если апгрейдишься со старой версии — почисти:
```bash
sqlite3 /opt/ladon/state/engine.db \
  "DELETE FROM dns_cache WHERE ip LIKE '%:%'"
systemctl restart ladon
```

**Сервис потребляет слишком много CPU**

Уменьши `ProbeBatch` или подними `ProbeInterval` в `engine.Defaults()` (требует
пересборки бинаря). Либо подними `ProbeCooldown` — домены будут пере-пробоваться
реже.

**Рост файла БД / `*.db-wal`**

Ladon сам подрезает БД фоновой стадией maintenance (`MaintenanceInterval`,
дефолт 1ч) — ручной уборки не нужно. На каждом тике: WAL checkpoint в режиме
TRUNCATE (схлопывает `*.db-wal` в основной файл — long-lived read-пул блокирует
пассивный auto-checkpoint, поэтому явно), прунинг `probes` старше `2 ×
Scorer.Window` и `dns_cache` старше `max(DNSFreshness, 7 суток)`. Это только
реклейм места, на корректность не влияет. Сам файл БД при этом не ужимается
(свободные страницы переиспользуются) — для разового сжатия `VACUUM` вручную в
окно обслуживания.
