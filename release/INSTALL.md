# Установка ladon

Пошаговая инструкция для Linux-гейта с WireGuard-подсетью пиров, dnsmasq,
fwmark-based routing через туннель наружу (stun0 / wg1 / hysteria / etc.).

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
TAG=v0.1.0
ARCH=amd64    # или arm64 для Raspberry Pi / ARM-серверов

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
```

## 3. Подготовка netfilter

```bash
# Создать ipset куда engine будет класть IP заблокированных доменов
ipset create prod hash:ip family inet maxelem 65536

# Добавить правило в твою существующую mangle-цепочку WG_ROUTE.
# Пример для pipeline, где peer 10.10.0.2 получает fwmark 0x1 → таблица enigma → stun0:
iptables -t mangle -A WG_ROUTE \
  -s 10.10.0.2/32 \
  -m set --match-set prod dst \
  -j MARK --set-mark 0x1

# Сохранить для переживания ребута
mkdir -p /etc/iptables
iptables-save > /etc/iptables/rules.v4
ipset save    > /etc/iptables/ipsets
systemctl enable netfilter-persistent
```

Подробная схема iptables/ip-rule для cascading gateway:

```
ip rule add fwmark 0x1 table enigma priority 1000
echo '666 enigma' >> /etc/iproute2/rt_tables
ip route replace default dev stun0 table enigma
```

(эта часть обычно уже настроена на вашем гейте — если нет, см. документацию
к EN1GMA / аналогичному стеку)

## 4. Инициализация и запуск

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
ipset prod: +5 -0 (total 5, etlds expanded 1)
```

## 5. Проверка работы

```bash
# Сколько доменов собрал
sqlite3 /opt/ladon/state/engine.db \
  "SELECT state, COUNT(*) FROM domains GROUP BY state"

# Сколько IP в ipset
ipset list prod -t | grep entries

# Последние 10 вердиктов
sqlite3 -column /opt/ladon/state/engine.db \
  "SELECT d.domain, d.state, p.latency_ms, p.failure_reason
   FROM domains d JOIN probes p ON p.id = d.last_probe_id
   WHERE d.state = 'hot'
   ORDER BY p.created_at DESC LIMIT 10"
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
ipset destroy prod
iptables -t mangle -D WG_ROUTE -s 10.10.0.2/32 \
  -m set --match-set prod dst -j MARK --set-mark 0x1
```

## Troubleshooting

**Engine запустился, но ipset пустой после часа**

Проверь что dnsmasq реально пишет лог:
```bash
tail -f /var/log/dnsmasq.log
```
Если молчит — убедись что `log-queries=extra` применён, `systemctl restart dnsmasq`.

**Логи показывают `ipset "prod" not found — skipping`**

Ты не создал ipset до старта engine. Создай и перезапусти сервис:
```bash
ipset create prod hash:ip family inet maxelem 65536
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
