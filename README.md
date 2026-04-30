<div align="center">

![Ladon](assets/logo-wide.jpg)

# 🩸 Ladon

**Автоматический split-tunneling для VPN-шлюзов в сетях с DPI**

[![CI](https://github.com/belotserkovtsev/ladon/actions/workflows/ci.yml/badge.svg)](https://github.com/belotserkovtsev/ladon/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/belotserkovtsev/ladon?include_prereleases&sort=semver)](https://github.com/belotserkovtsev/ladon/releases)
[![Go](https://img.shields.io/github/go-mod/go-version/belotserkovtsev/ladon)](go.mod)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

</div>

Ladon наблюдает трафик клиентов шлюза, проверяет домены на достижимость и строит список из ip-адресов, подверженных DPI-блокировкам. **За доли секунды**

Задуман для WireGuard-шлюзов с `dnsmasq` и апстрим-туннелем наружу,
но легко адаптируется под любой стек с fwmark-routing и ipset.

---

## 🩸 Ключевые возможности

- **Auto-discovery** — probe-driven обнаружение DPI-заблокированных доменов из живого трафика, без ручных списков
- **Sub-second routing** — от первого DNS-запроса клиента до правила в kernel ipset в среднем 0.5с
- **Долговременная память** — нестабильные блоки исчезают сами через 24ч, стабильные оседают в постоянный cache (≥50 fails / 24ч)
- **Exit-compare валидатор** (опционально) — отдельный probe-сервер на residential ISP / 4G / офшоре отсеивает методологические False Positive
-  **Curated extensions** — готовые allow-подборки (`ai`, `twitch`, `tiktok`, ...) подключаются одной строкой в YAML; deny-списки оператор ведёт сам или пишет свой deny-preset

---

## 📦 Установка

```bash
curl -fsSL https://github.com/belotserkovtsev/ladon/releases/latest/download/install.sh \
  | sudo bash
```

---

## 🔬 Методология

Полный pipeline от DNS-запроса клиента до правила в kernel ipset.

### 1. Source — dnsmasq.log

`dnsmasq` запускается с `log-queries=extra` и пишет в файл строки вида
`query[A] domain from peer` и `reply domain is IP`. Это единственный
источник probe-кандидатов: ladon реагирует на трафик клиентов, не
пробивает синтетический список.

### 2. Tail + parse + ingest

`internal/tail` через fsnotify читает append'ы. `internal/dnsmasq`
парсит строки в события `Query{Domain, Peer}` и `Reply{Domain, IP}`.
`internal/watcher` нормализует домен через `internal/etld` (eTLD+1) и
делает upsert:

- `Query` → `domains` (state=`new` если первый раз) + увеличивает peer_count
- `Reply` → `dns_cache(domain, ip, last_seen_at)`

### 3. Probe trigger

Два независимых driver'а probe:

- **Inline fast-path** — каждый новый домен пробивается синхронно с
  ingest'ом, ограниченный семафором `probe.concurrency` (default 8).
  Только local-probe, без remote. Цель — ~500ms reaction time.
- **Batch worker** — раз в `probe.interval` (2s) выбирает до
  `probe.batch` (4) кандидатов из `domains` с
  `last_probed_at < now − probe.cooldown` (5min). Здесь подключается
  remote-probe в exit-compare режиме.

### 4. Probe stages

`internal/prober.LocalProber.Probe(ctx, domain, ips)`. Если `ips`
переданы (из `dns_cache`) — DNS-стадия пропускается, иначе резолвится
через `net.Resolver`. v6 IPs отбрасываются (gateway routing v4-only).

| stage | действие | failure codes |
|---|---|---|
| DNS  | `LookupIPAddr` | `dns_nxdomain`, `dns_timeout`, `dns_error` |
| TCP  | parallel dial до `MaxIPsToTry`=3 IPs:443, первый success wins, остальные cancel'ятся через shared context | `tcp_timeout`, `tcp_reset`, `tcp_refused`, `tcp_unreachable` |
| TLS  | `tls.DialWithDialer` с `ServerName=domain`, `InsecureSkipVerify=true` (probe — про reachability, не authenticity) | `tls_handshake_timeout`, `tls_eof`, `tls_reset`, `tls_alert`, `mtls_required` |
| HTTP | на live tls.Conn пишется минимальный GET, читается до 32KB через `bufio` + `http.ReadResponse` | `http_cutoff`, `http_reset`, `http_timeout`, `http_error` |

HTTP-окно 32KB подобрано чтобы покрыть RU-DPI сигнатуру обрыва на
14-34KB передачи — без HTTP-стадии handshake выглядит чистым и блок
ускользает.

### 5. categorize

`internal/prober/failures.go::categorize(stage, err)` маппит low-level
ошибку на `FailureCode` через `errors.Is`/`errors.As` chain.
Дополнительно — string-fallback на `"remote error: tls: ..."` для
non-QUIC TLS alert'ов (Go stdlib оборачивает их в неэкспортированный
`tls.alert`, и typed `errors.As` на них не срабатывает; `mtls_required`
выделяется по подстроке `"certificate required"` в alert text).

`FailureCode` делятся на две группы:

- **server-active** — `tcp_refused`, `tls_alert`, `mtls_required`. Сервер
  активно ответил "нет", значит он достижим и DPI не вмешался. Decision
  → `Ignore`, никогда в туннель.
- **path-active** — все timeout/reset/eof/cutoff/error. Сервер не
  подтвердил доступность; кандидат на Hot.

### 6. Remote probe (опционально, только batch)

Если `probe.mode=exit-compare`, batch-worker дополнительно вызывает
`internal/prober.RemoteProber`: HTTP POST на `probe.remote.url` с JSON
`{domain, ips, port, sni}`, Bearer auth, ответ — `RemoteResponse` с
теми же полями (`dns_ok`, `tcp_ok`, `tls_ok`, `tls12_ok`, `tls13_ok`,
`http_ok`, `code`, `reason`). Транспортный fail → `code=remote_unreachable`,
не overrule'ит local. Inline fast-path remote НЕ дёргает.

### 7. Decision

`internal/decision.Classify(local, remote)`:

```
if local.DNSOK == false                      → Ignore
if local.FailureCode is server-active        → Ignore
if local.AllStagesOK                         → Ignore
if remote == nil                             → Hot
if remote.IsTransportFailure                 → Hot (sticky local)
if remote.AllStagesOK                        → Hot (real DPI)
if remote.HasFailure                         → Ignore (methodological FP)
```

Строка `local FAIL + remote FAIL → Ignore` — основная защита от
false-positive: если обе vantage точки видят failure, проблема в самом
сервере или общем пути за обоими, а не в DPI на пути конкретно local-клиента.

### 8. Persistence

`internal/storage` upsert'ит:

- `probes(domain, dns_ok, tcp_ok, tls_ok, http_ok, resolved_ips_json,
  failure_reason, latency_ms, created_at)` — каждая проба, append-only
- `domains.state` ← verdict из шага 7
- если Hot: `hot_entries(domain, expires_at = now + hot_ttl, reason)`,
  `expires_at` обновляется при повторных fail'ах

`failure_reason` хранит `"<failure_code>: <raw err>"` — код grep'абелен
SQL-запросом без отдельной колонки.

### 9. Ipset sync

`internal/ipset` (event-driven при изменении hot/cache + safety reconcile
раз в `ipset.interval` = 30s):

- читает `hot_entries ∪ cache_entries` → активные домены
- для каждого активного домена читает `dns_cache` где
  `last_seen_at > now − dns_freshness` (6h) → активные IPs
- diff с current `ladon_engine` ipset → `ipset add` / `ipset del`

Параллельно `internal/dnsmasqcfg` генерит `/etc/dnsmasq.d/ladon-manual.conf`
из `manual_allow` + extensions. dnsmasq на резолве этих доменов сам
заносит IP в `ladon_manual` ipset через `ipset=` directive (включая CNAME
chain walking). Это второй ipset, отдельный от probe-driven engine.

### 10. Routing (вне ladon, заводится оператором)

```
iptables -t mangle:
  PREROUTING -i <wan> -j LADON_ROUTE_ENGINE   # probe-driven hot/cache
  PREROUTING -i <wan> -j LADON_ROUTE_MANUAL   # extensions + manual-allow

LADON_ROUTE_ENGINE:
  -d 192.168.0.0/16,10.0.0.0/8,127.0.0.0/8 -j RETURN  (LAN bypass)
  -m set --match-set ladon_engine dst -j MARK --set-mark 0x1

ip rule fwmark 0x1 lookup 100
ip route table 100: default dev <tunnel-iface>
```

Любой пакет с dst в `ladon_engine` или `ladon_manual` ipset получает
MARK 0x1 → fwmark routing → table 100 → туннель.

### 11. Background

- **Hot expiry**: запись с `expires_at < now` удаляется автоматически.
  Domain выпадает из ipset на следующем sync.
- **Scorer** (раз в `scorer.interval` = 10min): для каждой `hot_entries`
  считает `probes` где `failure_reason != ""` и `created_at > now − scorer.window` (24h).
  Если count ≥ `scorer.fail_threshold` (50) → upsert в
  `cache_entries(domain, promoted_at, reason)`. cache — без TTL, до явного prune.

### Не покрывается

- **L7-fingerprint blocks** — DPI режет конкретный ClientHello (Chrome 120,
  iOS Safari). Probe использует Go stdlib fingerprint, у него другой
  паттерн в ClientHello → DPI не блеклистит → probe видит "OK".
  Workaround — `manual-allow.txt`.
- **Throttling** — DPI шейпит до сотен кбит/с вместо блока. Probe видит
  "медленно но работает" → Ignore.
- **Domainless flows** — Telegram mobile / Discord voice / WhatsApp calls
  идут на hardcoded IP, dnsmasq не получает DNS-запрос → tailer не
  пикапит → probe не запускается.
- **DNS-only blocks** — DPI poison'ит ISP-resolver. Ladon резолвит через
  свой апстрим (например `1.1.1.1` через VPN) → не видит фальсификацию.

---

## 🛠 Конфигурация

### Файлы

| путь | назначение |
|---|---|
| `/etc/ladon/config.yaml` | основной конфиг (опционально, без него — defaults) |
| `/etc/ladon/manual-allow.txt`, `/etc/ladon/manual-deny.txt` | списки операторских overrides |
| `/opt/ladon/extensions/<name>.txt` | bundled allow/deny-пресеты |
| `/var/log/dnsmasq.log` | источник probe-сигнала (читаем) |
| `/etc/dnsmasq.d/ladon-manual.conf` | генерим для dnsmasq ipset= directives |
| `/opt/ladon/state/engine.db` | SQLite со всем persistent state |

### YAML

```yaml
logfile: /var/log/dnsmasq.log
manual_allow: /etc/ladon/manual-allow.txt
manual_deny: /etc/ladon/manual-deny.txt

probe:
  mode: local            # local | exit-compare
  timeout: 800ms
  cooldown: 5m
  concurrency: 8

scorer:
  interval: 10m
  window: 24h
  fail_threshold: 50

ipset:
  engine_name: ladon_engine
  manual_name: ladon_manual
  interval: 30s

hot_ttl: 24h
dns_freshness: 6h
```

Полный набор полей и defaults — в
[`internal/engine/Defaults()`](internal/engine/engine.go) и
[`release/config.yaml.example`](release/config.yaml.example).

### CLI

```
ladon -db <path> [-config <path>] <subcommand> [args]
```

Подкоманды: `init-db`, `run`, `probe <domain>`, `observe <domain>`,
`list [N]`, `hot`, `tail <log>`, `prune`. Флаги `-manual-allow` /
`-manual-deny` на `run` перебивают одноимённые YAML-поля.

### Manual lists

По одному домену на строку, `#` — комментарий. eTLD+1 apex покрывает
все субдомены.

- `manual-allow.txt` — домены **всегда** в туннеле, минуют probe. Для
  L7-fingerprint blocks (`rutracker.org`) и операторских override'ов.
- `manual-deny.txt` — домены **никогда** не пробуются и не
  тоннелируются. Для банков, госуслуг, корпоративных LAN-сервисов,
  healthcheck endpoints.

### Extensions

```yaml
allow_extensions:
  - ai
  - twitch
  - tiktok
```

Каждый пресет — список доменов в `/opt/ladon/extensions/<name>.txt`,
dnsmasq заносит IP в `ladon_manual` ipset на резолве. Доступные:

| имя | покрытие |
|---|---|
| `ai` | OpenAI/ChatGPT, Anthropic/Claude |
| `twitch` | twitch.tv + CDN |
| `tiktok` | TikTok/ByteDance overseas (core, CDN, backbone, SDK) |

Свои allow/deny подборки кладутся в тот же каталог, подключаются по
имени. Формат — в [release/extensions/README.md](release/extensions/README.md).

### Exit-compare

```yaml
probe:
  mode: exit-compare
  remote:
    url: https://probe-server.example.com/probe
    timeout: 2s
    auth_header: Authorization
    auth_value: Bearer <token>
```

HTTP-контракт — в [`docs/probe-api.md`](docs/probe-api.md). Референсная
Go-реализация probe-server'а — [`probe-server/ladon/`](probe-server/ladon/),
переиспользует тот же `internal/prober.LocalProber`, чтобы local и remote
стадии были семантически идентичны (любое расхождение — про сетевой
путь, не про probe-логику).

### Prune

`ladon prune` чистит `hot_entries` / `cache_entries` / `probes` —
обычно после смены probe-логики или для подрезания истории.
Поддерживает `-dry-run`, `-before <RFC3339>`, комбинации флагов.
Полная справка — `ladon prune -h`. После prune `state` сбрасывается в
`new` для доменов без активных записей.
