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

Одной командой на Debian/Ubuntu (нужны root-права):

```bash
curl -fsSL https://github.com/belotserkovtsev/ladon/releases/latest/download/install.sh \
  | sudo bash
```

Установщик кладёт бинарник в `/opt/ladon/`, состояние — в `/opt/ladon/state/engine.db`,
конфигурацию — в `/etc/ladon/`, поднимает systemd-юнит `ladon.service`.
Зависимости (`dnsmasq`, `ipset`, `iptables`) ставятся отдельно — это твой шлюз, мы не лезем в его базу.

---

## 🔬 Методология

> **Главный вопрос:** когда клиент не может открыть сервис, как отличить
> "DPI режет на пути" от "сервер сам не отвечает / геоблок / мёртв"?

Ответ — **многоуровневая проба** + **arbitration** + **temporal evidence**. Каждый уровень отсекает свой класс false-positive'ов.

### Источник сигнала — пассивное наблюдение

Probe не генерит синтетический трафик. Ladon читает `dnsmasq.log` (`log-queries=extra`) через fsnotify-tailer и реактивно пробивает только те домены, которые **реальные клиенты** запрашивали. Каждый probe-кандидат — это домен, к которому юзер уже пошёл.

### Уровень 1 — stage-by-stage probe

```
[DNS] ──► [TCP:443] ──► [TLS handshake] ──► [HTTP read до 32KB]
   │           │              │                     │
   ▼           ▼              ▼                     ▼
 NXDOMAIN    SYN drop      Server alert         поток обрублен,
 timeout     RST           или ClientHello cut  garbage от DPI,
                                                read timeout
```

Каждая стадия — отдельный класс failure'ов. Категории кодов:

| stage  | failure code              | что значит                                    |
|--------|---------------------------|-----------------------------------------------|
| dns    | `dns_nxdomain`            | домен не существует                           |
| dns    | `dns_timeout`             | резолвер не отвечает                          |
| tcp    | `tcp_timeout`             | SYN drop — классика RU-DPI на Meta IPs        |
| tcp    | `tcp_reset`               | RST на SYN — active interception              |
| tcp    | `tcp_refused`             | порт реально закрыт — **сервер**, не DPI      |
| tcp    | `tcp_unreachable`         | ICMP unreachable                              |
| tls    | `tls_handshake_timeout`   | ClientHello уехал, ничего обратно             |
| tls    | `tls_reset`               | RST посреди handshake                         |
| tls    | `tls_eof`                 | TCP закрылся "тихо" mid-handshake             |
| tls    | `tls_alert`               | server активно ответил TLS alert              |
| tls    | `mtls_required`           | alert 116 — Apple Push, FindMy, iCloud Relay  |
| http   | `http_cutoff`             | поток обрублен mid-response                   |
| http   | `http_reset`              | RST во время чтения тела                      |
| http   | `http_timeout`            | поток stalled                                 |
| http   | `http_error`              | гарбидж от DPI вместо валидного HTTP          |

HTTP-стадия читает до 32KB — окно намеренно покрывает RU-DPI signature
"обрыв CDN/хостинга на 14-34KB передачи".

### Уровень 2 — server-active vs path-active

Ключевое различение для anti-FP:

```
┌─ server-active rejection (server сказал "нет") ──────────┐
│  tcp_refused, tls_alert, mtls_required                   │
│  → server reachable, отказ — его policy, не DPI          │
│  → IGNORE (не тоннелируем)                               │
└──────────────────────────────────────────────────────────┘

┌─ path-active rejection (что-то режет на пути) ───────────┐
│  *_timeout, *_reset, *_eof, http_cutoff, http_error      │
│  → server-side не подтверждено, нужно arbitrate          │
│  → HOT кандидат                                          │
└──────────────────────────────────────────────────────────┘
```

`tls_alert` детектится через `errors.As(err, &tls.AlertError{})` плюс
string-fallback на `"remote error: tls: ..."` (Go stdlib quirk: внутренний
`tls.alert` ≠ exported `tls.AlertError` для non-QUIC transport).
`mtls_required` отдельным кодом для observability.

### Уровень 3 — exit-compare arbitration

Path-active failures ещё не достаточно для Hot. Решение: **второе мнение из другого vantage'а**.

```
                один и тот же домен, та же проба
                            │
            ┌───────────────┴───────────────┐
            ▼                               ▼
    ┌───────────────┐              ┌────────────────┐
    │  LOCAL probe  │              │  REMOTE probe  │
    │  (gateway,    │              │  (out-of-region │
    │   через ISP   │              │   probe-server) │
    │   и DPI)      │              │                 │
    └───────┬───────┘              └────────┬────────┘
            │                               │
            └─────────────┬─────────────────┘
                          ▼
                ┌─────────────────────────────┐
                │   exit-compare matrix:      │
                │                             │
                │   L=OK              → IGNORE│  direct works
                │   L=FAIL  R=OK      → HOT   │  real DPI
                │   L=FAIL  R=FAIL    → IGNORE│  server-side, methodological FP
                │   L=FAIL  R=dead    → HOT   │  no opinion, sticky local
                └─────────────────────────────┘
```

`L=FAIL R=FAIL` — самый ценный кейс. Если **обе** точки видят failure,
значит проблема **в самом сервере** или в общем пути за обоими vantage'ами,
а не в DPI на пути конкретно local-клиента. Это отсекает FP типа "сервер
mTLS-required" / "geoblock с обеих сторон" / "сервер просто медленный".

Без exit-compare любой случайно медленный сервер попадал бы в Hot. С ним
remaining false-positive rate падает до единиц процентов.

### Уровень 4 — temporal arbitration (hot → cache)

Один failure ≠ окончательный приговор. Сервер мог быть перегружен на
момент пробы.

```
domain первый раз fail'ится
         │
         ▼
   hot_entries (TTL 24h)
         │  probe регулярно re-probes
         │  если за 24h ≥50 fails → реально устойчиво
         ▼
   scorer promotion → cache_entries (no TTL)
         │
         ▼
   считается надёжно заблокированным,
   тоннелируется до явного re-evaluation
```

Threshold ≥50 fails / 24h при probe.cooldown=5min даёт минимум ~4 часов
устойчивого failure'а — отсекает блипы провайдера.

### Что **не** детектируется

| класс блока | почему probe не видит | workaround |
|---|---|---|
| **L7-fingerprint** (DPI режет конкретный ClientHello, например Chrome 120) | probe использует Go's stdlib fingerprint — у него другой паттерн в ClientHello (порядок ciphers, отсутствие GREASE, ALPN list). DPI его не блеклистит → probe видит "OK" | `manual-allow.txt` — operator override |
| **Throttling** (DPI шейпит до сотен кбит/с вместо блока) | probe видит "медленно но работает" → IGNORE | speed-probe (read 32KB с измерением throughput) — отдельная фаза |
| **Domainless flows** (Telegram mobile / Discord voice / WhatsApp calls на hardcoded IP) | dnsmasq не получает DNS query → tailer ничего не пикапит | CIDR-extensions (bundled list known DC ranges) — отдельная фаза |
| **DNS-only blocks** (DPI poison'ит ISP-resolver на NXDOMAIN) | ladon резолвит через `1.1.1.1@stun0` (свой VPN-туннель), не через ISP-resolver | использовать апстрим-DNS, который не cooperates с ISP |
| **Адаптивный DPI** (блокирует первые попытки, пропускает повторные) | probe — статистический, повторяется, обычно выходит на устойчивое поведение | в большинстве случаев handled через temporal arbitration |

### Архитектурно

```
                           clients (LAN)
                                │
                                │ DNS query
                                ▼
                   ┌───────────────────────┐
                   │      dnsmasq.log      │
                   └────────────┬──────────┘
                                │ fsnotify tail
                                ▼
                   ┌───────────────────────┐
                   │     tailer/watcher    │ ingest в SQLite
                   └────────────┬──────────┘
                                │
              ┌─────────────────┴─────────────────┐
              ▼                                   ▼
     inline fast-path                       batch worker
     (sub-second, local-only)               (interval 2s, batch 4)
              │                                   │
              ▼                                   ▼
        ┌─────────────────────────────────────────────┐
        │  prober: LocalProber + (опц.) RemoteProber  │
        │  DNS → TCP → TLS-stage → HTTP-stage         │
        └────────────────────┬────────────────────────┘
                             ▼
                   ┌──────────────────┐
                   │ decision.Classify │ exit-compare matrix
                   └────────┬──────────┘
                            ▼
              ┌──────────────────────────┐
              │  hot_entries (TTL 24h)   │
              └────────┬─────────────────┘
                       │
                       ▼ scorer (≥50 fails / 24h)
              ┌──────────────────────────┐
              │  cache_entries (no TTL)  │
              └────────┬─────────────────┘
                       │
                       ▼ ipset-syncer
                ┌────────────────┐
                │ kernel ipset:  │
                │ ladon_engine   │ probe-driven
                │ ladon_manual   │ extensions + manual-allow
                └────────┬───────┘
                         │
                         ▼ iptables mangle PREROUTING
                  fwmark 0x1 → table 100 → tunnel
```

Состояние домена:

| state | значит | как попадает | как уходит |
|---|---|---|---|
| `new` | видели DNS-query, ещё не пробовали | первая ingest-строка | после первого probe |
| `ignore` | direct работает, тоннель не нужен | probe прошёл все стадии (или server-active rejection) | следующий probe может вернуть в цикл |
| `hot` | probe + arbitration сказали "блок" — в ipset на 24h | TLS/TCP/HTTP path-active fail + (если remote) подтверждение | TTL истёк ИЛИ scorer перевёл в cache |
| `cache` | устойчивый блок — в ipset навсегда | scorer: ≥50 fails / 24h в hot | пока вручную (cache-demotion на обратном пробе — backlog) |

---

## 🛠 Конфигурация

YAML-файл, путь передаётся флагом `-config`. Без файла — дефолты из
[`internal/engine/engine.go`](internal/engine/engine.go).

### Базовый конфиг

```yaml
logfile: /var/log/dnsmasq.log
manual_allow: /etc/ladon/manual-allow.txt
manual_deny: /etc/ladon/manual-deny.txt

probe:
  mode: local            # local | exit-compare
  timeout: 800ms         # на стадию (DNS / TCP / TLS / HTTP)
  cooldown: 5m           # минимальный интервал между probe одного домена
  concurrency: 8         # семафор для inline fast-path

scorer:
  interval: 10m
  window: 24h
  fail_threshold: 50     # ≥N fails в window → промоушн hot → cache

ipset:
  engine_name: ladon_engine   # probe-driven hot/cache
  manual_name: ladon_manual   # для manual-allow + extensions
  interval: 30s               # safety reconcile, hot-events триггерят сразу

hot_ttl: 24h
dns_freshness: 6h        # после этого IP из dns_cache считается устаревшим
```

### CLI

Дополнение к YAML — для override на ходу:

```
ladon -db <path> [-config <path>] run [-from-start] \
  [-manual-allow <path>] [-manual-deny <path>] <dnsmasq-log-path>
```

`-manual-allow` / `-manual-deny` перебивают одноимённые YAML-поля если оба заданы.
Тонкие knobs (timeouts, scorer, ipset) — только через файл.

### Manual lists

Два файла, по одному домену на строку, `#` — комментарий, поддерживаются eTLD+1 apex'ы (покрывают все subdomain'ы).

```
/etc/ladon/manual-allow.txt   # домены, которые ВСЕГДА в туннеле (минуют probe)
/etc/ladon/manual-deny.txt    # домены, которые НИКОГДА не пробуются и не тоннелируются
```

Use cases:
- **manual-allow**: L7-fingerprint blocks (rutracker.org), сервисы где probe не видит блок но реальный браузер видит, операторские override'ы
- **manual-deny**: внутренние LAN-домены, банки и госуслуги (ломаются через VPN), healthcheck endpoints (не нужны в probe-истории)

### Extensions — bundled пресеты

Тематические подборки доменов одной строкой в YAML. Шипаются с релизом в
`/opt/ladon/extensions/<name>.txt`.

```yaml
allow_extensions:
  - ai
  - twitch
  - tiktok

# deny_extensions:
#   - my-corp-internal       # bundled deny-пресетов не шипается, оператор пишет свой
# extensions_path: /opt/ladon/extensions   # default
```

Доступные allow-пресеты:

| имя | покрытие |
|---|---|
| `ai` | OpenAI / ChatGPT, Anthropic / Claude |
| `twitch` | twitch.tv + CDN |
| `tiktok` | TikTok / ByteDance overseas (core, regional CDN, backbone, SDK) |

Подробности и формат файлов — в [release/extensions/README.md](release/extensions/README.md).
Свои подборки кладутся в тот же каталог и подключаются по имени.

### Exit-compare

Поднимает arbitration probe pipeline до уровня "L+R verdict matrix" вместо одного local. Требует probe-server в out-of-region vantage point (чужой VPS, residential ISP, 4G-модем).

```yaml
probe:
  mode: exit-compare
  timeout: 800ms
  remote:
    url: https://my-probe-server.example.com/probe
    timeout: 2s
    auth_header: Authorization
    auth_value: Bearer mysecrettoken
```

HTTP-контракт probe-server'а описан в [`docs/probe-api.md`](docs/probe-api.md).
Референсная Go-имплементация переиспользует `internal/prober.LocalProber` —
лежит в [`probe-server/ladon/`](probe-server/ladon/), запускается с тем же
`-timeout`, что engine использует для local. Inline fast-path всегда только
local — remote дёргается только batch-worker'ом.

### Очистка состояния — `prune`

Сбросить накопленные данные: после смены логики probe (включили
exit-compare, и cache мог содержать FP, которые новая логика отсеяла бы),
или просто отрезать старую историю проб для размера БД.

```sh
# что бы удалилось (без выполнения)
ladon -db /opt/ladon/state/engine.db prune -cache -dry-run

# удалить весь cache
ladon -db /opt/ladon/state/engine.db prune -cache

# удалить probe-ряды старше конкретной даты (RFC3339)
ladon -db /opt/ladon/state/engine.db prune -probes -before 2026-04-16T11:14:00Z

# полная очистка трёх таблиц до отметки
ladon -db /opt/ladon/state/engine.db prune -cache -hot -probes -before 2026-04-16T11:14:00Z
```

| флаг | действие |
|---|---|
| `-cache` | удаляет `cache_entries` |
| `-hot` | удаляет `hot_entries` |
| `-probes` | удаляет `probes` |
| `-before <RFC3339>` | фильтр по дате; без флага удаляет всё |
| `-dry-run` | показать счётчики без выполнения |

После prune движок сбрасывает `state` в `new` для доменов, у которых не
осталось ни hot, ни cache записи — на следующем DNS-запросе домен пройдёт
пайплайн заново.
