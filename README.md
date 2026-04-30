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

---

## ⚡ Производительность

**От первого DNS-запроса до правила в kernel ipset — полсекунды в среднем.** В постоянный список попадает только то, что подтвердилось ≥50 раз за сутки — моргания провайдера не доезжают.

| Метрика | Значение |
|---|---|
| Реакция на новый блок | **0.3 – 1.1 с** (≈0.5 с) |
| Пропускная способность | **~65 доменов/с** на 2 CPU |
| Накладные расходы пайплайна | **~50 мс** сверх сети |
| RSS | **~20 МБ** |

Воспроизвести числа: `go test -run TestPipeline ./internal/engine/`

---

## 💡 Как это работает

```mermaid
flowchart LR
    Client([🖥 Клиент]) -->|"DNS-запрос"| DNS[dnsmasq]
    DNS -->|"наблюдение"| Ladon{Ladon}
    Ladon -->|"пробит достижимость"| Probe((TCP/TLS))
    Probe -->|"работает"| Direct[🌐 direct]
    Probe -->|"не работает"| Ipset[(kernel ipset)]
    Ipset -->|"трафик к этим IP"| Tunnel[🔒 туннель]

    classDef client fill:#e8f4fd,stroke:#1976d2,color:#0d47a1
    classDef proc fill:#fff3e0,stroke:#ef6c00,color:#3e2723
    classDef store fill:#fce4ec,stroke:#c2185b,color:#880e4f
    classDef path fill:#e8f5e9,stroke:#2e7d32,color:#1b5e20
    class Client client
    class DNS,Ladon,Probe proc
    class Ipset store
    class Direct,Tunnel path
```
<details>
<summary><b>🔌 Глубокая схема пайплайна</b></summary>

```mermaid
flowchart TB
    subgraph observe["🔎 Наблюдение"]
        direction LR
        DNS[/"dnsmasq log<br/>log-queries=extra"/]
        TAIL["tailer<br/><i>fsnotify, kernel events</i>"]
        WATCH["watcher<br/><i>нормализация + ingest</i>"]
        DOMS[("domains")]
        CACHE[("dns_cache")]
        DNS -->|строка лога| TAIL
        TAIL -->|"query[A] X from peer"| WATCH
        TAIL -->|"reply X is IP"| CACHE
        WATCH --> DOMS
    end

    subgraph decide["🩺 Проверка и вердикт"]
        direction LR
        WORKER["probe-worker<br/><i>batch раз в 2с</i>"]
        PROBE["prober<br/><i>TCP + TLS-SNI<br/>параллельные dials</i>"]
        DEC{{"decision"}}
        HOT[("hot_entries<br/>TTL 24ч")]
        IGN["state = ignore"]
        WORKER -->|"кандидаты из domains"| PROBE
        PROBE --> DEC
        DEC -->|"TCP/TLS fail"| HOT
        DEC -->|"direct OK"| IGN
    end

    subgraph promote["🧠 Долгосрочная память"]
        direction LR
        SCORE["scorer<br/><i>раз в 10 мин</i>"]
        CEN[("cache_entries<br/>без TTL")]
        SCORE -->|"≥50 fails / 24ч"| CEN
    end

    subgraph apply["⚙️ Применение (kernel)"]
        direction LR
        SYNC["ipset-syncer<br/><i>event-driven + 30с safety</i>"]
        MAN[("manual-allow + extensions")]
        DNSMASQ["dnsmasq<br/><i>ipset= directives</i>"]
        ENG[("kernel ipset<br/>ladon_engine")]
        MNL[("kernel ipset<br/>ladon_manual")]
        IPT["iptables mangle"]
        TUN["→ upstream tunnel"]
        DIR["→ direct egress"]
        SYNC -->|"ipset add / del"| ENG
        MAN -->|"writes ipset= dirs"| DNSMASQ
        DNSMASQ -->|"sync на резолве,<br/>walks CNAME"| MNL
        ENG --> IPT
        MNL --> IPT
        IPT -->|"dst ∈ ladon_*<br/>MARK 0x1"| TUN
        IPT -->|"иначе"| DIR
    end

    TAIL -. "inline fast-path<br/>(для нового домена)" .-> PROBE
    DOMS --> WORKER
    CACHE -->|"точные IP"| PROBE
    HOT --> SCORE
    HOT --> SYNC
    CEN --> SYNC

    classDef store fill:#e8f4fd,stroke:#1976d2,color:#0d47a1
    classDef proc fill:#fff3e0,stroke:#ef6c00,color:#3e2723
    classDef decisionNode fill:#fce4ec,stroke:#c2185b,color:#880e4f
    classDef kernelNode fill:#e8f5e9,stroke:#2e7d32,color:#1b5e20
    classDef source fill:#f3e5f5,stroke:#6a1b9a,color:#4a148c
    class DNS source
    class TAIL,WATCH,WORKER,PROBE,SCORE,SYNC,DNSMASQ proc
    class DOMS,CACHE,HOT,CEN,MAN store
    class DEC decisionNode
    class ENG,MNL,IPT,TUN,DIR,IGN kernelNode
```

</details>

<details>
<summary>🔌 Состояния домена</summary>

Состояние хранится в `domains.state`; «живые» списки для роутинга — в `hot_entries` и `cache_entries`.

| Состояние | Что значит | Как попадает | Как уходит |
|---|---|---|---|
| `new` | Видели DNS-query, но ещё не пробовали коннектиться | Первая ingest-строка | После первого probe |
| `ignore` | Прямой путь работает, туннель не нужен | Probe прошёл TCP+TLS | Следующий probe может вернуть в цикл, если начнёт падать |
| `hot` | Probe обнаружил блок — домен временно в ipset | Probe упал на TCP или TLS | Запись в `hot_entries` снимается через 24 ч после последнего fail; при ≥50 подтверждениях scorer переводит в `cache` |
| `cache` | Стабильно заблокирован, в ipset навсегда | Scorer: ≥50 fails за 24 ч | Только вручную (cache-demotion на обратном пробе — в бэклоге) |

</details>

---

## 🛠 Конфигурация

Основной способ — YAML-файл, путь которого передаётся флагом `-config`. Без файла движок едет на дефолтах из [`internal/engine/engine.go`](internal/engine/engine.go).

Пример `/etc/ladon/config.yaml`:

```yaml
logfile: /var/log/dnsmasq.log
manual_allow: /etc/ladon/manual-allow.txt
manual_deny: /etc/ladon/manual-deny.txt

probe:
  mode: local         # local | exit-compare
  timeout: 800ms
  cooldown: 5m
  concurrency: 8

scorer:
  interval: 10m
  window: 24h
  fail_threshold: 50

ipset:
  engine_name: ladon_engine # probe-driven hot/cache
  manual_name: ladon_manual # populates dnsmasq'ом для manual-allow + extensions
  cidr_name:   ladon_cidr   # hash:net для CIDR-блоков из extensions (Telegram MTProto и т.п.)
  interval: 30s

hot_ttl: 24h
dns_freshness: 6h
```

### CLI-флаги

Дополнение к YAML — для простых случаев и для разовых override'ов:

```
ladon -db <path> [-config <path>] run [-from-start] [-manual-allow <path>] [-manual-deny <path>] <dnsmasq-log-path>
```

Пути (`-manual-allow`, `-manual-deny`) перебивают одноимённые поля YAML, если заданы оба. Тонкие knobs задаются только через файл.

### Extensions — преднастроенные allow/deny-списки

Ladon шипает **allow-подборки** доменов — сервисы, которые гео-блокируют российский регион со своей стороны (probe их распознать не может — TLS handshake проходит, но сервис говорит «not available in your country»).

Для deny-списков механизм работает зеркально через `deny_extensions:`, но **bundled deny-пресетов не шипается** — что держать вне тоннеля зависит от среды оператора. Ведите список в `/etc/ladon/manual-deny.txt` или напишите свой deny-preset.

Подключаются опционально по имени:

```yaml
allow_extensions:
  - ai
  - twitch
  - tiktok
# deny_extensions:
#   - my-corp-internal
# extensions_path: /opt/ladon/extensions   # default
```

Доступные bundled allow-пресеты:

| Имя | Покрытие |
|---|---|
| `ai` | OpenAI / ChatGPT, Anthropic / Claude |
| `twitch` | twitch.tv + CDN |
| `tiktok` | TikTok / ByteDance overseas (core, regional CDN, backbone, SDK) |

Полный список — в `/opt/ladon/extensions/<name>.txt`. Свои подборки (allow или deny) можно положить в тот же каталог (или в `extensions_path` куда угодно) и подключить в config так же по имени. Подробности в [release/extensions/README.md](release/extensions/README.md).

Обычные `/etc/ladon/manual-allow.txt` и `/etc/ladon/manual-deny.txt` продолжают работать параллельно — extensions просто удобнее для тематических подборок, которые хочется включать/выключать одной строкой.

### Очистка состояния — `ladon prune`

Иногда нужно сбросить накопленные данные руками — например, после смены логики probe (включили exit-compare, и cache мог содержать FP, которые новая логика отсеяла бы), или просто отрезать старую историю проб для размера БД.

```sh
# Что бы удалилось (без выполнения)
ladon -db /opt/ladon/state/engine.db prune -cache -dry-run

# Удалить весь cache
ladon -db /opt/ladon/state/engine.db prune -cache

# Удалить probe-ряды старше конкретной даты (RFC3339)
ladon -db /opt/ladon/state/engine.db prune -probes -before 2026-04-16T11:14:00Z

# Полная очистка трёх таблиц до какой-то отметки
ladon -db /opt/ladon/state/engine.db prune -cache -hot -probes -before 2026-04-16T11:14:00Z
```

Флаги:

| флаг | действие |
|---|---|
| `-cache` | удаляет `cache_entries` |
| `-hot` | удаляет `hot_entries` |
| `-probes` | удаляет `probes` |
| `-before <RFC3339>` | фильтр по дате; без флага удаляет всё |
| `-dry-run` | показать счётчики без выполнения |

После `prune` движок автоматически сбрасывает `state` в `new` для доменов, у которых не осталось ни hot, ни cache записи — на следующем DNS-запросе домен пройдёт пайплайн заново.

### Exit-compare через внешний пробинг-сервер

Локальная проба видит мир глазами шлюза. Это хорошо ловит DPI-блоки, которые цепляются ровно к тому пути, по которому идёт клиент. Но даёт ложные срабатывания, когда сам домен не отвечает на :443 — `imap.gmail.com` живёт на :993, `bgp.he.net` на 8080, и т.д. Локальный probe в таких случаях видит «TCP fail» и тащит домен в hot, хотя блока нет.

`mode: exit-compare` решает это, добавляя вторую точку зрения: HTTP-сервер на твоей стороне, который пробит тот же домен из другого vantage point (residential ISP, 4G-модем, офшорная VPS, что угодно).

```yaml
probe:
  mode: exit-compare
  remote:
    url: https://my-probe-server.example.com/probe
    timeout: 2s
    auth_header: Authorization
    auth_value: Bearer mysecrettoken
```

Логика вердикта на batch-перепробе:

| local | remote | вердикт |
|---|---|---|
| OK | (не запускается) | Ignore — direct работает |
| FAIL | OK | **Hot** — настоящий DPI-блок, снаружи домен живой |
| FAIL | FAIL | **Ignore** — methodological FP (порт не тот / мёртвый сервер / domain не отвечает ниоткуда) |
| FAIL | unavailable | **Hot** — твой proб-сервер недоступен (timeout / non-200 / network) → не overrule'им, остаёмся с локальным вердиктом. Reason помечен `remote:unavailable:...` |

HTTP-контракт описан в [`docs/probe-api.md`](docs/probe-api.md), референсная имплементация на Go — в [`examples/probe-server/`](examples/probe-server/).

---

## 🔍 Наблюдаемость

Всё состояние живёт в SQLite. Полезные запросы:

```bash
DB=/opt/ladon/state/engine.db

# Распределение по состояниям
sqlite3 "$DB" "SELECT state, COUNT(*) FROM domains GROUP BY state"

# Топ-15 «горячих» доменов по количеству визитов
sqlite3 -column "$DB" \
  "SELECT domain, hit_count, state FROM domains
   WHERE state IN ('hot','cache')
   ORDER BY hit_count DESC LIMIT 15"

# Сколько IP сейчас в kernel ipset'ах
sudo ipset list ladon_engine -t | grep entries
sudo ipset list ladon_manual -t | grep entries

# Причины попадания в hot
sqlite3 -column "$DB" \
  "SELECT d.domain, p.failure_reason, p.latency_ms
   FROM domains d JOIN probes p ON p.id = d.last_probe_id
   WHERE d.state = 'hot' ORDER BY p.created_at DESC LIMIT 20"

# Промоушны в cache за последний час
sqlite3 -column "$DB" \
  "SELECT domain, promoted_at, reason FROM cache_entries
   WHERE promoted_at > datetime('now','-1 hour')"
```

Live-логи: `journalctl -u ladon -f`.

---

## 🏗 Разработка

```sh
# Unit + race-тесты (быстро, без сети)
go test -race -short ./...

# End-to-end пайплайн-перфтесты (живые TCP-timeout на RFC 5737 192.0.2.1)
go test -v -run TestPipeline ./internal/engine/

# Кросс-компиляция под Linux
GOOS=linux GOARCH=amd64 go build -o dist/ladon ./cmd/ladon
```

### Структура пакетов

| Путь | Ответственность |
|---|---|
| `cmd/ladon/` | CLI: `init-db`, `run`, `probe`, `observe`, `list`, `hot`, `tail` |
| `internal/tail/` | fsnotify-based follower для файла лога |
| `internal/dnsmasq/` | Парсер log-строк (query / reply / cached / forwarded) |
| `internal/watcher/` | Нормализация и ingest DNS-событий |
| `internal/storage/` | SQLite access layer + embedded schema |
| `internal/etld/` | Обёртка над `golang.org/x/net/publicsuffix` |
| `internal/prober/` | Probe: `LocalProber` (TCP + TLS-SNI) и `RemoteProber` (HTTP к внешнему сервису) за общим `Prober`-интерфейсом |
| `internal/config/` | Загрузка и валидация YAML-конфига |
| `internal/decision/` | Классификация probe → {Ignore, Hot} |
| `internal/dnsmasqcfg/` | Генерация `/etc/dnsmasq.d/ladon-manual.conf` для manual-allow + extensions |
| `internal/scorer/` | Промоушн hot → cache по количеству fails в окне |
| `internal/manual/` | Загрузчик allow/deny-списков из файлов |
| `internal/ipset/` | Обёртка над CLI `ipset` (Add / Del / Reconcile / Save) |
| `internal/publisher/` | Atomic-write текстового файла с hot-доменами |
| `internal/engine/` | Оркестровка: 6 горутин, каналы, lifecycle |

### CI

[GitHub Actions workflow](.github/workflows/ci.yml) прогоняет на каждый push
в `main` и на каждый PR:

- `go build ./...`
- `go vet ./...`
- `go test -race -short ./...` — unit-тесты с race-детектором.
- `go test -run TestPipeline ./internal/engine/` — end-to-end перфтесты.

---

## 📜 Лицензия

[MIT](LICENSE). Делайте что хотите — форкайте, встраивайте, коммерческое
использование, всё разрешено. Требуется только сохранить упоминание автора
в копиях.
