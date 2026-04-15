# 🩸 Ladon

[![CI](https://github.com/belotserkovtsev/ladon/actions/workflows/ci.yml/badge.svg)](https://github.com/belotserkovtsev/ladon/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/belotserkovtsev/ladon?include_prereleases&sort=semver)](https://github.com/belotserkovtsev/ladon/releases)
[![Go](https://img.shields.io/github/go-mod/go-version/belotserkovtsev/ladon)](go.mod)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

![Ladon](assets/logo-wide.jpg)

**Автоматический split-tunneling для VPN-шлюзов в сетях с DPI**

Ladon наблюдает трафик клиентов шлюза, проверяет домены на достижимость
напрямую и строит список того, что нужно пустить через VPN, а остальное
оставить идти прямо через провайдера. Ничего не нужно размечать руками —
движок учится сам на поведении пира и реакции сети.

Задуман для WireGuard-шлюзов с `dnsmasq` и апстрим-туннелем наружу,
но легко адаптируется под любой стек с fwmark-routing и ipset.

---

## ⚡ Производительность

| Метрика | Что она значит | Значение |
|---|---|---|
| **Реакция на новый блок** | От момента, когда клиент первый раз запросил домен, до момента, когда соответствующие IP уже лежат в kernel ipset и следующий пакет уйдёт через туннель | **0.3 – 1.1 с** (в среднем 0.5 с) |
| **Накладные расходы пайплайна** | Сколько добавляет движок поверх чистой сетевой задержки probe-а. То есть если probe сам по себе 800 мс, ladon прибавит ~50 мс на чтение лога, парсинг, запись в БД, сигнал ipset-syncer-у | ~50 мс |
| **Пропускная способность** | Сколько новых доменов в секунду движок способен провести через весь цикл «запрос → probe → решение → ipset» при пиковом трафике | ~65 доменов/с (на 2 CPU) |
| **Потребление памяти** | RSS процесса при ~500 наблюдаемых доменов в БД, из которых несколько десятков hot/cache | ~20 МБ |

**Что это даёт пользователю на практике**

Первый TCP-коннект клиента к заблокированному домену обычно падает —
мы физически не успеваем решить за те ~50-100 мс, которые проходят между
DNS-ответом и первым SYN. Но любой нормальный клиент (браузер, мобильное
приложение, Telegram) автоматически ретраит через 1-3 секунды. К этому
моменту ladon уже принял решение и положил IP в ipset, поэтому **ретрай
уходит через туннель и открывается**. Выглядит как «запнулось на секунду
и открылось».

**Разброс 0.3–1.1 секунды объясняется так:**

- **Нижняя граница (~0.3 с)** — DPI присылает мгновенный TCP RST. Probe
  падает сразу же, и цикл замыкается почти только за счёт чтения лога
  и записи в БД.
- **Верхняя граница (~1.1 с)** — DPI просто молчит (drop без ответа).
  Probe ждёт полный таймаут 800 мс, и общая задержка складывается из
  таймаута и накладных расходов.

Все числа воспроизводятся локально:

```sh
go test -run TestPipeline ./internal/engine/
```

Тест бьёт в [TEST-NET-1](https://datatracker.ietf.org/doc/html/rfc5737)
(`192.0.2.1`) — зарезервированный IP, пакеты в который отбрасываются
на апстрим-роутерах; получаем реалистичный «тихий drop» без опоры на
внешнюю сеть.

---

## 💡 Почему Ladon

Привычные режимы на обычном VPN:

- **«Всё через туннель»** — латенси растёт даже для российских сервисов,
  exit-канал становится бутылочным горлом, банки и госуслуги ломаются
  из-за гео-блока.
- **«Всё напрямую»** — заблокированные сайты не открываются.

Ladon держит золотую середину автоматически. Пир клиента ходит напрямую
по умолчанию; как только движок видит, что у некоторого домена прямой
путь не работает, он пропускает его через туннель. Всё это происходит
в течение одной секунды от момента первого запроса.

---

## 📋 TL;DR

1. **Наблюдение.** Tailer читает лог dnsmasq через kernel-события fsnotify
   и получает оба сигнала: кто какой домен запросил и какие IP ему
   отдал upstream. DNS-ответы складываются в `dns_cache` — это тот же
   набор адресов, что видит клиент.
2. **Проверка.** Prober берёт IP из `dns_cache` и выполняет стадийный probe:
   TCP на порт 443 параллельно на несколько IP, затем TLS-handshake с SNI.
   Мы не доверяем цепочке сертификатов, нам нужна только реальная
   достижимость порта.
3. **Вердикт.** Если TCP или TLS падают — домен попадает в `hot_entries`
   (24 часа). Если прямой путь работает — `ignore`.
4. **Память.** Scorer агрегирует повторные неудачи: ≥50 fails за 24 часа
   и домен переходит в `cache_entries` навсегда. Кратковременные сбои
   живут только в hot и не засоряют постоянное состояние.
5. **Маршрутизация.** ipset-syncer собирает union из hot + cache + manual
   allow и атомарно сверяет с kernel ipset `prod`. eTLD+1-агрегация
   подтягивает сиблингов CDN (например, Meta генерирует новые UUID-поддомены
   — один зафейлился, остальные уходят в туннель автоматически). Каждый
   новый Hot триггерит reconcile немедленно через буферный канал, так что
   задержка «решение → правило в ядре» исчисляется десятками миллисекунд.

---

## 🔌 Архитектура

<details>
<summary><b>Схема пайплайна (клик, чтобы развернуть)</b></summary>

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
        MAN[("manual-allow")]
        PROD[("kernel ipset «prod»")]
        IPT["iptables mangle<br/>WG_ROUTE"]
        TUN["→ upstream tunnel"]
        DIR["→ direct egress"]
        SYNC -->|"ipset add / del"| PROD
        MAN --> SYNC
        PROD --> IPT
        IPT -->|"dst ∈ prod<br/>MARK 0x1"| TUN
        IPT -->|"dst ∉ prod"| DIR
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
    class TAIL,WATCH,WORKER,PROBE,SCORE,SYNC proc
    class DOMS,CACHE,HOT,CEN,MAN store
    class DEC decisionNode
    class PROD,IPT,TUN,DIR,IGN kernelNode
```

</details>

### Потоки решений

- **Fast-path** (inline probe): dnsmasq пишет `query[A] X.com from peer` →
  tailer ловит fsnotify-событие → watcher записывает наблюдение → отдельная
  горутина запускает probe немедленно, не дожидаясь тикера воркера.
- **Batch-path** (probe-worker): каждые 2 секунды забирает до 4 кандидатов,
  у которых истёк cooldown. Нужен для перепроверки hot-доменов и когда
  inline-семафор переполнен на пике DNS-флуда.
- **Scorer** проходится раз в 10 минут и промоутит стабильно блокированные
  домены из hot в cache.
- **ipset-syncer** реагирует на сигнал канала при каждом Hot-событии;
  safety-тикер раз в 30 секунд подхватывает что-то, если сигнал потерялся.

---

## 🧭 Состояния домена

Каждый домен, который видит dnsmasq, проходит через конечный автомат.
Состояние хранится в колонке `domains.state`, пара таблиц `hot_entries` и
`cache_entries` хранят «живые» списки для роутинга.

```
                  ┌─── probe: direct OK ──▶ ignore
                  │
 новая            │
 query ──▶ new ───┤
                  │
                  └─── probe: TCP/TLS fail ──▶ hot ──≥50 fails/24 ч──▶ cache
                                                │
                                                └── TTL 24 ч истёк → запись
                                                    удаляется из hot_entries
                                                    (state остаётся пока
                                                     следующий probe не
                                                     переопределит)
```

| Состояние | Что значит | Как попадает | Как уходит |
|---|---|---|---|
| `new` | Видели DNS-query, но ещё не пробовали коннектиться | Первая ingest-строка | После первого probe |
| `watch` | Промежуточное, зарезервировано под будущий scorer | — | — |
| `ignore` | Прямой путь работает, тунель не нужен | Probe прошёл TCP+TLS | Следующий probe может вернуть в цикл, если начнёт падать |
| `hot` | Probe обнаружил блок — домен временно в ipset | Probe упал на TCP или TLS | Домен выпадает из `hot_entries` через 24 ч после последнего fail; если столько же раз подтверждалось — scorer продвигает в `cache` |
| `cache` | Стабильно заблокирован, в ipset навсегда | Scorer: ≥50 fails за 24 ч | Только оператором вручную (в v0.2.0 появится демоушн при обратном пробе) |
| `manual` / `deny` | Override от оператора | Файлы `manual-allow.txt` / `manual-deny.txt` | Только редактированием файла + рестартом |

### Manual override-ы

- **`manual-allow`** — домен попадает в ipset без probe. Полезно, когда
  блок проявляется на слое, который наш probe не видит (HTTP content
  filtering, SNI-спуфинг), или когда вы хотите форсировать домен через
  туннель из приватных соображений.
- **`manual-deny`** — домен никогда не пробуется и не туннелируется.
  Полезно для внутренних LAN-сервисов, гео-fenced российских сервисов
  (Госуслуги, банки), которые ломаются через иностранный exit, и для
  разного шумного мониторинга.

---

## 📦 Установка

### Требования

- Linux (Debian 11+ / Ubuntu 22.04+ или аналогичный).
- `iptables` (legacy или nft-режим).
- `ipset`, `iptables-persistent` (`apt install ipset iptables-persistent`).
- `dnsmasq` с `log-queries=extra` и `log-facility` в файл.
- Рут-права (нужен доступ к `ipset` и к логу dnsmasq).
- Работающий шлюз с fwmark-routing и upstream-туннелем (WireGuard, Hysteria,
  любой кастомный cascade).

### Quickstart

```bash
# 1. Скачать последний релиз (или зафиксировать версию: TAG=v0.2.0)
TAG=$(curl -sSL "https://api.github.com/repos/belotserkovtsev/ladon/releases/latest" \
  | grep '"tag_name":' | head -1 | cut -d'"' -f4)
curl -L "https://github.com/belotserkovtsev/ladon/releases/download/${TAG}/ladon-linux-amd64.tar.gz" \
  | sudo tar -xz -C /opt

sudo mv /opt/ladon-linux-amd64-${TAG} /opt/ladon
sudo mkdir -p /opt/ladon/state /etc/ladon

# 2. Примеры manual-списков
sudo cp /opt/ladon/manual-allow.txt.example /etc/ladon/manual-allow.txt
sudo cp /opt/ladon/manual-deny.txt.example  /etc/ladon/manual-deny.txt

# 3. Создать ipset и правило в iptables mangle
sudo ipset create prod hash:ip family inet maxelem 65536
sudo iptables -t mangle -A WG_ROUTE -m set --match-set prod dst \
  -j MARK --set-mark 0x1
sudo ipset save > /etc/iptables/ipsets   # чтобы переживало reboot

# 4. Инициализировать БД и поставить сервис
sudo /opt/ladon/ladon \
  -db /opt/ladon/state/engine.db init-db
sudo install -m 0644 /opt/ladon/ladon.service \
  /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now ladon

# 5. Проверить
systemctl status ladon
journalctl -u ladon -f
```

Подробнее — см. [release/INSTALL.md](release/INSTALL.md).

---

## 🛠 Конфигурация

Флаги передаются через systemd unit (`/etc/systemd/system/ladon.service`):

```
ladon -db <path> run [-from-start] [-manual-allow <path>] [-manual-deny <path>] <dnsmasq-log-path>
```

Значения по умолчанию из [`internal/engine/engine.go`](internal/engine/engine.go),
функция `Defaults()`:

| Параметр | Значение | Смысл |
|---|---|---|
| `ProbeTimeout` | 800 мс | Максимум на TCP/TLS dial |
| `ProbeCooldown` | 5 мин | Минимальный интервал между probe одного домена |
| `InlineProbeConcurrency` | 8 | Семафор для inline probe из tailer |
| `HotTTL` | 24 ч | Срок жизни записи в `hot_entries` |
| `IpsetInterval` | 30 с | Safety-реконсил ipset (помимо event-driven) |
| `DNSFreshness` | 6 ч | Возраст, после которого IP из dns_cache устаревает |
| `Scorer.Window` | 24 ч | Окно для подсчёта fails |
| `Scorer.FailThreshold` | 50 | Порог fails для промоушна hot → cache |
| `Scorer.Interval` | 10 мин | Как часто scorer проходится |

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

# Сколько IP сейчас в kernel ipset
sudo ipset list prod -t | grep entries

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
| `internal/prober/` | Probe: параллельные TCP + TLS-SNI с `InsecureSkipVerify` |
| `internal/decision/` | Классификация probe → {Ignore, Watch, Hot} |
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
