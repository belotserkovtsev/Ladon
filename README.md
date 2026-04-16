<div align="center">

![Ladon](assets/logo-wide.jpg)

# 🩸 Ladon

**Автоматический split-tunneling для VPN-шлюзов в сетях с DPI**

[![CI](https://github.com/belotserkovtsev/ladon/actions/workflows/ci.yml/badge.svg)](https://github.com/belotserkovtsev/ladon/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/belotserkovtsev/ladon?include_prereleases&sort=semver)](https://github.com/belotserkovtsev/ladon/releases)
[![Go](https://img.shields.io/github/go-mod/go-version/belotserkovtsev/ladon)](go.mod)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

</div>

Ladon наблюдает трафик клиентов шлюза, проверяет домены на достижимость и строит список из ip-адресов, которые нужно пустить через VPN. **За доли секунды**. Ничего не нужно размечать руками — движок учится сам на поведении пира и реакции сети.

Задуман для WireGuard-шлюзов с `dnsmasq` и апстрим-туннелем наружу,
но легко адаптируется под любой стек с fwmark-routing и ipset.

---

## ⚡ Производительность

**От первого DNS-запроса до правила в kernel ipset — полсекунды в среднем.** В постоянный список попадает только то, что подтвердилось ≥50 раз за сутки — моргания провайдера не доезжают.

| Метрика | Значение |
|---|---|
| Реакция на новый блок | **0.3 – 1.1 с** (≈0.5 с) |
| Пропускная способность | **~65 доменов/с** на 2 CPU |
| Накладные расходы пайплайна | **~50 мс** сверх сети |
| RSS | **~20 МБ** |

### Почему быстро и точно

- **Нет split-brain с клиентом** — probe бьёт по IP из `dns_cache`, тем же, что dnsmasq отдал клиенту.
- **Параллельные TCP-dials** — худший случай `max(timeout)` вместо `sum(timeout)`.
- **Event-driven ipset** — probe сигналит syncer сразу после вердикта, без ожидания тикера.
- **eTLD+1 агрегация** — ≥2 подтверждённых поддомена тянут в ipset всю семью (CDN с UUID-поддоменами не утекают через direct).

Воспроизвести числа: `go test -run TestPipeline ./internal/engine/` — тест бьёт в [TEST-NET-1](https://datatracker.ietf.org/doc/html/rfc5737) (`192.0.2.1`), пакеты туда дропаются на апстрим-роутерах = реалистичный «тихий drop» без сети. Разброс 0.3-1.1 с: нижняя граница — мгновенный TCP RST от DPI, верхняя — silent drop с ожиданием полного 800 мс таймаута.

---

## 💡 Как это работает

Обычный VPN ставит выбор без правильного ответа: **«всё через туннель»** ломает рос-сервисы которые требуют РФ-IP (банки, Госуслуги) и нагружает exit-канал, а **«всё напрямую»** не решает задачу ради которой VPN ставили. Ladon держит середину: пир ходит напрямую по умолчанию, движок в фоне наблюдает трафик и сам переключает через туннель только реально заблокированное.

### Путь одного домена

Предположим, клиент первый раз открывает `instagram.com`.

1. **Наблюдение.** Запрос прилетает в dnsmasq; тот пишет в лог пары строк — `query[A] instagram.com from 10.10.0.2` и `reply instagram.com is 157.240.20.174`. Tailer ловит обе через kernel-события fsnotify: первая уходит в таблицу `domains` (состояние `new`), IP-ы из второй складываются в `dns_cache`. Это ровно те адреса, которые увидел клиент — важно, чтобы движок бил именно по ним, а не по собственному resolve: на geo-routed CDN движок и клиент иначе видят разные IP.

2. **Проверка.** Как только watcher записал новый домен, в ту же миллисекунду запускается inline-проба: параллельные TCP-коннекты на `:443` по IP из `dns_cache` (берёт первый успешный), затем TLS-handshake с SNI. Сертификат не верифицируется — движку нужна только достижимость, а не доверие. Для старых доменов, у которых истёк 5-минутный cooldown, отдельный batch-воркер раз в 2 секунды делает то же самое по батчу кандидатов.

3. **Вердикт.** Если TCP или TLS упали — домен переходит в `hot` на 24 часа, и параллельно через буферный канал будится ipset-syncer: IP из `dns_cache` атомарно добавляются в kernel ipset `ladon_engine`. iptables mangle-правило `--match-set ladon_engine dst -j MARK 0x1` ловит следующий пакет клиента и разворачивает его в туннель. От первой DNS-записи до правила в ядре — в среднем полсекунды. Если прямой путь сработал — домен в `ignore`, никаких действий.

4. **Память.** Раз в 10 минут scorer проходится по `hot_entries`. Если домен за последние 24 часа упал ≥50 раз — он переезжает в `cache_entries` без TTL. Короткие сетевые штормы (провайдер моргнул на 30 секунд) живут только в hot и исчезают через сутки; стабильные блоки оседают в постоянной памяти и перестают зря пробиваться.

5. **Маршрутизация.** ipset-syncer держит `ladon_engine` синхронным с `hot ∪ cache`. Event-driven: каждое новое Hot-событие будит его немедленно, safety-тикер раз в 30 секунд ловит потерянное. Для семейств с ≥2 подтверждёнными сиблингами по eTLD+1 подтягиваются IP-ы всего корня (Meta раздаёт новые UUID-поддомены ежеминутно, один упавший уводит в туннель остальных). **Manual-allow домены** идут через **отдельный ipset `ladon_manual`** который наполняет dnsmasq нативно — см. секцию Extensions ниже.

<details>
<summary><b>🔌 Схема пайплайна (клик, чтобы развернуть)</b></summary>

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

### Состояния домена — справочник

Состояние домена хранится в колонке `domains.state`; «живые» списки для роутинга — в `hot_entries` и `cache_entries`. Переходы следуют из путя выше, вот таблица на случай если надо быстро свериться:

| Состояние | Что значит | Как попадает | Как уходит |
|---|---|---|---|
| `new` | Видели DNS-query, но ещё не пробовали коннектиться | Первая ingest-строка | После первого probe |
| `ignore` | Прямой путь работает, туннель не нужен | Probe прошёл TCP+TLS | Следующий probe может вернуть в цикл, если начнёт падать |
| `hot` | Probe обнаружил блок — домен временно в ipset | Probe упал на TCP или TLS | Запись в `hot_entries` снимается через 24 ч после последнего fail; при ≥50 подтверждениях за окно scorer переводит в `cache` |
| `cache` | Стабильно заблокирован, в ipset навсегда | Scorer: ≥50 fails за 24 ч | Только вручную оператором (cache-demotion на обратном пробе — в бэклоге) |

### Manual override-ы

Автоматика закрывает блоки **изнутри** — DPI режет соединение на пути от клиента к ресурсу, probe это видит и заворачивает в туннель. Есть второй класс блоков, который автоматика **принципиально не может определить**:

- **`manual-allow.txt`** — домены, которые блокируют твой регион **со своей стороны** (geo-fence на IP). С точки зрения probe всё работает: TCP/TLS проходят, но сервис в HTTP-ответе говорит «not available in your country». ChatGPT, Anthropic, Spotify, многие SaaS — типичные примеры. Решение принимает оператор: «знаю что снаружи блокирует — гнать в туннель». Также сюда content-уровень (HTTP body filtering, SNI-спуфинг) и принудительный туннель по приватным соображениям. **Архитектурно** manual-allow делегируется dnsmasq через native `ipset=/domain/ladon_manual` — он наполняет отдельный ipset синхронно при резолве, до возврата DNS-ответа клиенту.
- **`manual-deny.txt`** — домен не пробуется и не туннелируется. Для внутренних LAN-сервисов, гео-fenced рос-сервисов (Госуслуги, банки) которые ломаются через иностранный exit, и для шумного мониторинга. Здесь по-старому через ладонскую БД (engine консультирует список при ingest).

Файлы перечитываются при старте сервиса; правка требует `systemctl restart ladon`.

Типовые наборы гео-блокированных сервисов есть как **extensions** (см. ниже) — curated списки, шипающиеся с ладоном.

---

## 📦 Установка

Одной командой на Debian/Ubuntu (нужны root-права, systemd, dnsmasq):

```bash
curl -fsSL https://github.com/belotserkovtsev/ladon/releases/latest/download/install.sh \
  | sudo bash
```

Скрипт ставит зависимости, создаёт `ladon_engine` + `ladon_manual` ipset'ы, настраивает dnsmasq и запускает ladon. Re-run того же curl'а = upgrade (бинарь обновляется, конфиг сохраняется).

**Routing — твоя зона ответственности.** Ладон только наполняет ipset'ы; iptables / ip rule / fwmark routing зависят от твоей WG-топологии. В конце скрипт печатает example для типичного split-tunnel сетапа.

Удаление: `uninstall.sh` тем же путём. Пошагово или для нестандартного сетапа — [release/INSTALL.md](release/INSTALL.md).

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
  name: ladon_engine        # probe-driven hot/cache
  manual_name: ladon_manual # populates dnsmasq'ом для manual-allow + extensions
  interval: 30s

hot_ttl: 24h
dns_freshness: 6h
```

Все поля опциональны — пропущенные берутся из дефолтов:

| Параметр | Значение | Смысл |
|---|---|---|
| `probe.timeout` | 800 мс | Максимум на TCP/TLS dial |
| `probe.cooldown` | 5 мин | Минимальный интервал между probe одного домена |
| `probe.concurrency` | 8 | Семафор для inline probe из tailer |
| `hot_ttl` | 24 ч | Срок жизни записи в `hot_entries` |
| `ipset.interval` | 30 с | Safety-реконсил ipset (помимо event-driven) |
| `dns_freshness` | 6 ч | Возраст, после которого IP из dns_cache устаревает |
| `scorer.window` | 24 ч | Окно для подсчёта fails |
| `scorer.fail_threshold` | 50 | Порог fails для промоушна hot → cache |
| `scorer.interval` | 10 мин | Как часто scorer проходится |

### CLI-флаги

Дополнение к YAML — для простых случаев и для разовых override'ов:

```
ladon -db <path> [-config <path>] run [-from-start] [-manual-allow <path>] [-manual-deny <path>] <dnsmasq-log-path>
```

Пути (`-manual-allow`, `-manual-deny`) перебивают одноимённые поля YAML, если заданы оба. Тонкие knobs задаются только через файл.

### Extensions — преднастроенные allow-списки

С релизом ладона шипаются тематические подборки доменов, которые **гео-блокируют российский регион со своей стороны** (probe их распознать не может — TLS handshake проходит, но сервис в ответ говорит «not available in your country»). Подключаются опционально по имени:

```yaml
extensions:
  - ai
  - twitch
# extensions_path: /opt/ladon/extensions   # default
```

Семантика: домены **всегда** идут через туннель, минуя probe-пайплайн. Реализовано через делегирование dnsmasq: при старте ладон пишет `/etc/dnsmasq.d/ladon-manual.conf` со строками `ipset=/openai.com/ladon_manual`, `ipset=/twitch.tv/ladon_manual` и т.д., потом `systemctl reload dnsmasq`. Дальше **dnsmasq сам** при резолве каждого домена walks CNAME-цепочку и кладёт все финальные A-записи в kernel ipset `ladon_manual` — **до того как ответ DNS уйдёт клиенту**. Первый-же TCP SYN клиента уже находит свой destination в kernel set'е → tunnel.

Достаточно указать корневой домен — dnsmasq матчит по суффиксу. `openai.com` покрывает `cdn.openai.com` (Azure-CDN), `chat.openai.com` (CloudFlare), `developers.openai.com` (Vercel) и любые другие поддомены без необходимости их перечислять. CNAME-цепочки уходят в правильный ipset нативно, без нашей ladon-side логики.

Доступные пресеты:

| Имя | Покрытие |
|---|---|
| `ai` | OpenAI / ChatGPT, Anthropic / Claude (8 доменов) |
| `twitch` | twitch.tv + CDN (5 доменов) |

Полный список — в `/opt/ladon/extensions/<name>.txt`. Свои подборки можно положить в тот же каталог (или в `extensions_path` куда угодно) и подключить в config так же по имени.

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

**Почему нет авто-prune при upgrade:** cache-записи зарабатываются дорого (≥50 fails / 24ч), и тихая чистка при каждом релизе создавала бы UX-провалы. Делать prune — осознанное решение оператора.

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

Последняя строка важна: outage твоего proб-сервера **не должен** тихо снимать ipset с реально-заблокированных доменов. Поэтому транспортная ошибка интерпретируется как «нет мнения», а не как «remote сказал FAIL».

Inline fast-path всегда использует только локальную пробу — гонять remote round-trip на каждом первом запросе клиента сломало бы 0.5-секундный бюджет. Если inline ошибся — batch-перепроба с exit-compare его поправит и удалит запись из ipset.

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
