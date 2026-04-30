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

### Постановка задачи

Дано: домен `X`, к которому клиент обратился. Классифицировать: **DPI
режет связь к `X`** или нет. Классификация бинарная — `Hot`
(тоннелировать) или `Ignore` (направлять напрямую). Минимизируем оба
типа ошибок: false-positive (не тоннелировать что не нужно — лишний шум,
оверюзат туннеля) и false-negative (не пропустить реальный блок — иначе
клиент видит "не открывается").

### Источник наблюдений — реактивная подписка

Анализ применяется только к доменам, к которым клиенты **уже**
обратились. Probe-кандидат — это имя из живого DNS-трафика, не из
синтетического списка известных блокировок. Покрытие = реальный профиль
использования сети, не публикуемый "топ заблокированных".

### Probe как структурированное измерение

Один probe = последовательная серия из 4 независимых наблюдений:

1. **DNS** — резолвится ли имя
2. **TCP:443** — пускают ли SYN, приходит ли SYN/ACK
3. **TLS handshake** — проходит ли ClientHello/ServerHello, доходит до Finished
4. **HTTP read** — приходит ли первые ~32KB ответа после успешного handshake

Каждое наблюдение даёт `passed`/`failed` + при failure — категорию
ошибки. Категория несёт информацию о **природе** отказа, не только о
факте.

32KB-окно на HTTP-стадии подобрано чтобы покрыть наблюдаемую сигнатуру
"обрыв CDN/хостинга после 14-34KB передачи" — без HTTP-стадии TLS
handshake выглядит чистым и блок ускользает в `Ignore`.

### Семантика failures: server-active vs path-active

Failures разделяются по природе на два класса.

**Server-active rejection** — сервер активно ответил "нет":
- TCP `connection refused` — порт явно закрыт
- любой TLS alert от peer'а — `certificate required` (mTLS),
  `illegal parameter`, `handshake failure`, и т. д.

Эти отказы **доказывают**, что сервер достижим — чтобы прислать TLS
alert или RST на `connect()`, peer должен был получить и обработать наш
пакет. DPI на пути не подделывает TLS alert'ы (это требовало бы
поддерживать TLS state machine на L6), поэтому такие сигналы
интерпретируются как server-side policy, не как блок. Классифицируется
сразу в `Ignore`.

**Path-active rejection** — сервер не подтвердил доступность:
- timeout (любой стадии)
- TCP/TLS reset
- silent EOF (TCP закрылся без HTTP/TLS-ответа)
- HTTP cutoff (стрим обрублен mid-response)
- HTTP-level garbage (вместо валидного HTTP пришёл бинарный мусор —
  типичная сигнатура DPI, инжектящего фальшивый response в HTTP/2 stream)

Эти сигналы **не доказывают** что DPI режет — сервер мог сам не
отвечать, может временно лежит. Они означают только "доступность не
подтверждена", и требуют дополнительного arbitration'а.

### Arbitration через второй observer (exit-compare)

Path-active failure из одной точки — слабое доказательство DPI. Сервер
может быть просто медленным, geoblock'нутым, mTLS-only, dead. Решение —
**вторая независимая точка наблюдения**: тот же probe из другой
географической позиции (out-of-region vantage point — чужая VPS, другой
ISP, другой регион). Получаем матрицу 2×2:

|  | remote OK | remote FAIL |
|---|---|---|
| **local OK** | `Ignore` (direct работает) | (вырожденный, не вызываем remote) |
| **local FAIL** | **`Hot`** (снаружи живой → блок именно у нас) | **`Ignore`** (отказ из обеих точек → server-side, не путь) |

Ключевая строка — `local FAIL + remote FAIL → Ignore`. Без неё любой
geoblock, любой временно недоступный сервер, любой mTLS-сервис попадал
бы в `Hot`. С ней remaining false-positive rate близок к нулю на классе
server-side проблем.

Если remote-наблюдатель транспортно недоступен (timeout, network) —
сохраняется local-вердикт без overrule (sticky local). Это защита от
ситуации "remote умер → внезапно весь Hot список развалился".

### Arbitration через накопление (temporal evidence)

Одна проба — слабое доказательство. Сервер мог быть перегружен в
конкретный момент, DPI мог моргнуть, провайдер мог временно
ребутнуть промежуточное оборудование. Поэтому над probe-вердиктом
строится статистический слой:

- Первый зафиксированный path-active failure → домен попадает в Hot
  на 24 часа (активный, перепробуется)
- Если за 24h собирается ≥N подтверждённых failures (при дефолтных
  настройках N=50, что при 5-минутном cooldown означает минимум ~4
  часа устойчивого failure'а) → блок считается стабильным, переходит в
  постоянный список без TTL
- Если за 24h не собирается — TTL истекает, домен возвращается в обычный
  probe-цикл

Случайные блипы провайдера и временные DPI-моргания не доходят до
постоянного списка.

### Сводная декомпозиция

Конечная классификация домена выводится из четырёх независимых сигналов:

1. **stage** — где именно проба упала
2. **природа failure** — server-active или path-active (закрывает один
   класс false-positive — mTLS / cert-only сервисы)
3. **второй observer** — exit-compare matrix (закрывает другой класс
   false-positive — server-side проблемы и geoblock)
4. **накопление во времени** — статистический threshold на устойчивости
   (закрывает третий класс — случайные блипы)

Любой домен в постоянном списке прошёл фильтр на всех четырёх уровнях.

### Чего методология не различает

1. **L7-fingerprint discrimination** — DPI блокирует только конкретный
   ClientHello (например, Chrome) и пропускает другие. Probe — отдельный
   TLS-клиент с собственным fingerprint'ом; если DPI его не блеклистит,
   probe видит "OK", а реальный браузер юзера — нет. Без mimicry
   ClientHello не детектируется автоматически.

2. **Throttling vs blocking** — DPI шейпит bandwidth до низких значений
   вместо обрыва. Probe видит "медленно, но работает" → `Ignore`. Для
   детекции нужна отдельная проба на sustained throughput, не
   покрывается базовой методологией.

3. **Domain-less flows** — TCP/UDP-соединения на hardcoded IP без
   предварительного DNS-запроса (Telegram mobile DC, Discord voice,
   WhatsApp calls, Steam P2P). Реактивная подписка работает только на
   DNS-наблюдении: нет наблюдения — нет probe-кандидата.

4. **DNS-only blocks** — DPI poison'ит ISP-resolver, отдавая клиенту
   неверные IP. Probe резолвит через альтернативный апстрим (off-ISP
   DNS) → видит правильный IP → не замечает фальсификации, которую
   видит клиент через ISP-DNS. Для детекции нужна параллельная проба
   через ISP-resolver и сравнение результата.

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
