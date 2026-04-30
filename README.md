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

Ladon — реактивный split-tunneling роутер, в котором классификация домена как
DPI-блокированного — это не один TCP-пинг, а пайплайн arbitration'ов, где
каждый уровень отсекает свой класс false-positive'ов. Сильная сторона
методологии — именно в композиции уровней, а не в одной "умной" пробе.

### Реактивное наблюдение, а не synthetic probing

Ladon не ходит синтетически по лидерборду блокированных доменов. Вместо
этого fsnotify-tailer читает живой `dnsmasq.log` шлюза и пробивает только
те домены, к которым клиенты **уже** пошли. Каждый probe-кандидат — это
имя, которое реально нужно конкретному юзеру в конкретный момент. Никаких
синтетических списков "что в РФ блокируется в этом году" — список строится
из вашего настоящего трафика.

Inline fast-path запускает probe сразу при первом DNS-запросе нового
домена и обычно успевает положить результат в kernel ipset за ~500 мс.
Параллельно batch-worker в фоне переоценивает накопленные кандидаты раз в
2 секунды.

### Stage-by-stage probe с осмысленными failure-кодами

Probe идёт DNS → TCP:443 → TLS-handshake → HTTP-read (до 32KB), и каждая
стадия даёт своё семейство кодов. HTTP-стадия читает достаточно байт,
чтобы поймать классическую RU-DPI сигнатуру "обрыв CDN/хостинга на
14-34KB передачи" — без неё handshake выглядит чистым, и блок ускользает.

Коды специально гранулярные: `tcp_timeout`, `tcp_reset`, `tcp_refused`,
`tls_handshake_timeout`, `tls_reset`, `tls_eof`, `tls_alert`,
`mtls_required`, `http_cutoff`, `http_reset`, `http_timeout`,
`http_error`. Это не косметика для логов — каждый код несёт **другую
семантику** и движок ветвится по ним.

### Server-active vs path-active — главное различение

Самая ценная классификация в пайплайне: failures делятся на две группы.

**Server-active rejection** означает, что сервер **активно ответил**
"нет": `tcp_refused` — порт явно закрыт, `tls_alert` — TLS alert от
peer'а, `mtls_required` — alert 116 (mutual-TLS требуется, классика для
Apple Push, FindMy, iCloud Private Relay). Все три — **доказательство
доступности** сервера: чтобы прислать alert, peer должен был пройти TCP
и часть handshake'а. Значит DPI не вмешался — это policy сервера. Такие
домены идут в `Ignore`, никогда в туннель.

**Path-active rejection** — `*_timeout`, `*_reset`, `*_eof`,
`http_cutoff`, `http_error`. Здесь сервер не подтвердил доступность —
что-то могло его не пустить, и это "что-то" обычно DPI на пути.

Этот раздел отлавливает целый класс false-positive'ов, на котором
утыкаются простые TCP-checker'ы: Apple Push Service, FindMy, iCloud
Private Relay, корпоративные API с client-cert auth — все они отдают
`tls_alert: certificate required`, простой checker считает их
"unreachable", а Ladon правильно классифицирует как "сервер живой,
просто требует клиентский сертификат".

`tls_alert` детектится двумя путями: `errors.As(err, &tls.AlertError{})`
для QUIC-транспортов плюс string-fallback на `"remote error: tls: ..."`
для классических TCP-конекций (Go stdlib для не-QUIC оборачивает alert'ы
в неэкспортированный `tls.alert`, и `errors.As` на них не срабатывает).

### Arbitration через exit-compare

Path-active failure пока ещё не приговор. Может, конкретно этот сервер
лежит. Может, у него странная конфигурация на 443. Может, geoblock на
обе стороны.

Решает второе мнение: тот же probe запускается из второго vantage'а —
HTTP-сервиса в другом регионе (out-of-RU VPS, например). Получаем
матрицу:

| local | remote | вердикт | смысл |
|---|---|---|---|
| OK | — | Ignore | direct path работает |
| FAIL | OK | **Hot** | реальный DPI: снаружи живой, изнутри нет |
| FAIL | FAIL | Ignore | проблема в сервере, не в пути |
| FAIL | unavailable | Hot (sticky) | нет мнения, остаёмся с локальным |

Ключевая строка — `FAIL/FAIL → Ignore`. Без неё любой mTLS-сервис, любой
geoblock'нутый сервис, любой просто медленный сервер попадал бы в Hot.
С ней remaining false-positive rate в production падает до единиц
процентов. На стек из ~150 живых hot-доменов в день обычно ноль
заведомо ложных срабатываний.

### Temporal arbitration — hot/cache

Один fail ≠ приговор. Probe может попасть в момент перегрузки сервера,
DPI может моргнуть, провайдер может временно ребутнуть промежуточное
оборудование. Поэтому верхний слой памяти — двухуровневый:

`hot_entries` принимают новые блоки на 24 часа. Это активный список —
домен в туннеле, но движок продолжает регулярно его перепробовать. Если
за 24 часа набирается ≥50 подтверждённых fails (при 5-минутном cooldown
это означает минимум ~4 часа устойчивого failure'а), scorer переводит
домен в `cache_entries` — постоянный список без TTL.

Если же блок был временным, домен молча выпадет из hot через 24 часа и
вернётся в нормальный probe-цикл. Никаких списков "был блокирован на
прошлой неделе, теперь зависает в кэше навсегда" — каждое решение
живёт ровно столько, сколько подтверждается.

### Что покрывается без участия оператора

В сумме комбинация уровней автоматически и корректно классифицирует:

- **TCP-уровневые блоки** (SYN drop, RST на handshake) — Meta IPs, любые
  geo-targeted блокировки на L4
- **TLS-handshake блоки** на SNI/cipher-фингерпринте — Telegram DC,
  Discord voice, многие RU-blocked сервисы
- **L7-cutoff блоки** — обрыв TLS-стрима после 14-34KB CDN-трафика,
  любимый трюк некоторых RU-DPI deployments
- **HTTP-injection блоки** — DPI инжектит garbage в HTTP/2 stream
  (наблюдается на Google FCM `mtalk.google.com` и подобных gRPC-сервисах)
- **Сервисы с mTLS / client-cert требованиями** — корректно как доступные
  (не попадают в туннель ложно)
- **Geoblock'нутые сервисы** — корректно как недоступные глобально
  (не попадают в туннель)
- **Случайные блипы провайдера** — отсекаются temporal arbitration'ом,
  не доходят до постоянного кэша

### Что вне scope

Несколько классов блокировок методология не покрывает:
**L7-fingerprint blocks** (когда DPI режет конкретный ClientHello браузера —
у probe другой fingerprint, обходится через `manual-allow`),
**throttling** (DPI не блокирует, а шейпит — probe видит "медленно но
работает"), **domainless flows** на hardcoded IP (Telegram mobile,
Discord voice — нет DNS-запроса, нечего ingest'ить). Под каждый из этих
классов есть план в roadmap.

---

## 🛠 Конфигурация

Конфигурация задаётся YAML-файлом, путь передаётся флагом `-config`.
Без файла движок едет на дефолтах из
[`internal/engine/engine.go`](internal/engine/engine.go) — этого хватает
для базового запуска.

Минимальный пример:

```yaml
logfile: /var/log/dnsmasq.log
manual_allow: /etc/ladon/manual-allow.txt
manual_deny: /etc/ladon/manual-deny.txt

probe:
  mode: local         # local | exit-compare
  timeout: 800ms

ipset:
  engine_name: ladon_engine
  manual_name: ladon_manual
```

Полный набор опций (scorer thresholds, hot_ttl, dns_freshness,
publish_path, ipset.interval) задокументирован в
[`internal/engine/engine.go`](internal/engine/engine.go) и в комментариях
эталонного [`config.yaml.example`](release/config.yaml.example).

CLI принимает override `-manual-allow` / `-manual-deny` для случаев когда
пути нужны разовые. Тонкие knobs — только через YAML.

### Manual lists

`manual-allow.txt` и `manual-deny.txt` — два списка по одному домену на
строку. eTLD+1 apex покрывает все субдомены, `#` — комментарий.

`manual-allow` нужен для случаев, которые методология автоматически не
ловит (L7-fingerprint blocks, например `rutracker.org` через
Cloudflare-fronting, или сервисы где TLS handshake проходит, но реальный
браузерный traffic режется на байтовом уровне). Домены из allow-листа
**всегда** идут в туннель, минуя probe.

`manual-deny` — обратный, для случаев когда домен в туннеле принципиально
не должен оказаться: банки, госуслуги (часто ломаются через VPN из-за
fraud-detection), корпоративные LAN-сервисы, healthcheck endpoints. Эти
домены **никогда** не пробуются и не тоннелируются.

### Extensions

Тематические allow-подборки, активируются одной строкой в конфиге:

```yaml
allow_extensions:
  - ai
  - twitch
  - tiktok
```

Доступные пресеты:

| имя | покрытие |
|---|---|
| `ai` | OpenAI / ChatGPT, Anthropic / Claude |
| `twitch` | twitch.tv + CDN |
| `tiktok` | TikTok / ByteDance overseas (core, regional CDN, backbone, SDK) |

Каждый пресет — список доменов в `/opt/ladon/extensions/<name>.txt`,
который dnsmasq при резолве кладёт в `ladon_manual` ipset. Подробности и
формат — в [release/extensions/README.md](release/extensions/README.md).
Свои подборки (allow или deny) кладутся в тот же каталог и подключаются
по имени.

### Exit-compare

Опционально включает arbitration через второй vantage point.
Поднимается probe-server в любой out-of-RU точке (чужой VPS, residential
ISP в другой стране, 4G-модем), указывается в конфиге:

```yaml
probe:
  mode: exit-compare
  remote:
    url: https://my-probe-server.example.com/probe
    auth_value: Bearer mysecrettoken
```

HTTP-контракт probe-server'а описан в
[`docs/probe-api.md`](docs/probe-api.md). Референсная Go-реализация —
[`probe-server/ladon/`](probe-server/ladon/), переиспользует тот же
probe-pipeline что engine, чтобы local и remote стадии были семантически
идентичны.

### Очистка состояния

`ladon prune` сбрасывает накопленные таблицы: `cache_entries`,
`hot_entries`, `probes`. Используется обычно после изменения логики probe
(включили exit-compare и хочется отсеять старые вердикты, набранные
старым алгоритмом) или для подрезания истории. Поддерживается
`-dry-run`, временные фильтры через `-before <RFC3339>`, и комбинации
флагов. Полная справка — `ladon prune -h`.

После prune движок сам сбрасывает `state` в `new` для доменов, у которых
не осталось активных записей — они пройдут пайплайн заново на следующем
DNS-запросе.
