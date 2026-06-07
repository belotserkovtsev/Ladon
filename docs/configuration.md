# Конфигурация

← [README](../README.md) · [установка](install.md) · [extensions](extensions.md) · [методология](methodology.md)

Справочник: что где лежит, какие YAML-поля ладон понимает, какие
подкоманды у CLI и как настроить exit-compare. Установочный runbook —
в [install.md](install.md).

## Файлы

| путь | назначение |
|---|---|
| `/etc/ladon/config.yaml` | основной конфиг (опционально, без него — defaults) |
| `/etc/ladon/manual-allow.txt`, `/etc/ladon/manual-deny.txt` | списки операторских overrides |
| `/opt/ladon/extensions/<name>.txt` | bundled allow/deny-пресеты |
| `/var/log/dnsmasq.log` | источник probe-сигнала (читаем) |
| `/etc/dnsmasq.d/ladon-manual.conf` | генерим для dnsmasq ipset= directives |
| `/opt/ladon/state/engine.db` | SQLite со всем persistent state |

## YAML

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
  promote_threshold: 50   # blocked-вердиктов в окне для hot→cache

ipset:
  engine_name: ladon_engine # probe-driven hot/cache
  manual_name: ladon_manual # populates dnsmasq'ом для manual-allow + extensions
  cidr_name:   ladon_cidr   # hash:net для CIDR-блоков из extensions (Telegram MTProto и т.п.)
  interval: 30s

hot_ttl: 24h
dns_freshness: 6h
family_confirm_threshold: 10   # порог членов eTLD+1-семьи. один порог, две популяции: covered (новые поддомены не пробятся) считает только state=cache; экспансия IP всей семьи — hot+cache

log:
  level: info              # debug | info | warn | error
  format: text             # text | json
  source: false            # file:line в каждой строке
```

Полный набор полей и defaults — в
[`internal/engine/Defaults()`](../internal/engine/engine.go) и
[`release/config.yaml.example`](../release/config.yaml.example).

> `promote_threshold` считает probes по итоговому `verdict='blocked'` (исход
> `decision.Classify`), а не по сырым транспортным флагам — поэтому тонкие
> блоки (`tls13_block`, `http_cutoff`) с проходящими TCP+TLS тоже идут в зачёт.
> Вердикт штампуется только на batch-пути; inline-проба оставляет `verdict`
> NULL и не учитывается.

## Состояния домена

Состояние пайплайна (`domains.state`) отделено от исхода пробы (вердикт
`blocked` / `clear`):

| state | смысл |
|---|---|
| `new` | наблюдался, ещё не классифицирован |
| `hot` | проба дала `blocked`; строка в `hot_entries` (TTL = `hot_ttl`) |
| `cache` | scorer подтвердил блок (`promote_threshold` вердиктов в окне) → бессрочная строка в `cache_entries`, hot-строка снята |
| `covered` | член подтверждённой eTLD+1-семьи (≥ `family_confirm_threshold` в `cache`); индивидуально не пробится, маршрутизируется через экспансию IP семьи |
| `ignore` | проба дала `clear` (или exit-compare снял FP) |

`covered` исключён из probe-очередей; проверка семьи — единая точка в
`probeDomain`, общая для inline и batch.

## CLI

```
ladon [-version] -db <path> [-config <path>] <subcommand> [args]
```

Подкоманды: `init-db`, `run`, `probe <domain>`, `observe <domain> [peer]`,
`list [N]`, `hot`, `tail [-from-start] <log>`, `prune`, `status`,
`doctor [-config <path>] [-json]`, `why <domain>`. Глобальный `-version`
(или подкоманда `version`) печатает версию и выходит. Флаги `-manual-allow` /
`-manual-deny` на `run` перебивают одноимённые YAML-поля.

`run` самомигрирует БД на старте (`store.Init` → раннер `internal/migrate`):
на пустой БД разворачивает схему, на существующей — догоняет до актуальной,
так что swap бинарника + рестарт не оставят демон на устаревшей схеме.
`init-db` — явная идемпотентная команда создать БД заранее.

## Диагностика

Три команды отвечают на «работает ли ладон и почему домен (не) в туннеле». Все
читают БД (и среду), демон трогать не нужно — но `doctor` сверяет ipset'ы в
ядре, так что для полноты запускать его под `sudo`.

- **`ladon status`** — снимок одним взглядом: версия/uptime демона, свежесть
  последнего наблюдения DNS / пробы / reconcile, счётчики доменов по
  состояниям. Только чтение БД, без прав.
- **`ladon doctor`** — полная диагностика. Идёт по конвейеру (движок → вход →
  решение → накопление → ipset) и наверх выносит **первое порванное звено**
  простым языком, с командой-фиксом. Код выхода `0/1/2` (здоров/замечания/
  сломан) — годится для cron-алерта. `-json` — машинный вывод.

  Область строго **внутри ладона**: doctor не трогает туннель, iptables и
  exit-ноду (ладон только наполняет ipset и не управляет маршрутизацией).
  Поэтому зелёный doctor означает «ладон здоров — если сайты всё равно не
  работают, причина ниже ладона (туннель / exit / DPI)».
- **`ladon why <domain>`** — след решения по одному домену: состояние,
  backing-строка (hot/cache), наблюдавшиеся IP и история последних проб
  (коды/вердикты). Отвечает на «почему этот домен не туннелируется».

Демон пишет несколько фактов в таблицу `runtime_meta` (heartbeat, время и
размер последнего reconcile) — их `status`/`doctor` и читают, потому что
запускаются отдельным процессом и память демона не видят.

### Логи

Структурные (`log/slog`): уровень (`log.level`), `text`/`json` (`log.format`),
поля `component=<стадия>`, `domain`, `failure_code`, … вместо склеенных строк —
так `failure_code` и прочее можно грепать или парсить из JSON. Под systemd
ладон сам определяет journald, убирает свой таймстамп и проставляет приоритет:

```
journalctl -u ladon -f                 # хвост
journalctl -u ladon -p warning         # только warn+error
journalctl -u ladon -o json | jq 'select(.failure_code=="tls13_block")'
```

## Manual lists

По одному домену на строку, `#` — комментарий. eTLD+1 apex покрывает
все субдомены.

- `manual-allow.txt` — домены **всегда** в туннеле, минуют probe. Для
  L7-fingerprint blocks (`rutracker.org`) и операторских override'ов.
- `manual-deny.txt` — домены **никогда** не пробуются и не
  тоннелируются. Для банков, госуслуг, корпоративных LAN-сервисов,
  healthcheck endpoints.

## Extensions

Тематические подборки доменов (allow/deny), включаемые одной строкой
в `config.yaml`:

```yaml
allow_extensions: [ai, twitch, tiktok]
```

Полный список bundled пресетов, формат файла, поведение, CIDR-блоки —
в [extensions.md](extensions.md).

## Exit-compare

Опциональный режим: при path-active failure ladon, прежде чем
маршрутизировать домен через тоннель, спрашивает второго независимого
observer'а из другой геолокации — если *оттуда* домен тоже не работает,
проблема скорее всего у сервера, не в пути, и в туннель его тащить
бессмысленно.

```yaml
probe:
  mode: exit-compare
  remote:
    url: https://probe-server.example.com/probe
    timeout: 2s
    auth_header: Authorization
    auth_value: Bearer <token>
```

HTTP-контракт remote-сервера — в [probe-api.md](probe-api.md).
Референсная Go-реализация — [`probe-server/ladon/`](../probe-server/ladon/),
переиспользует тот же `internal/prober.LocalProber`, чтобы local и remote
стадии были семантически идентичны (любое расхождение — про сетевой
путь, не про probe-логику).

Подробнее о том, как exit-compare matrix закрывает FP-классы, — в
[methodology.md](methodology.md#arbitration-через-второй-observer-exit-compare).

## Prune

`ladon prune` чистит `hot_entries` / `cache_entries` / `probes` —
обычно после смены probe-логики или для подрезания истории.
Поддерживает `-dry-run`, `-before <RFC3339>`, комбинации флагов.
Полная справка — `ladon prune -h`. После prune домены в `hot`/`cache`/`ignore`
без backing-строки сбрасываются в `new` (перепроба с нуля); `covered` не
затрагивается — covered-домены вернутся к пробам, только когда семья перестанет
быть подтверждённой.
