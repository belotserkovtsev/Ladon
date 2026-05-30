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
family_confirm_threshold: 10   # ≥N подтверждённых поддоменов eTLD+1 → семья считается заблокированной (экспансия IP + новые поддомены не пробятся, state=covered)
```

Полный набор полей и defaults — в
[`internal/engine/Defaults()`](../internal/engine/engine.go) и
[`release/config.yaml.example`](../release/config.yaml.example).

## CLI

```
ladon -db <path> [-config <path>] <subcommand> [args]
```

Подкоманды: `init-db`, `run`, `probe <domain>`, `observe <domain>`,
`list [N]`, `hot`, `tail <log>`, `prune`. Флаги `-manual-allow` /
`-manual-deny` на `run` перебивают одноимённые YAML-поля.

`init-db` обязателен перед первым запуском — `run` НЕ создаёт schema
автоматически.

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
Полная справка — `ladon prune -h`. После prune `state` сбрасывается в
`new` для доменов без активных записей.
