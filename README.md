<div align="center">

![Ladon](assets/logo-wide.jpg)

# 🩸 Ladon

**Реактивный Anti-DPI движок**

[![CI](https://github.com/belotserkovtsev/ladon/actions/workflows/ci.yml/badge.svg)](https://github.com/belotserkovtsev/ladon/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/belotserkovtsev/ladon?include_prereleases&sort=semver)](https://github.com/belotserkovtsev/ladon/releases)
[![Go](https://img.shields.io/github/go-mod/go-version/belotserkovtsev/ladon)](go.mod)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

</div>

Ladon реактивно наблюдает DNS-трафик клиентов шлюза, четырёхстадийной пробой (DNS → TCP:443 → TLS handshake → HTTP read до 32KB) идентифицирует реальные DPI-блокировки и собирает IP в kernel ipset для tunnel-routing. **За доли секунды.**

## Установка

Один скрипт для обеих платформ — сам определит Debian/Ubuntu или OpenWRT:

```sh
curl -fsSL https://github.com/belotserkovtsev/ladon/releases/latest/download/install.sh | sudo sh
```

(на OpenWRT — `wget -O- ... | sh`, sudo не нужен).

Ставит бинарь, конфиги, ipset'ы и интеграцию с dnsmasq. Полные runbook'и + manual install + troubleshooting:
[docs/install.md](docs/install.md) (Debian/Ubuntu), [docs/install-openwrt.md](docs/install-openwrt.md) (OpenWRT, beta).

## Как работает

Классификация по сигнатуре отказа в живой сети, а не по готовому списку.

- **Реактивная подписка** — probe только на домены, которые клиенты сами запросили через DNS.
- **Четырёхстадийный probe** — DNS → TCP:443 → TLS handshake → HTTP read до 32KB.
- **20+ типизированных failure-кодов** — `tls_alert`, `tls_garbage`, `tls_reset`, `tls13_block`, `mtls_required`, `tcp_refused`, `http_cutoff`, `http_451`, ...
- **Server-active vs path-active** — TLS alert / RST / `connection refused` отделены от timeout / cutoff / garbage.
- **24h temporal accumulation** — порог подтверждённых failures для постоянного списка.
- **Опциональный exit-compare** — второй observer из другой геолокации.

Полная методология — в [docs/methodology.md](docs/methodology.md).

## Документация

| | |
|---|---|
| [docs/install.md](docs/install.md) | install Debian/Ubuntu (auto + manual), troubleshooting |
| [docs/install-openwrt.md](docs/install-openwrt.md) | install OpenWRT (beta — aarch64/armv7/x86_64) |
| [docs/configuration.md](docs/configuration.md) | YAML, CLI, manual lists, exit-compare, prune |
| [docs/methodology.md](docs/methodology.md) | как Ladon работает |
| [docs/extensions.md](docs/extensions.md) | bundled allow/deny-пресеты + формат своих списков |
| [docs/probe-api.md](docs/probe-api.md) | HTTP-контракт probe-сервера для exit-compare |
| [probe-server/ladon/](probe-server/ladon/) | референсная Go-имплементация probe-сервера |

## Благодарности

* [GoodbyeDPI](https://github.com/ValdikSS/GoodbyeDPI)
* [zapret-discord-youtube](https://github.com/Flowseal/zapret-discord-youtube)
* [dpi-detector](https://github.com/Runnin4ik/dpi-detector)

## Лицензия

MIT — см. [LICENSE](LICENSE).
