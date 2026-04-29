# Probe API

Контракт, которым ладон разговаривает с внешним проб-сервером в режиме
`probe.mode: exit-compare`. Фиксирован — имплементация на стороне потребителя
может использовать любой язык и любую внутреннюю механику (raw TCP, HTTP GET,
заход через мобильный SIM-модем, headless-браузер и т.д.), главное —
соблюдать формат запроса и ответа.

Референсная имплементация на Go — в [`examples/probe-server/`](../examples/probe-server/).

## Когда ладон вызывает remote

Локальная проба запускается всегда. Remote вызывается **только batch-воркером
и только после того, как локальная сказала FAIL** — это и единственный случай,
где remote может изменить вердикт (locally-OK означает что direct работает,
ничего тоннелировать не надо), и самый дешёвый по нагрузке на твой сервер.

Inline fast-path из tailer'а никогда не дёргает remote — там бюджет на
доли секунды.

## Endpoint

```
POST <url> HTTP/1.1
Content-Type: application/json
Authorization: <header-value>     ; только если настроено
```

Адрес берётся из `probe.remote.url` в конфиге ладона. Схема `http://` и
`https://` — обе допустимы; для продакшена настоятельно рекомендуется
TLS либо размещение проб-сервера в доверенной сети.

## Запрос

```json
{
  "domain": "instagram.com",
  "ips": ["157.240.20.174"],
  "port": 443,
  "sni": "instagram.com"
}
```

| поле | тип | обязательность | смысл |
|---|---|---|---|
| `domain` | string | обязательно | домен, запрошенный клиентом |
| `ips`    | string[] | опционально | IP-адреса, которые клиент получил из DNS (через dnsmasq). Если переданы — проб-сервер должен бить по ним напрямую и не делать собственный DNS-резолв. Это нужно чтобы «вид движка» совпал с «видом клиента» на geo-routed CDN'ах. |
| `port`   | int | обязательно | целевой порт, обычно `443` |
| `sni`    | string | обязательно | SNI для TLS-handshake, обычно равен `domain` |

## Ответ

```json
{
  "dns_ok": true,
  "tcp_ok": true,
  "tls_ok": true,
  "tls12_ok": null,
  "tls13_ok": true,
  "http_ok": false,
  "resolved_ips": ["157.240.20.174"],
  "reason": "http_cutoff: read tcp ... use of closed network connection",
  "code": "http_cutoff",
  "latency_ms": 1207
}
```

| поле | тип | обязательность | смысл |
|---|---|---|---|
| `dns_ok` | bool | опционально | удалось разрешить / получены IP'шники. Если в запросе передан `ips` — можно просто вернуть `true` |
| `tcp_ok` | bool | опционально | TCP-коннект прошёл |
| `tls_ok` | bool | опционально | TLS-handshake прошёл (без валидации сертификата — только достижимость) |
| `tls12_ok` | bool/null | опционально (probe-v2) | TLS 1.2-only retry результат: `true` — 1.2 прошёл, `false` — упал, `null`/отсутствует — не пробовали (1.3 уже прошёл) |
| `tls13_ok` | bool/null | опционально (probe-v2) | результат первой (нерестриктной) попытки. `false` + `tls12_ok=true` = вероятный ClientHello DPI на 1.3 |
| `http_ok` | bool/null | опционально (probe-v2) | HTTP-cutoff проба после TLS: `true` — прочитан полный response, `false` — поток оборван до или во время response, `null`/отсутствует — стадия не запускалась |
| `resolved_ips` | string[] | опционально | IP'шники, которые проб-сервер использовал. Если отсутствует — ладон считает что использовались те IP, которые он послал в `ips` |
| `reason` | string | опционально | текст причины фейла. С v0.6 рекомендуемый формат — `<code>: <raw err>` (например `tcp_timeout: i/o timeout`). Попадает в логи ладона и в таблицу `probes` |
| `code` | string | опционально (probe-v2) | стабильный enum, дублирует префикс `reason`. Допустимые значения: `dns_nxdomain`, `dns_timeout`, `dns_error`, `no_ips`, `tcp_refused`, `tcp_reset`, `tcp_timeout`, `tcp_unreachable`, `tcp_error`, `tls_handshake_timeout`, `tls_eof`, `tls_reset`, `tls_alert`, `tls_error`, `tls13_block`, `http_cutoff`, `http_timeout`, `http_reset`, `http_error`, `unknown`. Если не выставлено — ладон попытается выпарсить код из префикса `reason` (back-compat) |
| `latency_ms` | int | опционально | сколько миллисекунд заняла проба. Если 0 — ладон заменит на собственный замер round-trip |

**Статус 200** означает «проба завершена корректно, см. ответ». **Любой не-200**
трактуется ладоном как транспортная ошибка — домен считается `FAIL` с причиной
`remote:http_<code>:<snippet>`.

### Back-compat для probe-v1 серверов

Все probe-v2 поля (`tls12_ok`, `tls13_ok`, `http_ok`, `code`) опциональны.
Старый probe-сервер, возвращающий только `{dns_ok, tcp_ok, tls_ok, reason}`,
продолжает работать — ладон распарсит код из префикса `reason` если возможно
(`tcp:foo` → `unknown`, `tcp_timeout: foo` → `tcp_timeout`), а HTTP-стадия
просто не учитывается в decision (`http_ok=null` → fallback на TCP+TLS вердикт).

## Decision-таблица

`local` — результат локальной пробы (TCP+TLS с шлюза, всегда запускается).
`remote` — твой сервер (запускается только если local упал).

| local | remote | вердикт | почему |
|---|---|---|---|
| OK | — (не вызывается) | Ignore | direct работает, тоннель не нужен |
| FAIL | OK | **Hot** | настоящий DPI-блок: с шлюза не достучаться, твоя точка достучалась |
| FAIL | FAIL | **Ignore** | methodological FP: оба пути упали, домен не блокируется (порт не тот / мёртвый сервер / geofence на обеих точках) |
| FAIL | unavailable | **Hot** | remote недоступен (transport error, non-200, timeout) → «нет мнения», вердикт остаётся локальный |

«OK» / «FAIL» в этой таблице соответствуют итоговому вердикту локального
`decision.Classify`, который в probe-v2 учитывает не только TCP+TLS, но и
HTTP-cutoff: если `tls_ok=true` но `http_ok=false`, локальная проба считается
FAIL — это и есть сигнатура L7-DPI (handshake разрешён, но stream рвётся
посреди ответа), классическая для linkedin/instagram-семейства.

Последняя строка — критична: ладон **никогда не интерпретирует недоступность
твоего proб-сервера как сигнал «remote сказал FAIL»**. Иначе outage proб-сервера
тихо начал бы снимать ipset с реально-заблокированных доменов. Транспортная
ошибка распознаётся по префиксу `remote:` в reason — `RemoteProber` (см.
`internal/prober/remote.go::failedRemote`) проставляет его всегда, и движок
проверяет это в `engine.probeDomain` через `isRemoteTransportFailure`.

В `hot_entries.reason` пишется комбинированная причина:
`local:tcp:i/o timeout|remote:ok` — для дебага, чтобы видеть оба сигнала.

## Пример минимального сервера на bash

Чтобы показать, что имплементация не обязана быть сложной:

```bash
#!/bin/bash
# Listens on :8080, fails everything (sandbox / demo).
while true; do
  printf 'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 62\r\n\r\n{"dns_ok":false,"tcp_ok":false,"tls_ok":false,"reason":"stub"}' | nc -l -p 8080 -q 1
done
```

На Go — см. `examples/probe-server/main.go`.

## Безопасность

- Если проб-сервер доступен в публичной сети — **обязательно** настрой
  `auth_header` + `auth_value` в конфиге ладона и проверяй их на стороне
  сервера. Без auth любой сможет гонять пробы чужими руками.
- Для межсерверной связи предпочтителен TLS + bearer-token в `Authorization`.
- Если сервер в приватной сети за firewall'ом — можно обойтись без auth, но
  тогда убедись, что приватная сеть действительно изолирована.

## Что _не_ входит в контракт (v0.3.0)

- Нет механизма batch-проб — один запрос = один домен.
- Нет streaming / long-poll. Обычный запрос-ответ.
- Нет federation / aggregation: если нужны несколько vantage points, их должен
  склеивать сам проб-сервер внутри и отдавать ладону один вердикт.

Эти ограничения разумны для v1 — расширения (batch, chain, multi-vantage)
планируются в следующих версиях без breaking change.
