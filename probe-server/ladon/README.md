# probe-server (reference implementation)

Минимальный HTTP-сервер, реализующий контракт, которого ожидает ладон в режиме
`probe.mode: exit-compare`. Импортирует `internal/prober.LocalProber` напрямую,
то есть удалённый вантаж проходит **те же самые стадии**, что и local на ладоне:
DNS → TCP:443 → TLS-split (1.3, при failure — 1.2) → HTTP-cutoff чтение до 32KB.

Смысл: чистая семантика exit-compare — если local FAIL и remote FAIL, проба
сломалась одинаково с обеих точек (server-side или global), а не из-за разной
probe-логики. Если хочется кастомный вантаж (4G-модем, headless-браузер,
Raspberry Pi за residential ISP) — замени `probeIt.Probe(...)` в `main.go` своим
вызовом, главное соблюдай JSON-контракт ответа.

## Сборка и запуск

```bash
cd probe-server/ladon
go build -o probe-server .
./probe-server -listen :8080 -token secret -timeout 2s
```

Флаги:

| флаг | по умолчанию | смысл |
|---|---|---|
| `-listen` | `:8080` | адрес HTTP-сервера |
| `-token` | `""` | если задан, требует `Authorization: Bearer <token>` |
| `-timeout` | `2s` | таймаут на стадию (DNS / TCP / TLS / HTTP). Probe-v2 выполняет 4 стадии последовательно, поэтому реальный wall-time может быть до ~3-4× этого значения в worst case. |

## Проверка вручную

```bash
curl -X POST http://localhost:8080/probe \
  -H 'Authorization: Bearer secret' \
  -H 'Content-Type: application/json' \
  -d '{"domain":"example.com","port":443,"sni":"example.com"}'
```

Ответ:

```json
{
  "dns_ok": true,
  "tcp_ok": true,
  "tls_ok": true,
  "tls13_ok": true,
  "http_ok": true,
  "resolved_ips": ["93.184.216.34"],
  "latency_ms": 124
}
```

`tls12_ok` появится в ответе только если 1.3 fail и retry на 1.2 потребовался.
`http_ok=null` означает что HTTP-стадия не запускалась (kort-circuited на TCP/TLS
fail). Полный список полей — в [`docs/probe-api.md`](../../docs/probe-api.md).

## Подключение к ладону

В `/etc/ladon/config.yaml`:

```yaml
probe:
  mode: exit-compare
  remote:
    url: http://<probe-server-host>:8080/probe
    timeout: 2s
    auth_header: Authorization
    auth_value: Bearer secret
```

Контракт целиком описан в [`docs/probe-api.md`](../../docs/probe-api.md).
