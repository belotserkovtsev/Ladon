# probe-server (reference implementation)

Минимальный HTTP-сервер, реализующий контракт, которого ожидает ладон в режиме
`probe.mode: exit-compare`. Делает ровно то же самое, что встроенный
`LocalProber` (TCP:443 → TLS-SNI без проверки сертификата), но удалённо.

Смысл: показать формат запроса/ответа. Подмени функцию `probe()` в `main.go`
на свою логику — и получаешь проб-сервер, который ладон опрашивает как
exit-compare валидатор. Реальные use-case'ы: Raspberry Pi за residential ISP,
4G-модем, headless-браузер, что угодно ещё, где имеет смысл измерять
доступность не с gateway'я.

## Сборка и запуск

```bash
cd examples/probe-server
go build -o probe-server .
./probe-server -listen :8080 -token secret -timeout 2s
```

Флаги:

| флаг | по умолчанию | смысл |
|---|---|---|
| `-listen` | `:8080` | адрес HTTP-сервера |
| `-token` | `""` | если задан, требует `Authorization: Bearer <token>` |
| `-timeout` | `2s` | таймаут на стадию (TCP, TLS) |

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
  "resolved_ips": ["93.184.216.34"],
  "latency_ms": 124
}
```

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
