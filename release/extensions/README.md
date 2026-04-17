# Extensions — преднастроенные allow/deny-списки

Готовые подборки доменов для типовых сервисов. Два типа:

- **Allow-extensions** — домены, которые всегда идут через туннель
  (параллельно `manual-allow.txt`).
- **Deny-extensions** — домены, которые всегда остаются direct и никогда
  не пробуются (параллельно `manual-deny.txt`).

Оба включаются опционально через `config.yaml`:

```yaml
extensions:      [ai, twitch, tiktok]
deny_extensions: [ru-direct]
```

## Пресеты

| Имя | Тип | Что покрывает |
|---|---|---|
| `ai` | allow | OpenAI / ChatGPT, Anthropic / Claude |
| `twitch` | allow | Стриминг (twitch.tv + CDN-домены) |
| `tiktok` | allow | TikTok / ByteDance overseas (core, CDN, backbone, SDK) |
| `ru-direct` | deny | RU-порталы и госсервисы, которым оффшорный VPN не нужен / вреден |

## Семантика

**Allow-extensions** при старте ladon для каждого включённого имени читают
`<extensions_path>/<name>.txt` и добавляют домены в manual-allow через
dnsmasq's native `ipset=` directive. Эффект:

- Домен всегда в ipset `ladon_manual` (минуя probe).
- IP-адреса добавляются, как только клиент их разрешит через dnsmasq —
  proactive resolve не делаем.
- Probe-пайплайн не может выкинуть extension-домен из ipset: ladon не
  трогает `ladon_manual`.

**Deny-extensions** при старте читают `<extensions_path>/<name>.txt` и
грузят домены в `manual_entries` с `list_name='deny'`:

- tailer пропускает их (skip-at-ingest), в `domains` table не попадают.
- probe-worker исключает их из `ListProbeCandidates` (v0.4.1+).
- `prune` вычищает любые ранее накопленные denied rows через
  `DeleteDeniedDomains`.
- Фильтр срабатывает по точному домену ИЛИ по eTLD+1: `mail.ru` в списке
  закроет `privacy-cs.mail.ru` без явной записи.

## Где живут файлы

После install из tarball: `/opt/ladon/extensions/`. Общий пул для allow и
deny — один и тот же файл может быть включён только с одной стороны
(config.Validate отвергает пересечение имён). Переопределяется через:

```yaml
extensions_path: /etc/ladon/extensions
```

## Конфликт имён

Преcет, указанный одновременно в `extensions` и `deny_extensions`, ladon
отклонит при старте: домен, который и в allow, и в deny, — признак
операторской ошибки, а не полезный паттерн.

## Свои списки

Положите `extensions_path/<свое-имя>.txt` с тем же форматом (один домен
на строку, `#` — комменты) и включите в config:

```yaml
extensions:      [ai, twitch, my-vpn-only]
deny_extensions: [corp-internal, ru-direct]
```

Альтернатива — обычные `/etc/ladon/manual-allow.txt` и
`/etc/ladon/manual-deny.txt`. Формат тот же. Разница только
организационная: extensions удобно держать тематическими подборками,
которые легко включать/выключать одной строкой в config.

## Формат файла

```
# Это комментарий
# Пустые строки игнорируются

example.com
sub.example.com
# disabled.example.com   ← закомментировано, не загрузится
```

Один домен на строку. Без `https://`, без портов, без слэшей.
Регистронезависимо. Точка в конце (`example.com.`) отрезается.
