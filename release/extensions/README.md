# Extensions — преднастроенные allow-списки

Готовые подборки доменов для типовых сервисов, которые часто хочется
завернуть в туннель целиком. Включаются опционально через `config.yaml`:

```yaml
extensions:
  - ai
  - twitch
```

Доступные пресеты сейчас:

| Имя | Что покрывает |
|---|---|
| `ai` | OpenAI / ChatGPT, Anthropic / Claude |
| `twitch` | Стриминг (twitch.tv + CDN-домены) |
| `tiktok` | TikTok / ByteDance (основные домены, CDN, backbone) |

## Семантика

При старте ladon для каждого включённого имени читает
`<extensions_path>/<name>.txt` и грузит домены в `manual_entries` с
`list_name='allow'` — то есть точно так же, как обычный `manual-allow.txt`.

Эффект:

- Домен всегда в ipset `prod` (минуя probe).
- IP-адреса добавляются в ipset, как только клиент их разрешит через dnsmasq —
  proactive resolve мы не делаем.
- Probe-пайплайн (даже с exit-compare) **не может выкинуть** extension-домен
  из ipset: ipset-syncer всегда включает manual-allow в union.

## Где живут файлы

После install из tarball: `/opt/ladon/extensions/`. Можно переопределить
через config:

```yaml
extensions: [ai, twitch]
extensions_path: /etc/ladon/extensions
```

## Свои списки

Никто не мешает положить в `extensions_path/<свое-имя>.txt` собственный
файл с тем же форматом (один домен на строку, `#` — комменты) и включить
его в config так же, как пресеты:

```yaml
extensions: [ai, twitch, my-vpn-only]
```

Альтернатива — обычный `/etc/ladon/manual-allow.txt`, формат тот же.
Разница только организационная: extensions удобно держать как
тематические подборки.

## Формат файла

```
# Это комментарий
# Пустые строки игнорируются

example.com
sub.example.com
# disabled.example.com   ← закомментировано, не загрузится
```

Один домен на строку. Без `https://`, без портов, без слэшей.
Регистронезависимо.
