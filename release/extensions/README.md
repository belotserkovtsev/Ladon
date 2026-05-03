# Extensions — преднастроенные allow/deny-списки

Готовые подборки доменов для типовых сервисов. Два типа:

- **Allow-extensions** — домены, которые всегда идут через туннель
  (параллельно `manual-allow.txt`). Bundled пресеты — см. таблицу ниже.
- **Deny-extensions** — домены, которые всегда остаются direct и никогда
  не пробуются (параллельно `manual-deny.txt`). Bundled deny-пресетов
  ladon **не шипает** — deny-списки сильно зависят от среды оператора
  (РФ-услуги, LAN, internal corp). Оператор ведёт свой
  `manual-deny.txt` или пишет собственный deny-preset.

Оба типа включаются опционально через `config.yaml`:

```yaml
allow_extensions: [ai, twitch, tiktok]
# deny_extensions: [my-corp-internal]   # кастомные пресеты оператора
```

## Bundled пресеты

| Имя | Тип | Что покрывает |
|---|---|---|
| `ai` | allow | OpenAI / ChatGPT, Anthropic / Claude |
| `brawlstars` | allow | Brawl Stars (Supercell): game-сервер (TCP/UDP 9339), web/CDN/login/inbox + Supercell-owned CIDR |
| `discord` | allow | Discord (приложение, gateway, CDN, медиа, активити, мерч) |
| `soundcloud` | allow | SoundCloud (core domains) |
| `telegram` | allow | Telegram HTTP-уровень (web, t.me, Telegraph, fragment, downloads) + DC CIDRs для MTProto data-plane (мобильный/desktop клиент) |
| `tiktok` | allow | TikTok / ByteDance overseas (core, regional CDN, backbone, SDK) |
| `twitch` | allow | Twitch (core + CDN + community-расширения 7tv/BetterTTV/FrankerFaceZ) |

## Семантика

**Allow-extensions** при старте ladon для каждого включённого имени читает
`<extensions_path>/<name>.txt` и добавляет домены в manual-allow через
dnsmasq's native `ipset=` directive. Эффект:

- Домен всегда в ipset `ladon_manual` (минуя probe).
- IP-адреса добавляются, как только клиент их разрешит через dnsmasq —
  proactive resolve не делаем.
- Probe-пайплайн не может выкинуть extension-домен из ipset: ladon не
  трогает `ladon_manual`.

**Deny-extensions** при старте читают `<extensions_path>/<name>.txt` и
грузят домены в `manual_entries` с `list_name='deny'`:

- tailer пропускает их (skip-at-ingest), в `domains` table не попадают.
- probe-worker исключает их из `ListProbeCandidates`.
- `ladon prune` вычищает любые ранее накопленные denied rows через
  `DeleteDeniedDomains`.
- Фильтр срабатывает по точному домену ИЛИ по eTLD+1: `mail.ru` в списке
  закроет `privacy-cs.mail.ru` без явной записи.

### Что значит eTLD+1 раскрытие для allow

Allow-extensions тоже разворачиваются по eTLD+1 — `openai.com` в файле
превращается в `ipset=/openai.com/ladon_manual`, что у dnsmasq покрывает
все поддомены сразу (`api.openai.com`, `cdn.openai.com` и т.д.). Поэтому
в пресете достаточно перечислить регистрируемые домены — не надо
руками раскатывать `*.cdn.service.com`.

## Где живут файлы

После install из tarball: `/opt/ladon/extensions/`. Общий пул для allow и
deny — один и тот же файл может быть включён только с одной стороны
(config.Validate отвергает пересечение имён). Переопределяется через:

```yaml
extensions_path: /etc/ladon/extensions
```

## Конфликт имён

Пресет, указанный одновременно в `allow_extensions` и `deny_extensions`,
ladon отклонит при старте: домен, который и в allow, и в deny, — признак
операторской ошибки, а не полезный паттерн.

## Как включить и проверить

1. Отредактируйте `/etc/ladon/config.yaml`, добавьте имя пресета в
   нужный список.
2. Перезапустите ladon: `systemctl restart ladon`. Ladon перепишет
   `/etc/dnsmasq.d/ladon-manual.conf` и сам рестартанёт dnsmasq —
   руками трогать не надо.
3. Убедитесь в журнале:

   ```
   journalctl -u ladon -n 20 | grep extension
   # ожидается:
   #   allow extension ai: 8 domains from /opt/ladon/extensions/ai.txt
   #   deny extension my-corp: 3 domains from /opt/ladon/extensions/my-corp.txt
   ```

4. Для allow — проверьте, что ipset наполнился после резолва:

   ```
   nslookup <домен-из-пресета> <ladon-host>
   ipset list ladon_manual | grep -c -vE 'timeout|Name|Type|Revision|Header|Size|References|Number|Members'
   ```

## Свои списки

Положите `<extensions_path>/<свое-имя>.txt` с тем же форматом (один домен
на строку, `#` — комменты) и включите в config:

```yaml
allow_extensions: [ai, twitch, my-vpn-only]
deny_extensions:  [corp-internal]
```

Альтернатива — обычные `/etc/ladon/manual-allow.txt` и
`/etc/ladon/manual-deny.txt`. Формат тот же. Разница только
организационная: extensions удобно держать тематическими подборками,
которые легко включать/выключать одной строкой в config.

> **Переживёт ли кастомный пресет upgrade?** install.sh перезаписывает
> `/opt/ladon/extensions/*.txt` из tarball'а при каждом запуске. Если вы
> хотите сохранить кастомный файл между апгрейдами — держите его в
> отдельном каталоге и укажите `extensions_path:` на него, или
> отправьте PR чтобы заапстримить пресет в репозиторий.

## Формат файла

```
# Это комментарий
# Пустые строки игнорируются

example.com
sub.example.com
# disabled.example.com   ← закомментировано, не загрузится

# CIDR-блоки в том же файле (для сервисов, которые ходят на голые IP мимо DNS):
91.108.4.0/22
185.76.151.42        # одиночный IP — auto-промоутится в /32
```

Парсер сам разделяет: что распарсилось через `net.ParseCIDR` — попадает
в `ladon_cidr` (hash:net), остальное — в `ladon_manual` (через dnsmasq).
IPv6 CIDRs пока пропускаются с warning'ом — routing-пайплайн v4-only.

Один домен/CIDR на строку. Для доменов: без `https://`, без портов, без
слэшей; регистронезависимо; точка в конце (`example.com.`) отрезается.

### Зачем CIDR

Некоторые сервисы после первоначального bootstrap ходят на data-plane по
голому IP, минуя DNS. dnsmasq → ipset для них бесполезен. Пример —
Telegram MTProto: мобильный клиент после DC discovery подключается к
`91.108.x.x`/`149.154.x.x` напрямую. CIDR-блоки заливаются в `ladon_cidr`
при старте ladon и матчатся iptables на уровне dst IP — независимо от
DNS-резолва.
