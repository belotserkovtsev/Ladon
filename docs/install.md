# Установка

← [README](../README.md) · [конфигурация](configuration.md) · [extensions](extensions.md)

Ладон ставится одной командой. Дальше он сам находит заблокированные домены и
складывает их адреса в списки в ядре (`ipset`). Одно ты делаешь сам: связываешь
эти списки со своей маршрутизацией, чтобы помеченный трафик уходил в туннель.
Ладон в чужую маршрутизацию не лезет, только наполняет списки.

## Куда его можно поставить

Скрипт установки один на все случаи: он смотрит, на какую систему попал, и
спрашивает, каким способом ставить.

- **Службой на шлюзе (Debian/Ubuntu).** Основной путь, всё остальное в этом
  документе про него. Ладон живёт рядом с dnsmasq и наполняет списки в ядре.
- **Контейнером на обычной машине.** Образ приносит резолвер с собой и держит
  списки внутри своего сетевого пространства, так что на хосте не появляется
  ничего: ни правил, ни списков. Нужен там, где шлюза нет, а трафик разделить
  хочется. Что при этом остаётся сделать руками и как откатить, написано в
  [install-docker.md](install-docker.md).
- **На OPNsense.** Тем же скриптом, систему он распознаёт сам. Там вместо
  dnsmasq работает unbound, а вместо `ipset` таблицы `pf`; ставится это плагином
  `os-ladon` с вкладкой в веб-интерфейсе. Как это устроено и что делать
  дальше, в [install-opnsense.md](install-opnsense.md).

Чтобы скрипт не спрашивал, задай способ заранее: `LADON_MODE=systemd` или
`LADON_MODE=docker`.

## Быстрая установка (Debian/Ubuntu)

```bash
curl -fsSL https://github.com/belotserkovtsev/ladon/releases/latest/download/install.sh \
  | sudo bash
```

Скрипт всё делает сам:

- определяет архитектуру (amd64/arm64), скачивает последнюю версию и сверяет sha256;
- ставит зависимости (`ipset`, `sqlite3`, `dnsmasq`);
- раскладывает бинарь, systemd-юнит, конфиги и подборки доменов по `/opt/ladon` и `/etc/ladon`;
- создаёт списки `ladon_engine`, `ladon_manual`, `ladon_cidr` и сохраняет их, чтобы пережили перезагрузку;
- выдаёт dnsmasq право добавлять адреса в списки (capability `CAP_NET_ADMIN`);
- создаёт базу, перезапускает dnsmasq и запускает ладон;
- печатает пример правил маршрутизации, которые **тебе нужно дописать руками**.

Чего скрипт **не** делает: не трогает `iptables`, `ip rule` и таблицы
маршрутизации. Это твоя зона: только ты знаешь, как называется твой туннельный
интерфейс и как у тебя устроены метки и маршруты. Ладон лишь наполняет списки;
куда направить трафик, попавший в эти списки, решаешь ты. Пример для типичного
WireGuard-туннеля скрипт печатает в конце.

**Обновление.** Запусти тот же `install.sh` ещё раз. Он идемпотентен: подтянет
свежую версию, перезапишет бинарь, юнит и подборки, но **сохранит** твой
`config.yaml` и `manual-allow/deny.txt`, и перезапустит ладон. Схему базы руками
мигрировать не нужно: `run` сам догоняет её на старте.

**Удаление:**

```bash
curl -fsSL https://github.com/belotserkovtsev/ladon/releases/latest/download/uninstall.sh \
  | sudo bash
```

Для нестандартных путей есть переменные окружения: `IPSET_ENGINE`, `IPSET_MANUAL`,
`LADON_PREFIX`, `LADON_CONFIG_DIR`; дефолты смотри в
[`release/install.sh`](../release/install.sh).

---

## Установка вручную

Если хочешь понимать, что происходит под капотом, или у тебя нестандартная сеть,
ниже те же шаги вручную. Расчёт на Debian/Ubuntu, где уже есть туннель наружу,
dnsmasq и маршрутизация по меткам.

### 1. Зависимости

```bash
apt update
apt install ipset iptables-persistent sqlite3
```

Дальше нужен подробный лог dnsmasq: из него ладон и узнаёт, какие домены
запрашивали. В `/etc/dnsmasq.d/gateway.conf` добавь:

```
log-queries=extra
log-facility=/var/log/dnsmasq.log
```

После правки запусти `systemctl restart dnsmasq`. Проверь
`tail -f /var/log/dnsmasq.log`: там должны идти строки вида
`query[A] domain from ...` и `reply domain is ...`.

### 2. Бинарь

```bash
ARCH=amd64    # или arm64 для Raspberry Pi и ARM-серверов
# Берём последнюю версию (или закрепи свою через TAG=v3.0.0)
TAG=$(curl -sSL "https://api.github.com/repos/belotserkovtsev/ladon/releases/latest" \
  | grep '"tag_name":' | head -1 | cut -d'"' -f4)
echo "installing $TAG for $ARCH"

mkdir -p /opt/ladon/state /etc/ladon
cd /tmp
curl -L -O "https://github.com/belotserkovtsev/ladon/releases/download/${TAG}/ladon-linux-${ARCH}.tar.gz"
tar xzf ladon-linux-${ARCH}.tar.gz
cd ladon-linux-${ARCH}-${TAG}

install -m 0755 ladon                     /opt/ladon/ladon
install -m 0644 ladon.service             /etc/systemd/system/
install -m 0644 manual-allow.txt.example  /etc/ladon/manual-allow.txt
install -m 0644 manual-deny.txt.example   /etc/ladon/manual-deny.txt

# Подборки доменов (ai, twitch, ...). Необязательны, включаются по имени
# в config.yaml. Подробнее в docs/extensions.md.
install -d /opt/ladon/extensions
install -m 0644 extensions/*.txt /opt/ladon/extensions/
```

### 3. Три списка в ядре

```bash
# У каждого списка своя роль:
#   ladon_engine: то, что ладон нашёл пробами (hot/cache)
#   ladon_manual: то, что наполняет dnsmasq (manual-allow + allow-подборки)
#   ladon_cidr:   диапазоны адресов из подборок (Telegram, голос Discord);
#                 нужен, только если включаешь подборки с диапазонами
ipset create ladon_engine hash:ip  family inet maxelem 65536
ipset create ladon_manual hash:ip  family inet maxelem 65536 timeout 86400
ipset create ladon_cidr   hash:net family inet maxelem 65536
```

Теперь надо помечать трафик, который идёт на адреса из этих списков, чтобы
маршрутизация увела его в туннель. Метка `0x1` ниже это пример:

```bash
for SET in ladon_engine ladon_manual ladon_cidr; do
  iptables -t mangle -A PREROUTING \
    -m set --match-set "$SET" dst \
    -j MARK --set-mark 0x1
done

# Сохранить, чтобы пережило перезагрузку
mkdir -p /etc/iptables
iptables-save > /etc/iptables/rules.v4
ipset save    > /etc/iptables/ipsets
systemctl enable netfilter-persistent
```

(Хочешь гнать в туннель только часть клиентов: добавь к правилу
`-s <подсеть-клиента>`.)

**Почему три списка, а не один:**

- `ladon_engine` ладон периодически пересобирает сам по своим находкам, лишнее из него вычищается.
- `ladon_manual` наполняет dnsmasq прямо в момент резолва, через директивы `ipset=/домен/ladon_manual`, которые ладон пишет в `/etc/dnsmasq.d/ladon-manual.conf`. Будь это один список с `ladon_engine`, ладон при пересборке выкидывал бы адреса, добавленные dnsmasq, про которые он не знает. `timeout 86400` сам убирает протухшие адреса, а при каждом новом резолве таймер обновляется.
- `ladon_cidr`: диапазоны адресов из подборок (например, MTProto Telegram на `91.108.0.0/16`). Ладон заливает их на старте, и совпадение идёт прямо по адресу, мимо DNS.

#### Право dnsmasq добавлять адреса (обязательно)

Пакетный dnsmasq работает под своим пользователем, а не под root, и по умолчанию
**не может** добавлять адреса в списки ядра, даже если директивы `ipset=` прописаны.
Выглядит это так: dnsmasq домен резолвит, клиенту отвечает, а `ladon_manual`
остаётся пустым, и трафик идёт напрямую. Лечится дропином для systemd:

```bash
sudo install -d /etc/systemd/system/dnsmasq.service.d
sudo tee /etc/systemd/system/dnsmasq.service.d/ladon-ipset.conf > /dev/null <<'EOF'
[Service]
AmbientCapabilities=CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW CAP_SETUID CAP_SETGID CAP_CHOWN CAP_DAC_OVERRIDE CAP_FOWNER CAP_SETFCAP CAP_SETPCAP CAP_SYS_CHROOT CAP_KILL
EOF
sudo systemctl daemon-reload
sudo systemctl restart dnsmasq
```

Проверка:

```bash
dig @127.0.0.1 +short openai.com
sudo ipset list ladon_manual | tail -10
# ↳ должны появиться адреса с таймаутом
```

#### Метка в туннель

Связку «метка → таблица маршрутизации → туннельный интерфейс» обычно уже задаёт
твой VPN-стек. Если нет, вот минимум (замени `wg0` на имя своего туннеля):

```bash
echo '666 ladon' >> /etc/iproute2/rt_tables
ip rule add fwmark 0x1 table ladon priority 1000
ip route replace default dev wg0 table ladon
```

Ладон считает, что таблица и связка «метка → интерфейс» уже готовы, и просто
наполняет списки `ladon_engine`, `ladon_manual`, `ladon_cidr`.

### 4. Создать базу и запустить

> `run` сам создаёт и догоняет схему базы на старте (идемпотентно): на пустой
> базе создаст таблицы, на старой обновит. `init-db` ниже это явный шаг создать
> базу заранее, чтобы поймать ошибки до старта сервиса.

```bash
/opt/ladon/ladon -db /opt/ladon/state/engine.db init-db

systemctl daemon-reload
systemctl enable --now ladon

systemctl status ladon
journalctl -u ladon -f
```

Через минуту в логе пойдут строки вроде:

```
probe example.com → HOT (tcp_timeout, 812ms)
ipset ladon_engine: +5 -0 (total 5, etlds expanded 1)
```

### 5. Проверить, что работает

Быстрее всего это встроенная диагностика: она сама проходит по всему конвейеру
и показывает, где первое порванное звено.

```bash
sudo ladon -db /opt/ladon/state/engine.db doctor         # полная проверка; код выхода 0/1/2
ladon -db /opt/ladon/state/engine.db status              # снимок состояния, без прав
ladon -db /opt/ladon/state/engine.db why rutracker.org   # почему домен идёт (или не идёт) в туннель
```

Что значат эти команды и их вывод, подробнее в [конфигурации](configuration.md#диагностика).

Если хочешь копнуть в базу руками:

```bash
# Сколько доменов и в каком состоянии
sqlite3 /opt/ladon/state/engine.db \
  "SELECT state, COUNT(*) FROM domains GROUP BY state"

# Сколько адресов в каждом списке
for SET in ladon_engine ladon_manual ladon_cidr; do
  echo -n "$SET: "; ipset list "$SET" -t 2>/dev/null | grep '^Number'
done

# Последние блокировки. Вердикт ставится на фоновой перепроверке, поэтому
# на свежей базе пустой результат это нормально.
sqlite3 -column /opt/ladon/state/engine.db \
  "SELECT domain, verdict, failure_reason, created_at
   FROM probes WHERE verdict = 'blocked'
   ORDER BY created_at DESC LIMIT 10"
```

### 6. Править ручные списки

```bash
echo "myblocked.com" >> /etc/ladon/manual-allow.txt   # всегда в туннель
echo "mybank.ru"     >> /etc/ladon/manual-deny.txt     # не трогать

systemctl restart ladon   # списки читаются на старте
```

### 7. Снести вручную

```bash
systemctl disable --now ladon
rm /etc/systemd/system/ladon.service
rm -rf /opt/ladon /etc/ladon

# Убрать правила и списки (зеркало шага 3)
for SET in ladon_engine ladon_manual ladon_cidr; do
  iptables -t mangle -D PREROUTING -m set --match-set "$SET" dst -j MARK --set-mark 0x1
  ipset destroy "$SET"
done
iptables-save > /etc/iptables/rules.v4
ipset save    > /etc/iptables/ipsets
```

## Если что-то не так

**Ладон запустился, но через час список пустой.** Проверь, что dnsmasq реально
пишет лог: `tail -f /var/log/dnsmasq.log`. Если тихо, значит `log-queries=extra`
не применился, перезапусти dnsmasq.

**В логе `set not found — routing is NOT being programmed`.** Список не создан до
старта ладона или не пережил перезагрузку (не включён `netfilter-persistent`,
см. шаг 3). Рядом в строке лога есть готовая команда, которой список создаётся.
Создай и перезапусти сервис.

Соседний вариант той же беды — `cannot use the set`: список, может, и есть, но
дотянуться до него не выходит, чаще всего потому, что `ipset` не установлен или
демон запущен без нужных прав.

В обоих случаях ладон продолжает работать: наблюдает, пробует, ведёт базу. Он
только не программирует маршруты, о чём и сообщает. Падать в такой ситуации он
не станет, и это осознанно: список от перезапуска не появится, а вот дёргать за
собой dnsmasq по кругу демон будет, и DNS замигает у всех за шлюзом.

**Все домены уходят в `hot`, хотя напрямую всё работает.** Скорее всего на шлюзе
выключен IPv6, а в кэше осели адреса IPv6. Ладон отсеивает их на входе, но если
обновлялся со старой версии, почисти и перезапусти:

```bash
sqlite3 /opt/ladon/state/engine.db "DELETE FROM dns_cache WHERE ip LIKE '%:%'"
systemctl restart ladon
```

**Ладон ест много CPU.** Подними `ProbeCooldown` в `engine.Defaults()`: домены
будут перепробоваться реже (нужна пересборка бинаря).

**Растёт файл базы или `*.db-wal`.** Ладон подрезает базу сам, раз в час:
сворачивает `*.db-wal` в основной файл и чистит старые записи проб и DNS-кэша. Это
только освобождение места, на работу не влияет. Сам файл при этом не ужимается
(страницы переиспользуются); для разового сжатия запусти `VACUUM` вручную в
спокойное время.
