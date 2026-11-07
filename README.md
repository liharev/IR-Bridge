# CAMAI IR-Bridge

Модуль CAMAI для учёта успешных валидаций проездных документов на валидаторах с протоколом
IntelliReader (ООО «МУЛЬТИПАС»). Модуль пассивно наблюдает обмен «контроллер АСОП ↔ IntelliReader»
по TCP, восстанавливает кадры протокола, определяет исход каждого предъявления (APPROVED, REJECTED,
NO_DECISION, ABORTED) и публикует события в шину CAMAI вместе с интервалами «вошло / оплатило»
для оценки числа безбилетных пассажиров.

Платформа: Rockchip RK3588 (aarch64), Debian 11/12 или Ubuntu 22.04 arm64, systemd. Сборка и тесты
также на x86_64.

Документы: [ТЗ](docs/TZ_IR-Bridge.md) · [спецификация протокола v1.96](docs/vendor/intellireader-protocol-v1.96.pdf) ·
[промпты реализации](docs/camai-irbridge-llm-prompts.md).

## Как это работает

```
захват (mirror / bridge / proxy / pcap-file)
  → TCP-сборка (tcp)  → кадры IR, CRC-16/XMODEM (codec)
  → сопоставление запрос/ответ по MSGID (corr) → protobuf (proto)
  → детектор валидаций и правила индикации (detect) → хэш носителя HMAC-SHA256 (privacy)
  → интервалы по дверям и счётчику пассажиров (agg)
  → SQLite WAL (store) → MQTT QoS 1 и HTTP API (pub)
```

IntelliReader не сообщает «валидация успешна»: решение принимает контроллер. Модуль считает
предъявление одобренным, когда в окне `decision_window_ms` после ответа с носителем
(TransactionResult, Token, Event, QrCodeEvent, Troika) контроллер отправляет команду индикации,
совпадающую с правилами `detector.approve` (экран APPROVED, зелёный светодиод, RGB, турникет, текст).
Правила `detector.reject` имеют приоритет. Политики `indication_or_write` и `emv_status` добавляют
одобрение по подтверждённой записи на карту и по статусу EMV.

Номера карт не сохраняются и не передаются: из ответа берётся только `carrier_hash`
(HMAC-SHA256 с секретом устройства, 16 байт), платёжная система по AID, сумма и тип носителя.
Буферы protobuf обнуляются после разбора.

## Сборка

Зависимости (Debian/Ubuntu):

```
sudo apt install build-essential cmake pkg-config protobuf-compiler libprotobuf-dev \
  libsqlite3-dev libssl-dev libyaml-cpp-dev nlohmann-json3-dev libspdlog-dev \
  libmosquitto-dev libcpp-httplib-dev libsystemd-dev libgtest-dev
```

```
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
cd build && ctest --output-on-failure
```

Опции CMake: `IRBRIDGE_BUILD_TESTS` (ON), `IRBRIDGE_SANITIZE` (ASan/UBSan), `IRBRIDGE_BUILD_FUZZ`
(libFuzzer, нужен clang), `IRBRIDGE_WITH_MQTT` (ON), `IRBRIDGE_WITH_SYSTEMD` (ON), `IRBRIDGE_WERROR` (ON).

Полная проверка (Release, санитайзеры, сканирование выходных данных на номера карт, пакет):
`scripts/ci.sh` или `scripts/ci.sh --fuzz 60`.

Кросс-сборка для RK3588 (нужен sysroot arm64 с теми же -dev пакетами и `protoc` той же версии,
что и libprotobuf в sysroot):

```
cmake -S . -B build-arm64 -DCMAKE_TOOLCHAIN_FILE=cmake/toolchain-aarch64.cmake \
      -DCMAKE_SYSROOT=/opt/sysroot-arm64 -DCMAKE_BUILD_TYPE=Release
cmake --build build-arm64 -j && (cd build-arm64 && cpack)
```

Проще собирать нативно на самой плате или в arm64-контейнере (`docker run --platform linux/arm64 debian:12`).

## Установка

```
sudo apt install ./camai-irbridge_1.0.0_arm64.deb
sudoedit /etc/camai/irbridge.yaml          # vehicle_id, интерфейс, IP валидаторов, правила
irbridged --check-config --config /etc/camai/irbridge.yaml
sudo systemctl restart camai-irbridge
curl -s 127.0.0.1:8095/api/v1/health
```

Пакет создаёт пользователя `camai-irbridge` и каталог `/var/lib/camai/irbridge` (0700): база событий,
секрет хэширования `secret.key` (0600, создаётся при первом запуске; не копируйте его между машинами
без необходимости — от него зависят все `carrier_hash`).

Служба работает без root: захват требует `CAP_NET_RAW` (и `CAP_NET_ADMIN` для promiscuous-режима),
они выдаются unit-файлом через `AmbientCapabilities`. Проверка: `grep Cap /proc/$(pidof irbridged)/status`
или запуск вручную `sudo -u camai-irbridge irbridged` — без возможностей служба завершится с сообщением
`capture on ...: ... (CAP_NET_RAW required)`.

`systemctl reload camai-irbridge` (SIGHUP) перечитывает конфигурацию: при ошибке в файле остаётся
прежняя. SIGTERM: незавершённые предъявления закрываются как ABORTED, очереди сбрасываются на диск,
выход менее чем за 5 с. Watchdog systemd — 30 с.

## Режимы захвата

| Режим | Когда | Настройка |
| --- | --- | --- |
| `mirror` | Коммутатор с зеркалированием порта валидаторов на порт CAMAI | `capture.interface: eth1` |
| `bridge` | CAMAI включён в разрыв (мост без IP) | пример systemd-networkd в `packaging/networkd-bridge-example/` |
| `proxy` | Контроллер подключается к CAMAI, CAMAI — к IR; байты не меняются | `capture.proxy.listen: [{listen, upstream}]` |
| `pcap-file` | Разбор записи трафика | `capture.pcap_file` |

Ограничения: при TLS (порт 42800) содержимое не видно, валидатор получает статус `encrypted`;
IntelliReader внутри валидатора Full A (127.0.0.1) недоступен для наблюдения извне.

## Выходные данные

MQTT (QoS 1, `<prefix>` = `mqtt.topic_prefix`, по умолчанию `camai`):

| Топик | Содержимое |
| --- | --- |
| `<prefix>/<vehicle>/fare/validation` | событие `irbridge.validation/1` на каждое предъявление |
| `<prefix>/<vehicle>/fare/interval` | интервал `irbridge.fare_interval/1`: boarded, passengers_paid, unpaid_estimate, reliable |
| `<prefix>/<vehicle>/fare/validator/<id>` | retained-статус `irbridge.validator_status/1`: observed / silent / encrypted / faulty / unmapped |

Подписки модуля: `<prefix>/<vehicle>/pax/count` (`{door_id, ts, in, out}`), `<prefix>/<vehicle>/doors`
(`{door_id, ts, state: open|closed, stop_id?}`), `<prefix>/<vehicle>/pax/fault` (`{door_id?, ts, fault}`).
`ts` — RFC 3339 или миллисекунды Unix.

Доставка «как минимум один раз»: событие помечается отправленным только после PUBACK; без брокера
события копятся в SQLite и уходят после восстановления связи с тем же `event_id`.

HTTP (по умолчанию 127.0.0.1:8095): `/api/v1/health`, `/api/v1/validators`,
`/api/v1/events?since=<RFC3339|ms>&limit=<≤1000>`, `/api/v1/intervals?since=`, `/metrics` (Prometheus).

## Инструменты

```
irbridge-pcaptool synth  --scenario tests/data/scenarios/bank_card_approved.yaml --out s.pcap
irbridge-pcaptool replay --pcap s.pcap --config /etc/camai/irbridge.yaml --out events.jsonl
irbridge-pcaptool stats  --pcap capture.pcap
```

`replay` на записи с объекта показывает, какие предъявления получат APPROVED / REJECTED /
NO_DECISION при текущих правилах, — так подбираются `detector.approve` / `detector.reject` под
конкретную АСОП. Запись трафика (`tcpdump -i eth1 -w capture.pcap tcp port 42616`) содержит данные
карт: храните её как конфиденциальную и удаляйте после анализа. В модуле аналогичная запись
(`privacy.raw_capture`) выключена по умолчанию и ограничена по объёму и сроку.

## Тесты

- `tests/unit` — GoogleTest по компонентам: кодек (эталонные векторы CRC), TCP-сборка (порядок,
  повторы, переполнение номера последовательности, потери), BPF-фильтр, корреляция, детектор во всех
  политиках, агрегация, хранилище (WAL, ретеншн), конфигурация, JSON, proxy (задержка, медленный
  разборщик), публикация (PUBACK, переподключение), HTTP API.
- `tests/data/scenarios/*.yaml` → `synth` → `replay` → сравнение с `tests/data/expected/*.jsonl`
  (ctest `scenario_*`), затем проверка вывода на номера карт (`pan_scan`). Обновить эталоны после
  намеренного изменения: `cmake -DUPDATE=ON -DPCAPTOOL=... -DSCENARIO=... -DCONFIG=... -DEXPECTED=... -DWORKDIR=... -P cmake/RunScenario.cmake`.
- `tests/fuzz` — libFuzzer для кодека, TCP-сборки и protobuf (`-DIRBRIDGE_BUILD_FUZZ=ON`, clang).

## Лицензия протокола

Файлы `third_party/intellireader-proto/` и `docs/vendor/` — материалы ООО «МУЛЬТИПАС»
(IntelliReader protocol v1.96), включены без изменений. Условия их использования и распространения
в составе продукта нужно согласовать с правообладателем.
