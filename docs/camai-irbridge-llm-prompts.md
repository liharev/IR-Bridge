# Промпты для LLM: реализация модуля CAMAI IR-Bridge (интеграция с IntelliReader)

Версия 1.0 от 07.11.2026 · ООО «АБ Технолоджи»

Файл содержит последовательность промптов, по которым LLM-ассистент для программирования (Claude Code или аналог с доступом к репозиторию и терминалу) реализует модуль IR-Bridge по техническому заданию «Интеграция CAMAI с IntelliReader для учёта успешных валидаций» (далее — ТЗ).

## Как пользоваться

1. Перед первым промптом положите в репозиторий:
   - `docs/TZ_IR-Bridge.md` — ТЗ (экспорт документа в Markdown);
   - `docs/IntelliReader_API.md` — «Описание API IntelliReader при интеграции по IP-адресу»;
   - `third_party/intellireader-proto/` — содержимое каталога `protocol/` из архива `intellireader-protocol-v1.96.zip` без изменений;
   - `docs/vendor/intellireader-protocol-v1.96.pdf` — спецификация протокола из того же архива.
2. Вставьте **Системный промпт** (раздел 0) в начало сессии или в файл `CLAUDE.md` в корне репозитория.
3. Выполняйте промпты 1–14 строго по порядку, по одному за сессию или за шаг. Следующий промпт — только после того, как выполнены все пункты «Готово, когда» предыдущего.
4. После каждого промпта запускайте промпт **R (ревью)** из раздела 15.
5. Если LLM предлагает отступить от ТЗ, требуйте явного обоснования и вносите изменение в ТЗ, а не только в код.

Номера требований вида ФТ-4.6 ссылаются на ТЗ.

---

## 0. Системный промпт (постоянный контекст)

```text
Ты — ведущий инженер C++ встраиваемых Linux-систем. Ты реализуешь модуль CAMAI IR-Bridge
по техническому заданию docs/TZ_IR-Bridge.md. Протокол IntelliReader описан в
docs/IntelliReader_API.md и в docs/vendor/intellireader-protocol-v1.96.pdf; файлы .proto лежат
в third_party/intellireader-proto/ и НЕ изменяются.

Целевая платформа: Rockchip RK3588 (aarch64, 4×Cortex-A76 + 4×Cortex-A55), Linux BSP (ядро 5.10/6.1),
Debian 11/12 или Ubuntu 22.04 arm64, systemd. Сборка: CMake ≥ 3.16, GCC ≥ 10, C++17,
флаги -O2 -Wall -Wextra -Werror; для aarch64 добавляется -march=armv8.2-a.
Код должен собираться и проходить тесты также на x86_64 (CI) и кросс-собираться toolchain-файлом
cmake/toolchain-aarch64.cmake.

Разрешённые зависимости: protobuf ≥ 3.12 (proto2) и protoc, libpcap (опционально), SQLite3,
OpenSSL (только HMAC-SHA256 и SHA-256), Eclipse Paho MQTT C++ или libmosquitto, nlohmann/json,
yaml-cpp, spdlog, cpp-httplib, GoogleTest, libsystemd (sd_notify). Другие — только с моего согласия.

Ключевые факты протокола (не придумывай других):
- Кадр: 'I''R' (0x49 0x52) | LENGTH BE16 = len(MSGID+MODULE+TYPE+PAYLOAD) | MSGID u8 | MODULE u8 |
  TYPE u8 | PAYLOAD (protobuf proto2) | CRC BE16.
- CRC-16/XMODEM: poly 0x1021, init 0x0000, без отражения, без xorout; по байтам от HEADER до
  конца PAYLOAD. Кадр целиком 9..4128 байт, значит LENGTH 3..4122.
- TYPE: 0x01 Command, 0x02 Successful, 0x03 Failure (common.failure.FailureResponse),
  0x04 Pending (пустой), 0x05 Notification (MSGID=MODULE=0, common.notification.Notification),
  0x06 Control (отмена, пустой).
- MODULE: 0x00 служебный, 0x01 Miscellaneous, 0x02 Contact L1, 0x03 Contactless L1,
  0x04 Contactless L2, 0x05 Mifare, 0x06 PIN-pad, 0x07 Service, 0x08 STM, 0x09 NTAG, 0x0A GUI,
  0x0B Touchscreen, 0x0C Complex, 0x0D QR-code, 0x0E CIPURSE, 0x10 Turnstile, 0x11 Mifare Extended,
  0x12 Troika, 0x13 Speaker.
- PAYLOAD команды — обёртка модуля из intellireader/commands.proto (oneof).
  PAYLOAD успешного ответа — само сообщение-результат БЕЗ обёртки; его тип определяется по
  команде с тем же MSGID и MODULE в том же TCP-сеансе.
- TCP: IR — сервер (порт 42616 без шифрования, 42800 TLS), контроллер АСОП — клиент.

Жёсткие правила:
1. Модуль никогда не отправляет данные в IR и контроллер (кроме режима proxy, где он только
   ретранслирует байты без изменений).
2. PAN, теги 57/5A/5F20/56/9F6B, masked_pan, encrypted_sensitive_data, содержимое блоков
   Mifare и данные QR-кода не попадают на диск, в логи, в MQTT и HTTP. Буферы с ними обнуляются.
3. Любые входные байты не должны приводить к падению, UB или неограниченному росту памяти.
4. Сетевой ввод-вывод, время и файловая система — за интерфейсами, чтобы логику тестировать
   на x86_64 без сети и с виртуальными часами.
5. Каждое изменение сопровождается тестами GoogleTest; не помечай задачу выполненной,
   пока `cmake --build` и `ctest` не проходят без ошибок и предупреждений.
6. Не выдумывай поля и значения протокола: при сомнении открой .proto или PDF и процитируй
   место (файл и строку или раздел спецификации).
7. Пиши кратко: в конце каждого шага — список изменённых файлов, что сделано, как проверено,
   открытые вопросы.

Структура репозитория (создаётся в промпте 1, далее соблюдается):
  CMakeLists.txt, cmake/, third_party/intellireader-proto/, proto_gen/ (генерируется),
  include/irbridge/*.hpp, src/<component>/*.cpp, apps/irbridged/main.cpp,
  apps/irbridge-pcaptool/main.cpp, tests/unit/, tests/data/pcap/, tests/fuzz/,
  packaging/ (systemd, deb, config), docs/.
Пространство имён: irbridge::{capture, tcp, codec, proto, corr, detect, privacy, agg, store,
  pub, health, config, util}.
```

---

## 1. Каркас проекта и генерация Protobuf

```text
Задача: создать каркас репозитория по структуре из системного промпта.

Сделай:
1. Корневой CMakeLists.txt: C++17, опции IRBRIDGE_WITH_PCAP (ON), IRBRIDGE_BUILD_TESTS (ON),
   IRBRIDGE_BUILD_FUZZ (OFF), IRBRIDGE_SANITIZE (OFF → -fsanitize=address,undefined).
2. Генерацию C++ из ВСЕХ .proto в third_party/intellireader-proto/ через protoc в
   ${CMAKE_BINARY_DIR}/proto_gen с корректными include-путями (корни: каталог protocol/ и
   protocol/intellireader/, так как импорты вида "misc/leds.proto" и "common/failure.proto").
   Собери статическую библиотеку irbridge_proto. Предупреждения сгенерированного кода не должны
   ломать -Werror (подключай как SYSTEM).
3. cmake/toolchain-aarch64.cmake для aarch64-linux-gnu-g++ с sysroot из переменной.
4. Пустые цели: библиотека irbridge_core, исполняемые irbridged и irbridge-pcaptool,
   тесты irbridge_tests.
5. .clang-format (Google, ColumnLimit 110), .clang-tidy (bugprone-*, performance-*,
   modernize-*, readability-identifier-naming), скрипт scripts/ci.sh: сборка Release и
   ASan/UBSan, ctest.
6. Тест-заглушка: сериализовать ::Miscellaneous{set_leds_state{blue:true}} (commands.proto не
   объявляет package, поэтому обёртки модулей лежат в глобальном пространстве имён; вложенные
   типы — в пакетах вида misc::leds) и проверить байты PAYLOAD == 0A 02 08 01.

Готово, когда: чистая сборка на x86_64 и кросс-сборка aarch64 проходят; тест из п. 6 зелёный;
в README.md описаны команды сборки.
```

## 2. CRC и кодек кадров IR

```text
Задача: компонент codec (ФТ-3.1–3.3).

API (include/irbridge/codec.hpp):
  uint16_t crc16_xmodem(const uint8_t* data, size_t n, uint16_t init = 0);
  struct Frame { uint8_t msgid, module, type; std::vector<uint8_t> payload; };
  enum class FrameType : uint8_t { Command=1, Success=2, Failure=3, Pending=4, Notification=5, Control=6 };
  class StreamDecoder {  // потоковый, по одному направлению TCP
   public:
    void feed(const uint8_t* data, size_t n);   // любые куски
    void mark_gap();                             // потеря данных в TCP
    template<class F> void drain(F&& on_frame);  // выдаёт готовые Frame
    const DecoderStats& stats() const;           // frames, crc_errors, bad_length, resyncs, bytes_skipped
  };
  std::vector<uint8_t> encode(const Frame&);     // только для тестов и генератора pcap

Правила: поиск 'I''R'; LENGTH 3..4122; CRC по HEADER..PAYLOAD; при ошибке длины или CRC —
сдвиг на 1 байт от начала кандидата и повторный поиск; буфер не растёт больше 2×4128 байт.

Тесты (обязательные векторы, CRC уже проверены):
  4952 0007 01 01 01 0A020801 09DF          Command set_leds_state{blue:true}
  4952 0003 01 01 02 B26B                   Successful, пустой PAYLOAD
  4952 0003 02 03 04 ED9F                   Pending, модуль 0x03
  4952 0005 01 03 03 080D AA1F              Failure CARD_TIMEOUT
  4952 0003 00 00 06 F6EE                   Control (отмена)
  4952 000F 01 01 01 420A1A08616E797468696E67 5025   get_echo{data:"anything"}
  4952 000D 01 01 02 0A08616E797468696E67 0901       ответ echo
Плюс: подача по 1 байту; разрез в каждой позиции; два кадра в одном куске; мусор до, между и
после; испорченный CRC (кадр отброшен, следующий найден); LENGTH=0xFFFF; mark_gap посреди кадра.

Готово, когда: все тесты зелёные; на 10 МБ случайных байт без зависаний и с ограниченной памятью.
```

## 3. Реестр сообщений Protobuf и декодер

```text
Задача: компонент proto — превращение Frame в типизированное сообщение (ФТ-3.4, 3.5, 4.2).

API:
  enum class ModuleId : uint8_t { Notify=0x00, Misc=0x01, ContactL1=0x02, ContactlessL1=0x03,
    ContactlessL2=0x04, Mifare=0x05, PinPad=0x06, Service=0x07, Stm=0x08, Ntag=0x09, Gui=0x0A,
    Touch=0x0B, Complex=0x0C, QrCode=0x0D, Cipurse=0x0E, Turnstile=0x10, MifareExt=0x11,
    Troika=0x12, Speaker=0x13 };
  struct CommandKey { ModuleId module; int oneof_field; std::string name; };  // напр. {0x04,1,"perform_transaction"}
  std::optional<DecodedCommand> decode_command(const Frame&);
     // разбирает обёртку модуля из commands.proto: Miscellaneous, ContactlessLevel1,
     // ContactlessLevel2, Mifare, Gui, Complex, QrCode, Cipurse, Turnstile, MifareExtended,
     // TroikaCard; для прочих модулей — только CommandKey без разбора полей.
  std::optional<DecodedResponse> decode_success(const CommandKey&, const Frame&);
     // perform_transaction → contactless::transaction::TransactionResult
     // poll_for_token      → contactless::token::Token
     // poll_for_event      → complex::poll::Event
     // poll_for_qrcode     → qrcode::event::QrCodeEvent
     // troika_av3_read_ticket → troika::av3::read_ticket::Ticket
     // read_device_info → misc::device::DeviceInfo; get_device_statistic → misc::stats::DeviceStatistic
     // остальные → пустой результат «успех» без разбора
  std::optional<DecodedResponse> decode_success_inferred(ModuleId, const Frame&);
     // ФТ-4.3: 0x04 → TransactionResult, 0x0C → Event, 0x0D → QrCodeEvent; флаг inferred=true
  FailureResponse / Notification — для TYPE 0x03 / 0x05.

Требования: имена C++-пакетов бери из сгенерированного кода, не угадывай; сверь номера полей
oneof с commands.proto и процитируй их в комментарии таблицы соответствия. ParseFromArray с
проверкой результата; неизвестные поля игнорируются. Чувствительные поля (ФТ-5.2) не копируются
наружу из TransactionResult: сделай функцию extract_safe(TransactionResult) → SafeTxnInfo
{status, token_type, token_id_bytes (только для хеша), carrier_type, pan_hash, aid, payment_system,
amount, ir_version}, после которой исходное сообщение очищается (Clear()) и буферы обнуляются.

Тесты: собери команды и ответы protobuf-объектами, закодируй через codec::encode, раскодируй
обратно; проверь, что extract_safe не содержит PAN и что тег 57/5A не попадает в результат.
```

## 4. Захват трафика и сборка TCP

```text
Задача: компоненты capture и tcp (ФТ-1.1–1.3, 2.1–2.5).

capture:
  class PacketSource { virtual bool next(Packet&) = 0; };  // Packet{ts_us, bytes}
  AfPacketSource(iface, bpf, cpu_affinity)  — TPACKET_V3, PACKET_MMAP, promiscuous,
     BPF "tcp port 42616 or tcp port 42800" (порты из конфигурации), 802.1Q.
  PcapFileSource(path) — через libpcap (если включена) или собственный читатель .pcap.
Разбор L2–L4: Ethernet (+VLAN) → IPv4 (только) → TCP; фрагменты IP отбрасываются со счётчиком.

tcp:
  class FlowTable — ключ: (ip_ir, port_ir, ip_ctl, port_ctl); сторона IR = порт из ir_ports
  или tls_ports. Для каждого направления: ожидаемый seq, буфер внеочередных сегментов
  ≤ 64 КиБ, удаление дублей и перекрытий, SYN/FIN/RST, idle_timeout. Поток без SYN начинается
  с первого увиденного сегмента. При дыре: callback on_gap(direction). Порт TLS → поток
  помечается encrypted и данные не передаются в codec.
  Колбэки: on_open(flow), on_data(flow, dir, bytes, ts), on_gap(flow, dir), on_close(flow, reason).

Тесты: синтетические сегменты: порядок, перестановка, дубли, частичное перекрытие, потеря,
wrap seq через 2^32, RST, таймаут по виртуальным часам; сквозной тест PcapFileSource →
FlowTable → StreamDecoder на pcap из tests/data/pcap (создай генератор в промпте 13 или здесь
маленький pcap вручную через libpcap-writer в тесте).

Готово, когда: тесты зелёные; на RK3588 AfPacketSource запускается под пользователем с
CAP_NET_RAW,CAP_NET_ADMIN без root (проверочная команда описана в README).
```

## 5. Корреляция запросов и ответов

```text
Задача: компонент corr (ФТ-4.1–4.3).

class SessionCorrelator (по одному на TCP-сеанс):
  on_command(Frame, ts)   → запоминает {msgid → CommandKey, ts, cancelled=false}
  on_control(ts)          → помечает текущую незавершённую команду отменённой
  on_pending(Frame, ts)   → продлевает ожидание
  on_success(Frame, ts)   → находит команду по msgid и module, вызывает proto::decode_success;
                            если нет — decode_success_inferred
  on_failure(Frame, ts)   → FailureResponse
  on_notification(Frame)  → лог уровня debug без PAYLOAD-данных карт
Выход: поток CorrelatedEvent { ts, kind: CommandIssued | Succeeded | Failed | Cancelled,
  CommandKey, decoded command (для индикации), decoded response, inferred }.
Учти: MSGID 0..255 по кругу; несовпадение module у ответа — счётчик ошибок; записи старше
30 с удаляются; on_gap сбрасывает таблицу ожидания.

Тесты: Command→Pending→Success; Command→Pending→Control→Failure(PROCESSING_STOPPED);
wrap 255→0; ответ без команды (inferred); дубликат ответа; ответ с чужим module.
```

## 6. Детектор валидаций и правила

```text
Задача: компонент detect (ФТ-4.4–4.8).

struct ValidatorContext { validator_id, door_id, ip, ... };
class ValidationDetector (по одному на валидатор):
  void on_event(const CorrelatedEvent&);
  void on_tick(TimePoint now);         // таймауты decision_window_ms
  void on_session_closed();            // ABORTED для незавершённой
  сигнал: on_validation(ValidationRecord)

Автомат: IDLE → PRESENTED → {APPROVED | REJECTED | NO_DECISION | ABORTED} → IDLE.
Предъявление: Succeeded с TransactionResult (любой status), Token, Event
(contactless_token | contactless_txn_result | qrcode | troika_ticket), QrCodeEvent.
Склейка: повтор того же carrier в пределах same_carrier_merge_ms до решения — та же валидация
(цепочка EMV first: TransactionResult NON_EMV_CARD → чтение/запись транспортной карты).
Новое предъявление другого носителя в PRESENTED → текущая закрывается NO_DECISION.

Правила (из конфигурации, список матчеров; первое совпадение побеждает, reject проверяется
раньше approve в той же команде):
  gui_picture{ids}           — рекурсивный обход gui::widget::Widget в Gui.show_screen и в
                               Complex.poll_for_event.on_event_ui_action.show_screen
  gui_text{regex, icase}     — Text.text и GeneratedText.prefix; первая группа захвата → passengers
  gui_customer_picture{names}
  leds{green|red}            — Miscellaneous.set_leds_state и UserInterface.set_leds_state
  rgb_color{color, tolerance}— set_all_rgb_leds / set_rgb_leds
  turnstile_pass             — Turnstile.allow_one_pass
require_ack: учитывать индикацию только после Succeeded этой команды.
success_policy: indication | indication_or_write (успешная запись mfr_*_write_*, *_modify_counter,
  cipurse.modify_value / update_*, troika_av3_write_ticket без последующего reject) |
  emv_status (status 0/1 без последующего reject — для indication = FULL).
Запиши в запись indication_mode из PerformTransaction.indication, card_write_confirmed, decision_rule.

Тесты по сценариям ТЗ 8.2: банковская карта одобрена (TransactionResult → show_screen APPROVED);
отклонена (REJECTED); транспортная карта (NON_EMV_CARD → mifare read/write → APPROVED);
QR (QrCodeEvent → green LED); нет решения (таймаут); две разные карты подряд; одобрение через
текст «ОПЛАЧЕНО x3» → passengers=3; require_ack с Failure на show_screen → не одобрено;
каждая политика success_policy. Все — на виртуальных часах.
```

## 7. Идентификатор носителя и защита данных

```text
Задача: компонент privacy (ФТ-5.1–5.4).

- Секрет 32 байта: /var/lib/camai/irbridge/secret.key, создаётся при первом запуске из
  getrandom(), права 0600, владелец — пользователь службы; при неверных правах служба не
  стартует.
- carrier_hash = hex(HMAC-SHA256(secret, domain || material)[0..16]), где material =
  pan_hash, иначе token.id, иначе SHA-256(данные QR); domain — "pan:", "uid:", "qr:".
- payment_system по AID: A000000658 MIR, A000000003 VISA, A000000004 MASTERCARD,
  A000000333 UNIONPAY, иначе OTHER.
- secure_zero для всех буферов с данными карт (explicit_bzero).
- Фильтр логирования: ни один форматтер spdlog не печатает PAYLOAD на уровне ≥ info; на debug —
  только длина и MODULE/TYPE.
- raw_capture (pcap для пусконаладки) — по умолчанию выключен; при включении — ротация по
  max_mb и max_age_h, права 0600.

Тесты: детерминированность хеша при одном секрете; разные хеши при разных секретах; Luhn-сканер
(утилита tests/tools/pan_scan) находит PAN в тестовом файле и не находит в выходе модуля.
```

## 8. Хранилище событий

```text
Задача: компонент store (ФТ-8.1, 8.2).

SQLite в режиме WAL, synchronous=NORMAL. Таблицы:
  validations(event_id TEXT PK, ts_presented, ts_decided, outcome, json TEXT, published INT)
  intervals(interval_id TEXT PK, ts_start, ts_end, json TEXT, published INT)
  validator_status(validator_id PK, json TEXT, updated_at)
  meta(key PK, value)  — версия схемы, миграции
Запись батчами не чаще 1 раза в секунду (очередь в памяти ≤ 10 000 записей, при переполнении —
счётчик потерь и предупреждение). Очистка по retention ежечасно. Объём БД ≤ 512 МБ: при
превышении удаляются самые старые опубликованные записи. event_id — UUIDv7.

Тесты: вставка/чтение; восстановление после kill -9 (WAL); retention на виртуальных часах;
выборка неопубликованных по порядку.
```

## 9. Публикация: MQTT и HTTP

```text
Задача: компонент pub (раздел 5 ТЗ).

MQTT (Paho C++ или libmosquitto): QoS 1; топики camai/{vehicle_id}/fare/validation,
.../fare/interval, .../fare/validator/{validator_id} (retained). Отправка из store по флагу
published, подтверждение — по PUBACK; переподключение с экспоненциальной задержкой до 60 с;
TLS по конфигурации. Подписка: camai/{vehicle_id}/pax/count и camai/{vehicle_id}/doors →
в aggregator (формат входа вынеси в адаптер pax_adapter.cpp, т. к. он задаётся шиной CAMAI;
сделай реализацию по образцу JSON {door_id, ts, in, out} и {door_id, ts, state: open|closed},
и пометь TODO для сверки с фактической схемой шины).
JSON строго по таблице 5.1 ТЗ (схема irbridge.validation/1), nlohmann/json.

HTTP (cpp-httplib), только на адресах из http.listen:
  GET /api/v1/health, /api/v1/validators, /api/v1/events?since=&limit= (≤ 1000),
  /api/v1/intervals?since=, /metrics (формат Prometheus text 0.0.4).

Тесты: сериализация совпадает с примером из ТЗ (кроме event_id/ts); mock-брокер (интерфейс
IMqttClient) — повтор после разрыва, отсутствие потерь и допустимые дубли с тем же event_id.
```

## 10. Агрегатор «вошли − оплатили»

```text
Задача: компонент agg (раздел 2 и ФТ-7.1–7.4).

Интервал открывается при первом open любой двери (или fallback_window_s без сигналов дверей),
закрывается через post_close_tail_s после закрытия последней двери. match_scope: vehicle | door.
Расчёт: unpaid_estimate = max(0, boarded − Σ passengers по APPROVED в интервале).
reliable=false и причина, если: любой валидатор интервала не observed (silent/encrypted/faulty),
счётчик пассажиров сообщил о сбое, часы не синхронизированы. Валидация, пришедшая в хвосте после
закрытия, относится к интервалу, в хвост которого попала.

Тесты: остановка с 5 вошедшими и 3 валидациями → 2; валидации после закрытия дверей в хвосте;
два последовательных интервала без перекрытия; door-scope; валидатор silent → reliable=false.
```

## 11. Режимы proxy и bridge

```text
Задача: ФТ-1.4 и режим bridge.

proxy: epoll, неблокирующие сокеты, для каждой пары listen→upstream: принять соединение
контроллера, подключиться к IR, ретранслировать байты в обе стороны без изменений, TCP_NODELAY,
закрытие одной стороны закрывает другую. Копия байтов уходит в StreamDecoder через lock-free
очередь SPSC; при её переполнении ретрансляция продолжается, разбор помечается gap.
Задержка ретрансляции ≤ 2 мс (p99) — замерь в тесте на localhost.

bridge: модуль не настраивает мост сам; в packaging/ положи пример конфигурации
systemd-networkd (br0 из eth0+eth1 без IP) и readme. Захват — AfPacketSource на br0.

Тесты: proxy с фейковым IR-сервером (эхо кадров) и фейковым контроллером; разрыв любой стороны;
медленный потребитель разбора не замедляет ретрансляцию.
```

## 12. Демон, конфигурация, health, упаковка

```text
Задача: apps/irbridged и packaging (разделы 6.3, 7 ТЗ, ФТ-6.1–6.3).

- Загрузка YAML строго по примеру из раздела 7 ТЗ; валидация с понятными ошибками; флаг
  --check-config; значения по умолчанию из ТЗ.
- Многопоточность: поток захвата (привязка к cpu_affinity), поток логики (tcp→codec→corr→
  detect→agg), поток store, поток MQTT, поток HTTP. Обмен — очереди с ограничением размера.
- health: статусы валидаторов observed/silent/encrypted/faulty/unmapped, переходы как события;
  метрики Prometheus; sd_notify READY=1 и WATCHDOG=1 из потока логики.
- Сигналы: SIGTERM — сброс очередей и выход ≤ 5 с; SIGHUP — перечитать конфигурацию.
- packaging/camai-irbridge.service: User=camai-irbridge, AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN,
  NoNewPrivileges=yes, ProtectSystem=strict, ReadWritePaths=/var/lib/camai/irbridge,
  Restart=always, WatchdogSec=30, ExecReload=/bin/kill -HUP $MAINPID.
- Пакет .deb (CPack): бинарники, unit, /etc/camai/irbridge.yaml (conffile), postinst создаёт
  пользователя и каталог.

Готово, когда: пакет ставится на чистый Debian arm64, служба стартует, /api/v1/health отвечает,
irbridged --check-config ловит ошибочный конфиг.
```

## 13. Генератор тестового трафика и pcaptool

```text
Задача: apps/irbridge-pcaptool и тестовые данные (раздел 8.2 ТЗ).

Подкоманды:
  synth  --scenario <yaml> --out file.pcap  — генерирует TCP-сеансы контроллер↔IR с корректными
         кадрами IR (через codec::encode и protobuf), с SYN/ACK, seq, временными метками.
  replay --pcap file.pcap --config irbridge.yaml --out events.jsonl — прогоняет конвейер
         без сети и печатает события (без event_id и ts для сравнения с эталоном).
  stats  --pcap file.pcap — сводка: сеансы, кадры по MODULE/TYPE, ошибки CRC.
Сценарии в tests/data/scenarios/*.yaml: все сценарии из промпта 6 плюс потеря пакета, старт
посреди сеанса, 16 валидаторов × 1 час с потоком 200 кадров/с (для нагрузочного теста).
Номера карт в синтетике — только тестовые (не проходящие проверку Луна).
Эталоны в tests/data/expected/*.jsonl; ctest сравнивает replay с эталоном.
```

## 14. Фаззинг, санитайзеры, производительность

```text
Задача: раздел 6.3 и 6.5 ТЗ.

- tests/fuzz/fuzz_codec.cpp, fuzz_tcp.cpp, fuzz_proto.cpp (libFuzzer, clang), словарь с 'IR',
  типичными MODULE/TYPE и векторами из промпта 2; корпус из кадров synth.
- Сборка IRBRIDGE_SANITIZE=ON проходит весь ctest без замечаний.
- Бенчмарк на RK3588: tcpreplay сценария 16×200 кадров/с на интерфейс зеркала 8 часов;
  отчёт: CPU на ядре A55, RSS, задержка решение→публикация (p50/p99), потери. Сравни с
  таблицей 6.2 ТЗ и перечисли отклонения.
```

---

## 15. Служебные промпты

### R. Ревью после каждого шага

```text
Проведи ревью изменений текущего шага как независимый строгий ревьюер.
Проверь: соответствие ФТ из ТЗ (перечисли номера и статус каждого); жёсткие правила системного
промпта (особенно 1–3); корректность работы с протоколом по .proto и PDF (процитируй);
утечки PAN и данных карт; рост памяти и блокировки; обработку ошибок; покрытие тестами
граничных случаев; предупреждения компилятора и clang-tidy.
Выдай список замечаний по убыванию важности с файлом и строкой, затем исправь все замечания
уровня «критично» и «важно» и снова прогони ctest.
```

### D. Сверка с протоколом при сомнении

```text
Мне нужно точно знать <поле / сообщение / поведение> протокола IntelliReader.
Найди ответ в third_party/intellireader-proto/ и docs/vendor/intellireader-protocol-v1.96.pdf
(используй pdftotext), процитируй файл и строку или раздел спецификации. Если ответа нет —
так и скажи и предложи, как проверить на стенде (irc.py или IntelliReader Manager).
```

### F. Настройка правил под конкретную АСОП

```text
Вот вывод `irbridge-pcaptool stats` и выдержка `replay` (без данных карт) с объекта перевозчика
<название>. Определи, какими командами контроллер этой АСОП показывает одобрение и отказ
(show_screen с какими виджетами, светодиоды, RGB, турникет), и предложи блок detector.approve /
detector.reject и success_policy для irbridge.yaml. Покажи, сколько предъявлений из записи
получат исход APPROVED, REJECTED и NO_DECISION с предложенными правилами.
```

### A. Приёмочная проверка

```text
Пройди раздел 8 ТЗ как чек-лист. Для каждого пункта: как проверено (команда, тест, отчёт),
результат, доказательство (путь к файлу или вывод). Для невыполненного — что мешает и
план исправления. Итог: готово ли к опытной эксплуатации (да/нет) с обоснованием.
```
