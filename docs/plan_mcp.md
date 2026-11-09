# План разработки MCP-сервера `v8i-mcp.exe`

**Проект:** v8inject — инжектор и точка расширения для процессов 1С:Предприятие
**Ветка:** `feature/mcp`
**Цель:** MCP-сервер, через который LLM-клиент (Qoder, Claude Desktop, VS Code
и т. п.) управляет живым Конфигуратором 1С: находит процессы, внедряет payload,
выполняет команды дизайнера, читает диагностику и работает с хуками.
**Целевые платформы:** 1С 8.3 (x86/x64) и 8.5 (x64).
**Протокол:** MCP, две эры — legacy `initialize` (2025-11-25, 2025-06-18,
2025-03-26, 2024-11-05) и stateless 2026-07-28 (`server/discover`, версия в
`_meta` каждого запроса).

---

## 0. Что делаем и чего не делаем

Входит в v1:

- stdio-транспорт (сервер запускает MCP-клиент, отдельного демона нет);
- discovery процессов 1С и сессии «MCP → цель»;
- обёртки над существующими командами payload (`version`, `mods`, `objects`,
  `pe`, `cmd`/`cmd85`, `gitbar`) с типизированными схемами аргументов;
- запуск 1С с немедленным внедрением (по флагу) и выгрузка конфигурации;
- чтение памяти и reverse (`find`, `str`, `peek`, `disasm`, `around`, `xref`,
  `imports`) за `allowReverse`, хуки (`hook`/`hooks`/`unhook`/`trace`) — за
  `allowHooks`;
- кросс-разрядность: один сервер обслуживает и x86-1С (8.3), и x64-1С (8.5);
- тесты протокола и smoke-тест на `v8i_hook_target.exe` в CI.

Не входит в v1:

- Streamable HTTP, OAuth, многопользовательский доступ;
- MCP resources/prompts (задел заложен, включаем после стабилизации tools);
- произвольный запуск сторонних EXE, инжект в не-1С процессы, загрузка
  произвольной DLL;
- автоматическое прописывание сервера в конфиги редакторов;
- GUI у сервера: это консольный процесс, весь диагностический вывод — stderr;
  stdout занят протоколом (§3.1).

---

## 1. Ключевые решения

| Вопрос | Решение | Почему |
|---|---|---|
| Транспорт | stdio, JSON-RPC 2.0, одна строка — одно сообщение | Требование MCP для локальных серверов; клиент сам запускает процесс |
| Эра протокола | Dual-era: legacy `initialize` + modern 2026-07-28 | Клиенты 2026 года в массе ещё на `initialize`; спека 2026-07-28 требует `server/discover` и `_meta` |
| Язык/стек | C++17, MSVC, CMake — как весь проект | Общий код: `v8i::Client`/`SharedIo` в helper'е, UTF-8/UTF-16-хелперы и `procs` в сервере |
| JSON | Вендорить `nlohmann/json` single header в `third_party/` | Сборка герметична и offline, как с Capstone; свой парсер — лишний риск |
| Доступ к 1С | Сервер **не инжектит сам**: запускает helper `v8inject.exe rpc` нужной разрядности | Один сервер обслуживает x86 и x64; падение цели/helper'а не роняет сервер |
| Сессии | Явный `sessionId`, один helper на цель | Payload однопоточный (CAS в `SharedIo`), параллелить вызовы к одной цели нельзя |
| Опасные операции | Метаданные всегда; чтение памяти/кода и хуки — за ini/флагами | Инжект и хуки — это исполнение кода в чужом процессе |
| Первый клиент | Qoder Desktop, затем Claude Desktop | Qoder — рабочее окружение автора; оба говорят по stdio, отдельной интеграции не требуется |
| Логи | stderr + файл, stdout только протокол | Клиент читает stdout построчно и не прощает мусора |

---

## 2. Архитектура

```
┌──────────────────────┐   stdio: newline-delimited JSON-RPC 2.0
│  MCP-клиент          │◀──────────────────────────────────────────┐
│  (Qoder / Claude)    │                                           │
└──────────────────────┘                                           │
                                                        ┌──────────┴──────────┐
                                                        │     v8i-mcp.exe     │
                                                        │  транспорт, JSON-RPC │
                                                        │  lifecycle, tools    │
                                                        │  реестр сессий       │
                                                        └──────┬────────┬──────┘
                                    pipes (JSON-строки)        │        │
                                          ┌────────────────────┘        └──────────────┐
                                          ▼                                            ▼
                                 ┌──────────────────┐                        ┌──────────────────┐
                                 │ x86\v8inject.exe │                        │ x64\v8inject.exe │
                                 │   rpc --pid N    │                        │   rpc --pid N    │
                                 └────────┬─────────┘                        └────────┬─────────┘
                                          │ разделяемая память                      │
                                          ▼                                         ▼
                                 ┌──────────────────┐                        ┌──────────────────┐
                                 │ 1cv8.exe (x86)   │                        │ 1cv8.exe (x64)   │
                                 │ v8i_payload.dll  │                        │ v8i_payload.dll  │
                                 └──────────────────┘                        └──────────────────┘
```

Почему helper, а не прямой `v8i::Client` в сервере:

1. `CreateRemoteThread(LoadLibraryW)` работает только при совпадении разрядности
   хоста и цели — x64-сервер физически не внедрит payload в x86-1С;
2. helper — это уже существующий `v8inject.exe`, из которого используются
   `src/host/*`; новый бинарь не нужен;
3. падение helper'а (например, при экспериментах с хуками) не убивает сервер,
   сессия помечается мёртвой, клиент может её пересоздать;
4. сервер остаётся «тонким»: протокол, схемы, маршрутизация — без реверс-кода.

### 2.1. Компоненты и файлы

| Файл | Роль |
|---|---|
| `src/mcp/main.cpp` | разбор аргументов, конфиг, запуск stdio-цикла |
| `src/mcp/transport_stdio.cpp` | чтение строк UTF-8, лимит размера, запись ответа одной строкой |
| `src/mcp/jsonrpc.cpp` | Request/Response/Notification, коды ошибок, сериализация |
| `src/mcp/server.cpp` | `initialize`, `server/discover`, `ping`, `tools/list`, `tools/call`, `notifications/*` |
| `src/mcp/dispatcher.cpp` | reader-поток, очередь запросов, worker pool, отмена, mutex записи в stdout |
| `src/mcp/tool_registry.cpp` | реестр инструментов, JSON-схемы, аннотации, валидация аргументов |
| `src/mcp/tools_1c.cpp` | инструменты сессии и команд payload |
| `src/mcp/session.cpp` | helper-процессы: запуск, JSON-строки, таймауты, job object |
| `src/cli/rpc.cpp` | новый режим `v8inject.exe rpc` — машинный RPC-хост |
| `src/host/client.{h,cpp}` | новый метод `AttachExisting` для подключения к уже загруженному payload |
| `src/payload/v8i_export.cpp` | mutex живости `Local\v8inject.session.<pid>`: создаётся/захватывается в `RunPayload` после маппинга и освобождается в самом конце, после `UnmapViewOfFile`/`CloseHandle` |
| `include/v8inject/mcp_helper.h` | структуры протокола helper↔сервер |
| `third_party/nlohmann/json.hpp` | JSON-парсер/сериализатор (MIT) |
| `docs/MCP.md` | пользовательская документация и настройка клиентов |
| `docs/CMD-NUMBERS.md` | калиброванная таблица номеров команд дизайнера (пополняется) |
| `tests/mcp_protocol.ps1` | конформанс-тест протокола без 1С |
| `tests/mcp_smoke.ps1` | smoke на `v8i_hook_target.exe` |

CMake: новый консольный таргет `v8i-mcp`, линкует `v8i_common` и
`src/host/procs.cpp` (список процессов нужен локально). Инжект и `Client` в
сервер не попадают — только helper. Режим `rpc` добавляется в существующий
`v8inject`.

---

## 3. Протокол MCP

### 3.1. stdio

- Сообщение — один JSON-объект в одной строке UTF-8, без вложенных переводов
  строки; строки могут приходить с `CRLF`, `\r` срезается.
- `stdout` — **только** MCP-сообщения. Любая отладка, предупреждения и ошибки
  helper'ов — в `stderr` (UTF-8) и в лог-файл.
- Потоки открываются в бинарном режиме; каждый ответ пишется одним `WriteFile`
  под общим mutex'ом писателя (ответы воркеров не должны перемешиваться) и
  сбрасывается, чтобы клиент не ждал буферизации CRT.
- Лимит входящей строки — 2 МиБ. Это лимит транспорта, а не payload: команда,
  уходящая в `SharedIo::request`, ограничена 4096 `wchar_t` (включая имя
  команды). Инструмент, чьи аргументы не помещаются, возвращает `isError`
  «command too long for payload», а не обрезает запрос. Строка транспорта
  длиннее 2 МиБ отбрасывается с ответом `-32600` (`id: null`), чтение
  продолжается.
- Ответ payload ограничен `SharedIo::responseBytes` = 512 КиБ; `maxOutputBytes`
  по умолчанию тоже 512 КиБ (§6), и pretty-print/обрезка выполняются с учётом
  этого лимита (текст не разрастается сверх него).
- EOF на `stdin` — штатное завершение: прекратить приём, снять очередь,
  параллельно закрыть все сессии с общим бюджетом 5 с, выйти с кодом 0.
  Helper'ы, не ответившие за бюджет, снимаются Job object'ом
  (`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`); фоновых процессов не остаётся.

### 3.2. Две эры

**Legacy (2025-11-25, 2025-06-18, 2025-03-26, 2024-11-05).** Сервер принимает
`initialize`, сверяет `protocolVersion` со своим списком; если версия знакома —
возвращает её же, иначе — последнюю поддерживаемую. Ответ:

```json
{
  "protocolVersion": "2025-06-18",
  "capabilities": { "tools": { "listChanged": false } },
  "serverInfo": { "name": "v8i-mcp", "version": "0.3.0" },
  "instructions": "Локальный сервер для работы с процессами 1С. Сначала вызовите v8i_list_processes, затем v8i_attach."
}
```

После ответа клиент присылает `notifications/initialized` — принимаем без
ответа. До успешного `initialize` методы `tools/list` и `tools/call`
отвечают `-32002` (Server not initialized); разрешены только `initialize`,
`ping` и `server/discover` (выбор эры). Ждать `notifications/initialized`
перед `tools/list` не требуется: часть клиентов присылает его с задержкой,
и блокировать из-за этого работу нельзя.

**Modern (2026-07-28).** Handshake отсутствует. Сервер реализует
`server/discover`, клиент передаёт в каждом запросе `_meta`:

```json
{
  "io.modelcontextprotocol/protocolVersion": "2026-07-28",
  "io.modelcontextprotocol/clientCapabilities": {},
  "io.modelcontextprotocol/clientInfo": { "name": "client", "version": "1.0" }
}
```

Правила:

- `server/discover` разрешён первым сообщением и не требует `_meta`;
- любой другой запрос в modern-эре без обязательных полей `_meta` → `-32602`
  (Invalid params); notifications без `_meta` принимаются и логируются;
- версия не поддерживается → `-32022` (UnsupportedProtocolVersion) с
  `data.supported` и `data.requested`;
- `ping` работает в обеих эрах и не требует `_meta`;
- сервер не инициирует запросы к клиенту (правило обеих эр: MCP-сервер
  отвечает только на запросы);
- `capabilities` и `serverInfo` отдаются в ответе `server/discover`; точную
  форму ответа сверить с JSON-схемой 2026-07-28 перед реализацией —
  предполагаются `supportedVersions`, `capabilities`, `serverInfo`,
  `instructions`;
- в modern-ответах `serverInfo` дублируется в
  `_meta["io.modelcontextprotocol/serverInfo"]`, чтобы клиент видел сервер
  и без отдельного discovery-обмена.

**Выбор эры.** Первое сообщение решает режим процесса:

- `initialize` → legacy (версия `2025-11-25`, `2025-06-18`, `2025-03-26` или
  `2024-11-05`; незнакомая версия → последняя поддерживаемая);
- `server/discover` или любой запрос с `_meta` → modern;
- `ping` эру не выбирает и обслуживается в обоих режимах;
- любой другой запрос до выбора эры (`tools/list`, `tools/call`) → `-32002`
  Server not initialized.

Смешивать режимы в одном процессе нельзя: `initialize` после modern-сообщения
или `_meta`/`server/discover` после legacy-`initialize` → `-32600`.
`notifications/initialized` в modern-эре игнорируется (лог, без ответа).

### 3.3. Методы v1

| Метод | Ответ |
|---|---|
| `initialize` | версия, `capabilities.tools`, `serverInfo`, `instructions` |
| `notifications/initialized` | нет ответа |
| `server/discover` | modern: версии, capabilities, serverInfo |
| `ping` | `{}` |
| `tools/list` | `{ "tools": [ … ] }`, порядок детерминированный, без курсоров |
| `tools/call` | `{ "content": [{ "type": "text", "text": "…" }], "structuredContent": {…}, "isError": false }` |
| `notifications/cancelled` | вызов, ещё стоящий в очереди, не запускается и ответа по нему не получает; уже исполняемый не прерывается (§5), отмена только логируется; неизвестный `requestId` игнорируется |
| `tools/*` до выбора эры | `-32002` Server not initialized |
| batch (массив) | `-32600`: MCP не использует пакеты |
| неизвестный метод | `-32601` |
| неизвестный инструмент | `-32602` |
| битый JSON | `-32700`, `id: null` |

Разделение ошибок:

- **протокольные** (неизвестный метод/инструмент, невалидные аргументы) —
  JSON-RPC `error`;
- **исполнения** (1С не запущена, инжект не удался, таймаут, `BUSY`,
  `{"status":"error"}` от payload) — успешный JSON-RPC-ответ с
  `isError: true`; текст пригоден для самокоррекции модели.

`structuredContent` — распарсенный JSON payload'а, `content[0].text` — тот же
JSON, но pretty-printed и обрезанный до лимита (по умолчанию 512 КиБ, как
`SharedIo::responseBytes`).

**Параллелизм.** Чтение stdin и исполнение запросов разделены: reader-поток
непрерывно читает строки (поэтому `notifications/cancelled` видна даже во
время долгого `tools/call`), а запросы исполняет пул из `workerThreads`
воркеров (§6). Вызовы внутри одной сессии сериализуются очередью (payload
однопоточный), разные сессии работают параллельно. Очередь ограничена
`maxQueuedCalls`; переполнение — `isError` «server busy». `initialize`,
`ping`, `tools/list` и `server/discover` обслуживаются без ожидания сессий.

### 3.4. Пример `tools/list`

```json
{
  "tools": [
    {
      "name": "v8i_attach",
      "title": "Attach to a 1C process",
      "description": "Внедряет payload в процесс 1С и открывает сессию. Возвращает sessionId для остальных инструментов. Укажите ровно одно из pid/exe.",
      "inputSchema": {
        "type": "object",
        "properties": {
          "pid": { "type": "integer", "minimum": 1 },
          "exe": { "type": "string", "enum": ["1cv8.exe", "1cv8c.exe", "1cv8s.exe"] }
        },
        "oneOf": [
          { "required": ["pid"] },
          { "required": ["exe"] }
        ],
        "additionalProperties": false
      },
      "annotations": {
        "readOnlyHint": false,
        "destructiveHint": false,
        "idempotentHint": true,
        "openWorldHint": false
      }
    }
  ]
}
```

---

## 4. Инструменты

Имена — `v8i_*`, только `[a-z0-9_]`, стабильны. Каждый инструмент
валидирует аргументы по схеме до вызова helper'а.

### 4.1. Ядро (без флагов `allowReverse`/`allowHooks`/`allowLaunch`)

| Инструмент | Аргументы | Что делает / payload |
|---|---|---|
| `v8i_list_processes` | — | `ListProcesses()`, фильтр `1cv8*.exe`, поля pid/name/path/bitness |
| `v8i_list_sessions` | — | живые сессии сервера: id, pid, arch, платформа |
| `v8i_attach` | `pid` \| `exe` | helper нужной разрядности → проверка mutex'а живости → `AttachExisting` (payload жив) или `Open` (payload не запущен/поток завершён) → `version`; возвращает `sessionId`, `arch`, `platform`, `mode` |
| `v8i_detach` | `session` | `close` helper'у → payload при штатном выходе снимает хуки (`HookRemoveAll`) и завершает поток, `Client::Close`; DLL остаётся в процессе 1С и будет переиспользована следующим `attach` |
| `v8i_payload_version` | `session` | `version` |
| `v8i_modules` | `session`, `filter?`, `limit?=200` | `mods` |
| `v8i_objects` | `session` | `objects` |
| `v8i_pe` | `session`, `module?` | `pe` (заголовки и таблицы PE-модуля, не произвольные байты) |
| `v8i_designer_command` | `session`, `command`, `sub?=0` | `cmd` (8.3) / `cmd85` (8.5); номера вне `allowedCommands` отклоняются |
| `v8i_dump_config` | `session` | алиас команды 45 под тем же `allowedCommands`; если 45 убран из allowlist, инструмент отсутствует в `tools/list`; возвращает предупреждение, что 1С открыла модальный диалог |
| `v8i_gitbar` | `session`, `visible?=true` | `gitbar` / `gitbar hide` |

Все инструменты ядра доступны без опасных флагов. `v8i_dump_config` —
исключение по другой причине: он зависит от `allowedCommands` (команда 45) и
исчезает из `tools/list`, если 45 убрали из allowlist.

Метаданные (`mods`, `objects`, `pe`) не читают произвольную память процесса:
`mods` — список загруженных модулей, `objects` — объекты конфигурации,
`pe` — разобранные заголовки/экспорты конкретного модуля. Поэтому они
доступны всегда. Всё, что читает строки, байты или код по адресу, вынесено в
§4.2: диагностический ассистент обычно не нуждается в дампах памяти, а утечка
пароля из кучи 1С — реальный риск.

### 4.2. Чтение памяти, reverse и хуки (за разрешением)

| Инструмент | Аргументы | Payload | Группа |
|---|---|---|---|
| `v8i_find` | `session`, `pattern`, `wide?`, `module?`, `limit?=50` | `find` | `allowReverse` |
| `v8i_read_string` | `session`, `address` | `str` | `allowReverse` |
| `v8i_peek` | `session`, `address`, `length?=64` (≤ 4096) | `peek` | `allowReverse` |
| `v8i_disasm` | `session`, `address?`, `module?`, `count?` | `disasm` | `allowReverse` |
| `v8i_around` | `session`, `address`, `count?` | `around` | `allowReverse` |
| `v8i_xref` | `session`, `target`, `from?`, `to?`, `count?` | `xref` | `allowReverse` |
| `v8i_imports` | `session`, `module`, `filter?` | `imports` | `allowReverse` |
| `v8i_hook` | `session`, `target`, `name?` | `hook` | `allowHooks` |
| `v8i_hooks` | `session` | `hooks` | `allowHooks` |
| `v8i_unhook` | `session`, `id` (`all` разрешён только явной строкой) | `unhook` | `allowHooks` |
| `v8i_trace` | `session`, `since?`, `count?`, `clear?` | `trace` | `allowHooks` |

`allowReverse` — один флаг на все инструменты, читающие память и код:
включать их по отдельности смысла нет, все они дают модели содержимое
процесса. `allowHooks` — отдельный флаг: это уже изменение поведения 1С.
Хуки живут до `detach`/EOF — это нужно явно писать в описании инструментов,
иначе модель снимет хук «одноразовым» вызовом и потеряет наблюдение.

### 4.3. Запуск и выгрузка (за разрешением `allowLaunch`)

| Инструмент | Аргументы | Реализация |
|---|---|---|
| `v8i_launch` | `exePath?` (только 1cv8*.exe из allowlist), `designer=true`, `basePath`, `args?[]` | `CreateProcessW` + helper attach сразу после старта; пароли `/P` в лог не пишутся; при неудачном attach процесс не убивается, инструмент возвращает `isError` с pid |
| `v8i_dump_config_headless` | `basePath`, `targetDir`, `exePath?` | `1cv8 DESIGNER /F <base> /DumpConfigToFiles <targetDir>`, ожидание с таймаутом; не зависит от payload и модальных окон |

Запущенный через `v8i_launch` процесс 1С **не** входит в kill-on-close Job
object сервера: после EOF он остаётся работать, как если бы пользователь
запустил его сам. Job object снимает только helper'ы. Headless-выгрузка
запускает свой процесс 1С и дожидается его завершения; зомби после неё не
остаются.

Headless-выгрузка — предпочтительный путь для автоматизации; `v8i_dump_config`
(команда 45) остаётся для случая, когда нужен именно живой Конфигуратор.

Команда проверена 2026-11-09 на тестовых базах:

| Платформа | База | Результат |
|---|---|---|
| 8.3.27.1989 x86 | `E:\work\1cv83.db\awa_empty` | exit 0, 101 файл, есть `ConfigDumpInfo.xml` |
| 8.5.1.1529 x64 | `E:\work\1cv83.db\awa_empty_851` | exit 0, 101 файл, есть `ConfigDumpInfo.xml` |

Рабочая строка: `1cv8.exe DESIGNER /F <база> /DumpConfigToFiles <каталог>
/DisableStartupDialogs /DisableStartupMessages /Out <лог>`. Занятая база и
отсутствие лицензии проверяются отдельно в M4: они дают ненулевой код
возврата, который инструмент обязан вернуть текстом, а не «успехом».

### 4.4. Ресурсы и prompts (после v1)

- `v8i://processes` — список 1С-процессов;
- `v8i://sessions/{id}` — состояние сессии;
- `v8i://sessions/{id}/log` — хвост `v8inject.log` (только чтение, ≤ 256 КиБ);
- prompt `diagnose_1c` — шаблон «собери модули, найди ошибку, предложи гипотезу».

Включаем только после того, как tools подтверждены конформанс-тестами: спека
меняется, а ценность resources для 1С ниже, чем у tools.

---

## 5. Helper: режим `v8inject.exe rpc`

Новый режим того же CLI, без нового бинаря. Запуск:

```
v8inject.exe rpc <exe> [--pid <n>] [--dll <path>] [--timeout <ms>]
```

Поведение:

1. Разрешает PID (по `--pid` или имени) и определяет состояние payload'а
   двумя независимыми проверками:

   - `FindModuleInProcess` — загружена ли DLL;
   - `OpenMutexW(SYNCHRONIZE, FALSE, L"Local\\v8inject.session.<pid>")` +
     `WaitForSingleObject(h, 0)` — жив ли командный цикл. Mutex создаётся и
     захватывается в `RunPayload` сразу после маппинга, а освобождается в
     самом конце — после `UnmapViewOfFile`/`CloseHandle` старого блока. Это
     исключает гонку «helper увидел, что mutex свободен, и запустил новый
     цикл, пока старый ещё делает cleanup». `WAIT_TIMEOUT` — цикл жив;
     `WAIT_ABANDONED`, `WAIT_OBJECT_0` или ошибка `OpenMutex` — потока нет
     (нормальный выход, падение или TerminateThread); в случаях
     `WAIT_ABANDONED`/`WAIT_OBJECT_0` helper сначала освобождает mutex, затем
     закрывает хэндл.

   Дальше:

   | DLL | mutex | Что делает helper | `mode` |
   |---|---|---|---|
   | есть | есть | `Client::AttachExisting` — подключение к живому payload'у без второго `v8i_probe` | `attach` |
   | есть | нет | `Client::Open` штатно: `LoadLibraryW` вернёт уже загруженный модуль, новый mapping создаёт хост, remote-поток запускает новый `v8i_probe` | `reopen` |
   | нет | — | обычный `Client::Open` | `open` |

   `reopen` — это не «второй экземпляр»: старый командный цикл уже завершён,
   повторный `v8i_probe` безопасен. Именно этот путь используется после
   штатного `detach`, когда DLL осталась в процессе 1С.
2. `AttachExisting` открывает **существующий** mapping (`OpenFileMappingW`, не
   `CreateFileMappingW`; секция жива, пока payload держит view/хэндл) и обязан
   корректно принять состояние разделяемого блока:
   дождаться `idle`; если `ready == kStateResponse` — прочитать и отбросить
   ответ прошлой сессии; если `ready == kStateRequest` — подождать ответ до
   5 с; если состояние так и не стало `idle`, вернуть ошибку «payload busy
   from a previous session» с советом перезапустить 1С. Слепо сбрасывать
   `ready`/`request` нельзя: можно потерять выполняющийся вызов.
3. До запуска helper'а (и до любого повторного использования payload) сервер
   берёт mutex владения `Local\v8inject.mcp.<pid>` и держит его до
   `detach`/EOF — второй MCP-сервер к тому же PID получает `isError` «target
   is managed by another MCP server». Mutex освобождается ОС при падении
   сервера. Совместная работа с `v8inject-agent`/CLI на одной цели не
   поддерживается и документируется: `cleanStaleHooks` может снять их хуки.
4. При `cleanStaleHooks=1` (по умолчанию) и `mode` равном `attach` или
   `reopen` сразу после подключения выполняется `unhook all`; число снятых
   хуков попадает в результат `v8i_attach`. `attach` — хуки прошлого живого
   цикла; `reopen` — остатки аварийно завершившегося потока
   (`TerminateThread`/падение, когда mutex уже брошен). Для `open` шаг
   пропускается: DLL только что загружена, хуков быть не может.
5. Пишет в stdout одну строку готовности:
   `{"ready":true,"pid":1234,"arch":"x64","mode":"open","log":"…\\v8inject.log"}`.
6. Читает stdin построчно:

   ```json
   {"id":1,"command":"mods","timeoutMs":15000}
   ```

7. Отвечает одной строкой:

   ```json
   {"id":1,"ok":true,"reply":{"status":"ok","modules":[…]}}
   ```

   или `{"id":1,"ok":false,"error":"timeout","detail":"…"}`.
8. Команда `{"id":N,"command":"__close"}` → `Client::Close()`, ответ и выход 0.
   EOF → тоже `Close()` и выход.
9. Ошибка открытия — `{"ready":false,"stage":2,"win32":5,"error":"…"}`, код
   возврата 3/4 (как у CLI).

Сервер:

- держит не более одной сессии на PID; повторный `v8i_attach` к тому же PID
  возвращает существующую сессию;
- внутри сессии — очередь и один исполнитель (mutex), разные сессии работают
  параллельно; пул воркеров задаёт `workerThreads` (§6);
- таймаут helper-вызова вычисляет сервер: `callTimeoutMs` (15 с) для
  обычных команд, `scanTimeoutMs` (120 с) для `find`/`disasm`/`xref`/
  `modules`; аргумента `timeoutMs` в схемах инструментов нет;
- смерть helper'а → сессия `dead`, инструмент возвращает `isError` с кодом
  возврата и хвостом stderr (stderr helper'а читается отдельным потоком в
  кольцевой буфер, последние 8 КиБ);
- idle-таймаут 30 мин → штатный `Close` и удаление сессии;
- пути helper'ов: явные `helperX86`/`helperX64` из ini, иначе
  `<exe dir>\x86\v8inject.exe` / `<exe dir>\x64\v8inject.exe`, иначе
  одноимённый рядом (dev-сборка);
- payload: `payloadX86`/`payloadX64` или `<helper dir>\v8i_payload.dll`.

**Жизненный цикл сессии.** Сессия живёт в процессе сервера: MCP-клиент
перезапустил сервер — `sessionId` недействителен, нужен новый `v8i_attach`.
Фонового брокера в v1 нет. Штатный выход (EOF/`detach`) отправляет payload'у
`exit`: тот снимает все свои хуки (`HookRemoveAll` перед выходом из цикла),
поток завершается, `Client::Close` освобождает хэндлы. **DLL при этом не
выгружается** — `LoadLibraryW` не имеет парного `FreeLibrary`, и это
осознанно: следующий `attach` пойдёт по пути `reopen`/`attach`, не трогая
диск. Если сервер убили силой, Job object снимает helper'ы без `Close`, а
payload с хуками продолжает жить — ровно как после работы
`v8inject-agent`. Следующий `v8i_attach` видит mutex живости, переиспользует
payload (`mode=attach`) и снимает чужие хуки. Если `version` не отвечает,
инструмент возвращает `isError` с рекомендацией перезапустить 1С, а не
пытается внедрять второй экземпляр вслепую.

Ограничение v1: отмена уже выполняющегося payload-вызова не прерывает
`Client::Call` (поллинг в `src/host/client.cpp:131`). Reader-поток видит
`notifications/cancelled`, пока воркер ждёт ответа, но снять может только
вызов, ещё стоящий в очереди. Все вызовы ограничены таймаутом; в фазе 3 —
опциональный cancel-флаг в `Client::Call` или отдельный control-канал
helper'а.

---

## 6. Конфигурация и безопасность

Файл: `%APPDATA%\v8inject\mcp.ini`, секция `[mcp]`; путь можно переопределить
`--config`. Приоритет: аргументы CLI → переменные `V8I_MCP_*` → ini →
значения по умолчанию.

```ini
[mcp]
allowedProcesses=1cv8.exe,1cv8c.exe,1cv8s.exe
allowedCommands=2,45
allowReverse=0
allowHooks=0
allowLaunch=0
cleanStaleHooks=1
helperX86=
helperX64=
payloadX86=
payloadX64=
callTimeoutMs=15000
scanTimeoutMs=120000
workerThreads=4
maxQueuedCalls=32
maxSessions=8
maxOutputBytes=524288
idleTimeoutSec=1800
logFile=%LOCALAPPDATA%\v8inject\mcp.log
```

Правила:

1. **Только 1С.** `v8i_attach` отклоняет процесс, чьё имя не в
   `allowedProcesses`; `v8i_launch` — путь, не оканчивающийся на `1cv8*.exe`.
2. **Никаких произвольных DLL.** Путь payload'а — только из конфига; поля
   `dll` в аргументах инструментов нет.
3. **Команды дизайнера — по allowlist.** По умолчанию 2 (открыть
   конфигурацию) и 45 (выгрузить в файлы); остальные номера — после правки ini.
   `v8i_dump_config` — алиас 45 и подчиняется тому же списку: убрали 45 из
   `allowedCommands` — инструмент исчез из `tools/list`.
4. **Опасные группы — явным флагом.** `allowReverse` (`find`,
   `read_string`, `peek`, `disasm`, `around`, `xref`, `imports`),
   `allowHooks` (`hook`, `hooks`, `unhook`, `trace`), `allowLaunch`
   (`launch` + `dump_config_headless`); если группа выключена, инструменты не
   попадают в `tools/list` и не вызываются. Метаданные — `mods`, `objects`,
   `pe` — доступны всегда.
   `cleanStaleHooks=1` снимает хуки прошлой сессии при подключении к уже
   загруженному payload (`mode=attach` или `reopen`); `0` оставляет их (нужно
   для отладки «что осталось после падения»). Совместная работа с другим
   хостом (CLI/agent) на одной цели не поддерживается — см. §5.
5. **Аннотации — честные.** `readOnlyHint` только у чтения; `v8i_attach`,
   `v8i_gitbar`, `v8i_designer_command`, хуки — не read-only;
   `destructiveHint` у `v8i_unhook`, `v8i_detach`, `v8i_dump_config`,
   `v8i_dump_config_headless` (пишут файлы), `v8i_launch`.
6. **Логи без секретов.** Полные дампы памяти и аргументы `/P` не логируются;
   в лог — метод, session, pid, длительность, статус, размер ответа.
7. **Лимиты.** Строка транспорта ≤ 2 МиБ, команда payload ≤ 4096 `wchar_t`,
   ответ инструмента ≤ `maxOutputBytes` (512 КиБ — предел `SharedIo`), сессий
   ≤ `maxSessions`, очередь ≤ `maxQueuedCalls`, `peek` ≤ 4096 байт.
8. **Никакой сети.** v1 слушает только stdio; сетевой поверхности нет.
9. **Права.** Если 1С запущена elevated, сервер тоже должен быть elevated —
   иначе `OpenProcess` вернёт «отказано в доступе»; это пишется в ошибку
   инструмента.
10. **Владение процессом.** Запущенные `v8i_launch` процессы 1С не входят в
    kill-on-close Job object и переживают EOF сервера; helper'ы — входят.
    Mutex `Local\v8inject.mcp.<pid>` исключает второй MCP-сервер на той же
    цели.

---

## 7. Этапы

Оценка — в человеко-днях одного разработчика, без учёта ревью и релиза.

### M0. Каркас и протокол — 2 дня

- вендорить `nlohmann/json`, CMake-таргет `v8i-mcp`;
- stdio-транспорт, JSON-RPC (parse/serialize, коды ошибок), `ping`;
- reader-поток, пул воркеров, mutex писателя, очередь и отмена
  (`notifications/cancelled`);
- legacy `initialize`/`initialized` + `server/discover`/`_meta`, правила
  выбора эры и `-32002`;
- `tools/list` с пустым/тестовым набором, `tools/call` с заглушкой;
- лог в stderr и файл, бинарные режимы потоков, EOF-завершение.

**Проверка:** `tests/mcp_protocol.ps1` — все кейсы §8.1 проходят; в stdout
нет ни одной не-JSON строки.

### M1. Helper и сессии — 4 дня

- режим `v8inject.exe rpc` (`src/cli/rpc.cpp`) + заголовок протокола;
- `SessionManager`: запуск helper'а нужной разрядности, pipes, job object,
  таймауты, kill-on-close, переиспользование по PID;
- mutex живости `Local\v8inject.session.<pid>` в payload и mutex владения
  `Local\v8inject.mcp.<pid>` в сервере;
- `Client::AttachExisting`: подключение к живому payload'у без второго
  `v8i_probe`, корректный разбор `ready` (stale response / pending request);
- три пути подключения `open`/`reopen`/`attach` и `cleanStaleHooks` для
  `attach`/`reopen`;
- инструменты `v8i_list_processes`, `v8i_attach`, `v8i_list_sessions`,
  `v8i_detach`, `v8i_payload_version`;
- маппинг ошибок `Client::Open` (stage/win32/LastError) в `isError`.

**Проверка:** `mcp_smoke.ps1` на `v8i_hook_target.exe`; x64-сервер цепляется
к x86-таргету через x86-helper; после EOF сервера не остаётся helper'ов
(`v8inject.exe`), а тестовый таргет завершает сам скрипт; после сильного
убийства сервера повторный attach переиспользует payload и снимает хук; после
штатного `detach` повторный attach идёт путём `reopen` и работает без
перезапуска цели.

### M2. Инструменты 1С — 3 дня

- `v8i_modules`, `v8i_objects`, `v8i_pe`, `v8i_gitbar`;
- `v8i_designer_command` + `v8i_dump_config` с allowlist и понятным текстом
  про модальный диалог («UI thread did not answer» — это открытый диалог,
  а не ошибка связи);
- обрезка/pretty-print ответов, лимиты, `structuredContent`.

**Проверка:** живой прогон 8.3 x86 и 8.5 x64: list → attach → modules →
objects → gitbar show/hide → cmd 2 → cmd 45 → detach.

### M3. Чтение памяти, reverse, хуки, отмена — 3–4 дня

- `v8i_find`, `v8i_read_string`, `v8i_peek` за `allowReverse`;
- `v8i_disasm`, `v8i_around`, `v8i_xref`, `v8i_imports` там же;
- `v8i_hook`, `v8i_hooks`, `v8i_unhook`, `v8i_trace` за `allowHooks`;
- поведение «хуки живут до detach» в описаниях и в тексте ошибок;
- по возможности — cancel-флаг в `Client::Call` (иначе зафиксировать
  ограничение в MCP.md).

**Проверка:** цикл hook → trace → unhook на `v8i_hook_target.exe` через MCP;
проверка, что после `v8i_detach` хуки сняты, а 1С жива.

### M4. Запуск и headless-выгрузка — 2–3 дня

- `v8i_launch` (только 1cv8*.exe, без shell, пароли не логируются); при
  неудачном attach процесс остаётся жив, возвращается `isError` с pid;
- `v8i_dump_config_headless` (`/DumpConfigToFiles`), ожидание завершения,
  код возврата 1С;
- обработка занятой базы (два Конфигуратора на одну ИБ) и блокировок.

**Проверка:** счастливый путь уже подтверждён 2026-11-09 (8.3 x86 и 8.5 x64:
exit 0, по 101 файлу); в M4 добавить негативные сценарии — занятая база, нет
лицензии, непустой каталог: инструмент возвращает код и текст 1С, а не
«успех»; повторный запуск не падает.

### M5. Документация, упаковка, релиз — 2 дня

- `docs/MCP.md`: настройка Qoder/Claude Desktop/VS Code, таблица инструментов,
  разрешения, типовые сценарии, ограничения (включая несовместимость с
  CLI/agent на одной цели);
- `docs/CMD-NUMBERS.md`: заполнить проверенными номерами 2/45, завести раздел
  «как калибровать»;
- `README.md` и `docs/ARCHITECTURE.md`: новая цель сборки и helper-режим;
- `RELEASE.md` для v0.3.0;
- релизная упаковка (см. §9), тесты в CI, тег `v0.3.0`.

**Проверка:** чистая машина/каталог: распаковать zip, прописать сервер в
клиент, пройти сценарий из MCP.md.

Итого: **16–18 рабочих дней** (без ревью и без непредвиденного в реверсе 1С).
Прибавка к исходным 15–17 — работа с живостью payload'а (`AttachExisting`,
`reopen`) и конкурентный диспетчер с отменой.

---

## 8. Тестирование и CI

### 8.1. Конформанс протокола (без 1С)

`tests/mcp_protocol.ps1` запускает собранный `v8i-mcp.exe`, пишет строки в
stdin и проверяет ответы с таймаутом:

1. `initialize` legacy с `2025-06-18` и `2025-11-25` → та же версия,
   `capabilities.tools`;
2. `initialize` с неизвестной версией → последняя поддерживаемая;
3. `notifications/initialized` → нет ответа;
4. `ping` → `{}`;
5. `tools/list` → ожидаемый набор, детерминированный порядок, валидные схемы;
6. `tools/call` с неизвестным именем → `-32602`;
7. битый JSON → `-32700`, `id: null`;
8. `tools/list`/`tools/call` до `initialize`/выбора эры → `-32002`; `ping` до
   `initialize` работает;
9. `server/discover` и запрос с `_meta` → modern-ответ, `serverInfo` есть и в
   ответе, и в `_meta`;
10. `_meta` без обязательного поля → `-32602`;
11. неподдерживаемая версия в `_meta` → `-32022` с `supported`;
12. строка > 2 МиБ → `-32600`, сервер жив;
13. `CRLF` и кириллица в аргументах → корректный UTF-8;
14. массив (batch) → `-32600`;
15. смешивание эр: `initialize` после modern-сообщения и `_meta` после
    legacy-`initialize` → `-32600`;
16. `notifications/cancelled` для вызова в очереди → вызов не исполняется и
    ответа по нему нет; для исполняемого → ответ приходит, отмена в логе;
17. EOF → выход ≤ 6 с (бюджет закрытия helper'ов 5 с), код 0, stdout
    заканчивается полными строками.

Каждый полученный stdout-чанк обязан парситься как JSON — это отдельная
проверка «чистоты stdout».

### 8.2. Smoke с целью (CI, без 1С)

`tests/mcp_smoke.ps1`:

1. запускает `v8i_hook_target.exe`;
2. стартует `v8i-mcp.exe`, `v8i_attach` по PID;
3. `v8i_payload_version` → API и разрядность;
4. `v8i_hook` на функцию таргета → `v8i_trace` видит вызов → `v8i_unhook`;
5. снова `v8i_hook`, затем сервер убивается (`TerminateProcess`) — helper
   умирает без `Close`, payload остаётся;
6. новый сервер, `v8i_attach` → `mode=attach`, `v8i_hooks` пуст
   (`cleanStaleHooks`), таргет жив;
7. `v8i_detach`; helper завершился, хуки сняты payload'ом;
8. повторный `v8i_attach` к тому же PID без перезапуска таргета →
   `mode=reopen` (mutex'а живости нет), `v8i_payload_version` отвечает;
   затем `v8i_detach`;
9. EOF сервера → нет осиротевших helper'ов; таргет завершает сам скрипт.

Для кросс-разрядности: x64-сервер + x86-helper + x86-таргет (и наоборот), если
в CI собраны обе конфигурации.

### 8.3. E2E с живой 1С (локально)

`tools/check_mcp.sh [8.3|8.5]` по образцу `check_gitbar.sh`:

- запуск Конфигуратора на тестовой базе;
- `v8i_list_processes` → `v8i_attach` → `v8i_modules`/`v8i_objects`;
- `v8i_gitbar` show/hide;
- `v8i_designer_command 2` (открыть конфигурацию);
- `v8i_dump_config` (45) — допускается открытый модальный диалог, проверяем
  что сессия жива и `detach` работает;
- `v8i_dump_config_headless` в пустой каталог;
- завершение только процессов, запущенных тестом.

### 8.4. CI

`.github/workflows/build.yml`: новые тесты автоматически попадают в `ctest`
(`mcp_protocol`, `mcp_smoke`); сборка x86/x64 уже покрывает оба helper'а.
Тесты с живой 1С в CI не запускаются — как и `check_gitbar.sh`.
Релизный job дополняется сборкой комбинированного zip (§9).

---

## 9. Упаковка и распространение

Один сервер должен уметь обе разрядности, поэтому к текущим per-arch zip
добавляется комбинированный `v8inject-mcp-v0.3.0.zip`:

```
v8i-mcp.exe                 # x64 front end (для работы хватает любой разрядности)
mcp.ini.example
x64\v8inject.exe
x64\v8i_payload.dll
x86\v8inject.exe
x86\v8i_payload.dll
```

Front end собирается и тестируется в x64 и x86 (общий код, ловим разрядные
ошибки), но в zip кладётся x64-сборка: она управляет и x86-, и x64-целями
через helper'ы. Вариант «два MCP-сервера, по одному на разрядность» остаётся
запасным: `helperX86/helperX64` можно указать на уже распакованные сборки.

Существующие `v8inject-vX-x64.zip` / `-x86.zip` не меняются (обратная
совместимость).

Пример конфигурации клиента (документируется в `docs/MCP.md`):

```json
{
  "mcpServers": {
    "v8inject": {
      "command": "C:\\opt\\v8inject-mcp\\v8i-mcp.exe",
      "args": ["--config", "C:\\opt\\v8inject-mcp\\mcp.ini"]
    }
  }
}
```

Аргументы CLI сервера:

```
v8i-mcp.exe [--config <path>] [--log-file <path>] [--allow-reverse]
            [--allow-hooks] [--allow-launch] [--version] [--help]
```

---

## 10. Риски и меры

| Риск | Вероятность | Мера |
|---|---|---|
| Клиент не понимает modern 2026-07-28 | средняя | dual-era; legacy `initialize` как основной путь, modern — по `_meta`/`server/discover` |
| Схема `server/discover` в спеке уточнится | средняя | сверить с JSON-схемой 2026-07-28 в M0; вынести в один модуль и покрыть фикстурами |
| x64-сервер и x86-1С | высокая без helper | helper нужной разрядности; тест кросс-разрядности в CI |
| Payload `BUSY` при параллельных вызовах | высокая | очередь на сессию, понятная ошибка «target busy», без ретраев внутри payload |
| Модальный диалог 1С блокирует UI-поток | высокая | таймаут 120 с, текст «диалог открыт», сессия не считается мёртвой |
| Хуки переживают сессию и ломают 1С | средняя | `detach`/EOF отправляют payload'у `exit`, тот снимает хуки перед выходом; если цикл не успел завершиться — следующий attach (`mode=attach`) делает `unhook all` |
| На цели уже работает CLI/agent и его хуки | низкая | mutex владения исключает второй MCP-сервер; совместная работа с другими хостами не поддерживается и явно документируется, `cleanStaleHooks` сообщает число снятых хуков |
| LLM вызывает опасные инструменты без спроса | средняя | группы выключены по умолчанию, честные аннотации, allowlist процессов/команд |
| Утечка памяти процесса в ответах | средняя | лимиты `peek`, `allowReverse`, обрезка ответа, логи без дампов |
| Вендоринг JSON раздувает репозиторий | низкая | один заголовок ~1 МБ, MIT, как Capstone; фиксированная версия |
| Антивирус реагирует на инжект | средняя | не лечится кодом; документируем исключения и подпись в перспективе |

---

## 11. Решения по открытым вопросам (2026-11-09)

| № | Вопрос | Решение | Обоснование и следствие |
|---|---|---|---|
| 1 | Приоритетный клиент | **Qoder Desktop**, затем Claude Desktop; VS Code — по необходимости | Qoder — рабочее окружение автора, оба клиента говорят по stdio. E2E и инструкция в `docs/MCP.md` — сначала Qoder; legacy `initialize` проверяем на нём первым, modern — конформанс-тестом |
| 2 | Именованные команды дизайнера | В v1 — только проверенные **2 и 45**; остальные номера — числом через `allowedCommands`. Калибровка — отдельная процедура, не блокирует v1 | Внутренние номера меняются между релизами; неверный номер — это чужое действие или падение. Процедура: attach → hook `transmitCommand` → клик по пункту меню → `trace` с аргументами `Command` → номер в таблицу. Результат — `docs/CMD-NUMBERS.md`, пополняется по мере надобности |
| 3 | Reverse по умолчанию | Метаданные (`mods`, `objects`, `pe`) — всегда. Память и код (`find`, `read_string`, `peek`, `disasm`, `around`, `xref`, `imports`) — `allowReverse=0`. Хуки — `allowHooks=0` | Куча 1С содержит пароли и данные; удобство диагностики не оправдывает выдачу этого модели по умолчанию. Флаги включаются явно, инструменты вне групп не попадают в `tools/list` |
| 4 | Срок жизни сессии | Сессии живут в процессе сервера, фонового брокера нет. Состояние payload'а различается по mutex'у живости `Local\v8inject.session.<pid>`: живой → `Client::AttachExisting`; DLL есть, цикла нет (штатный `detach`) → `Client::Open` через `mode=reopen`; DLL нет → обычный инжект. Если сервер убили силой, payload остаётся — следующий `v8i_attach` переиспользует его (`mode=attach`) и снимает хуки (`cleanStaleHooks=1`). Тот же `unhook all` выполняется при `mode=reopen` — на случай аварийно завершившегося потока. Если блок занят (`kStateRequest`) и не освобождается за 5 с — `isError` с советом перезапустить 1С, без сброса состояния и слепого повторного инжекта. Второй MCP-сервер на ту же цель отсекается mutex'ом `Local\v8inject.mcp.<pid>` | Брокер — лишняя поверхность и служба; payload и так переживает хосты по дизайну агента. Цена решения — mutex в payload, `Client::AttachExisting`, аккуратный разбор `ready` и тесты «detach → повторный attach» и «убили сервер → attach → хуки пусты» в M1 |
| 5 | Headless-выгрузка | Инструмент **поддержан**: проверено 2026-11-09 на 8.3.27.1989 x86 (`awa_empty`) и 8.5.1.1529 x64 (`awa_empty_851`) — exit 0, по 101 файлу, `ConfigDumpInfo.xml` на месте | Строка `1cv8 DESIGNER /F <база> /DumpConfigToFiles <каталог> /DisableStartupDialogs /DisableStartupMessages /Out <лог>` работает на обеих платформах. Остаётся проверить негативные сценарии (занятая база, нет лицензии) в M4 |

### 11.1. Что осталось проверить (не открытые вопросы)

Это проверки фактов, а не выбор направления; каждая закрывается на своём этапе:

- какую версию протокола реально присылает Qoder Desktop — снять первый обмен
  (`initialize` или `server/discover` с `_meta`) в M0/M5;
- отличия legacy-ревизии `2025-11-25` от `2025-06-18` — сверить при вендоринге
  схем; если отличий нет, ревизия просто добавляется в список поддерживаемых;
- точная JSON-схема `server/discover` и `_meta` 2026-07-28 — сверить со
  схемой в M0;
- поведение headless-выгрузки при занятой базе и без лицензии — M4;
- путь и формат MCP-конфига Qoder Desktop / Claude Desktop — M5.

---

## 12. Критерии готовности v1

- [ ] `v8i-mcp.exe` собирается и проходит тесты в x64 и x86 (в релизный zip
      идёт x64), запускается без 1С и отвечает на `initialize`/`ping`/`tools/list`;
- [ ] dual-era: legacy и modern-клиенты проходят конформанс-тесты;
- [ ] Qoder Desktop подключается к серверу и проходит сценарий attach → modules;
- [ ] x64-сервер работает с x86-1С (8.3) и x64-1С (8.5);
- [ ] сценарий `list_processes → attach → modules/objects → designer_command →
      detach` проходит на обеих платформах;
- [ ] после штатного `detach` повторный `attach` к той же 1С работает без
      перезапуска цели (`mode=reopen`), а после убийства сервера —
      `mode=attach` с очисткой хуков;
- [ ] `v8i_dump_config_headless` выгружает конфигурацию на 8.3 и 8.5 (exit 0,
      непустой каталог);
- [ ] опасные инструменты недоступны без явных флагов;
- [ ] после EOF/`detach` не остаётся helper'ов и установленных хуков; payload
      не выгружается, но его цикл остановлен;
- [ ] после сильного убийства сервера повторный `attach` переиспользует payload
      и снимает хуки;
- [ ] stdout содержит только валидные MCP-сообщения;
- [ ] `ctest` (включая `mcp_protocol`, `mcp_smoke`) зелёный на x86 и x64;
- [ ] `docs/MCP.md`, `docs/CMD-NUMBERS.md`, README и RELEASE.md обновлены,
      комбинированный zip собирается релизным job'ом.
