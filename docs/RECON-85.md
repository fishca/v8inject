# RECON-85 — инвентарь платформы 1С 8.5.1.1529

Результат **Фазы 0** плана `docs/plan_inj_ext.md`. Источник данных — файлы на
диске (в памяти 8.5 зануляет export directory), плюс `v8api` из проекта
`fishca/v8snack` (готовые раскладки слотов интерфейсов).

---

## 1. Билд

| Параметр | Значение |
|---|---|
| Платформа | 1С:Предприятие 8.5.1.1529, x64 |
| `1cv8.exe` | `C:\Program Files\1cv8\8.5.1.1529\bin\1cv8.exe` |
| FileVersion | `8.5.1.1529` |
| SHA-256 (первые 32) | `636ab6f2379b197bc85ce3f7c46de354…` |
| Тестовая база | `E:\work\1cv83.db\awa_empty_851` |

Эталон для сравнения: 8.3.27.1989, x86
(`C:\Program Files (x86)\1cv8\8.3.27.1989\bin\1cv8.exe`).

---

## 2. Модули и экспорты

Собрано `tools/recon_exports.py` (pefile, чтение с диска).

| Модуль | Экспортов | Комментарий |
|---|---|---|
| `core85.dll` | **4531** | публичная C++-поверхность ядра; здесь `?current_process@core@@…` |
| `wbase85.dll` | **540** | обёртки Win32-слоя (`V8CreateWindowEx` и др.) |
| `frame.dll` | 1 | только `SCOM_Main` (RVA `0x950520`) |
| `mngcore.dll` | 1 | только `SCOM_Main` (RVA `0x420860`) |
| `mngui.dll` | 1 | только `SCOM_Main` (RVA `0x4BD410`) |
| `config.dll` | 1 | только `SCOM_Main` (RVA `0x189550`) |

**Вывод:** у `frame/mngcore/mngui/config` публичной поверхности нет — только
точка входа `SCOM_Main`. Всё остальное — внутренние функции, доступные лишь
через vtable объектов. Это и есть причина, почему «найти функцию по имени» для
них не работает: искать надо **методы интерфейсов**, а не экспорты.

Сравнение с 8.3 (по именам): `core85` 4531 против `core83` 4457; совпадений
мало (3946 имён есть только в 8.3, 4020 — только в 8.5), потому что имена
манглированы и зависят от версии. Сравнивать имеет смысл по **базовому имени**
(до `@`) или по конкретным функциям, а не по всей таблице.

### 2.1 Контрольные точки (проверено живыми вызовами)

| Что | Значение |
|---|---|
| `core85!?current_process@core@@…` | RVA `0x2EB2A0` |
| vtable `SCOM_Process` | `core85+0x418838` (в `.rdata`) |
| `getService` | **слот 14** vtable `SCOM_Process` |
| `getService(IID_IEventService)` | vtable `core85+0x3D6298` |
| `getService(IID_ICommandService)` | vtable `frame.dll+0xC9B988` |

---

## 3. Раскладки интерфейсов (из `v8snack/snegopat-client/x64/modules/snegopat/v8api`)

Использован готовый результат Снегопата (P0-1 плана) — реверс слотов не нужен.

### 3.1 `ITopLevelFrame` `{DE300901-A120-11d4-9429-008048DA11F9}` — `window.v`

| Слот | Метод | Примечание |
|---|---|---|
| 0 | `init(title, icon, parent, rect, nCmdShow)` | |
| 1 | `close(testAbility)` | |
| 2 | `canClose()` | |
| 3 | `cancelClose()` | |
| 4 | `frameType()` | `eTLFT_Main` у главного |
| 5 | `openView(...)` | пропущен в `.v` (`+1`) |
| 6 | — | `+1` для 8.3.6+ |
| 7 | `closeView(id)` | |
| 8 | `getView(out, id)` | |
| 9 | `activateView(id)` | |
| 10 | `showView(id, show)` | |
| 11 | `isViewVisible(id)` | |
| 12 | `enumAllViews(vector)` | |
| 13 | `getCoreTopLevelFrame(out)` | |
| 14 | `getShellTopLevelFrame(out)` | |
| 15–19 | — | `+1` ×5 |
| **24** | `getCaption()` | для `ver >= 8.3.18` (абсолютный слот) |
| 25 | `getTitle()` | |
| 26 | `setTitle(str)` | |
| 27 | `setAdditionalTitle(str)` | |
| 28 | `getAdditionalTitle()` | |
| 29 | — | `+1` |
| **30** | **`commandReceiver(out)`** | ★ цель Фазы 1 |
| 31 | — | `+1` (`setForeground`) |

> Для 8.3.17.1549 слот `getCaption` — 23, для 8.3.18+ (в т.ч. 8.5) — 24.
> Считать слоты нужно по этой таблице, а не «на глаз»: ошибка на единицу даёт
> вызов чужого метода и падение.

### 3.2 `ICommandReceiver` `{377A2018-C51B-4cf5-AC03-A1509266DF2D}` — `command.v`

| Слот | Метод |
|---|---|
| **0** | **`transmitCommand(const Command&, bool deactivate = true)`** ★ |
| 1 | `updateState(ICommandState*)` |
| 2 | `hasHandler(const CommandID&)` |

### 3.3 Структуры

```cpp
struct CommandID { GUID group; uint32_t num; };            // 20 байт, выравнивание 8
struct Command   { CommandID id; int32_t param; intptr_t object; };  // 40 байт
```

`Command` выравнивается: `GUID`(16) + `num`(4) + pad(4) + `param`(4) + pad(4) +
`object`(8) = 40 байт. Передавать по указателю (`const Command&`).

### 3.4 `ICommandService` `{8F885821-D353-11D3-8A57-008048DA06DF}`

| Слот | Метод |
|---|---|
| 0 | `commandDescription(out ICmdDescription*, const CommandID&)` |

### 3.5 `IEventService` `{EBF766AA-F32C-11D3-9851-008048DA1252}` — `event.v`

| Слот | Метод |
|---|---|
| 3 | `notify(eventID, val, obj)` |
| 4 | `_subscribe(eventID, recipient, srcName, srcFlag)` |
| 5 | `unsubscribe(eventID, recipient)` |

`subscribe()` в Снегопате — обёртка: `_subscribe(eventID, recipient,
"snegopat", 0)`. В 8.3.24+ имя источника обязательно (с NULL платформа падает
на `strlen`).

### 3.6 `SCOM_Process` — `process.v`

| Слот | Метод |
|---|---|
| 14 | `getService(const GUID&, void** out)` (на 8.3 — слот 11) |

---

## 4. Итоговая цепочка вызова команды (цель Фаз 1 и 4)

```
frame (ITopLevelFrame*)
   └─ vtable[30] → commandReceiver(&recv)      // ITopLevelFrame::commandReceiver
        └─ recv->vtable[0] → transmitCommand(&cmd, deactivate)
             где cmd = { CommandID{ group, num }, param, object }
```

Всё, чего не хватает для работы, — **сам указатель `frame`** (Фаза 1). Слоты,
структуры и сигнатуры уже известны.

---

## 5. Ограничения, выясненные на практике (не повторять)

1. **`user32!CreateWindowExW` и `wbase85!V8CreateWindowEx` для окон 1С не
   вызываются.** Окно создаётся через `win32u!NtUserCreateWindowEx`
   (пролог `4C 8B D1 B8 6F 10 00 00 …`, 16 целых байт).
2. **Инжект после старта не успевает к созданию окна** — окно уже существует
   (`cwHits=0` во всех прогонах, включая инжект на первом опросе процесса).
3. **Подписка внутри detour создания окна роняет 1С** (`0xC000041D` —
   исключение в callback): в этот момент ядро ещё не готово.
4. **`/FE:<путь>` при запуске из другого процесса даёт `exit code 1`**;
   работает `/F <путь>` двумя аргументами.
5. **Ответ payload ограничен 512 КБ** — `exports85` без `--count` обрезается
   (для полного инвентаря есть `tools/recon_exports.py`, читающий диск).

---

## 6. Что дальше (Фаза 1)

1. `frames` — сохранять объект из `eventCreateFrame` (указатель, vtable, 64
   байта), как только подписка начнёт ловить событие.
2. Ранняя подписка: `WH_CBT` из `v8i_probe` до сессии + ожидание готовности ядра
   (опрос `current_process` под SEH), либо работа через движок `core_as.dll`.
3. `svcscan` — перебор известных IID через `getService` (слот 14), включая
   `ICommandService` (`{8F885821-D353-11D3-8A57-008048DA06DF}`).
4. Как только `frame` получен — `transmitCommand` вызывается по таблице §3.1–3.3
   без дальнейшего реверса.

---

## 7. Дизасм Снегопата: как ставится WH_CBT (дополнение к P0-2)

Инструменты: `tools/recon_coreas_cbt.py` (обращения к хукам в `core_as.dll`),
`tools/recon_snegopat_hooks.py` (то же для `snegopat.dll`). Без дизасма всего
движка — только точечный разбор.

Уточнение (после первого прохода): **WH_CBT-хук ставит сам `snegopat.dll`**
(модуль Снегопата), не `core_as`:

- импорты `USER32` в `snegopat.dll`: `SetWindowsHookExW`, `CallNextHookEx`,
  `UnhookWindowsHookEx`, **`CreateWindowExW`** — хуки окон стоят в модуле, и
  модуль же создаёт свои нативные окна;
- импорты `core_as.dll`: только движковые API (`asRegisterProp`,
  `CScriptArray`, …) — `SetWindowsHookExW` в `core_as` отсутствует;
- экспорты `snegopat.dll`: `moduleInit` (точка входа модуля, вызывается
  ядром `core_as`) и вспомогательный;
- вызовы в `.text` `snegopat.dll`: `SetWindowsHookExW` @ `0x2399` и `0x7A93`,
  рядом пары `CallNextHookEx`/`UnhookWindowsHookEx` (процедуры ~0x1900,
  ~0x7700 — см. `--rva` в скрипте для контекста).

То есть в цепочке Снегопата хук создания окна — это часть модуля: core_as
загружает `snegopat.dll`, вызывает `moduleInit`, а тот регистрирует свой API и
ставит `WH_CBT` (и `CreateWindowExW` для своих окон).

Следствия для v8inject:
- повторять приём `WH_CBT` без патчей кода можно — хуки ставятся штатно;
- но требования к контексту (поток 1С, готовность ядра) — те же, что мы
  видели: у Снегопата работает, потому что весь доступ к ядру идёт через
  обёртки `core_as`; прямой вызов `current_process` в этот момент у нас падал;

```
0x13E040  sub  rsp, 0x28
0x13E044  mov  r9d,  [rip+0x25D169]   ; threadId — глобал (поток 1С)
0x13E04B  lea  rdx,  [rip+0x1E]       ; lpfn = 0x13E070 (хук-процедура)
0x13E052  xor  r8d,  r8d              ; hMod = NULL (код уже в процессе)
0x13E055  lea  ecx,  [r8+3]           ; idHook = 3 = WH_CBT
0x13E059  call  [SetWindowsHookExW]
0x13E05F  mov   [rip+0x25D142], rax   ; g_hook
```

Хук-процедура `0x13E070`:

| Ветка | Что делает |
|---|---|
| `nCode != 0` | `CallNextHookEx` |
| `g_engine == NULL` | `CallNextHookEx` |
| первый вызов (флаг==1) | `CallNextHookEx`, затем `[engine->vtable[0]](engine, nCode+1)` — **инициализация движка (run()) на заставке**, флаг сбрасывается |
| последующие | обход списка окон движка (`engine+0x1B8`) |

**Вывод:** Снегопат не подписывается «в хуке» — он вызывает инициализацию
движка на первом CBT-событии (когда все DLL платформы уже загружены, а главное
окно ещё не создано), и уже внутри `run()` идёт подписка на
`eventCreateFrame`. Это согласуется с нашей схемой: `WH_CBT` + вызов
инициализации на первом событии. Разница с нашим прямым путём — **движок**:
всё ядро 1С вызывается через обёртки `core_as` (кэш, потоки, SEH), а не
напрямую — поэтому у Снегопата это работает в момент заставки, а у нас падало.

Следствия для v8inject:
- повторять приём `WH_CBT` (idHook=3, hMod=NULL) можно — хук ставится без
  патчей кода и без инжекта DLL (процедура уже в процессе);
- но подписку нужно выполнять через тот же контекст, что и у Снегопата:
  сначала инициализация/ожидание готовности ядра, потом `current_process`;
- либо использовать `core_as.dll` как библиотеку — он уже загружен в процесс,
  экспортирует `core_as_print`/аллокаторы; вопрос — публичный ли API для
  запуска скрипта (см. `moduleInit` в `snegopat.dll` — модуль регистрируется
  через ядро).
