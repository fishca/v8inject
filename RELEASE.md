Иконки GitBar теперь берутся из соседнего проекта **qtv8reader**
(`fishca/qtv8reader`): его набор иконок типов метаданных — это открытый
MIT-набор `metadata-icons` (`zerobig/vscode-1c-metadata-viewer`),
перекрашенный в палитру 1С. Для пунктов GitBar выбраны подходящие по смыслу
глифы; картинок из ресурсов 1С в проекте по-прежнему нет.

## Что нового

- **Иконки из qtv8reader.** 16×16 PNG взяты из
  `qtv8reader/resources/icons/metadata` — это визуально тот же стиль, что в
  соседнем проекте: плоские цветные глифы в палитре 1С. Исходники 15 выбранных
  иконок лежат в `src/payload/icons/qtv8reader/` вместе с
  `LICENSE-METADATA-ICONS.txt` (MIT, Copyright (c) 2023 zerobig and
  contributors) и `ATTRIBUTION.md` с таблицей «роль → файл».
- **Подбор по назначению пунктов.** Выбраны глифы, ближайшие по смыслу:
  `document` — выгрузка исходников, `dataProcessor` — выгрузка расширения,
  `constant` — создание репозитория, `externalDataSource` — клонирование,
  `accountingFlag` — коммит, `exchangePlan` — push, `businessProcess` — pull,
  `ws` — fetch, `group` — ветки, `settingsStorage` — stash,
  `filterCriteria` — теги, `extDimensionAccountingFlag` — рабочая копия,
  `scheduledJob` — история, `sessionParameter` — настройки,
  `subsystem` — сам пункт «GitBar».
- **Один набор на всё.** `tools/select_icons.py` раскладывает выбранные PNG по
  ролям (`src/payload/icons/<role>.png`), `tools/gen_icons.py` собирает
  `icons.h` (premultiplied BGRA для панели) и `icons_png.h` (PNG для
  `file:///`-URL нативного меню). Панель и нативное подменю используют одни и
  те же картинки.

## Изменено

- `tools/render_icons.cjs` и каталог `src/payload/icons/phosphor/` удалены —
  иконки больше не рендерятся из Phosphor, а берутся готовыми из qtv8reader.
  Новый скрипт `tools/select_icons.py` только раскладывает их по ролям.
- Документация (`README.md`, `docs/GITBAR.md`, `docs/ARCHITECTURE.md`,
  `docs/plan_mainmenu_re.md`) обновлена под новый источник иконок и лицензию.

## Проверено

- Release-сборки x64 и x86 собираются без предупреждений; на каждой
  архитектуре пройдены 4/4 CTest: `cli_help`, `unit`, `hook_smoke`,
  `hook_stress`.
- Live 8.3.27.2342 x64: в журнале payload —
  `иконки заданы в описаниях (15/15, загружено платформой 15/15, …)`, то есть
  платформа собрала `IImage` по всем нашим `file:///`-URL; панель и нативное
  подменю открываются с новыми глифами.

## Установка

`v8inject-v0.8.0-x64.zip` / `v8inject-v0.8.0-x86.zip` — `v8inject.exe`,
`v8inject-gui.exe`, `v8inject-agent.exe`, `v8i_payload.dll`. Распакуйте архив
той же разрядности, что ваша платформа 1С, и запускайте `v8inject.exe`,
`v8inject-gui.exe` или `v8inject-agent.exe` из каталога с `v8i_payload.dll`.
Нативный пункт меню включён по умолчанию; ключ `[git] nativemenu=0` в
`%APPDATA%\v8inject\gitbar.ini` возвращает оверлей-реплику.

## Лицензии

Иконки GitBar — metadata-icons из `zerobig/vscode-1c-metadata-viewer`
(MIT, Copyright (c) 2023 zerobig and contributors), взяты в перекрашенном
виде из `fishca/qtv8reader`; текст лицензии — в
`src/payload/icons/qtv8reader/LICENSE-METADATA-ICONS.txt`.
Остальное — MIT, см. `LICENSE`; Capstone — 3-clause BSD (см. `third_party/`).
