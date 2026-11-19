Иконки GitBar из qtv8reader
===========================

16-пиксельные PNG в этом каталоге взяты из соседнего проекта
**qtv8reader** (`fishca/qtv8reader`, каталог `resources/icons/metadata`).
Там они, в свою очередь, происходят из открытого набора
[`zerobig/vscode-1c-metadata-viewer`](https://github.com/zerobig/vscode-1c-metadata-viewer)
(лицензия MIT, Copyright (c) 2023 zerobig and contributors — полный текст
в `LICENSE-METADATA-ICONS.txt`): qtv8reader перекрасил эти SVG в палитру,
близкую к 1С:Предприятие, и отрендерил в PNG 16/24/32.

GitBar использует их как готовые картинки действий: подходящие по смыслу
глифы типов метаданных выбраны под пункты меню (см. таблицу ниже). Никакие
картинки из ресурсов 1С не используются.

| Роль | Файл qtv8reader | Назначение |
|---|---|---|
| `dump` | `document_16.png` | выгрузить исходники в файлы |
| `dumpext` | `dataProcessor_16.png` | выгрузить расширение в файлы |
| `init` | `constant_16.png` | создать репозиторий в папке выгрузки |
| `clone` | `externalDataSource_16.png` | клонировать репозиторий |
| `commit` | `accountingFlag_16.png` | коммит изменений |
| `push` | `exchangePlan_16.png` | пуш в удалённый репозиторий |
| `pull` | `businessProcess_16.png` | забрать изменения |
| `fetch` | `ws_16.png` | получить изменения |
| `branches` | `group_16.png` | ветки |
| `stash` | `settingsStorage_16.png` | отложенные изменения |
| `tags` | `filterCriteria_16.png` | теги |
| `status` | `extDimensionAccountingFlag_16.png` | рабочая копия |
| `log` | `scheduledJob_16.png` | история коммитов |
| `settings` | `sessionParameter_16.png` | настройки |
| `gitbar` | `subsystem_16.png` | фирменный глиф пункта «GitBar» |

`tools/select_icons.py` копирует выбранные файлы в `../<role>.png`;
`python tools/gen_icons.py` собирает из них `../icons.h` и `../icons_png.h`.
