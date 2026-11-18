Иконки GitBar
=============

SVG-исходники в этом каталоге — из открытого набора **Phosphor Icons**
(https://phosphoricons.com), стиль Fill, пакет `@phosphor-icons/core` 2.1.1,
лицензия MIT (полный текст — `LICENSE.txt` рядом).

Иконки перекрашены в палитру Конфигуратора (вертикальный градиент
«светлый сверху → тёмный снизу») и отрендерены в 16×16 PNG скриптом
`tools/render_icons.cjs`; таблица `ROLES` в нём задаёт глиф и цвета для
каждой роли, назначение ролей — в `../SOURCE.json`.

| Файл | Phosphor Glyph | Назначение |
|---|---|---|
| `dump.svg` | `file-arrow-down-fill` | выгрузить исходники в файлы |
| `dumpext.svg` | `puzzle-piece-fill` | выгрузить расширение в файлы |
| `init.svg` | `folder-plus-fill` | создать репозиторий в папке выгрузки |
| `clone.svg` | `copy-fill` | клонировать репозиторий |
| `commit.svg` | `git-commit-fill` | коммит изменений |
| `push.svg` | `arrow-circle-up-fill` | пуш в удалённый репозиторий |
| `pull.svg` | `arrow-circle-down-fill` | забрать изменения |
| `fetch.svg` | `arrows-clockwise-fill` | получить изменения |
| `branches.svg` | `git-branch-fill` | ветки |
| `stash.svg` | `archive-fill` | отложенные изменения |
| `tags.svg` | `tag-fill` | теги |
| `status.svg` | `list-checks-fill` | рабочая копия |
| `log.svg` | `clock-counter-clockwise-fill` | история коммитов |
| `settings.svg` | `gear-fill` | настройки |
| `gitbar.svg` | `git-fork-fill` | фирменный глиф пункта «GitBar» |

Это не картинки из ресурсов 1С: никакие данные ресурсов платформы в репозитории
не используются. MIT-лицензия Phosphor требует сохранять уведомление об
авторских правах — оно лежит в `LICENSE.txt` и упомянуто в README/RELEASE.md
проекта (иконки вкомпилированы в payload, поэтому уведомление должно ехать
вместе со сборкой).
