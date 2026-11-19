# Сторонние компоненты

v8inject распространяется под MIT — полный текст в `LICENSE`. В собранные
бинарники входят или линкуются чужие компоненты, и их лицензии требуют, чтобы
текст ехал вместе с бинарной поставкой. Поэтому релизный zip содержит каталог
`LICENSES/` с этими текстами (A88), а не только исходники репозитория.

## Capstone — дизассемблер

- Что: `third_party/capstone` — вендоренная сборка Capstone (только x86/x64),
  линкуется в payload и в тесты. В zip её текст лежит отдельно от бинарников.
- Лицензия: 3-clause BSD, Copyright (c) 2013, COSEINC.
- Текст: `LICENSES/capstone/LICENSE.TXT`
  (в репозитории — `third_party/capstone/LICENSE.TXT`).
- X86-дизассемблер Capstone основан на коде LLVM: University of
  Illinois/NCSA Open Source License, `LICENSES/capstone/LICENSE_LLVM.TXT`
  (`third_party/capstone/LICENSE_LLVM.TXT`).

## Иконки GitBar

- Что: 15 иконок 16×16 из **qtv8reader** (`fishca/qtv8reader`), набор
  metadata-icons (`zerobig/vscode-1c-metadata-viewer`), перекрашенные
  qtv8reader в палитру 1С. В zip попадают как часть `v8i_payload.dll`.
- Лицензия: MIT, Copyright (c) 2023 zerobig and contributors.
- Текст: `LICENSES/icons/LICENSE-METADATA-ICONS.txt`.
- Атрибуция и таблица «роль → исходный файл»: `LICENSES/icons/ATTRIBUTION.md`
  (в репозитории — `src/payload/icons/qtv8reader/`).
