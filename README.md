# v8inject

Инжектор и точка расширения для процессов 1С:Предприятие.

## Что делает

- находит процесс `1cv8.exe` / `1cv8c.exe` / `1cv8s.exe` по имени
- внедряет payload-DLL в целевой процесс (`LoadLibrary` + `CreateRemoteThread`)
- внутри процесса читает PE-модули через PEB и разбирает COM type library
  (`ITypeInfo`): `memid`, `oVft`, `cParams`, типы параметров, имена методов
- отдаёт отчёт наружу в JSON через разделяемую память

## Сборка

Требуется Windows и Visual Studio 2022 (или Build Tools) с C++ workload.

```bat
cmake -S . -B build\x86 -G "Visual Studio 17 2022" -A Win32
cmake --build build\x86 --config Release

cmake -S . -B build\x64 -G "Visual Studio 17 2022" -A x64
cmake --build build\x64 --config Release
```

Результат:

```
build\x86\bin\x86\v8inject.exe
build\x86\bin\x86\v8i_payload.dll
build\x64\bin\x64\v8inject.exe
build\x64\bin\x64\v8i_payload.dll
```

Payload и хост должны совпадать по разрядности с целевым процессом.

## Использование

```bat
v8inject --help
v8inject modules 1cv8.exe
v8inject inject 1cv8.exe --dll bin\x64\v8i_payload.dll

# диалог с загруженным payload — команды идут вторым аргументом после exe:
v8inject probe   1cv8.exe                  # версия payload, проверка связи
v8inject objects 1cv8.exe                  # окна/объекты, найденные по vtable
v8inject pe      1cv8.exe [module]         # PE-заголовок модуля
v8inject peek    1cv8.exe <addr> [len]     # дамп памяти по адресу
v8inject find    1cv8.exe <pattern> [--wide] [--max N]
v8inject scan    1cv8.exe <iunknown> [--module 1cv8.exe]   # разбор COM-интерфейса

# реверс-инжиниринг (доступны и в GUI через строку команды):
v8inject disasm 1cv8.exe [<addr>] [--module m]        # дизассемблер Capstone
v8inject around 1cv8.exe <addr> [--count N]           # инструкции вокруг адреса
v8inject xref   1cv8.exe <addr|imp-name> [--from A --to B] [--count N]
v8inject imports 1cv8.exe <module> [filter]           # импорты модуля
v8inject memmap 1cv8.exe [--count N]                  # карта приватной памяти
v8inject heapobjects 1cv8.exe [--module m] [--count N]   # живые объекты кучи
v8inject findvalue 1cv8.exe <hex> [--count N] [--module m] # все 4-байтные вхождения
v8inject byhwnd 1cv8.exe <hwnd> [--offset 0x200]       # объект, владеющий окном

# слой расширения: inline-хуки и трассировка вызовов
v8inject attach 1cv8.exe                               # интерактивная сессия
#   в сессии одной строкой на команду: hook <addr|module!Export|module+0xRVA>
#   [--name text], hooks, unhook <id|all>, trace [--count N] [--since N] [--clear],
#   sleep <ms> (выполняется хостом между командами), exit
v8inject hook   1cv8.exe <addr|module!Export|module+0xRVA> [--name text]
v8inject hooks   1cv8.exe
v8inject unhook  1cv8.exe <id|all>
v8inject trace   1cv8.exe [--count N] [--since N] [--clear]
v8inject log [--clear]                                # лог хоста
```

`v8inject-gui.exe` — оконная версия: список процессов с фильтром,
выбор payload-DLL по разрядности цели, строка команды и живой лог.

## Хуки

`hook` ставит inline-детур на начало функции: первые байты пролога заменяются
переходом на заглушку, заглушка передаёт регистры общему thunk'у, тот пишет
запись в кольцевой буфер и уходит в трамплин — копию перезаписанных инструкций
плюс переход назад в функцию. Функция продолжает работать, а вызовы видны
снаружи.

Что поддерживается:

- x86 и x64; патч — 5-байтный `jmp rel32` на обеих архитектурах, поэтому блок
  хука всегда выделяется в пределах ±2 ГБ от цели, а пролог перезаписывается
  минимально (целыми инструкциями, длины берутся из Capstone);
- RIP/EIP-относительные операнды переносятся: дисплейсмент правится на разницу
  адресов;
- относительные переходы и вызовы в прологе переносятся: `rel32` правится на
  месте, `rel8` (`jmp`/`jcc`) переписывается в 32-битную форму, цель внутри
  перезаписываемого окна переназначается на копию инструкции в трамплине;
- `loop`/`jecxz`/`jrcxz` отклоняются: у них нет формы с 32-битным смещением;
- пролог, который заканчивается `ret` или переходом *за пределы* пролога
  раньше, чем набралось 5 байт, отклоняется — байты за ним могут принадлежать
  другой функции;
- запись вызова: id хука, tid, тик, адрес возврата и первые четыре аргумента
  (`rcx/rdx/r8/r9` на x64, первые четыре стека на x86). SSE-аргументы не
  перехватываются;
- снятие хука восстанавливает оригинальные байты; блок с трамплином не
  освобождается — поток, уже находящийся в трамплине, иначе прыгнул бы в
  освобождённую память.

Хуки живут столько же, сколько сессия: одиночная команда (`v8inject hook ...`)
снимает их при закрытии сессии, поэтому для наблюдения за живым процессом
используется `attach`. Падение внутри хукнутой функции попадает в
`v8inject.log` (векторный обработчик пишет регистры и адрес исключения).

Вывод payload — JSON (UTF-8). Команды принимают адреса в виде `0x...`,
числа — шестнадцатеричные или десятичные.

## Структура

```
include/v8inject/   публичные заголовки
src/common/         PE-разбор, ITypeInfo, JSON-отчёт
src/payload/        DLL, которая грузится В целевой процесс
src/host/           внедрение (снаружи)
src/cli/            консольный интерфейс
src/gui/            оконная версия v8inject-gui
```

## CI

GitHub Actions собирает обе разрядности на `windows-latest`,
прогоняет smoke-тест и складывает артефакты.

## Статус

В разработке. API нестабилен.

## Совместимость

1С:Предприятие 8.3.x (проверялось на 8.3.24).

## Отказ от ответственности

Проект не связан с фирмой «1С». Внедрение кода в чужой процесс может
нарушать лицензионное соглашение приложения и привести к потере данных.
Использование — на свой риск, автор ответственности не несёт.

## Лицензия

MIT — см. [LICENSE](LICENSE).
