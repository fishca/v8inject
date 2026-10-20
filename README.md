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
```

## Структура

```
include/v8inject/   публичные заголовки
src/common/         PE-разбор, ITypeInfo, JSON-отчёт
src/payload/        DLL, которая грузится В целевой процесс
src/host/           внедрение (снаружи)
src/cli/            консольный интерфейс
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
