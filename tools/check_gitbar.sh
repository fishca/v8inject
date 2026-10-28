#!/usr/bin/env bash
# check_gitbar.sh — полная автоматическая проверка работоспособности GitBar.
#
# Что делает:
#   1) закрывает все 1cv8 (только свои тестовые — предупреждаем в выводе);
#   2) запускает Конфигуратор нужной версии на тестовой базе;
#   3) внедряет payload командой gitbar;
#   4) проверяет: ответ payload (status/visible), окно панели V8iGitBar
#      (видимо, ненулевой размер), процесс 1С жив;
#   5) закрывает 1С и печатает отчёт. Код возврата: 0 — всё хорошо, 1 — провал.
#
# Использование:
#   tools/check_gitbar.sh                # 8.5.1 x64 (по умолчанию)
#   tools/check_gitbar.sh 8.3            # 8.3.27 x86
#   tools/check_gitbar.sh 8.5 --keep     # не закрывать 1С после проверки
#
set -u

VER="${1:-8.5}"
KEEP=0
for a in "$@"; do [ "$a" = "--keep" ] && KEEP=1; done

case "$VER" in
  8.3) PLATFORM='C:\Program Files (x86)\1cv8\8.3.27.1989\bin\1cv8.exe'
       BASEPATH='E:\work\1cv83.db\awa_empty'
       BIN='build/x86/bin/x86' ;;
  8.5) PLATFORM='C:\Program Files\1cv8\8.5.1.1529\bin\1cv8.exe'
       BASEPATH='E:\work\1cv83.db\awa_empty_851'
       BIN='build/x64/bin/x64' ;;
  *) echo "неизвестная версия: $VER (ожидается 8.3 или 8.5)" >&2; exit 2 ;;
esac

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT" || exit 2
V8I="$BIN/v8inject.exe"
[ -x "$V8I" ] || [ -f "$V8I" ] || { echo "нет $V8I — сначала соберите" >&2; exit 2; }

fail() { echo "FAIL: $*" >&2; RESULT=1; }
RESULT=0

echo "== GitBar check ($VER) =="
echo "   платформа: $PLATFORM"
echo "   база     : $BASEPATH"
echo "   payload  : $V8I"

# 1. чистим свои тестовые процессы
powershell -NoProfile -Command 'Get-Process -Name 1cv8 -ErrorAction SilentlyContinue | Stop-Process -Force' >/dev/null 2>&1
sleep 2

# 2. запускаем конфигуратор (через Start-Process: bash-фоновый запуск Windows-путей не переваривает)
powershell -NoProfile -Command "Start-Process -FilePath '$PLATFORM' -ArgumentList 'DESIGNER','/F','$BASEPATH','/DisableStartupDialogs','/DisableStartupMessages'" >/dev/null 2>&1
sleep 8

PID=$(powershell -NoProfile -Command '(Get-Process -Name 1cv8 -ErrorAction SilentlyContinue | Select-Object -First 1).Id' 2>/dev/null | tr -d '\r\n ')
if [ -z "$PID" ]; then
  fail "1С не запустилась"
  echo "РЕЗУЛЬТАТ: FAIL"
  exit 1
fi
echo "   1С pid   : $PID"

# 3. внедряем payload и просим показать панель
REPLY=$(timeout 40 "$V8I" gitbar 1cv8.exe --pid "$PID" 2>&1 | sed -n 's/^reply : //p' | head -1)
echo "   ответ    : ${REPLY:-<нет ответа>}"

case "$REPLY" in
  *'"status":"ok"'*) : ;;
  *) fail "payload не подтвердил запуск панели" ;;
esac
case "$REPLY" in
  *'"visible":true'*) : ;;
  *) fail "панель не отчиталась как видимая" ;;
esac

# 4. проверяем окно панели и живость процесса
sleep 2
ALIVE=$(powershell -NoProfile -Command "(Get-Process -Id $PID -ErrorAction SilentlyContinue).Id" 2>/dev/null | tr -d '\r\n ')
[ -n "$ALIVE" ] || fail "процесс 1С умер после инжекта"

WINFO=$(powershell -NoProfile -Command "
Add-Type @'
using System; using System.Text; using System.Runtime.InteropServices; using System.Collections.Generic;
public class W2 {
  [DllImport(\"user32.dll\")] static extern bool EnumWindows(EnumProc cb, IntPtr l);
  [DllImport(\"user32.dll\")] static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport(\"user32.dll\")] static extern int GetClassName(IntPtr h, StringBuilder s, int n);
  [DllImport(\"user32.dll\")] static extern bool IsWindowVisible(IntPtr h);
  [DllImport(\"user32.dll\")] static extern bool GetWindowRect(IntPtr h, out RECT r);
  public struct RECT { public int L,T,R,B; }
  delegate bool EnumProc(IntPtr h, IntPtr l);
  public static string Find(uint target) {
    string res = \"\";
    EnumWindows((h,l) => { uint p; GetWindowThreadProcessId(h, out p); if (p == target) {
      var c = new StringBuilder(256); GetClassName(h, c, 256);
      if (c.ToString() == \"V8iGitBar\") { RECT r; GetWindowRect(h, out r);
        res = String.Format(\"{0}x{1} vis={2}\", r.R-r.L, r.B-r.T, IsWindowVisible(h)); }
    } return true; }, IntPtr.Zero);
    return res;
  }
}
'@
[W2]::Find($PID)
" 2>/dev/null | tr -d '\r\n ')
if [ -z "$WINFO" ]; then
  fail "окно V8iGitBar не найдено"
else
  echo "   панель   : $WINFO"
  case "$WINFO" in
    *vis=True*) : ;;
    *) fail "окно панели невидимо" ;;
  esac
  case "$WINFO" in
    *'x0 '*|*'0x'*) fail "у панели нулевой размер" ;;
    *) : ;;
  esac
fi

# 5. убираемся
if [ "$KEEP" -eq 1 ]; then
  echo "   (1С оставлена запущенной: pid=$PID)"
else
  powershell -NoProfile -Command 'Get-Process -Name 1cv8 -ErrorAction SilentlyContinue | Stop-Process -Force' >/dev/null 2>&1
fi

if [ "$RESULT" -eq 0 ]; then
  echo "РЕЗУЛЬТАТ: OK"
else
  echo "РЕЗУЛЬТАТ: FAIL"
fi
exit "$RESULT"
