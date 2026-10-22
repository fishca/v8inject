# End-to-end test for the inline hook engine.
#
# Starts the disposable target, injects the payload, hooks a function whose
# arguments are known, checks the recorded arguments, then unhooks and confirms
# the target keeps running and nothing is recorded any more.

param(
    [Parameter(Mandatory = $true)][string]$BinDir
)

$ErrorActionPreference = 'Stop'

function Fail($msg) {
    Write-Host "FAIL: $msg"
    if ($script:proc -and -not $script:proc.HasExited) { Stop-Process -Id $script:proc.Id -Force }
    exit 1
}

$exe    = Join-Path $BinDir 'v8inject.exe'
$target = Join-Path $BinDir 'v8i_hook_target.exe'
foreach ($p in @($exe, $target)) {
    if (-not (Test-Path $p)) { Fail "missing $p" }
}

$outFile = Join-Path ([System.IO.Path]::GetTempPath()) ("v8i_hook_" + [guid]::NewGuid().ToString('N') + ".txt")

# Make sure no leftover target from an earlier run is picked up by name.
Get-Process -Name 'v8i_hook_target' -ErrorAction SilentlyContinue | Stop-Process -Force

$script:proc = Start-Process -FilePath $target -RedirectStandardOutput $outFile -PassThru -NoNewWindow

$tick = $null
for ($i = 0; $i -lt 100 -and -not $tick; $i++) {
    Start-Sleep -Milliseconds 100
    if (Test-Path $outFile) {
        $text = Get-Content $outFile -Raw
        if ($text -match 'tick=(0x[0-9A-Fa-f]+)') { $tick = $Matches[1] }
    }
}
if (-not $tick) { Fail "target did not report its function address" }
Write-Host "target pid=$($script:proc.Id) tick=$tick"

# The whole scenario runs inside one attach session: hooks persist there, and
# `sleep` is handled by the host between commands. A hook installed by a
# separate one-shot invocation would be removed again when that session closes.
$script = @"
hook $tick
sleep 500
trace --count 3
unhook all
trace --clear
sleep 400
trace --count 3
exit
"@

$out = $script | & $exe attach 'v8i_hook_target.exe' 2>&1 | Out-String
Write-Host $out.Trim()

if ($out -notmatch '"id":1,') { Fail "hook not installed: $out" }

# The first trace: at least a few calls in 500 ms (20 ms per loop iteration).
$m = [regex]::Match($out, '("head":(\d+),)')
if (-not $m.Success -or [int]$m.Groups[2].Value -lt 5) {
    Fail "too few call records: $out"
}
if ($out -notmatch '"hook":1')          { Fail "no call records: $out" }
if ($out -notmatch '"args":\["0x1111"') { Fail "first argument not captured: $out" }
if ($out -notmatch '"0x2222"')          { Fail "second argument not captured: $out" }
if ($out -notmatch '"0x4444"')          { Fail "fourth argument not captured: $out" }
if ($out -notmatch '"removed":1')       { Fail "unhook failed: $out" }

# After the unhook the function runs natively again; the trace that starts with
# --clear must stay at zero instead of growing by one every 20 ms.
$tail = $out.Substring($out.LastIndexOf('{'))
if ($tail -notmatch '"head":0') { Fail "still recording after unhook: $out" }

if ($script:proc.HasExited) { Fail "target died during the test" }

Stop-Process -Id $script:proc.Id -Force
Remove-Item $outFile -ErrorAction SilentlyContinue
Write-Host "hook smoke test passed"
exit 0
