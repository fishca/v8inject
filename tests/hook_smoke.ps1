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
    # Annotations are single-line, so the whole transcript is flattened: the
    # cause of a CI failure has to fit in one line to be readable at all.
    # The end of the transcript (last replies, death note) is what matters.
    $flat = ($msg -replace "`r?`n", " | ")
    if ($flat.Length -gt 1200) { $flat = "..." + $flat.Substring($flat.Length - 1200) }
    Write-Host "FAIL: $flat"
    Get-Process -Name 'v8i_hook_target' -ErrorAction SilentlyContinue | Stop-Process -Force
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
$branchy = $null
$tailAddr = $null
$stubAddr = $null
for ($i = 0; $i -lt 100 -and -not $tick; $i++) {
    Start-Sleep -Milliseconds 100
    if (Test-Path $outFile) {
        $text = Get-Content $outFile -Raw
        if ($text -match 'tick=(0x[0-9A-Fa-f]+) branchy=(0x[0-9A-Fa-f]+) tail=(0x[0-9A-Fa-f]+) stub=(0x[0-9A-Fa-f]+)') {
            $tick = $Matches[1]
            $branchy = $Matches[2]
            $tailAddr = $Matches[3]
            $stubAddr = $Matches[4]
        }
    }
}
if (-not $tick) { Fail "target did not report its function addresses" }
Write-Host "LINE: $text"
Write-Host "target pid=$($script:proc.Id) tick=$tick branchy=$branchy tail=$tailAddr stub=$stubAddr"

# An empty address would turn "hook $addr" into a bare "hook", which the payload
# rejects as an unknown command -- name the missing one instead.
foreach ($pair in @(@('tick', $tick), @('branchy', $branchy),
                    @('tail', $tailAddr), @('stub', $stubAddr))) {
    if (-not $pair[1]) {
        Fail ("target line has no " + $pair[0] + " address: " + $text)
    }
}

# The whole scenario runs inside one attach session: hooks persist there, and
# `sleep` is handled by the host between commands. A hook installed by a
# separate one-shot invocation would be removed again when that session closes.
#
# Three hooks, one per relocation case: a plain prologue, a prologue with a
# conditional branch, and a prologue that is a single tail-call jmp.
$script = @"
hook $tick
hook $branchy
hook $tailAddr
hook $stubAddr
hooks
sleep 500
trace --count 9
unhook all
trace --clear
sleep 400
trace --count 3
exit
"@

$out = $script | & $exe attach 'v8i_hook_target.exe' 2>&1 | Out-String
Write-Host $out.Trim()

if ($out -notmatch '"id":1,') { Fail "hook 1 not installed: $out" }
if ($out -notmatch '"id":2,') { Fail "hook 2 not installed (branchy prologue): $out" }
if ($out -notmatch '"id":3,') { Fail "hook 3 not installed (tail-call prologue): $out" }
if ($out -notmatch '"id":4,') { Fail "hook 4 not installed (rel8/rel32 stub): $out" }
if ($out -notmatch '"count":4,') { Fail "hooks list does not report four hooks: $out" }

# The first trace: at least a few calls in 500 ms (20 ms per loop iteration).
$m = [regex]::Match($out, '("head":(\d+),)')
if (-not $m.Success -or [int]$m.Groups[2].Value -lt 5) {
    Fail "too few call records: $out"
}
foreach ($id in 1..4) {
    if ($out -notmatch ('"hook":' + $id)) { Fail "no records for hook $id`: $out" }
}
if ($out -notmatch '"args":\["0x1111"') { Fail "first argument not captured: $out" }
if ($out -notmatch '"0x2222"')          { Fail "second argument not captured: $out" }
if ($out -notmatch '"0x4444"')          { Fail "fourth argument not captured: $out" }
if ($out -notmatch '"removed":4')       { Fail "unhook failed: $out" }

# After the unhook the function runs natively again; the trace that starts with
# --clear must stay at zero instead of growing by one every 20 ms.
$tail = $out.Substring($out.LastIndexOf('{'))
if ($tail -notmatch '"head":0') { Fail "still recording after unhook: $out" }

if ($script:proc.HasExited) {
    $log = if (Test-Path $outFile) { Get-Content $outFile -Raw } else { "" }
    Fail "target died during the test (exit code $($script:proc.ExitCode)): $log"
}

Stop-Process -Id $script:proc.Id -Force
Remove-Item $outFile -ErrorAction SilentlyContinue
Write-Host "hook smoke test passed"
exit 0
