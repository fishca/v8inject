# End-to-end test for the inline hook engine.
#
# Starts the disposable target, injects the payload, hooks a function whose
# arguments are known, checks the recorded arguments, then unhooks and confirms
# the target keeps running and nothing is recorded any more.
#
# Package 9 of the stabilisation plan added three targets to the list:
#   * a function with double arguments and a __thiscall member function, whose
#     arguments travel in xmm/ecx and used to be destroyed by the thunk (A59);
#   * a hand-written prologue with a rip-relative operand, so the relocation
#     formula is exercised on bytes that are not compiler-generated (A75).
# It also checks the two protective behaviours: a second hook on the same target
# is refused (A71), and the cost of removed hooks is visible (A74).

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
$ripAddr = $null
$dblAddr = $null
$thisAddr = $null
for ($i = 0; $i -lt 100 -and -not $tick; $i++) {
    Start-Sleep -Milliseconds 100
    if (Test-Path $outFile) {
        $text = Get-Content $outFile -Raw
        if ($text -match 'tick=(0x[0-9A-Fa-f]+) branchy=(0x[0-9A-Fa-f]+) tail=(0x[0-9A-Fa-f]+) stub=(0x[0-9A-Fa-f]+) rip=(0x[0-9A-Fa-f]+) dbl=(0x[0-9A-Fa-f]+) thisptr=(0x[0-9A-Fa-f]+)') {
            $tick = $Matches[1]
            $branchy = $Matches[2]
            $tailAddr = $Matches[3]
            $stubAddr = $Matches[4]
            $ripAddr = $Matches[5]
            $dblAddr = $Matches[6]
            $thisAddr = $Matches[7]
        }
    }
}
if (-not $tick) { Fail "target did not report its function addresses" }
Write-Host "LINE: $text"
Write-Host "target pid=$($script:proc.Id) tick=$tick branchy=$branchy tail=$tailAddr stub=$stubAddr rip=$ripAddr dbl=$dblAddr thisptr=$thisAddr"

# An empty address would turn "hook $addr" into a bare "hook", which the payload
# rejects as an unknown command -- name the missing one instead.
foreach ($pair in @(@('tick', $tick), @('branchy', $branchy),
                    @('tail', $tailAddr), @('stub', $stubAddr),
                    @('dbl', $dblAddr), @('thisptr', $thisAddr))) {
    if (-not $pair[1]) {
        Fail ("target line has no " + $pair[0] + " address: " + $text)
    }
}

# One hook per relocation/ABI case, in install order (the id is the reply order).
$targets = @(
    @('tick', $tick, 'plain prologue'),
    @('branchy', $branchy, 'branching prologue'),
    @('tail', $tailAddr, 'tail-call prologue'),
    @('stub', $stubAddr, 'rel8/rel32 stub'),
    @('double', $dblAddr, 'double arguments (A59)'),
    @('thiscall', $thisAddr, 'thiscall this-pointer (A59)')
)
# x86 has no rip-relative form; the target reports 0 there.
if ($ripAddr -and $ripAddr -notmatch '^0x0+$') {
    $targets += ,@('rip', $ripAddr, 'rip-relative prologue (A75)')
}
$hookCount = $targets.Count
$hookCmds = ($targets | ForEach-Object { 'hook ' + $_[1] }) -join "`n"

# The whole scenario runs inside one attach session: hooks persist there, and
# `sleep` is handled by the host between commands. A hook installed by a
# separate one-shot invocation would be removed again when that session closes.
$script = @"
$hookCmds
hook $tick
hooks
sleep 500
trace --count 200
unhook all
hooks
trace --clear
sleep 400
trace --count 3
exit
"@

# Force BOM-less UTF-8 into the pipe: with the runner's default the first
# command arrived as "\uFEFFhook ...", which the payload cannot match.
$OutputEncoding = New-Object System.Text.UTF8Encoding $false
$out = $script | & $exe attach 'v8i_hook_target.exe' 2>&1 | Out-String
Write-Host $out.Trim()

# The ids come from the payload's counter, which need not start at 1: the
# payload installs a hook of its own during start-up, so the first id of an
# attach session depends on the target. Take them from the replies in order.
$ids = @([regex]::Matches($out, '"status":"ok","id":(\d+),') |
         ForEach-Object { [int]$_.Groups[1].Value })
if ($ids.Count -ne $hookCount) {
    Fail ("expected " + $hookCount + " installed hooks, got replies for: " + ($ids -join ','))
}
for ($i = 1; $i -lt $ids.Count; $i++) {
    if ($ids[$i] -ne $ids[0] + $i) {
        Fail ("hook ids are not consecutive: " + ($ids -join ','))
    }
}

# A71: the same target twice must be refused, not stacked. The second attempt is
# the one that follows the list, so its reply is easy to spot.
if ($out -notmatch 'already hooked') { Fail "a duplicate hook was not refused: $out" }
if ($out -notmatch ('"count":' + $hookCount + ',')) {
    Fail ("hooks list does not report $hookCount hooks: " + $out)
}

# The first trace: at least a few calls in 500 ms (20 ms per loop iteration).
$m = [regex]::Match($out, '("head":(\d+),)')
if (-not $m.Success -or [int]$m.Groups[2].Value -lt 5) {
    Fail "too few call records: $out"
}
for ($i = 0; $i -lt $ids.Count; $i++) {
    if ($out -notmatch ('"hook":' + $ids[$i])) { Fail "no records for hook $($ids[$i])`: $out" }
}
if ($out -notmatch '"args":\["0x1111"') { Fail "first argument not captured: $out" }
if ($out -notmatch '"0x2222"')          { Fail "second argument not captured: $out" }
if ($out -notmatch '"0x4444"')          { Fail "fourth argument not captured: $out" }
# A60: the caller chain must not be empty. On x64 rbp is not a frame pointer,
# so the old walk read [rbp] of an arbitrary value and either stopped at once
# ("stack":[]) or -- when the value pointed at the last bytes of a mapping --
# faulted in the target. A non-empty chain is the observable part of the fix.
if ($out -notmatch '"stack":\["0x')     { Fail "caller chain is empty: $out" }
if ($out -notmatch ('"removed":' + $hookCount))   { Fail "unhook failed: $out" }

# A74: removed hooks keep their code block on purpose. The count has to be
# reported, and has to match what was removed -- a silent leak is what the audit
# called out.
if ($out -notmatch ('"retired":' + $hookCount + ',')) {
    Fail "removed blocks are not accounted for: $out"
}

# After the unhook the function runs natively again. A90: --clear no longer
# zeroes the ring, it moves the start marker, so the trace that follows must
# report the same head and no records at all -- that is "nothing more was
# recorded", which the old `head == 0` check could not distinguish from a reset.
$heads = @([regex]::Matches($out, '"head":(\d+)') | ForEach-Object { [int]$_.Groups[1].Value })
if ($heads.Count -lt 2) { Fail "trace replies are missing: $out" }
$clearHead = $heads[$heads.Count - 2]
$finalHead = $heads[$heads.Count - 1]
if ($finalHead -ne $clearHead) { Fail "still recording after unhook: $out" }
if ($out -notmatch '"records":\[\]\}') { Fail "records after unhook: $out" }

if ($script:proc.HasExited) {
    $log = if (Test-Path $outFile) { Get-Content $outFile -Raw } else { "" }
    Fail "target died during the test (exit code $($script:proc.ExitCode)): $log"
}

Stop-Process -Id $script:proc.Id -Force
Remove-Item $outFile -ErrorAction SilentlyContinue
Write-Host "hook smoke test passed"
exit 0
