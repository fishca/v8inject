# Stress and resilience tests for the inline hook engine (plan_roadmap Ф1.4).
#
# Scenario A (stress): the target runs four worker threads hammering the hooked
# function while the host installs and removes a hook in repeated cycles. Under
# that load the engine may legitimately REFUSE an install ("a thread is
# executing the prologue; try again" -- documented audit item 1 in hook.cpp):
# the test retries and requires eventual success, which is exactly the recovery
# a host user relies on. The trace must capture calls from several threads, the
# target must keep its self-checks green, and it must exit cleanly on its own
# at the end of the hammer run.
#
# Scenario B (target dies mid-session): the host must terminate the attach
# session in bounded time after the target process is killed -- no infinite
# hang on a dead payload. The kill lands while the host is inside its own
# `sleep 3000`, i.e. after the hook has been confirmed: the attach command
# timeout is 120 s, so a kill in the middle of an in-flight command would make
# the session wait that timeout out legitimately, which would test nothing.

param(
    [Parameter(Mandatory = $true)][string]$BinDir
)

$ErrorActionPreference = 'Stop'

function Fail($msg) {
    # Annotations are single-line, so the whole transcript is flattened: the
    # cause of a CI failure has to fit in one line to be readable at all.
    $flat = ($msg -replace "`r?`n", " | ")
    if ($flat.Length -gt 1200) { $flat = "..." + $flat.Substring($flat.Length - 1200) }
    Write-Host "FAIL: $flat"
    Get-Process -Name 'v8i_hook_target' -ErrorAction SilentlyContinue | Stop-Process -Force
    Get-Process -Name 'v8inject' -ErrorAction SilentlyContinue | Stop-Process -Force
    exit 1
}

$exe    = Join-Path $BinDir 'v8inject.exe'
$target = Join-Path $BinDir 'v8i_hook_target.exe'
foreach ($p in @($exe, $target)) {
    if (-not (Test-Path $p)) { Fail "missing $p" }
}

# Make sure no leftover target from an earlier run is picked up by name.
Get-Process -Name 'v8i_hook_target' -ErrorAction SilentlyContinue | Stop-Process -Force

function Wait-AddressLine($outFile, $proc) {
    for ($i = 0; $i -lt 100; $i++) {
        Start-Sleep -Milliseconds 100
        if (Test-Path $outFile) {
            $text = Get-Content $outFile -Raw
            if ($text -match 'tick=(0x[0-9A-Fa-f]+)') { return $Matches[1] }
        }
        if ($proc.HasExited) { break }
    }
    return $null
}

# Interactive attach session: one command in, one reply line out. The attach
# prints one JSON line per command, so a reply can be awaited and inspected --
# that is what makes the refusal-retry loop possible.
function Start-Session {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $exe
    $psi.Arguments = 'attach v8i_hook_target.exe'
    $psi.WorkingDirectory = $BinDir
    $psi.RedirectStandardInput = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.UseShellExecute = $false
    $p = [System.Diagnostics.Process]::Start($psi)
    [void]$p.Handle   # cache the handle now: ExitCode is empty otherwise (PS 5.1)
    $errTask = $p.StandardError.ReadToEndAsync()
    $line = Read-Reply $p 'attached' 30000
    if ($line -notmatch '^attached:') { Fail "unexpected first session line: $line" }
    return $p
}

function Read-Reply([System.Diagnostics.Process]$p, [string]$forCmd, [int]$timeoutMs = 20000) {
    $task = $p.StandardOutput.ReadLineAsync()
    if (-not $task.Wait($timeoutMs)) {
        Fail "no reply to '$forCmd' within $timeoutMs ms"
    }
    return $task.Result
}

function Send-Cmd([System.Diagnostics.Process]$p, [string]$cmd) {
    $p.StandardInput.WriteLine($cmd)
    $p.StandardInput.Flush()
    return Read-Reply $p $cmd
}

# ---------------------------------------------------------------------------
# Scenario A: multi-threaded stress across repeated install/remove cycles
# ---------------------------------------------------------------------------

$outFile = Join-Path ([System.IO.Path]::GetTempPath()) ("v8i_hook_stress_" + [guid]::NewGuid().ToString('N') + ".txt")

$script:proc = Start-Process -FilePath $target -ArgumentList '--stress', '15000' `
    -RedirectStandardOutput $outFile -PassThru -NoNewWindow
[void]$script:proc.Handle   # cache the handle now: ExitCode is empty otherwise (PS 5.1)
$tick = Wait-AddressLine $outFile $script:proc
if (-not $tick) { Fail "stress target did not report its function address" }
Write-Host "stress target pid=$($script:proc.Id) tick=$tick"

$p = Start-Session

# Five install/remove cycles while four worker threads call the hooked
# function. An install may be refused under load (a thread inside the stolen
# window) -- retrying until success is the documented recovery path.
$cycles = 5
$installed = 0
$removed = 0
$retries = 0
$allTids = New-Object 'System.Collections.Generic.HashSet[string]'

for ($c = 1; $c -le $cycles; $c++) {
    $reply = Send-Cmd $p "hook $tick"
    $tries = 0
    while ($reply -match 'a thread is executing the prologue') {
        $tries++; $retries++
        if ($tries -gt 20) { Fail "hook install kept being refused: $reply" }
        Start-Sleep -Milliseconds 50
        $reply = Send-Cmd $p "hook $tick"
    }
    if ($reply -notmatch '"id":\d+') { Fail "hook install failed: $reply" }
    $installed++

    [void](Send-Cmd $p 'sleep 400')
    $trace = Send-Cmd $p 'trace --count 12'
    foreach ($m in [regex]::Matches($trace, '"tid":(\d+)')) {
        [void]$allTids.Add($m.Groups[1].Value)
    }

    # Same story for removal: the restore is refused while a thread is inside
    # the prologue ("removed":0, refusal logged) -- retry until the bytes are
    # back, that is the documented recovery.
    $reply = Send-Cmd $p 'unhook all'
    $utries = 0
    while ($reply -match '"removed":0') {
        $utries++; $retries++
        if ($utries -gt 20) { Fail "unhook kept being refused: $reply" }
        Start-Sleep -Milliseconds 50
        $reply = Send-Cmd $p 'unhook all'
    }
    if ($reply -notmatch '"removed":1') { Fail "unhook did not remove exactly one hook: $reply" }
    $removed++

    [void](Send-Cmd $p 'sleep 200')
}

if ($installed -ne $cycles -or $removed -ne $cycles) {
    Fail "cycles incomplete: installed=$installed removed=$removed"
}

# The calls came from four worker threads: the trace must show at least two
# distinct thread ids, otherwise the engine recorded only one of them.
if ($allTids.Count -lt 2) {
    Fail ("trace captured calls from " + $allTids.Count + " thread(s), expected >= 2")
}
Write-Host ("trace tids: " + ($allTids -join ',') + "; install retries: $retries")

$p.StandardInput.WriteLine('exit')
$p.StandardInput.Flush()
$p.StandardInput.Close()
if (-not $p.WaitForExit(20000)) { Fail "attach session did not exit" }

# The target must finish the hammer run on its own, with green self-checks.
if (-not $script:proc.WaitForExit(40000)) { Fail "stress target did not exit in time" }
if ($script:proc.ExitCode -ne 0) {
    $log = if (Test-Path $outFile) { Get-Content $outFile -Raw } else { "" }
    Fail "stress target exited with code $($script:proc.ExitCode): $log"
}
$final = Get-Content $outFile -Raw
if ($final -notmatch 'stress done calls=\d+ mismatches=0') { Fail "no clean stress summary: $final" }
Write-Host "stress scenario passed"
Remove-Item $outFile -ErrorAction SilentlyContinue

# ---------------------------------------------------------------------------
# Scenario B: the target dies while a session is open
# ---------------------------------------------------------------------------

$outFile2 = Join-Path ([System.IO.Path]::GetTempPath()) ("v8i_hook_kill_" + [guid]::NewGuid().ToString('N') + ".txt")

$script:proc2 = Start-Process -FilePath $target `
    -RedirectStandardOutput $outFile2 -PassThru -NoNewWindow
[void]$script:proc2.Handle
$tick2 = Wait-AddressLine $outFile2 $script:proc2
if (-not $tick2) { Fail "target (kill scenario) did not report its function address" }

$p2 = Start-Session

# Injection plus handshake takes ~2 s (up to more on a slow CI runner); only
# after the hook has been answered is the session in a known state.
$reply = Send-Cmd $p2 "hook $tick2" 60000
if ($reply -notmatch '"id":\d+') { Fail "hook install failed (kill scenario): $reply" }
[void](Send-Cmd $p2 'sleep 3000')

Stop-Process -Id $script:proc2.Id -Force
Write-Host "target killed mid-session"
Start-Sleep -Milliseconds 200
$p2.StandardInput.WriteLine('exit')    # end the session; no command in flight
$p2.StandardInput.Flush()
$p2.StandardInput.Close()

# Bounded termination is the whole point: a hang here is the failure.
if (-not $p2.WaitForExit(45000)) {
    Fail "attach session did not terminate within 45 s after the target died"
}
Write-Host "attach session ended"

Get-Process -Name 'v8i_hook_target' -ErrorAction SilentlyContinue | Stop-Process -Force
Get-Process -Name 'v8inject' -ErrorAction SilentlyContinue | Stop-Process -Force
Write-Host "hook stress test passed"
exit 0
