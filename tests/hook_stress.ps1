# Stress and resilience tests for the inline hook engine (plan_roadmap Ф1.4).
#
# Scenario A (stress): the target runs four worker threads hammering the hooked
# function while the host installs and removes a hook in repeated cycles. The
# trace must capture calls from several threads, the target must keep its
# self-checks green while its prologue is rewritten under running threads, and
# it must exit cleanly on its own at the end of the hammer run.
#
# Scenario B (target dies mid-session): the host must terminate the attach
# session in bounded time after the target process is killed -- no infinite
# hang on a dead payload. The kill lands while the host is inside its own
# `sleep 3000`, i.e. after the hook has been confirmed: the attach command
# timeout is 120 s, so a kill in the middle of an in-flight command would make
# the session wait that timeout out legitimately, which would test nothing.
# The session ends with an explicit `exit` (EOF delivery through a closed
# StandardInput is less reliable).

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

# ---------------------------------------------------------------------------
# Scenario A: multi-threaded stress across repeated install/remove cycles
# ---------------------------------------------------------------------------

$outFile = Join-Path ([System.IO.Path]::GetTempPath()) ("v8i_hook_stress_" + [guid]::NewGuid().ToString('N') + ".txt")

$script:proc = Start-Process -FilePath $target -ArgumentList '--stress', '12000' `
    -RedirectStandardOutput $outFile -PassThru -NoNewWindow
# Cache the process handle now: without this the ExitCode property comes back
# empty on Windows PowerShell 5.1 when the process has already exited by the
# time it is read.
[void]$script:proc.Handle
$tick = Wait-AddressLine $outFile $script:proc
if (-not $tick) { Fail "stress target did not report its function address" }
Write-Host "stress target pid=$($script:proc.Id) tick=$tick"

# Five install/remove cycles while four worker threads call the hooked
# function. Each cycle: install, let the calls pile up, read the trace, remove.
$cycles = 5
$script = ""
for ($c = 0; $c -lt $cycles; $c++) {
    $script += "hook $tick`nsleep 400`ntrace --count 12`nunhook all`nsleep 200`n"
}
$script += "exit`n"

# Force BOM-less UTF-8 into the pipe (same reason as hook_smoke.ps1).
$OutputEncoding = New-Object System.Text.UTF8Encoding $false
$out = $script | & $exe attach 'v8i_hook_target.exe' 2>&1 | Out-String
Write-Host $out.Trim()

$installed = ([regex]::Matches($out, '"id":\d+,')).Count
if ($installed -lt $cycles) { Fail "expected $cycles hook installs, got $installed : $out" }
$removed = ([regex]::Matches($out, '"removed":1')).Count
if ($removed -lt $cycles) { Fail "expected $cycles unhook cycles, got $removed : $out" }

# The calls came from four worker threads: the trace must show at least two
# distinct thread ids, otherwise the engine recorded only one of them.
$tids = [regex]::Matches($out, '"tid":(\d+)') |
    ForEach-Object { $_.Groups[1].Value } |
    Sort-Object -Unique
if ($tids.Count -lt 2) {
    Fail ("trace captured calls from " + $tids.Count + " thread(s), expected >= 2 : " + $out)
}
Write-Host ("trace tids: " + ($tids -join ','))

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

$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $exe
$psi.Arguments = 'attach v8i_hook_target.exe'
$psi.WorkingDirectory = $BinDir
$psi.RedirectStandardInput = $true
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError = $true
$psi.UseShellExecute = $false
$p = [System.Diagnostics.Process]::Start($psi)
$outTask = $p.StandardOutput.ReadToEndAsync()
$errTask = $p.StandardError.ReadToEndAsync()
$in = $p.StandardInput

# Injection plus handshake takes ~2 s (up to more on a slow CI runner); only
# after the hook has been answered is the session in a known state.
$in.WriteLine('hook ' + $tick2)
$in.Flush()
Start-Sleep -Milliseconds 5000
$in.WriteLine('sleep 3000')
$in.Flush()
Start-Sleep -Milliseconds 1500         # the host is inside its sleep now
Stop-Process -Id $script:proc2.Id -Force
Write-Host "target killed mid-session"
Start-Sleep -Milliseconds 200
$in.WriteLine('exit')                  # end the session; no command in flight
$in.Flush()
$in.Close()

# Bounded termination is the whole point: a hang here is the failure.
if (-not $p.WaitForExit(45000)) {
    Fail "attach session did not terminate within 45 s after the target died"
}
$tail = $outTask.Result
$tail = $tail.Substring([Math]::Max(0, $tail.Length - 200))
Write-Host "attach session ended: $tail"
Remove-Item $outFile2 -ErrorAction SilentlyContinue

Get-Process -Name 'v8i_hook_target' -ErrorAction SilentlyContinue | Stop-Process -Force
Write-Host "hook stress test passed"
exit 0
