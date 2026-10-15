<#
HomeGuard AI - single-laptop capture orchestrator (loopback).

Captures labelled pcaps for benign / portscan / bruteforce / dos (default 3 runs
each) while generating the matching loopback traffic, so the Phase B model can be
trained on REAL flows instead of the synthetic demo model.

Lab-only: reuses client/client_intent.py and hacker/hacker_intent.py exactly as-is,
so all their guards (loopback/RFC1918 target, --confirm-lab, duration cap, dummy
wordlist, bounded DoS) still apply. No hotspot / firewall rules needed (loopback).

Every attack run captures for (phase seconds + -MarginSecs) so the pcap always
covers the whole attack plus a little tail.

Usage:
  powershell -ExecutionPolicy Bypass -File lab\capture_single_laptop.ps1
  powershell -ExecutionPolicy Bypass -File lab\capture_single_laptop.ps1 -Runs 3 -AttackSecs 40 -BruteSecs 90
  powershell -ExecutionPolicy Bypass -File lab\capture_single_laptop.ps1 -SkipServe

After it finishes:
  $env:HOMEGUARD_FLOW_IDLE_SECS="8"; .\.venv\Scripts\python.exe lab\convert.py --single-laptop
  .\.venv\Scripts\python.exe src\04_train_lab.py
#>
param(
    [string]$Iface = "\Device\NPF_Loopback",
    [int]$Runs = 3,
    [int]$AttackSecs = 40,
    [int]$BruteSecs = 90,
    [int]$MarginSecs = 15,
    [int]$WarmupSecs = 4,
    [int]$DosThreads = 5,
    [switch]$SkipServe
)

$ErrorActionPreference = "Stop"
$Root = Split-Path $PSScriptRoot -Parent
Set-Location $Root

$VenvPy = Join-Path $Root ".venv\Scripts\python.exe"
$Py = if (Test-Path $VenvPy) { $VenvPy } else { "python" }
$Client = Join-Path $Root "client\client_intent.py"
$Hacker = Join-Path $Root "hacker\hacker_intent.py"
$Capture = Join-Path $Root "lab\capture.py"

function Test-Port([int]$Port) {
    try {
        $c = New-Object System.Net.Sockets.TcpClient
        $c.Connect("127.0.0.1", $Port)
        $ok = $c.Connected
        $c.Close()
        return $ok
    } catch { return $false }
}

function Ensure-Serve {
    if ($SkipServe) { Write-Host "(-SkipServe) not starting client servers."; return }
    if ((Test-Port 8080) -and (Test-Port 2121)) {
        Write-Host "Client servers already up (8080/2121)."
        return
    }
    Write-Host "Starting client servers..." -ForegroundColor Yellow
    & $Py $Client serve
}

function Invoke-Run {
    param([string]$Label, [int]$Run, [string]$Phase, [int]$PhaseSecs, [string[]]$AttackArgs)
    $capSecs = $PhaseSecs + $MarginSecs
    Write-Host ""
    Write-Host ("== {0} run {1}: capture {2}s, generate '{3}' for {4}s ==" -f $Label, $Run, $capSecs, $Phase, $PhaseSecs) -ForegroundColor Cyan

    $capArgs = '"{0}" --iface "{1}" --label {2} --run {3} --duration {4}' -f $Capture, $Iface, $Label, $Run, $capSecs
    $errLog = Join-Path $Root ("data\captured\_capture_{0}_run{1}.err" -f $Label, $Run)
    $cap = Start-Process -FilePath $Py -ArgumentList $capArgs `
        -WorkingDirectory $Root -PassThru -WindowStyle Hidden -RedirectStandardError $errLog

    Start-Sleep -Seconds $WarmupSecs
    if ($Phase -eq "benign") {
        & $Py $Client benign --duration $PhaseSecs
    } else {
        & $Py $Hacker $Phase --target 127.0.0.1 --confirm-lab --duration $PhaseSecs @AttackArgs
    }
    $cap.WaitForExit()

    $pcap = Join-Path $Root ("data\captured\{0}\run{1}.pcap" -f $Label, $Run)
    if ((Test-Path $pcap) -and (Get-Item $pcap).Length -gt 24) {
        Write-Host ("   saved {0} ({1} KB)" -f $pcap, [math]::Round((Get-Item $pcap).Length / 1KB, 1)) -ForegroundColor Green
    } else {
        Write-Host "   WARNING: pcap missing/empty; see $errLog" -ForegroundColor Red
        if (Test-Path $errLog) { Get-Content $errLog -Tail 5 }
    }
}

Write-Host "HomeGuard single-laptop capture (lab-only) iface=$Iface" -ForegroundColor Magenta
Ensure-Serve

for ($r = 1; $r -le $Runs; $r++) { Invoke-Run "benign" $r "benign" $AttackSecs @() }

$speeds = @("slow", "normal", "fast")
for ($r = 1; $r -le $Runs; $r++) {
    $speed = $speeds[($r - 1) % $speeds.Count]
    Invoke-Run "portscan" $r "portscan" $AttackSecs @("--speed", $speed)
}

for ($r = 1; $r -le $Runs; $r++) {
    Invoke-Run "bruteforce" $r "bruteforce" $BruteSecs @()
}

for ($r = 1; $r -le $Runs; $r++) {
    Invoke-Run "dos" $r "dos" $AttackSecs @("--threads", "$DosThreads")
}

Write-Host ""
Write-Host "Capture complete. Next:" -ForegroundColor Green
Write-Host '  $env:HOMEGUARD_FLOW_IDLE_SECS="8"; .\.venv\Scripts\python.exe lab\convert.py --single-laptop'
Write-Host '  .\.venv\Scripts\python.exe src\04_train_lab.py'
