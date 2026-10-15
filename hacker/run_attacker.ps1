<#
HomeGuard AI - Laptop B (attacker/lure host) launcher.

Lab-only. Reuses hacker/hacker_intent.py and hacker/lure_server.py exactly as-is;
all their safety guards (RFC1918-only target, --confirm-lab, duration cap, dummy
wordlist, bounded DoS) still apply.

Modes:
  -Mode Verify        setup + guard/dry-run checks against loopback (sends nothing)
  -Mode DirectDryRun  show the direct-attack plan for -Target (sends nothing)
  -Mode Serve         host the lure page, attack nobody (safe default)
  -Mode Arm           host the lure page and attack each private-IP visitor
  -Mode SingleLaptop  verify, then arm the lure against 127.0.0.1 (client+attacker on one PC)

Examples:
  powershell -ExecutionPolicy Bypass -File hacker\run_attacker.ps1 -Mode Verify
  powershell -ExecutionPolicy Bypass -File hacker\run_attacker.ps1 -Mode Arm -Port 8090 -Duration 20
  powershell -ExecutionPolicy Bypass -File hacker\run_attacker.ps1 -Mode DirectDryRun -Target 192.168.1.50
  powershell -ExecutionPolicy Bypass -File hacker\run_attacker.ps1 -Mode SingleLaptop -Port 8090 -Duration 60
#>
param(
    [ValidateSet("Verify", "DirectDryRun", "Serve", "Arm", "SingleLaptop")]
    [string]$Mode = "Verify",
    [string]$Target = "",
    [int]$Port = 8090,
    [int]$Duration = 20,
    [int]$Threads = 20,
    [string]$Speed = "normal",
    [switch]$SkipSetup
)

$ErrorActionPreference = "Stop"
$LocalhostMode = ($Mode -eq "SingleLaptop")
$HackerDir = $PSScriptRoot
$Root = Split-Path $HackerDir -Parent
$VenvPy = Join-Path $Root ".venv\Scripts\python.exe"
$Req = Join-Path $Root "requirements-hacker.txt"
$HackerIntent = Join-Path $HackerDir "hacker_intent.py"
$LureServer = Join-Path $HackerDir "lure_server.py"

function Write-Section($text) {
    Write-Host ""
    Write-Host "== $text ==" -ForegroundColor Cyan
}

function Get-LanIpv4 {
    try {
        $ips = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop |
            Where-Object { $_.IPAddress -notlike "127.*" -and $_.PrefixOrigin -ne "WellKnown" } |
            Select-Object -ExpandProperty IPAddress
        if ($ips) { return @($ips | Sort-Object -Unique) }
    } catch { }
    $out = @()
    foreach ($line in (ipconfig)) {
        if ($line -match "IPv4 Address[^:]*:\s*([0-9\.]+)") {
            $ip = $Matches[1].Trim()
            if ($ip -notlike "127.*") { $out += $ip }
        }
    }
    return @($out | Sort-Object -Unique)
}

function Show-Network {
    Write-Section "Laptop network"
    if ($LocalhostMode) {
        Write-Host "Single-laptop mode: open this locally (no hotspot/firewall needed):" -ForegroundColor Green
        Write-Host "  http://127.0.0.1:$Port/"
        Write-Host "Attacks run against 127.0.0.1; the agent must sniff the Npcap loopback iface." -ForegroundColor DarkGray
        return
    }
    $ips = Get-LanIpv4
    if ($ips.Count -gt 0) {
        Write-Host "This laptop's LAN IPv4 (give this to Laptop A):" -ForegroundColor Green
        foreach ($ip in $ips) { Write-Host "  http://${ip}:$Port/" }
    } else {
        Write-Host "No non-loopback IPv4 found; check your Wi-Fi/hotspot connection." -ForegroundColor Yellow
    }
    $nmap = Get-Command nmap -ErrorAction SilentlyContinue
    if ($nmap) {
        Write-Host "nmap found: $($nmap.Source) (portscan will use it)" -ForegroundColor Green
    } else {
        Write-Host "nmap not found: portscan falls back to the bounded Python TCP-connect scan." -ForegroundColor Yellow
    }
}

function Ensure-Env {
    if ($SkipSetup) { Write-Host "Skipping env setup (-SkipSetup)."; return }
    Write-Section "Environment"
    if (-not (Test-Path $VenvPy)) {
        Write-Host "Creating venv at $Root\.venv ..."
        python -m venv (Join-Path $Root ".venv")
    }
    Write-Host "Installing requirements-hacker.txt ..."
    & $VenvPy -m pip install --quiet --disable-pip-version-check -r $Req
    Write-Host "Python: $(& $VenvPy --version)"
}

function Get-VenvPython {
    if (Test-Path $VenvPy) { return $VenvPy }
    Write-Host "venv not found; using system python. Run without -SkipSetup first." -ForegroundColor Yellow
    return "python"
}

function Test-LureFirewall {
    $rule = "HomeGuard Lure $Port"
    $found = Get-NetFirewallRule -DisplayName $rule -ErrorAction SilentlyContinue
    Write-Section "Lure firewall"
    if ($found) {
        Write-Host "Inbound rule '$rule' present." -ForegroundColor Green
    } else {
        Write-Host "Inbound rule '$rule' NOT found. Laptop A cannot reach the lure until you run this" -ForegroundColor Yellow
        Write-Host "in an ADMINISTRATOR PowerShell:" -ForegroundColor Yellow
        Write-Host "  New-NetFirewallRule -DisplayName `"$rule`" -Direction Inbound -Protocol TCP -LocalPort $Port -Action Allow"
    }
}

function Invoke-Verify {
    $py = Get-VenvPython
    Write-Section "Verify attacker (loopback, sends nothing)"
    & $py $HackerIntent all --target 127.0.0.1 --confirm-lab --dry-run
    $results = @()
    $cases = @(
        @{ Name = "refuses public IP 8.8.8.8"; Args = @("portscan", "--target", "8.8.8.8", "--confirm-lab") },
        @{ Name = "refuses missing --confirm-lab"; Args = @("portscan", "--target", "127.0.0.1") },
        @{ Name = "refuses --duration over cap"; Args = @("dos", "--target", "127.0.0.1", "--confirm-lab", "--duration", "999") }
    )
    $prev = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    foreach ($c in $cases) {
        & $py $HackerIntent @($c.Args) *> $null
        $ok = ($LASTEXITCODE -ne 0)
        $results += [pscustomobject]@{ Check = $c.Name; Result = $(if ($ok) { "PASS" } else { "FAIL" }) }
    }
    $ErrorActionPreference = $prev
    Write-Section "Guard results"
    $results | Format-Table -AutoSize
    if ($results | Where-Object { $_.Result -eq "FAIL" }) {
        Write-Host "One or more guards did NOT refuse as expected." -ForegroundColor Red
    } else {
        Write-Host "All guards refused correctly." -ForegroundColor Green
    }
}

function Invoke-DirectDryRun {
    if (-not $Target) { throw "-Mode DirectDryRun requires -Target <A_IP>." }
    $py = Get-VenvPython
    Write-Section "Direct attack plan (dry-run, sends nothing)"
    & $py $HackerIntent all --target $Target --confirm-lab --dry-run
}

function Invoke-Lure([bool]$Arm) {
    $py = Get-VenvPython
    Show-Network
    if (-not $LocalhostMode) { Test-LureFirewall }
    Write-Section $(if ($Arm) { "Lure ARMED" } else { "Lure serve-only (safe)" })
    $args = @($LureServer, "--port", "$Port", "--duration", "$Duration",
              "--threads", "$Threads", "--speed", $Speed)
    if ($Arm) { $args += @("--arm", "--confirm-lab") }
    Write-Host "Starting: $py $($args -join ' ')"
    & $py @args
}

Write-Host "HomeGuard attacker launcher - mode=$Mode (lab-only)" -ForegroundColor Magenta
Ensure-Env
Show-Network

switch ($Mode) {
    "Verify"       { Invoke-Verify }
    "DirectDryRun" { Invoke-DirectDryRun }
    "Serve"        { Invoke-Lure $false }
    "Arm"          { Invoke-Lure $true }
    "SingleLaptop" { Invoke-Verify; Invoke-Lure $true }
}
