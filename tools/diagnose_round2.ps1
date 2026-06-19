#requires -Version 5.1
<#
.SYNOPSIS
    AI-IDS firewall block bypass diagnostic, round 2. INTERACTIVE.

.DESCRIPTION
    6 sequential tests to find what is letting Kali (192.168.1.16)
    reach Windows (192.168.1.8) on TCP/80 despite a correctly-formed
    netsh block rule. Each test mutates firewall state; each test
    restores its own state inside a try/finally so Ctrl-C is safe.

    Between tests, Read-Host pauses for you to run `curl` from Kali
    and report the observed result. Those reports are collected and
    rendered in a summary table at the end.

    READ-ONLY for application code -- does not touch firewall.py,
    app.py, or any Python file. Only firewall configuration changes
    are made, and they are all reverted in finally blocks.

.USAGE
    Open an elevated PowerShell window in the project root and run:
        .\tools\diagnose_round2.ps1

    Do NOT pipe to a file with ">" -- Read-Host prompts go to the
    console and you'd lose them. Copy/paste terminal output afterward.

    Cleanup is automatic. To also disable firewall logging when done:
        netsh advfirewall set allprofiles logging droppedconnections disable
#>

$ErrorActionPreference = 'Continue'

# ── Constants ──────────────────────────────────────────────────────
$KaliIP  = '192.168.1.16'
$HostIP  = '192.168.1.8'
$FwLog   = "$env:SystemRoot\System32\LogFiles\Firewall\pfirewall.log"
$ApiBase = 'http://127.0.0.1:8000'

# Per-test result store, keyed by test ID, rendered at the end.
$Results = [ordered]@{}

# ── Helpers ────────────────────────────────────────────────────────
function Pause-ForUser([string]$prompt, [string]$resultKey) {
    $ans = Read-Host $prompt
    if ($resultKey) { $Results[$resultKey] = $ans }
    return $ans
}

function Tail-FirewallLog {
    if (Test-Path $FwLog) {
        "--- pfirewall.log last 20 lines ---"
        Get-Content $FwLog -Tail 20 -ErrorAction SilentlyContinue
        "--- end log tail ---"
    } else {
        "(pfirewall.log not found at $FwLog -- ensure dropped-connection logging is enabled)"
    }
}

# ── Pre-flight: ensure firewall logging is on ─────────────────────
Write-Host "Pre-flight: enabling firewall dropped-connection logging..." -ForegroundColor Cyan
netsh advfirewall set allprofiles logging filename $FwLog | Out-Null
netsh advfirewall set allprofiles logging maxfilesize 4096 | Out-Null
netsh advfirewall set allprofiles logging droppedconnections enable | Out-Null
Write-Host "OK." -ForegroundColor Cyan
Write-Host ""

Write-Host "AI-IDS round-2 firewall block bypass diagnostic" -ForegroundColor Cyan
Write-Host "Started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
Write-Host "Kali (src):    $KaliIP" -ForegroundColor Cyan
Write-Host "Windows (dst): $HostIP" -ForegroundColor Cyan

# ════════════════════════════════════════════════════════════════════
function Test-1 {
    Write-Host "`n=== TEST 1: Disable Python allow rule, retest block ===" -ForegroundColor Yellow

    $disabledRules = @()
    $testRuleAdded = $false
    try {
        Write-Host "  (a) Enabled inbound ALLOW rules whose Program contains 'python':" -ForegroundColor Cyan
        $allRules = Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True
        $pythonRules = foreach ($r in $allRules) {
            $af = $r | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue
            if ($af -and $af.Program -match 'python') {
                [PSCustomObject]@{
                    Name        = $r.Name
                    DisplayName = $r.DisplayName
                    Profile     = ($r.Profile -join ',')
                    Program     = $af.Program
                    Group       = $r.Group
                }
            }
        }
        if ($pythonRules) {
            $pythonRules | Format-Table -AutoSize -Wrap
        } else {
            Write-Host "      (no python-matching allow rules found)" -ForegroundColor DarkGray
        }

        Write-Host "  (b) Disabling each matched rule (will re-enable in cleanup)..." -ForegroundColor Cyan
        foreach ($pr in $pythonRules) {
            Disable-NetFirewallRule -Name $pr.Name -ErrorAction Stop
            $disabledRules += $pr.Name
            Write-Host "      disabled: $($pr.DisplayName)  (Name=$($pr.Name))" -ForegroundColor DarkGray
        }

        Write-Host "  (c) Adding temporary block rule DIAG_R2_TEST1 (TCP/80 from anywhere)..." -ForegroundColor Cyan
        netsh advfirewall firewall add rule name="DIAG_R2_TEST1" dir=in action=block protocol=TCP localport=80 | Out-Null
        $testRuleAdded = $true

        Write-Host ""
        Write-Host "  >>> NOW from Kali run:" -ForegroundColor Magenta
        Write-Host "      curl -v --connect-timeout 5 -I http://$HostIP/" -ForegroundColor Magenta
        Pause-ForUser "  Result? (connected / timeout / refused) [Enter]" 'TEST1'

        Tail-FirewallLog
    } finally {
        Write-Host "  (cleanup) Deleting test rule and re-enabling Python allow rules..." -ForegroundColor Cyan
        if ($testRuleAdded) {
            netsh advfirewall firewall delete rule name="DIAG_R2_TEST1" | Out-Null
        }
        foreach ($name in $disabledRules) {
            Enable-NetFirewallRule -Name $name -ErrorAction SilentlyContinue
        }
        Write-Host "  TEST 1 cleanup done." -ForegroundColor Green
    }
}

# ════════════════════════════════════════════════════════════════════
function Test-2 {
    Write-Host "`n=== TEST 2: WFP layer inspection ===" -ForegroundColor Yellow

    $captureStarted = $false
    try {
        $stateFile   = Join-Path (Get-Location) 'wfp_state.xml'
        $eventsFile  = Join-Path (Get-Location) 'wfp_events.xml'
        $captureFile = Join-Path (Get-Location) 'wfp_capture.etl'

        Write-Host "  (a) Dumping full WFP state to wfp_state.xml (file is 5-20MB)..." -ForegroundColor Cyan
        netsh wfp show state file=$stateFile | Out-Null
        if (Test-Path $stateFile) {
            "      wrote $stateFile  ($([math]::Round((Get-Item $stateFile).Length/1MB,2)) MB)"
        }

        Write-Host "  (b) Dumping recent WFP netevents to wfp_events.xml..." -ForegroundColor Cyan
        netsh wfp show netevents file=$eventsFile | Out-Null
        if (Test-Path $eventsFile) {
            "      wrote $eventsFile  ($([math]::Round((Get-Item $eventsFile).Length/1KB,2)) KB)"
            "      (may be empty if WFP netevent capture wasn't already on -- next step starts it)"
        }

        Write-Host "  (c) Starting WFP capture to wfp_capture.etl..." -ForegroundColor Cyan
        netsh wfp capture start file=$captureFile | Out-Null
        $captureStarted = $true

        Write-Host ""
        Write-Host "  >>> NOW from Kali run:" -ForegroundColor Magenta
        Write-Host "      curl -v --connect-timeout 5 -I http://$HostIP/" -ForegroundColor Magenta
        Pause-ForUser "  Press Enter when curl is done." 'TEST2_runs'

        Write-Host "  (d) Stopping WFP capture..." -ForegroundColor Cyan
        netsh wfp capture stop | Out-Null
        $captureStarted = $false

        $Results['TEST2'] = "files: wfp_state.xml, wfp_events.xml, wfp_capture.etl"
        Write-Host "  ETL written. To convert ETL to readable events later, run:" -ForegroundColor Cyan
        Write-Host "      netsh wfp show netevents file=netevents.xml" -ForegroundColor DarkGray
        Write-Host "  Then open netevents.xml and look for entries near the curl timestamp." -ForegroundColor DarkGray
        Write-Host "  Pay attention to: layerName, filterName, and especially callout drivers." -ForegroundColor DarkGray
    } finally {
        if ($captureStarted) {
            Write-Host "  (cleanup) Stopping WFP capture (was left running)..." -ForegroundColor Cyan
            netsh wfp capture stop | Out-Null
        }
        Write-Host "  TEST 2 cleanup done." -ForegroundColor Green
    }
}

# ════════════════════════════════════════════════════════════════════
function Test-3 {
    Write-Host "`n=== TEST 3: Npcap NDIS LWF binding inspection ===" -ForegroundColor Yellow

    try {
        Write-Host "  (a) Npcap / NPF related services..." -ForegroundColor Cyan
        Get-Service -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match 'npcap|npf' } |
            Format-Table Name, Status, StartType -AutoSize

        # Resolve actual Wi-Fi adapter (literal name "Wi-Fi" is common but
        # not guaranteed; fall back to description match).
        $wifi = Get-NetAdapter -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -eq 'Wi-Fi' -or $_.InterfaceDescription -match 'Wi-Fi|Wireless|WLAN' } |
            Select-Object -First 1

        if (-not $wifi) {
            Write-Host "  Could not resolve a Wi-Fi adapter. Skipping binding checks." -ForegroundColor Red
            $Results['TEST3'] = 'no Wi-Fi adapter found'
            return
        }
        Write-Host "  (b) Resolved Wi-Fi adapter: Name='$($wifi.Name)'  Desc='$($wifi.InterfaceDescription)'" -ForegroundColor Cyan

        Write-Host "  (c) Enabled bindings on Wi-Fi (full list)..." -ForegroundColor Cyan
        Get-NetAdapterBinding -Name $wifi.Name |
            Where-Object { $_.Enabled -eq $true } |
            Format-Table Name, DisplayName, ComponentID -AutoSize

        Write-Host "  (d) Npcap NDIS LWF binding (ComponentID = *npcap*)..." -ForegroundColor Cyan
        $npcapBinding = Get-NetAdapterBinding -Name $wifi.Name -ComponentID "*npcap*" -ErrorAction SilentlyContinue
        if ($npcapBinding) {
            $npcapBinding | Format-Table Name, DisplayName, Enabled, ComponentID -AutoSize
            $Results['TEST3'] = "npcap bound: enabled=$($npcapBinding.Enabled)"
        } else {
            Write-Host "      (no binding matched ComponentID *npcap*)" -ForegroundColor DarkGray
            $Results['TEST3'] = 'no *npcap* ComponentID binding'
        }

        Write-Host "  (e) Wi-Fi adapter advanced properties (look for stack-ordering hints)..." -ForegroundColor Cyan
        Get-NetAdapterAdvancedProperty -Name $wifi.Name -ErrorAction SilentlyContinue |
            Format-Table DisplayName, DisplayValue -AutoSize
    } finally {
        Write-Host "  TEST 3 made no state changes -- nothing to undo." -ForegroundColor Green
    }
}

# ════════════════════════════════════════════════════════════════════
function Test-4 {
    Write-Host "`n=== TEST 4: Stop live capture, retest block ===" -ForegroundColor Yellow

    $testRuleAdded = $false
    try {
        Pause-ForUser "  >>> Stop live capture in the AI-IDS dashboard (sidebar). Press Enter when stopped." 'TEST4_stopped'

        Write-Host "  (a) Verifying /capture/status reports running=false..." -ForegroundColor Cyan
        try {
            $st = Invoke-RestMethod -Uri "$ApiBase/capture/status" -TimeoutSec 5
            "      running = $($st.running);  iface = $($st.iface)"
            if ($st.running) {
                Write-Host "      WARNING: capture is still running. Test will not be conclusive." -ForegroundColor Red
            }
        } catch {
            Write-Host "      Could not reach $ApiBase/capture/status: $($_.Exception.Message)" -ForegroundColor Red
        }

        Write-Host "  (b) Adding test block rule DIAG_R2_TEST4 (TCP/80 remoteip=$KaliIP)..." -ForegroundColor Cyan
        netsh advfirewall firewall add rule name="DIAG_R2_TEST4" dir=in action=block protocol=TCP localport=80 remoteip=$KaliIP | Out-Null
        $testRuleAdded = $true

        Write-Host ""
        Write-Host "  >>> NOW from Kali run:" -ForegroundColor Magenta
        Write-Host "      curl -v --connect-timeout 5 -I http://$HostIP/" -ForegroundColor Magenta
        Pause-ForUser "  Result? (connected / timeout / refused) [Enter]" 'TEST4'

        Tail-FirewallLog
    } finally {
        if ($testRuleAdded) {
            netsh advfirewall firewall delete rule name="DIAG_R2_TEST4" | Out-Null
        }
        Write-Host "  TEST 4 cleanup done." -ForegroundColor Green
    }
}

# ════════════════════════════════════════════════════════════════════
function Test-5 {
    Write-Host "`n=== TEST 5: Public profile DefaultInboundAction = Block ===" -ForegroundColor Yellow
    Write-Host "  WARNING: this denies ALL inbound traffic on Public profile" -ForegroundColor Red
    Write-Host "  for the duration of the test. Restored in finally." -ForegroundColor Red

    $originalAction = $null
    $modified = $false
    try {
        Write-Host "  (a) Reading current Public profile DefaultInboundAction..." -ForegroundColor Cyan
        $prof = Get-NetFirewallProfile -Profile Public
        $originalAction = $prof.DefaultInboundAction
        Write-Host "      original = $originalAction" -ForegroundColor DarkGray

        Write-Host "  (b) Setting DefaultInboundAction = Block..." -ForegroundColor Cyan
        Set-NetFirewallProfile -Profile Public -DefaultInboundAction Block -ErrorAction Stop
        $modified = $true

        Write-Host ""
        Write-Host "  >>> NOW from Kali run:" -ForegroundColor Magenta
        Write-Host "      curl -v --connect-timeout 5 -I http://$HostIP/" -ForegroundColor Magenta
        Pause-ForUser "  Result? (connected / timeout / refused) [Enter]" 'TEST5'

        Tail-FirewallLog
    } finally {
        if ($modified -and $originalAction) {
            Write-Host "  (cleanup) Restoring Public profile DefaultInboundAction = $originalAction..." -ForegroundColor Cyan
            Set-NetFirewallProfile -Profile Public -DefaultInboundAction $originalAction -ErrorAction SilentlyContinue
        }
        Write-Host "  TEST 5 cleanup done." -ForegroundColor Green
    }
}

# ════════════════════════════════════════════════════════════════════
function Test-6 {
    Write-Host "`n=== TEST 6: Fresh TCP connection (kill keepalives) ===" -ForegroundColor Yellow

    $testRuleAdded = $false
    try {
        Write-Host "  (a) Python listener and its TCP connections..." -ForegroundColor Cyan
        $listener = Get-NetTCPConnection -LocalPort 80 -State Listen -ErrorAction SilentlyContinue |
                    Select-Object -First 1
        if ($listener) {
            $pyPid = $listener.OwningProcess
            Write-Host "      listener PID = $pyPid" -ForegroundColor DarkGray
            Get-NetTCPConnection -OwningProcess $pyPid -ErrorAction SilentlyContinue |
                Format-Table LocalAddress, LocalPort, RemoteAddress, RemotePort, State -AutoSize
        } else {
            Write-Host "      no listener on port 80" -ForegroundColor Red
        }

        Write-Host ""
        Write-Host "  (b) If you see ESTABLISHED rows with RemoteAddress $KaliIP above," -ForegroundColor Magenta
        Write-Host "      curl may be reusing them. Cleanup options:" -ForegroundColor Magenta
        Write-Host "        - Easiest: in the http.server terminal, Ctrl-C and restart it" -ForegroundColor Magenta
        Write-Host "          (python -m http.server 80)." -ForegroundColor Magenta
        Write-Host "        - Alternative (newer Windows only): Stop-NetTCPConnection" -ForegroundColor DarkGray
        Write-Host "          per-row, with -LocalAddress / -LocalPort / -RemoteAddress /" -ForegroundColor DarkGray
        Write-Host "          -RemotePort / -Confirm:`$false. Not universally available." -ForegroundColor DarkGray

        Pause-ForUser "  Restart Python http.server now if needed, then press Enter." 'TEST6_restart'

        Write-Host "  (c) Adding fresh block rule DIAG_R2_TEST6 (TCP/80 remoteip=$KaliIP)..." -ForegroundColor Cyan
        netsh advfirewall firewall add rule name="DIAG_R2_TEST6" dir=in action=block protocol=TCP localport=80 remoteip=$KaliIP | Out-Null
        $testRuleAdded = $true

        Write-Host ""
        Write-Host "  >>> NOW from Kali run:" -ForegroundColor Magenta
        Write-Host "      curl -v --connect-timeout 5 -I http://$HostIP/" -ForegroundColor Magenta
        Pause-ForUser "  Result? (connected / timeout / refused) [Enter]" 'TEST6'

        Tail-FirewallLog
    } finally {
        if ($testRuleAdded) {
            netsh advfirewall firewall delete rule name="DIAG_R2_TEST6" | Out-Null
        }
        Write-Host "  TEST 6 cleanup done." -ForegroundColor Green
    }
}

# ════════════════════════════════════════════════════════════════════
# Main: run all 6 tests, then print summary regardless of how we exit
# ════════════════════════════════════════════════════════════════════
try {
    Test-1
    Test-2
    Test-3
    Test-4
    Test-5
    Test-6
} finally {
    Write-Host ""
    Write-Host "==========================================" -ForegroundColor Cyan
    Write-Host "             FINAL SUMMARY"                  -ForegroundColor Cyan
    Write-Host "==========================================" -ForegroundColor Cyan
    if ($Results.Count -eq 0) {
        Write-Host "  (no results collected)" -ForegroundColor DarkGray
    } else {
        foreach ($k in $Results.Keys) {
            "{0,-20}  {1}" -f $k, $Results[$k]
        }
    }
    Write-Host ""
    Write-Host "All per-test 'finally' blocks have run -- state is restored." -ForegroundColor Cyan
    Write-Host "To disable firewall logging when done:" -ForegroundColor DarkGray
    Write-Host "  netsh advfirewall set allprofiles logging droppedconnections disable" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "Finished: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
}

<#
INTERPRETATION KEY (read after running):

TEST 1 (Python allow disabled, block-all on TCP/80)
  - connected -> allow rule was NOT the culprit. Something below the
                 netsh layer is letting traffic through.
  - timeout   -> the python allow rule (or one of its variants) was
                 winning over our block. Real fix: scope the allow or
                 remove it.

TEST 2 (WFP files)
  - wfp_state.xml -- a snapshot of every active WFP filter on this
    machine. Search it for filterName containing "ai-ids" or the
    block rule's GUID. Absence = our rule didn't reach WFP.
  - wfp_capture.etl converted to netevents.xml -- shows ALLOW/BLOCK
    decisions per packet. Search for src=192.168.1.16 around the
    curl timestamp. If you see BLOCK from our filter -> rule fired
    but something downstream let traffic through (unlikely). If you
    see ALLOW from a callout driver -> that driver is bypassing WF.

TEST 3 (Npcap NDIS LWF)
  - npcap bound + enabled on Wi-Fi -> Npcap's lightweight filter is
    in the path. Combined with TEST 4 result, this either does or
    doesn't matter.

TEST 4 (capture stopped + block)
  - connected -> Npcap is NOT the bypass path. Look elsewhere.
  - timeout   -> stopping capture restored the firewall path. Npcap
                 is intercepting or steering packets while running.

TEST 5 (profile DefaultInboundAction = Block)
  - connected -> NOTHING in Windows Firewall is being honored for
                 this packet path. Almost certainly Section 7 of
                 round-1 territory: VMware/Npcap shim bypassing WF.
  - timeout   -> WF can block this packet path. Our specific rules
                 just aren't matching. Tighten the rule.

TEST 6 (fresh TCP, no keepalive)
  - connected -> the bypass is not a keepalive artifact.
  - timeout   -> curl was riding an existing connection that
                 pre-dated our rule. Real fix: rules apply on next
                 connect, not retroactively.

Hand back to the user the four "connected/timeout/refused" answers
plus any DROP lines from pfirewall.log captured during the tests.
#>
