#requires -Version 5.1
<#
.SYNOPSIS
    AI-IDS one-click developer boot script.

.DESCRIPTION
    Replaces the manual PowerShell ritual for booting a live-capture session:
      0a. Detects existing IDS process chains (launch.py / uvicorn / streamlit /
          python http.server) and prompts (R)estart / (K)eep / (C)ontinue.
      0b. Warns if XAMPP Apache is running (will fight for port 80).
      1.  Self-elevates to administrator (live capture needs raw-socket access).
      2.  Launches START.bat if uvicorn isn't already on :8000, then waits for /health.
      3.  POSTs /capture/start on the VMnet8 NPF device + verifies running=true.
      4.  Spawns python http.server on port 80 in C:\ as a *hidden background
          process* (no fragile cmd window) + verifies the response header is ours.
      5.  Opens the Streamlit dashboard in the default browser.

    Failure semantics:
      - Capture failure  -> red banner + Read-Host + exit 1 (hard stop).
      - HTTP-target fail -> red banner + Read-Host acknowledgement, script
        continues. Capture is still useful for demo without the HTTP target.
      - Green "All up" banner only prints when every check passed.

    Entry point: double-click tools\dev_up.bat (which invokes this script with
    ExecutionPolicy Bypass).
#>

# ── Self-elevate if not admin ──────────────────────────────────
$id = New-Object Security.Principal.WindowsPrincipal(
    [Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $id.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Re-launching as administrator (live capture needs raw-socket privileges)..."
    Start-Process powershell `
        -ArgumentList @("-NoProfile","-ExecutionPolicy","Bypass","-File",$PSCommandPath) `
        -Verb RunAs
    exit
}

# ── Config ─────────────────────────────────────────────────────
$ScriptRoot    = $PSScriptRoot
$ProjectRoot   = (Resolve-Path (Join-Path $ScriptRoot "..")).Path
$StartBat      = Join-Path $ProjectRoot "START.bat"
$LogDir        = Join-Path $ProjectRoot "logs"
$HttpOutLog    = Join-Path $LogDir "http_target.out.log"
$HttpErrLog    = Join-Path $LogDir "http_target.err.log"
$ApiBase       = "http://127.0.0.1:8000"
$DashboardUrl  = "http://127.0.0.1:8501"
# VMnet8 NPF device (host-only adapter Kali attacks travel over)
$VmnetIface    = "\Device\NPF_{6BBC0B16-5BEF-4007-861A-3080B00E4182}"
$ApiTimeoutSec = 60

# Admin login. Phase 2 wired RBAC onto /capture/start, so dev_up must
# log in as admin before posting. Leave these blank to be prompted at
# run time; or set them inline for fully unattended boots.
$AdminUser = ""    # e.g. "admin" to skip prompt
$AdminPass = ""    # e.g. "admin123456789" to skip prompt
$script:AuthToken = $null

if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }

# Status flags consumed by the final summary
$script:HttpProc       = $null
$script:HttpTargetOk   = $false
$script:DuplicatesKept = $false

Write-Host ""
Write-Host "  AI-IDS one-click dev boot" -ForegroundColor Cyan
Write-Host "  =========================" -ForegroundColor Cyan
Write-Host "  Project: $ProjectRoot"
Write-Host ""

function Test-ApiUp {
    try {
        $r = Invoke-WebRequest -Uri "$ApiBase/health" -UseBasicParsing -TimeoutSec 2
        return $r.StatusCode -eq 200
    } catch { return $false }
}

function Get-AuthToken {
    # Returns a bearer token for the configured admin user, or $null on failure.
    if (-not $AdminUser) {
        $AdminUser = Read-Host "  Admin username"
    }
    if (-not $AdminPass) {
        $secure = Read-Host -AsSecureString "  Admin password"
        $AdminPass = [System.Net.NetworkCredential]::new("", $secure).Password
    }
    $body = @{ username = $AdminUser; password = $AdminPass } | ConvertTo-Json -Compress
    try {
        $resp = Invoke-RestMethod -Method Post -Uri "$ApiBase/auth/login" `
            -ContentType "application/json" -Body $body -TimeoutSec 5
        return $resp.token
    } catch {
        Write-Host "        ERROR: /auth/login failed: $($_.Exception.Message)" -ForegroundColor Red
        if ($_.Exception.Response) {
            try {
                $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
                Write-Host "        Body: $($reader.ReadToEnd())" -ForegroundColor Red
            } catch {}
        }
        return $null
    }
}

function Get-IdsChain {
    # Match python processes that belong to the IDS chain (incl. a prior
    # http.server target spawned by a previous dev_up.ps1 run).
    $procs = Get-CimInstance Win32_Process -Filter "Name = 'python.exe'" -ErrorAction SilentlyContinue
    if (-not $procs) { return @() }
    $procs | Where-Object {
        $_.CommandLine -and
        ($_.CommandLine -match 'launch\.py' -or
         $_.CommandLine -match 'src\.serve\.app' -or
         $_.CommandLine -match 'streamlit\s+run' -or
         $_.CommandLine -match 'http\.server')
    }
}

function Get-IdsRole($cmdLine) {
    if ($cmdLine -match 'http\.server')   { return 'http target (port 80)' }
    if ($cmdLine -match 'streamlit\s+run'){ return 'streamlit dashboard' }
    if ($cmdLine -match 'src\.serve\.app'){ return 'uvicorn FastAPI' }
    if ($cmdLine -match 'launch\.py')     { return 'launch.py supervisor' }
    return 'unknown'
}

# ── Pre-check 0a: existing IDS chain ───────────────────────────
$existing = @(Get-IdsChain)
if ($existing.Count -gt 0) {
    Write-Host "  +----------------------------------------------------------+" -ForegroundColor Yellow
    Write-Host "  |  EXISTING IDS CHAIN DETECTED                             |" -ForegroundColor Yellow
    Write-Host "  +----------------------------------------------------------+" -ForegroundColor Yellow
    foreach ($p in $existing) {
        $role = Get-IdsRole $p.CommandLine
        Write-Host ("    PID {0,6}  {1}" -f $p.ProcessId, $role) -ForegroundColor Yellow
    }
    Write-Host ""
    Write-Host "  (R)estart cleanly  /  (K)eep existing and exit  /  (C)ontinue anyway?" -ForegroundColor Yellow
    $choice = Read-Host "  [R]"
    if ([string]::IsNullOrWhiteSpace($choice)) { $choice = 'R' }
    switch -Regex ($choice.Trim()) {
        '^[Rr]$' {
            Write-Host "  Stopping existing chain..." -ForegroundColor Yellow
            foreach ($p in $existing) {
                try {
                    Stop-Process -Id $p.ProcessId -Force -ErrorAction Stop
                    Write-Host ("    [killed] PID {0}" -f $p.ProcessId)
                } catch {
                    Write-Host ("    [skip]   PID {0} ({1})" -f $p.ProcessId, $_.Exception.Message) -ForegroundColor DarkYellow
                }
            }
            Start-Sleep -Seconds 2  # let ports release
        }
        '^[Kk]$' {
            Write-Host "  Keeping existing chain. Note: re-running dev_up.bat without" -ForegroundColor Yellow
            Write-Host "  cleaning up can cause port-binding conflicts on :8000/:8501/:80." -ForegroundColor Yellow
            Write-Host ""
            Read-Host "Press Enter to exit"
            exit 0
        }
        '^[Cc]$' {
            $script:DuplicatesKept = $true
            Write-Host "  Continuing despite duplicates (will flag in final banner)." -ForegroundColor Yellow
        }
        default {
            Write-Host "  Unrecognized choice '$choice' -> treating as Restart." -ForegroundColor Yellow
            foreach ($p in $existing) {
                try { Stop-Process -Id $p.ProcessId -Force -ErrorAction Stop } catch {}
            }
            Start-Sleep -Seconds 2
        }
    }
    Write-Host ""
}

# ── Pre-check 0b: XAMPP Apache running on port 80 ──────────────
$xamppPresent = Test-Path 'C:\xampp\apache\bin\httpd.exe'
$apacheRunning = [bool](Get-Process httpd -ErrorAction SilentlyContinue)
if ($xamppPresent -and $apacheRunning) {
    Write-Host "  +----------------------------------------------------------+" -ForegroundColor Yellow
    Write-Host "  |  XAMPP APACHE IS RUNNING                                 |" -ForegroundColor Yellow
    Write-Host "  |  It will fight with python http.server for port 80.      |" -ForegroundColor Yellow
    Write-Host "  |  Stop Apache from the XAMPP control panel if step 4 WARNs.|" -ForegroundColor Yellow
    Write-Host "  +----------------------------------------------------------+" -ForegroundColor Yellow
    Write-Host ""
}

# ── Step 1: API + Streamlit ────────────────────────────────────
if (Test-ApiUp) {
    Write-Host "  [1/4] API already responding on :8000" -ForegroundColor Yellow -NoNewline
    Write-Host "  [skip]"
} else {
    Write-Host "  [1/4] Launching START.bat (uvicorn + Streamlit)..." -ForegroundColor Green
    if (-not (Test-Path $StartBat)) {
        Write-Host "        ERROR: $StartBat not found." -ForegroundColor Red
        Read-Host "Press Enter to exit"; exit 1
    }
    # DEV/LAB ONLY: allows blocking the Kali attacker on the private subnet 192.168.142.0/24. Remove in production.
    $env:MITIGATION_ALLOW_PRIVATE = "true"
    Start-Process -FilePath $StartBat -WorkingDirectory $ProjectRoot
    Write-Host "        Waiting for /health (up to ${ApiTimeoutSec}s)..."
    $deadline = (Get-Date).AddSeconds($ApiTimeoutSec)
    while (-not (Test-ApiUp)) {
        if ((Get-Date) -gt $deadline) {
            Write-Host "        ERROR: API did not respond within ${ApiTimeoutSec}s." -ForegroundColor Red
            Write-Host "        Check the START.bat window for errors, then re-run dev_up.bat."
            Read-Host "Press Enter to exit"; exit 1
        }
        Start-Sleep -Seconds 1
    }
    Write-Host "        API is up."
}

# ── Step 1b: Admin login (Phase 2: /capture/start is RBAC-gated) ───
Write-Host "  [1b]  Logging in as admin..." -ForegroundColor Green
$script:AuthToken = Get-AuthToken
if (-not $script:AuthToken) {
    Write-Host "        ERROR: could not obtain a bearer token. /capture/start will fail with 401." -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}
Write-Host "        Got bearer token (truncated): $($script:AuthToken.Substring(0,8))..."

# ── Step 2: Live capture on VMnet8 ─────────────────────────────
$capStatus = $null
try { $capStatus = Invoke-RestMethod -Uri "$ApiBase/capture/status" -TimeoutSec 5 } catch {}

if ($capStatus -and $capStatus.running) {
    Write-Host "  [2/4] Capture already running on $($capStatus.iface)" -ForegroundColor Yellow -NoNewline
    Write-Host "  [skip]"
} else {
    Write-Host "  [2/4] Starting live capture on VMnet8..." -ForegroundColor Green
    $body = @{ iface = $VmnetIface } | ConvertTo-Json -Compress
    $authHeaders = @{ Authorization = "Bearer $($script:AuthToken)" }
    try {
        $resp = Invoke-RestMethod -Method Post -Uri "$ApiBase/capture/start" `
            -ContentType "application/json" -Body $body `
            -Headers $authHeaders -TimeoutSec 10
        Write-Host "        POST /capture/start returned: iface=$($resp.iface)"
    } catch {
        Write-Host "        ERROR: /capture/start failed." -ForegroundColor Red
        Write-Host "        $_"
        if ($_.Exception.Response) {
            try {
                $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
                Write-Host "        Body: $($reader.ReadToEnd())"
            } catch {}
        }
    }
}

# ── Verify capture actually started ────────────────────────────
Start-Sleep -Seconds 2
$verify = $null
try { $verify = Invoke-RestMethod -Uri "$ApiBase/capture/status" -TimeoutSec 5 } catch {}
Write-Host ""
if ($verify -and $verify.running) {
    Write-Host "  ============================================================" -ForegroundColor Green
    Write-Host "    [OK] CAPTURE RUNNING on $($verify.iface)"               -ForegroundColor Green
    Write-Host "  ============================================================" -ForegroundColor Green
} else {
    Write-Host "  ============================================================" -ForegroundColor Red
    Write-Host "    [FAIL] CAPTURE START FAILED"                             -ForegroundColor Red
    if ($verify -and $verify.error) {
        Write-Host "    Last error: $($verify.error)"                        -ForegroundColor Red
    } else {
        Write-Host "    No error from /capture/status; check fastapi.log."   -ForegroundColor Red
    }
    Write-Host "  ============================================================" -ForegroundColor Red
    Write-Host ""
    Read-Host "Press Enter to close"
    exit 1
}
Write-Host ""

# ── Step 3: Target HTTP server on port 80 (hidden background) ─
$port80 = $null
try {
    $port80 = Get-NetTCPConnection -State Listen -LocalPort 80 -ErrorAction Stop
} catch {}

if ($port80) {
    $pid80 = ($port80 | Select-Object -First 1).OwningProcess
    Write-Host "  [3/4] Port 80 already in use (PID $pid80)" -ForegroundColor Yellow -NoNewline
    Write-Host "  [skip spawn -- will verify header below]"
} else {
    Write-Host "  [3/4] Spawning python http.server on port 80 in C:\..." -ForegroundColor Green
    try {
        $script:HttpProc = Start-Process -FilePath 'python.exe' `
            -ArgumentList @('-m','http.server','80') `
            -WorkingDirectory 'C:\' `
            -WindowStyle Hidden `
            -PassThru `
            -RedirectStandardOutput $HttpOutLog `
            -RedirectStandardError  $HttpErrLog
        Write-Host "        Spawned PID $($script:HttpProc.Id) (hidden); logs in logs\http_target.out.log and logs\http_target.err.log"
    } catch {
        Write-Host "        ERROR: failed to spawn python http.server: $_" -ForegroundColor Red
    }
}

# ── Verify HTTP target ─────────────────────────────────────────
Start-Sleep -Seconds 2

# Process-liveness check first (only meaningful when we spawned it)
if ($script:HttpProc -and $script:HttpProc.HasExited) {
    Write-Host ""
    Write-Host "  ============================================================" -ForegroundColor Red
    Write-Host "    [FAIL] HTTP TARGET PROCESS EXITED IMMEDIATELY"           -ForegroundColor Red
    Write-Host "    PID $($script:HttpProc.Id) exited with code $($script:HttpProc.ExitCode)" -ForegroundColor Red
    Write-Host "    Check $HttpErrLog for the bind error (port taken, perm, etc.)." -ForegroundColor Red
    Write-Host "  ============================================================" -ForegroundColor Red
    Write-Host ""
    Read-Host "Press Enter to acknowledge the warning above and continue to dashboard"
} else {
    # Header check -- confirms we're talking to OUR python http.server, not
    # XAMPP Apache or some other listener that happened to be on :80.
    $serverHdr = ''
    $statusCode = 0
    try {
        $r = Invoke-WebRequest -Uri 'http://127.0.0.1/' -UseBasicParsing -TimeoutSec 3
        $statusCode = [int]$r.StatusCode
        $serverHdr  = "$($r.Headers['Server'])"
    } catch {}
    $script:HttpTargetOk = ($statusCode -eq 200) -and ($serverHdr -match 'SimpleHTTP|Python')

    Write-Host ""
    if ($script:HttpTargetOk) {
        Write-Host "  ============================================================" -ForegroundColor Green
        Write-Host "    [OK] HTTP TARGET RESPONDING (server: $serverHdr)"        -ForegroundColor Green
        Write-Host "  ============================================================" -ForegroundColor Green
    } else {
        Write-Host "  ============================================================" -ForegroundColor Red
        Write-Host "    [WARN] HTTP TARGET ON PORT 80 NOT OURS"                  -ForegroundColor Red
        if ($statusCode -gt 0) {
            Write-Host "    Got status=$statusCode, server-header='$serverHdr'"  -ForegroundColor Red
            Write-Host "    Expected: status=200, server header containing 'SimpleHTTP' or 'Python'." -ForegroundColor Red
            Write-Host "    Something else (XAMPP Apache, IIS, etc.) owns port 80." -ForegroundColor Red
        } else {
            Write-Host "    No HTTP response on port 80 at all."                 -ForegroundColor Red
            Write-Host "    Check $HttpErrLog for the python http.server error." -ForegroundColor Red
        }
        Write-Host "    Capture is still active; Kali attacks against port 80"   -ForegroundColor Red
        Write-Host "    will only work after this is fixed."                     -ForegroundColor Red
        Write-Host "  ============================================================" -ForegroundColor Red
        Write-Host ""
        Read-Host "Press Enter to acknowledge the warning above and continue to dashboard"
    }
}
Write-Host ""

# ── Step 4: Dashboard in browser ───────────────────────────────
Write-Host "  [4/4] Opening dashboard at $DashboardUrl..." -ForegroundColor Green
Start-Process $DashboardUrl

# ── Final summary (green only if every check passed) ───────────
Write-Host ""
$allOk = $script:HttpTargetOk -and -not $script:DuplicatesKept
if ($allOk) {
    Write-Host "  ============================================================" -ForegroundColor Cyan
    Write-Host "    ALL UP. Dashboard: $DashboardUrl"                          -ForegroundColor Cyan
    Write-Host "  ============================================================" -ForegroundColor Cyan
} else {
    Write-Host "  Dashboard at $DashboardUrl (started with warnings - see above)." -ForegroundColor Yellow
    if ($script:DuplicatesKept) {
        Write-Host "  Reminder: you chose [C]ontinue with existing duplicate IDS chain." -ForegroundColor Yellow
    }
}

# ── Stop instructions ──────────────────────────────────────────
Write-Host ""
Write-Host "  To stop everything:" -ForegroundColor Cyan
Write-Host "    - Close the START.bat window (kills uvicorn + Streamlit)."
if ($script:HttpProc) {
    Write-Host "    - Kill the hidden http target:  Stop-Process -Id $($script:HttpProc.Id)"
    Write-Host "      (or just re-run dev_up.bat; it will detect and offer to clean up)"
} else {
    Write-Host "    - Re-run dev_up.bat; it will detect any leftover python.exe IDS"
    Write-Host "      processes and offer to clean them up."
}
Write-Host ""

Read-Host "Press Enter to close this launcher"
