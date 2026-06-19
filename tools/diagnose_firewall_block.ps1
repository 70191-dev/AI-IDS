#requires -Version 5.1
<#
.SYNOPSIS
    AI-IDS firewall block diagnostic (read-only).

.DESCRIPTION
    Phase 2 W3-Sub4 hotfix follow-up. We confirmed:
      - /health admin_elevated = true
      - netsh rule "AI-IDS Block 192.168.142.128" exists, Enabled=Yes,
        Direction=In, Action=Block, RemoteIP=192.168.142.128/32
      - All 3 firewall profiles ON (Domain/Private/Public)
      - Kali = 192.168.142.128, Windows VMnet8 = 192.168.142.1
    ...yet `curl -I http://192.168.142.1/` from Kali still returns 200.

    This script gathers every piece of evidence needed to explain why.
    It is read-only EXCEPT for one side effect: Section 4 enables
    Windows Firewall dropped-connection logging. It does NOT auto-
    disable logging -- you need time to generate Kali traffic first.
    Re-disable manually when you're done (instructions printed in Sec 4).

.USAGE
    Run from elevated PowerShell, in the project root:
        .\tools\diagnose_firewall_block.ps1 > diag_output.txt 2>&1

    Between Section 4 and reading the log file, run ONCE from Kali:
        curl -I http://192.168.142.1/

    Then read the firewall log:
        Get-Content C:\Windows\System32\LogFiles\Firewall\pfirewall.log -Tail 50
    Look for "DROP" lines mentioning 192.168.142.128. Paste diag_output.txt
    and any DROP lines back for diagnosis.
#>

$ErrorActionPreference = 'Continue'

$RuleName = 'AI-IDS Block 192.168.142.128'
$KaliIP   = '192.168.142.128'
$HostIP   = '192.168.142.1'
$FwLog    = "$env:SystemRoot\System32\LogFiles\Firewall\pfirewall.log"

function Write-Section([string]$title) {
    ""
    "=== $title ==="
    ""
}

function Try-Run([string]$label, [scriptblock]$block) {
    "--- $label ---"
    try {
        & $block
    } catch {
        "ERROR in '$label': $($_.Exception.Message)"
    }
    ""
}

"AI-IDS firewall block diagnostic"
"Run at: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
"Rule under investigation: $RuleName"
"Source (Kali):  $KaliIP"
"Target (Windows VMnet8 host): $HostIP"
""

# ════════════════════════════════════════════════════════════════════
Write-Section "Section 1: Target rule details"

Try-Run "netsh advfirewall firewall show rule (verbose)" {
    netsh advfirewall firewall show rule name=$RuleName verbose
}

Try-Run "Get-NetFirewallRule | Format-List *" {
    Get-NetFirewallRule -DisplayName $RuleName | Format-List *
}

Try-Run "AddressFilter (Remote/Local IP)" {
    Get-NetFirewallRule -DisplayName $RuleName | Get-NetFirewallAddressFilter | Format-List *
}

Try-Run "PortFilter (Protocol/Ports)" {
    Get-NetFirewallRule -DisplayName $RuleName | Get-NetFirewallPortFilter | Format-List *
}

Try-Run "InterfaceTypeFilter" {
    Get-NetFirewallRule -DisplayName $RuleName | Get-NetFirewallInterfaceTypeFilter | Format-List *
}

Try-Run "InterfaceFilter" {
    Get-NetFirewallRule -DisplayName $RuleName | Get-NetFirewallInterfaceFilter | Format-List *
}

Try-Run "ApplicationFilter" {
    Get-NetFirewallRule -DisplayName $RuleName | Get-NetFirewallApplicationFilter | Format-List *
}

Try-Run "Profile binding" {
    Get-NetFirewallRule -DisplayName $RuleName | Get-NetFirewallProfile | Format-List *
}

# ════════════════════════════════════════════════════════════════════
Write-Section "Section 2: Conflicting allow rules"

Try-Run "Enabled inbound ALLOW rules touching port 80 or 'Any'" {
    Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True |
        Where-Object { $_.Profile -match 'Private|Public|Any' } |
        ForEach-Object {
            $r  = $_
            $pf = $r | Get-NetFirewallPortFilter
            if ($pf.LocalPort -eq 'Any' -or
                $pf.LocalPort -contains '80' -or
                $pf.LocalPort -match '80') {
                [PSCustomObject]@{
                    DisplayName = $r.DisplayName
                    LocalPort   = ($pf.LocalPort -join ',')
                    Protocol    = $pf.Protocol
                    Profile     = ($r.Profile -join ',')
                    Program     = ($r | Get-NetFirewallApplicationFilter).Program
                }
            }
        } | Format-Table -AutoSize -Wrap
}

Try-Run "Enabled inbound ALLOW rules with broad remote-address scope" {
    Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True |
        ForEach-Object {
            $r  = $_
            $af = $r | Get-NetFirewallAddressFilter
            if ($af.RemoteAddress -eq 'Any' -or
                $af.RemoteAddress -match '192\.168\.|0\.0\.0\.0|^Any$') {
                [PSCustomObject]@{
                    DisplayName   = $r.DisplayName
                    RemoteAddress = ($af.RemoteAddress -join ',')
                    LocalPort     = (($r | Get-NetFirewallPortFilter).LocalPort -join ',')
                    Profile       = ($r.Profile -join ',')
                }
            }
        } | Format-Table -AutoSize -Wrap
}

Try-Run "Any inbound rule matching python.exe" {
    Get-NetFirewallRule -Direction Inbound -Enabled True |
        ForEach-Object {
            $r  = $_
            $af = $r | Get-NetFirewallApplicationFilter
            if ($af.Program -match 'python') {
                [PSCustomObject]@{
                    DisplayName = $r.DisplayName
                    Action      = $r.Action
                    Program     = $af.Program
                    Profile     = ($r.Profile -join ',')
                }
            }
        } | Format-Table -AutoSize -Wrap
}

# ════════════════════════════════════════════════════════════════════
Write-Section "Section 3: Windows interface and profile mapping"

Try-Run "Get-NetConnectionProfile (per-adapter network category)" {
    Get-NetConnectionProfile | Format-Table InterfaceAlias, NetworkCategory, IPv4Connectivity -AutoSize
}

Try-Run "Get-NetAdapter (VMnet|Ethernet)" {
    Get-NetAdapter |
        Where-Object { $_.Name -match 'VMnet|Ethernet' } |
        Format-Table Name, InterfaceDescription, ifIndex, Status, MediaType -AutoSize
}

Try-Run "Get-NetIPAddress for 192.168.142.*" {
    Get-NetIPAddress -AddressFamily IPv4 |
        Where-Object { $_.IPAddress -like '192.168.142.*' } |
        Format-Table IPAddress, InterfaceAlias, InterfaceIndex, PrefixOrigin -AutoSize
}

# ════════════════════════════════════════════════════════════════════
Write-Section "Section 4: Enable firewall logging (then YOU run curl from Kali)"

Try-Run "Set log filename" {
    netsh advfirewall set allprofiles logging filename $FwLog
}

Try-Run "Set log max size (4096 KB)" {
    netsh advfirewall set allprofiles logging maxfilesize 4096
}

Try-Run "Enable dropped-connection logging" {
    netsh advfirewall set allprofiles logging droppedconnections enable
}

"Log file path: $FwLog"
""
@"
==> MANUAL STEPS BETWEEN SECTIONS (do these now, before reading the log):

  1. From Kali, run this ONCE:
       curl -I http://$HostIP/

  2. Then from this Windows PowerShell window, tail the log:
       Get-Content '$FwLog' -Tail 50
     Look for "DROP" lines where the src or dst contains $KaliIP.

  3. When you're done diagnosing, disable logging:
       netsh advfirewall set allprofiles logging droppedconnections disable

This script intentionally does NOT auto-disable logging -- you need
time to generate Kali traffic between sections.
"@
""

# ════════════════════════════════════════════════════════════════════
Write-Section "Section 5: Local listener check (who owns port 80)"

Try-Run "Get-NetTCPConnection LocalPort=80 Listen" {
    Get-NetTCPConnection -LocalPort 80 -State Listen -ErrorAction SilentlyContinue |
        Format-List LocalAddress, LocalPort, OwningProcess
}

Try-Run "Owning process(es)" {
    $conns = Get-NetTCPConnection -LocalPort 80 -State Listen -ErrorAction SilentlyContinue
    if (-not $conns) {
        "No listener on port 80."
        return
    }
    $pids = $conns | Select-Object -ExpandProperty OwningProcess -Unique
    foreach ($procId in $pids) {
        Get-Process -Id $procId -ErrorAction SilentlyContinue |
            Select-Object Id, ProcessName, Path | Format-List
    }
}

# ════════════════════════════════════════════════════════════════════
Write-Section "Section 6: Routing table for 192.168.142.0/24"

Try-Run "Get-NetRoute (DestinationPrefix matches 192.168.142.*)" {
    Get-NetRoute -AddressFamily IPv4 |
        Where-Object { $_.DestinationPrefix -like '192.168.142.*' } |
        Format-Table DestinationPrefix, NextHop, InterfaceAlias, RouteMetric -AutoSize
}

# ════════════════════════════════════════════════════════════════════
Write-Section "Section 7: VMware shim / adapter binding"

Try-Run "VMware-related services" {
    Get-Service |
        Where-Object { $_.Name -match 'VMware|VMnet' } |
        Format-Table Name, Status, StartType -AutoSize
}

# Resolve the VMnet8 adapter name robustly -- the literal "VMware Network
# Adapter VMnet8" assumption is fragile across host configurations.
$vmnetAdapter = Get-NetAdapter -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -match 'VMnet8' -or $_.InterfaceDescription -match 'VMnet8' } |
    Select-Object -First 1

if ($vmnetAdapter) {
    "Resolved VMnet8 adapter:"
    "  Name        : $($vmnetAdapter.Name)"
    "  Description : $($vmnetAdapter.InterfaceDescription)"
    "  Status      : $($vmnetAdapter.Status)"
    ""

    Try-Run "Enabled bindings on VMnet8" {
        Get-NetAdapterBinding -Name $vmnetAdapter.Name |
            Where-Object { $_.Enabled -eq $true } |
            Format-Table Name, DisplayName, Enabled, ComponentID -AutoSize
    }

    Try-Run "All bindings on VMnet8 (including disabled, for comparison)" {
        Get-NetAdapterBinding -Name $vmnetAdapter.Name |
            Format-Table Name, DisplayName, Enabled, ComponentID -AutoSize
    }
} else {
    "Could not resolve any adapter whose Name or InterfaceDescription matches 'VMnet8'."
    "Fallback: listing bindings on all adapters with a VMware-ish name."
    Get-NetAdapter -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match 'VMware|VMnet' -or $_.InterfaceDescription -match 'VMware' } |
        ForEach-Object {
            "--- $($_.Name) ($($_.InterfaceDescription)) ---"
            Get-NetAdapterBinding -Name $_.Name -ErrorAction SilentlyContinue |
                Format-Table Name, DisplayName, Enabled -AutoSize
        }
}

# ════════════════════════════════════════════════════════════════════
Write-Section "Section 8: Direct counter-test instructions"

@"
INDEPENDENT COUNTER-TESTS (run by hand after this script finishes):

(a) From THIS Windows host (NOT from Kali), confirm the listener works
    over loopback. Loopback is never firewalled, so this MUST succeed
    regardless of the block rule:
        Test-NetConnection -ComputerName $HostIP -Port 80
    Green TcpTestSucceeded=True confirms the listener is alive. If
    this fails too, the HTTP target itself is broken (not a firewall
    problem at all).

(b) From Kali, send a verbose TCP probe:
        curl -v -I http://$HostIP/
    Outcomes and what they mean:
      - 200 OK returned         -> rule is NOT being enforced for this
                                   packet path. Firewall is either not
                                   evaluating it (Section 7 bug) or
                                   an allow rule overrides it (Section 2).
      - hang / timeout          -> rule IS enforced. SYN is being
                                   silently dropped. Our W3-Sub4 chain
                                   is working end-to-end.
      - TCP RST / refused       -> NOT a firewall block (block ACTION
                                   drops, doesn't RST). The listener
                                   went away or refused on its own.

(c) Cross-check with the firewall log captured in Section 4:
        Get-Content '$FwLog' -Tail 50
    Look for DROP entries with src=$KaliIP dst=$HostIP. Presence of
    DROP entries = firewall sees the traffic. Absence = the packet
    bypasses the firewall layer entirely (the smoking gun for Section 7).
"@
""

# ════════════════════════════════════════════════════════════════════
Write-Section "Diagnostic run complete"

"Finished at: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
""

<#
INTERPRETATION KEY (for the user when reading diag_output.txt):

- Section 1: If InterfaceTypes is anything other than "Any" (or
  doesn't cover "LocalSubnet"), rule won't match VMnet traffic. If
  Profile excludes the category VMnet8 belongs to (per Section 3),
  same effect.

- Section 2: ANY rule found in any of these queries is a candidate
  for precedence override. Block normally wins, BUT scoped allow
  rules (specific RemoteAddress / specific Program) can win against
  an "Any" block per Windows Firewall merge logic. Pay closest
  attention to allow rules with Program=python.exe or
  Program=...launch.py.

- Section 3: If VMnet8 NetworkCategory shows DomainAuthenticated but
  the rule's profile is only Private/Public, that's the bug -- match
  the categories. The rule above shows Profile=Any, so this should
  be fine, but verify.

- Section 4: After Kali curls, DROP entries with src=192.168.142.128
  in pfirewall.log prove the firewall IS evaluating and blocking.
  Absence of DROP entries means the packet never hit the firewall
  layer (Section 7 territory).

- Section 5: Python listening on 0.0.0.0:80 is normal; not the
  problem. IPv6-only would be wrong but Python's http.server defaults
  to IPv4.

- Section 6: A route via a non-VMnet8 interface would mean Kali
  traffic is hitting Windows via a path the firewall rule's interface
  doesn't cover. Usually the route shows VMnet8 directly attached.

- Section 7: VMnet8 adapter without Windows Defender Firewall binding
  (ms_wfp / ms_ndiscap) = smoking gun. VMware can install a
  passthrough shim that bypasses Windows Firewall entirely on that
  interface.

- Section 8: Kali curl succeeds AND no DROP log entry = firewall
  isn't seeing the packet (Section 7 or Section 6). Kali curl times
  out = firewall IS enforcing and our W3-Sub4 chain is correct;
  whatever the user observed was something else.
#>
