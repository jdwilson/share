#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Checks every location that could define an RDS idle/session timeout.
    Run on the affected RDS Session Host as Administrator.

.NOTES
    Idle timeout of 900000ms (900 sec / 15 min) is the target value to find.
    The warning popup before disconnect is standard RDS behavior when a session
    limit is hit and fResetBroken = 0 (disconnect, not logoff).
#>

$ErrorActionPreference = "Continue"

$TARGET_MS    = 900000   # 15 minutes in milliseconds
$TARGET_MIN   = 15       # 15 minutes
$SEPARATOR    = "-" * 70

function Format-Timeout {
    param([object]$Value)
    if ($null -eq $Value -or $Value -eq 0) { return "0 (no limit)" }
    $ms = [long]$Value
    $min = [math]::Round($ms / 60000, 2)
    $flag = if ($ms -eq $TARGET_MS) { " <-- [!] 15 MIN MATCH" } else { "" }
    return "$ms ms  ($min min)$flag"
}

function Format-MinTimeout {
    param([object]$Value)
    if ($null -eq $Value -or $Value -eq 0) { return "0 (no limit)" }
    $flag = if ([int]$Value -eq $TARGET_MIN) { " <-- [!] 15 MIN MATCH" } else { "" }
    return "$Value min$flag"
}

function Read-RegValue {
    param([string]$Path, [string]$Name)
    try {
        $val = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop
        return $val.$Name
    } catch {
        return $null
    }
}

function Show-RegPath {
    param([string]$Path, [string]$Label)
    Write-Host ""
    Write-Host "  [$Label]"
    Write-Host "  Path: $Path"

    $exists = Test-Path $Path
    if (-not $exists) {
        Write-Host "  (registry key not found)"
        return
    }

    $names = @("MaxIdleTime", "MaxDisconnectionTime", "MaxConnectionTime",
               "MaxSessionTime", "fResetBroken", "TimeLimitPolicy")

    $found = $false
    foreach ($name in $names) {
        $val = Read-RegValue -Path $Path -Name $name
        if ($null -ne $val) {
            $found = $true
            $formatted = if ($name -eq "fResetBroken") {
                "$val  (0=Disconnect, 1=Logoff)"
            } else {
                Format-Timeout $val
            }
            Write-Host "    $name = $formatted"
        }
    }

    if (-not $found) {
        Write-Host "  (key exists but no timeout values set)"
    }
}

# ============================================================
Write-Host $SEPARATOR
Write-Host "  RDS TIMEOUT AUDIT  --  $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Host "  Server: $env:COMPUTERNAME"
Write-Host "  Target: $TARGET_MS ms ($TARGET_MIN minutes)"
Write-Host $SEPARATOR


# ------------------------------------------------------------
Write-Host ""
Write-Host "[1] GROUP POLICY - COMPUTER (HKLM Policies)"
Write-Host $SEPARATOR

Show-RegPath "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
    "HKLM Policies\Terminal Services"


# ------------------------------------------------------------
Write-Host ""
Write-Host "[2] GROUP POLICY - USER (HKCU Policies)"
Write-Host $SEPARATOR

Show-RegPath "HKCU:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" `
    "HKCU Policies\Terminal Services"


# ------------------------------------------------------------
Write-Host ""
Write-Host "[3] RDS SESSION HOST - WinStation RDP-Tcp (tsconfig.msc / direct config)"
Write-Host $SEPARATOR

Show-RegPath "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" `
    "WinStations\RDP-Tcp"

# Also check any custom WinStation listeners
Write-Host ""
Write-Host "  [Custom WinStation Listeners]"
$wsBase = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations"
try {
    $listeners = Get-ChildItem -Path $wsBase -ErrorAction Stop |
        Where-Object { $_.PSChildName -ne "RDP-Tcp" }
    foreach ($listener in $listeners) {
        Show-RegPath $listener.PSPath "WinStations\$($listener.PSChildName)"
    }
} catch {
    Write-Host "  (could not enumerate WinStations)"
}


# ------------------------------------------------------------
Write-Host ""
Write-Host "[4] WMI - Win32_TSSessionSetting"
Write-Host $SEPARATOR

try {
    $sessions = Get-CimInstance -Namespace "root\cimv2\terminalservices" `
        -ClassName "Win32_TSSessionSetting" -ErrorAction Stop

    if ($sessions) {
        foreach ($s in $sessions) {
            Write-Host ""
            Write-Host "  Terminal: $($s.TerminalName)"
            Write-Host "    MaxIdleTime          = $(Format-Timeout $s.MaxIdleTime)"
            Write-Host "    MaxDisconnectionTime = $(Format-Timeout $s.MaxDisconnectionTime)"
            Write-Host "    MaxConnectionTime    = $(Format-Timeout $s.MaxConnectionTime)"
            $broken = $s.BrokenConnectionAction
            $brokenLabel = if ($broken -eq 0) { "0 (Disconnect)" } else { "1 (Logoff)" }
            Write-Host "    BrokenConnectionAction = $brokenLabel"
            Write-Host "    ReconnectionPolicy   = $($s.ReconnectionPolicy)"
        }
    } else {
        Write-Host "  (no results)"
    }
} catch {
    Write-Host "  [!] WMI query failed: $_"
}


# ------------------------------------------------------------
Write-Host ""
Write-Host "[5] WMI - Win32_TerminalServiceSetting"
Write-Host $SEPARATOR

try {
    $svc = Get-CimInstance -Namespace "root\cimv2\terminalservices" `
        -ClassName "Win32_TerminalServiceSetting" -ErrorAction Stop
    if ($svc) {
        Write-Host "  TimeoutSettingsEnabled : $($svc.TimeoutSettingsEnabled)"
        Write-Host "  SessionBrokerEnabled   : $($svc.SessionBrokerEnabled)"
    }
} catch {
    Write-Host "  [!] WMI query failed: $_"
}


# ------------------------------------------------------------
Write-Host ""
Write-Host "[6] RDS SESSION COLLECTION (requires RDMS role)"
Write-Host $SEPARATOR

try {
    $rdsMod = Get-Module -ListAvailable -Name "RemoteDesktop" -ErrorAction SilentlyContinue
    if ($rdsMod) {
        Import-Module RemoteDesktop -ErrorAction SilentlyContinue
        $collections = Get-RDSessionCollection -ErrorAction Stop
        foreach ($col in $collections) {
            $cfg = Get-RDSessionCollectionConfiguration -CollectionName $col.CollectionName `
                -ErrorAction SilentlyContinue
            Write-Host ""
            Write-Host "  Collection: $($col.CollectionName)"
            if ($cfg) {
                Write-Host "    DisconnectedSessionLimitMin  = $(Format-MinTimeout $cfg.DisconnectedSessionLimitMin)"
                Write-Host "    IdleSessionLimitMin          = $(Format-MinTimeout $cfg.IdleSessionLimitMin)"
                Write-Host "    ActiveSessionLimitMin        = $(Format-MinTimeout $cfg.ActiveSessionLimitMin)"
                Write-Host "    BrokenConnectionAction       = $($cfg.BrokenConnectionAction)"
                Write-Host "    AutomaticReconnectionEnabled = $($cfg.AutomaticReconnectionEnabled)"
            }
        }
    } else {
        Write-Host "  (RemoteDesktop module not available - not an RDMS server)"
    }
} catch {
    Write-Host "  (no RDS Collections found or RDMS not installed)"
}


# ------------------------------------------------------------
Write-Host ""
Write-Host "[7] ACTIVE DIRECTORY USER PROPERTIES (Session tab)"
Write-Host $SEPARATOR

$adAvailable = $false
try {
    $adMod = Get-Module -ListAvailable -Name "ActiveDirectory" -ErrorAction SilentlyContinue
    if ($adMod) {
        Import-Module ActiveDirectory -ErrorAction SilentlyContinue
        $adAvailable = $true
    }
} catch { }

if ($adAvailable) {
    Write-Host "  Checking currently logged-on users for AD session settings..."
    try {
        $loggedOn = query user 2>$null |
            Select-Object -Skip 1 |
            ForEach-Object { (($_ -replace "^>", "").Trim() -split "\s+")[0] } |
            Where-Object { $_ }

        if ($loggedOn) {
            foreach ($user in $loggedOn) {
                try {
                    $tsAttrs = Get-ADUser -Identity $user -Properties `
                        "TerminalServicesMaxIdleTime",
                        "TerminalServicesMaxDisconnectionTime",
                        "TerminalServicesMaxConnectionTime",
                        "TerminalServicesReconnectionAction",
                        "TerminalServicesBrokenConnectionAction" `
                        -ErrorAction SilentlyContinue

                    Write-Host ""
                    Write-Host "  User: $user"
                    if ($tsAttrs) {
                        $idle = $tsAttrs.TerminalServicesMaxIdleTime
                        $disc = $tsAttrs.TerminalServicesMaxDisconnectionTime
                        $conn = $tsAttrs.TerminalServicesMaxConnectionTime
                        Write-Host "    MaxIdleTime          = $(Format-Timeout $idle)"
                        Write-Host "    MaxDisconnectionTime = $(Format-Timeout $disc)"
                        Write-Host "    MaxConnectionTime    = $(Format-Timeout $conn)"
                        Write-Host "    BrokenConnectionAction = $($tsAttrs.TerminalServicesBrokenConnectionAction)"
                    } else {
                        Write-Host "    (no TS session attributes found)"
                    }
                } catch {
                    Write-Host "  User: $user  -- (AD lookup failed: $_)"
                }
            }
        } else {
            Write-Host "  (no active sessions found via 'query session')"
        }
    } catch {
        Write-Host "  (query session failed: $_)"
    }
} else {
    Write-Host "  (ActiveDirectory module not available)"
    Write-Host "  To check manually: ADUC > User Properties > Sessions tab"
    Write-Host "  Or: Get-ADUser -Identity <user> -Properties TerminalServicesMaxIdleTime"
}


# ------------------------------------------------------------
Write-Host ""
Write-Host "[8] RESULTANT SET OF POLICY (GPResult)"
Write-Host $SEPARATOR

Write-Host "  Generating gpresult... (this may take a moment)"
try {
    $gpResult = gpresult /Scope Computer /v 2>&1
    $rdLines = $gpResult | Select-String -Pattern "idle|session.time|disconnect|MaxIdle|Terminal" -CaseSensitive:$false
    if ($rdLines) {
        Write-Host ""
        Write-Host "  [Computer Policy - RDS-related lines from gpresult]"
        $rdLines | ForEach-Object { Write-Host "    $_" }
    } else {
        Write-Host "  (no RDS-related lines found in Computer scope gpresult)"
    }
} catch {
    Write-Host "  (gpresult failed: $_)"
}


# ------------------------------------------------------------
Write-Host ""
Write-Host "[9] LOCAL / LEGACY TERMINAL SERVER REGISTRY SETTINGS"
Write-Host $SEPARATOR

Show-RegPath "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server" `
    "HKLM\...\Terminal Server (legacy)"

Show-RegPath "HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server" `
    "HKCU\...\Terminal Server (legacy)"


# ------------------------------------------------------------
Write-Host ""
Write-Host "[10] SCAN COMPLETE"
Write-Host $SEPARATOR
