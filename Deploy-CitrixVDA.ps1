<#
.SYNOPSIS
    Automated Citrix Virtual Desktop Agent (VDA) upgrade script.
    
.DESCRIPTION
    This script automates the upgrade process of Citrix Virtual Desktop Agent from version 1912 LTSR 
    to version 2402 LTSR.    

.PARAMETER None
    This script does not require any parameters. All configurations are set within the script.

.EXAMPLE
    .\Deploy-CitrixVDA.ps1
      
.NOTES
    File Name  : Deploy-CitrixVDA.ps1
    Version    : 0.2
    Author     : Jacob Wilson
    Email      : jwilson@agsi.us
    Date       : October 2025
    
    Prerequisites:
    - Windows PowerShell 5.1 or higher
    - Administrative privileges
    - Citrix VDA older than 2402 CU3 LTSR currently installed
    - Citrix VDA 2402 CU3 LTSR standalone installer available
    
#>

[CmdletBinding()]
param()

#region Configuration
# ============================================================================
# Configuration Settings
# ============================================================================

$Config = @{
    # Installer settings
    InstallerPath = "C:\Citrix\bin\VDAServerSetup_2402_3100.exe"
    
    # Logging configuration - unique log created per execution locally 
    LogDirectory = "C:\Citrix\logs"
    DetailedLogName = "VDAUpgrade_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
    
    # State management
    RestartFlagFile = "C:\Citrix\state\VDAUpgradeRestart.flag"
    MaxRestartAttempts = 5
    
    # Scheduled task settings
    TaskName = "CitrixVDAUpgradeContinuation"
    TaskDescription = "Continues Citrix VDA upgrade process after system restart"
    
    # Citrix specific paths
    CitrixSetupPath = "$env:ProgramData\Citrix\XenDesktopSetup"
    CitrixContinuationExe = "$env:ProgramData\Citrix\XenDesktopSetup\XenDesktopVdaSetup.exe"
    CitrixInstallStatusXML = "$env:ProgramData\Citrix\XenDesktopSetup\CitrixVirtualDesktopAgent.xml"
}

# VDA installation arguments
$BaseInstallArgs = @(
    "/quiet"
    "/noreboot"
    "/noresume"
    "/components vda"
    "/enable_hdx_ports"
    "/remove_pvd_ack"
    "/remove_appdisk_ack"
)

#endregion

#region Functions
# ============================================================================
# Helper Functions
# ============================================================================

function Initialize-Environment {
    <#
    .SYNOPSIS
        Initializes the script environment and creates necessary directories
    #>
    
    Write-LogMessage "Initializing environment..." -Level Info
    
    # Stop script execution if any error occurs
    $ErrorActionPreference = 'Stop'

    # Check administrative privileges, VDA upgrade requires admin rights
    Write-LogMessage "Checking admin privileges..." -Level Info
    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]"Administrator")) {
        throw "The VDA upgrade requires Administrator permissions. Please try again as Administrator."
    }
    
    # Create log directory if it doesn't exist
    Write-LogMessage "Checking for log directory..." -Level Info
    if (-not (Test-Path $Config.LogDirectory)) {
        New-Item -Path $Config.LogDirectory -ItemType Directory -Force | Out-Null
        Write-LogMessage "Created log directory: $($Config.LogDirectory)" -Level Info
    }
    
    # Create state directory if it doesn't exist
    Write-LogMessage "Checking for state directory..." -Level Info
    $StateDirectory = Split-Path $Config.RestartFlagFile -Parent
    if (-not (Test-Path $StateDirectory)) {
        New-Item -Path $StateDirectory -ItemType Directory -Force | Out-Null
        Write-LogMessage "Created state directory: $StateDirectory" -Level Info
    }
    
    # Check Print Spooler service to ensure it is running prior to install and set to Automatic startup
    Write-LogMessage "Checking Print Spooler service status..." -Level Info
    try {
        $SpoolerService = Get-Service -Name "Spooler" -ErrorAction Stop
        
        # Check and set startup type to Automatic
        if ((Get-Service -Name "Spooler").StartType -ne 'Automatic') {
            Set-Service -Name "Spooler" -StartupType Automatic
            Write-LogMessage "Print Spooler startup type set to Automatic" -Level Info
        }
        
        # Check if service is running and start if needed
        if ($SpoolerService.Status -ne 'Running') {
            Write-LogMessage "Print Spooler service is not running - Starting service..." -Level Warning
            Start-Service -Name "Spooler" -ErrorAction Stop
            
            # Wait for service to fully start
            $Timeout = 30
            $Timer = 0
            while ((Get-Service -Name "Spooler").Status -ne 'Running' -and $Timer -lt $Timeout) {
                Start-Sleep -Seconds 1
                $Timer++
            }
            
            if ((Get-Service -Name "Spooler").Status -eq 'Running') {
                Write-LogMessage "Print Spooler service started successfully" -Level Success
            } else {
                Write-LogMessage "Print Spooler service failed to start within timeout period" -Level Warning
            }
        } else {
            Write-LogMessage "Print Spooler service is running" -Level Success
        }
    }
    catch {
        Write-LogMessage "Failed to configure Print Spooler service: $($_.Exception.Message)" -Level Warning
        Write-LogMessage "Continuing with upgrade despite Print Spooler issue" -Level Warning
    }
    
    Write-LogMessage "Environment initialization completed successfully" -Level Success
}

function Write-LogMessage {
    <#
    .SYNOPSIS
        Writes formatted log messages to console and log file
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        
        [Parameter(Mandatory=$false)]
        [ValidateSet("Info", "Warning", "Error", "Success", "Debug")]
        [string]$Level = "Info"
    )
    
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry = "[$Timestamp] [$Level] $Message"
    
    # Console output with color coding
    switch ($Level) {
        "Info"    { Write-Host $LogEntry -ForegroundColor Cyan }
        "Warning" { Write-Host $LogEntry -ForegroundColor Yellow }
        "Error"   { Write-Host $LogEntry -ForegroundColor Red }
        "Success" { Write-Host $LogEntry -ForegroundColor Green }
        "Debug"   { Write-Host $LogEntry -ForegroundColor Gray }
    }
    
    # File logging
    $LogFile = Join-Path $Config.LogDirectory $Config.DetailedLogName
    Add-Content -Path $LogFile -Value $LogEntry -ErrorAction SilentlyContinue
}

function Test-Prerequisites {
    <#
    .SYNOPSIS
        Validates all prerequisites before starting the upgrade
    #>
    
    Write-LogMessage "Performing pre-flight validation checks..." -Level Info
    $ValidationIssues = @()
    
    # Check installer availability
    Write-LogMessage "Validating VDA installer availability..." -Level Info
    if (-not (Test-Path $Config.InstallerPath)) {
        $ValidationIssues += "VDA installer not found at: $($Config.InstallerPath)"
    } else {
        Write-LogMessage "VDA installer verified at: $($Config.InstallerPath)" -Level Success
    }
    
    # Check for pending system reboots
    Write-LogMessage "Checking for pending system reboots..." -Level Info
    $RebootPending = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending"
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"
        "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\PendingFileRenameOperations"
    )
    
    foreach ($Path in $RebootPending) {
        if (Test-Path $Path -ErrorAction SilentlyContinue) {
            $ValidationIssues += "System reboot pending detected at: $Path"
            Write-LogMessage "Warning: System has pending reboot requirements" -Level Warning
        }
    }
    
    # Report validation results
    if ($ValidationIssues.Count -gt 0) {
        Write-LogMessage "Validation completed with issues:" -Level Warning
        foreach ($Issue in $ValidationIssues) {
            Write-LogMessage "  - $Issue" -Level Warning
        }
        
        # Check for critical failures (installer not found)
        $CriticalFailures = $ValidationIssues | Where-Object { $_ -like "*installer not found*" }
        if ($CriticalFailures.Count -gt 0) {
            throw "Critical validation failures detected. Upgrade cannot proceed."
        }
    } else {
        Write-LogMessage "All validation checks passed successfully" -Level Success
    }
    
    return $true
}

function Set-RestartContinuation {
    <#
    .SYNOPSIS
        Configures the system to continue upgrade after restart
    #>
    param(
        [Parameter(Mandatory=$true)]
        [int]$RestartAttempt
    )
    
    Write-LogMessage "Configuring automatic continuation after restart (Attempt $RestartAttempt of $($Config.MaxRestartAttempts))..." -Level Info
    
    # Save restart attempt count
    $RestartAttempt | Out-File -FilePath $Config.RestartFlagFile -Force
    
    # Create scheduled task for continuation
    try {
        $TaskAction = New-ScheduledTaskAction -Execute "PowerShell.exe" `
            -Argument "-ExecutionPolicy Bypass -NoProfile -File `"$PSCommandPath`""
        
        $TaskTrigger = New-ScheduledTaskTrigger -AtStartup
        
        $TaskSettings = New-ScheduledTaskSettingsSet `
            -StartWhenAvailable `
            -RestartCount 3 `
            -RestartInterval (New-TimeSpan -Minutes 1)
        
        $TaskPrincipal = New-ScheduledTaskPrincipal `
            -UserId "SYSTEM" `
            -LogonType ServiceAccount `
            -RunLevel Highest
        
        $Task = New-ScheduledTask `
            -Action $TaskAction `
            -Trigger $TaskTrigger `
            -Settings $TaskSettings `
            -Principal $TaskPrincipal `
            -Description $Config.TaskDescription
        
        Register-ScheduledTask -TaskName $Config.TaskName -InputObject $Task -Force | Out-Null
        
        Write-LogMessage "Restart continuation task configured successfully" -Level Success
        
        return $true
    }
    catch {
        Write-LogMessage "Failed to configure restart continuation: $($_.Exception.Message)" -Level Error
        return $false
    }
}

function Remove-RestartContinuation {
    <#
    .SYNOPSIS
        Removes restart continuation configuration after successful completion
    #>
    
    Write-LogMessage "Cleaning up restart continuation configuration..." -Level Info
    
    # Remove scheduled task
    try {
        Unregister-ScheduledTask -TaskName $Config.TaskName -Confirm:$false -ErrorAction SilentlyContinue
        Write-LogMessage "Scheduled task removed successfully" -Level Debug
    }
    catch {
        Write-LogMessage "Unable to remove scheduled task: $($_.Exception.Message)" -Level Warning
    }
    
    # Remove flag files
    if (Test-Path $Config.RestartFlagFile) {
        Remove-Item $Config.RestartFlagFile -Force -ErrorAction SilentlyContinue
        Write-LogMessage "Removed flag file: $($Config.RestartFlagFile)" -Level Debug
    }
}

function Test-InstallationComplete {
    <#
    .SYNOPSIS
        Checks if the VDA installation is complete by verifying the absence of the CitrixVirtualDesktopAgent.xml file
    #>
    
    $XMLExists = Test-Path $Config.CitrixInstallStatusXML
    
    if ($XMLExists) {
        Write-LogMessage "Installation status XML found - Installation is not complete" -Level Info
        return $false
    } else {
        Write-LogMessage "Installation status XML not found - Installation is complete" -Level Info
        return $true
    }
}

function Invoke-VDAUpgrade {
    <#
    .SYNOPSIS
        Executes the VDA upgrade installation process
    #>
    
    Write-LogMessage "========================================" -Level Info
    Write-LogMessage "Starting VDA 2402 LTSR CU3 Upgrade      " -Level Info
    Write-LogMessage "========================================" -Level Info
    
    # Build installation command
    $MSILogPath = Join-Path $Config.LogDirectory "CTX_VDA_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    $InstallArgs = $BaseInstallArgs + @("/logpath `"$MSILogPath`"")
    
    Write-LogMessage "Installer: $($Config.InstallerPath)" -Level Info
    Write-LogMessage "Arguments: $($InstallArgs -join ' ')" -Level Debug
    
    # Execute installation
    Write-LogMessage "Executing VDA installer - this may take several minutes..." -Level Info
    
    try {
        $InstallProcess = Start-Process -FilePath $Config.InstallerPath `
            -ArgumentList $InstallArgs `
            -Wait `
            -PassThru `
            -NoNewWindow
        
        $ExitCode = $InstallProcess.ExitCode
        Write-LogMessage "Installation completed with exit code: $ExitCode" -Level Info
        
        # Installer exit codes
        switch ($ExitCode) {
            0 { 
                # Success - Installation complete, reboot needed
                Write-LogMessage "VDA upgrade completed - System restart required" -Level Success
                return "RestartRequired"
            }
            3 { 
                # Reboot needed and installer needs to be continued after reboot
                Write-LogMessage "VDA upgrade requires restart and continuation" -Level Warning
                return "RestartRequired"
            }
            8 {
                # Success - Installation complete, restart required
                Write-LogMessage "VDA upgrade completed - System restart required" -Level Success
                return "RestartRequired"
            }
            3010 { 
                # Success - Restart required (MSI standard)
                Write-LogMessage "VDA upgrade completed - System restart required (3010)" -Level Success
                return "RestartRequired"
            }
            1641 { 
                # Success - Installer initiated restart
                Write-LogMessage "VDA upgrade completed - Installer initiating restart (1641)" -Level Success
                return "RestartRequired"
            }
            default { 
                # Unknown error
                Write-LogMessage "Installation failed with exit code: $ExitCode" -Level Error
                Write-LogMessage "Review detailed logs at: $MSILogPath" -Level Error
                return "Failed"
            }
        }
    }
    catch {
        Write-LogMessage "Installation process encountered an error: $($_.Exception.Message)" -Level Error
        return "Failed"
    }
}

function Complete-RestartCycle {
    <#
    .SYNOPSIS
        Handles system restart with proper continuation setup
    #>
    param(
        [Parameter(Mandatory=$true)]
        [int]$RestartAttempt
    )
    
    if ($RestartAttempt -gt $Config.MaxRestartAttempts) {
        Write-LogMessage "Maximum restart attempts exceeded ($($Config.MaxRestartAttempts))" -Level Error
        Remove-RestartContinuation
        exit 1
    }
    
    if (Set-RestartContinuation -RestartAttempt $RestartAttempt) {
        Write-LogMessage "System will restart in 10 seconds..." -Level Warning
        Write-LogMessage "The upgrade will continue automatically after restart" -Level Info
        
        # Initiate restart with warning
        shutdown.exe /r /t 10 /c "Citrix VDA Upgrade - System will restart in 10 seconds to continue the upgrade process."
        
        Start-Sleep -Seconds 15
        exit 0
    } else {
        Write-LogMessage "Failed to configure restart continuation - Manual intervention required" -Level Error
        exit 1
    }
}

function Test-ContinuationRequired {
    <#
    .SYNOPSIS
        Checks if VDA installer needs to continue after restart and continues if needed
    #>
    
    # First check if the installation status XML exists
    if (Test-Path $Config.CitrixInstallStatusXML) {
        Write-LogMessage "Installation status XML detected - Installation must be continued" -Level Info
        
        if (Test-Path $Config.CitrixContinuationExe) {
            Write-LogMessage "VDA installation continuation executable found" -Level Info
            Write-LogMessage "Resuming installation process..." -Level Info
            
            try {
                # Run continuation without parameters
                $ContinueProcess = Start-Process -FilePath $Config.CitrixContinuationExe `
                    -Wait `
                    -PassThru `
                    -NoNewWindow
                
                $ExitCode = $ContinueProcess.ExitCode
                Write-LogMessage "Continuation completed with exit code: $ExitCode" -Level Info
                
                return $ExitCode
            }
            catch {
                Write-LogMessage "Failed to continue installation: $($_.Exception.Message)" -Level Error
                return -1
            }
        } else {
            Write-LogMessage "Continuation executable not found at: $($Config.CitrixContinuationExe)" -Level Error
            return -1
        }
    } else {
        Write-LogMessage "No installation status XML found - No continuation needed" -Level Info
        return $null
    }
}

#endregion

#region Main Execution
# ============================================================================
# Main Script Execution
# ============================================================================

try {
    Write-LogMessage "========================================" -Level Info
    Write-LogMessage "Citrix VDA Upgrade Script v0.2" -Level Info
    Write-LogMessage "========================================" -Level Info
    Write-LogMessage "Machine: $env:COMPUTERNAME" -Level Info
    Write-LogMessage "Domain: $env:USERDOMAIN" -Level Info
    Write-LogMessage "User: $env:USERNAME" -Level Info
    Write-LogMessage "========================================" -Level Info

    # Initialize environment
    Initialize-Environment  
    
    # Check for restart continuation
    $RestartAttempt = 0
    if (Test-Path $Config.RestartFlagFile) {
        $RestartAttempt = [int](Get-Content $Config.RestartFlagFile)
        Write-LogMessage "Resuming upgrade after restart (Attempt $RestartAttempt of $($Config.MaxRestartAttempts))" -Level Info
        
        # Check for VDA continuation
        $ContinuationResult = Test-ContinuationRequired
        
        if ($null -ne $ContinuationResult) {
            # Process continuation result
            if ($ContinuationResult -in @(0, 8)) {
                # Installation complete but check if XML still exists
                if (Test-Path $Config.CitrixInstallStatusXML) {
                    Write-LogMessage "Installation returned success but XML still exists - Restart required" -Level Warning
                    Complete-RestartCycle -RestartAttempt ($RestartAttempt + 1)
                } else {
                    Write-LogMessage "Installation continuation completed successfully" -Level Success
                    Remove-RestartContinuation
                    exit 0
                }
            } elseif ($ContinuationResult -eq 3) {
                # Need another restart and continuation
                Write-LogMessage "Installation requires another restart and continuation" -Level Warning
                Complete-RestartCycle -RestartAttempt ($RestartAttempt + 1)
            } else {
                # Error during continuation
                Write-LogMessage "Installation continuation failed with exit code: $ContinuationResult" -Level Error
                Remove-RestartContinuation
                exit $ContinuationResult
            }
        } else {
            # No continuation needed - check if installation is truly complete
            if (Test-InstallationComplete) {
                Write-LogMessage "VDA installation verified as complete" -Level Success
                Remove-RestartContinuation
                exit 0
            } else {
                Write-LogMessage "Installation status XML exists but no continuation executable - Manual intervention may be required" -Level Error
                Remove-RestartContinuation
                exit 1
            }
        }
    } else {
        # Initial run
        Write-LogMessage "Starting initial upgrade process" -Level Info
        
        Write-LogMessage "Running pre-flight validation checks" -Level Info
        if (-not (Test-Prerequisites)) {
            Write-LogMessage "Pre-flight validation failed - Upgrade aborted" -Level Error
            exit 1
        }
        
        # Execute VDA upgrade
        $Result = Invoke-VDAUpgrade
        
        switch ($Result) {
            "RestartRequired" {
                # Check if installation is complete or needs continuation
                if (Test-Path $Config.CitrixInstallStatusXML) {
                    Write-LogMessage "Installation requires continuation after restart" -Level Warning
                    $NewAttempt = 1
                    Complete-RestartCycle -RestartAttempt $NewAttempt
                } else {
                    # Installation complete
                    Write-LogMessage "Installation complete - Final restart required" -Level Success
                    Write-LogMessage "========================================" -Level Success
                    Write-LogMessage "VDA UPGRADE COMPLETED SUCCESSFULLY" -Level Success
                    Write-LogMessage "Please restart the system to complete the upgrade" -Level Success
                    Write-LogMessage "========================================" -Level Success
                    Remove-RestartContinuation
                    exit 0
                }
            }
            "Failed" {
                Write-LogMessage "========================================" -Level Error
                Write-LogMessage "VDA UPGRADE FAILED" -Level Error
                Write-LogMessage "========================================" -Level Error
                Remove-RestartContinuation
                exit 1
            }
        }
    }
}
catch {
    Write-LogMessage "========================================" -Level Error
    Write-LogMessage "CRITICAL ERROR ENCOUNTERED" -Level Error
    Write-LogMessage "========================================" -Level Error
    Write-LogMessage "Error: $($_.Exception.Message)" -Level Error
    Write-LogMessage "Stack Trace: $($_.ScriptStackTrace)" -Level Error
    
    Remove-RestartContinuation
    
    exit 1
}
finally {
    Write-LogMessage "========================================" -Level Info
    Write-LogMessage "Script execution completed at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -Level Info
    Write-LogMessage "========================================" -Level Info
}

#endregion