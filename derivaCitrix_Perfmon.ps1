<#
.SYNOPSIS
    Creates a performance monitoring data collector set for Citrix environments.

.DESCRIPTION
    This PowerShell script creates and configures a Data Collector Set using logman to monitor
    various performance counters relevant to Citrix environments. It collects metrics for
    processor, memory, disk, and network performance.

.PARAMETER None
    This script doesn't accept any parameters through the command line.

.EXAMPLE
    .\derivaCitrix_Perfmon.ps1
    
    Runs the script and creates the data collector set.

.NOTES
    File Name      : derivaCitrix_Perfmon.ps1
    Author         : Jacob Wilson (jwilson@agsi.us)
    Prerequisite   : PowerShell 5.1 or later
    Version        : 1.0
    Date           : 2025-05-20
    
.LINK
    https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/logman
#>

#Requires -Version 5.1

#-----------------------------------------------------------[Variables]------------------------------------------------------------

# Configuration settings for the data collector set
$CollectorSetName = "Citrix_Perfmon_CollectorSet"  # Name of the data collector set
$OutputPath = "$env:USERPROFILE\PerfLogs\$CollectorSetName"  # Where logs will be stored
$SampleInterval = 5  # Sampling interval in seconds
$LogFileFormat = "bin"  # Binary format for performance logs
$LogRetention = "24:00:00"  # Retain logs for 24 hours

#-----------------------------------------------------------[Execution]------------------------------------------------------------

# Create output directory if it doesn't exist
if (-not (Test-Path -Path $OutputPath)) {
    New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
}

# Delete existing collector set with the same name if it exists
logman delete -n $CollectorSetName

# Create a new Data Collector Set using logman
logman create counter -n $CollectorSetName -o "$OutputPath\$CollectorSetName" -f $LogFileFormat -si $SampleInterval -v mmddhhmm

#-----------------------------------------------------------[Counters]------------------------------------------------------------

logman update counter -n $CollectorSetName -c `
    "\Processor(_Total)\% Processor Time" `
    "\System\Processor Queue Length" `
    "\Memory\Available Bytes" `
    "\Memory\Pages/sec" `
    "\Paging File(_Total)\% Usage" `
    "\LogicalDisk(*)\% Free Space" `
    "\LogicalDisk(*)\% Disk Time" `
    "\LogicalDisk(*)\Current Disk Queue Length" `
    "\LogicalDisk(*)\Avg. Disk sec/Read" `
    "\LogicalDisk(*)\Avg. Disk sec/Write" `
    "\LogicalDisk(*)\Avg. Disk sec/Transfer" `
    "\PhysicalDisk(*)\% Disk Time" `
    "\PhysicalDisk(*)\Current Disk Queue Length" `
    "\PhysicalDisk(*)\Avg. Disk sec/Read" `
    "\PhysicalDisk(*)\Avg. Disk sec/Write" `
    "\PhysicalDisk(*)\Avg. Disk sec/Transfer" `
    "\Network Interface(*)\Bytes Total/sec"

# Configure Data Collector Set properties
logman update -n $CollectorSetName -rf $LogRetention -f bin -o "$OutputPath\$CollectorSetName" -si $SampleInterval -v mmddhhmm

#-----------------------------------------------------------[Output]------------------------------------------------------------

# Output status and instructions
Write-Host "Data Collector Set '$CollectorSetName' has been created successfully." -ForegroundColor Green
Write-Host ""
Write-Host "Usage Instructions:" -ForegroundColor Yellow
Write-Host "1. To start collecting data: logman start -n $CollectorSetName" -ForegroundColor Cyan
Write-Host "2. To stop collecting data:  logman stop -n $CollectorSetName" -ForegroundColor Cyan
Write-Host "3. To view collected data:   Open Performance Monitor > Performance Monitor > Click 'View Log Data' icon > Select log file" -ForegroundColor Cyan
Write-Host "4. Log files are saved to:   $OutputPath" -ForegroundColor Cyan