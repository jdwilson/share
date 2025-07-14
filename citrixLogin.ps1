# Citrix User Login Script
# Usage: .\CitrixLoginScript.ps1 [-Debug]

param(
    [switch]$Debug
)

# File paths
$networkExceptionFile = "\\<JDW:POPULATE>\share\scripts\login\exception.sites"
$localExceptionFile = "$env:APPDATA\LocalLow\Sun\Java\Deployment\security\exception.sites"

# Get current user and session information
$currentUser = $env:USERNAME
$computerName = $env:COMPUTERNAME
$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

# Detect Citrix session type
$sessionType = "Unknown"
if ($env:SESSIONNAME -match "ICA") {
    $sessionType = "Citrix ICA Session"
} elseif ($env:CLIENTNAME) {
    $sessionType = "Citrix Published App/Desktop"
}

# Debug logging function
function Write-DebugLog {
    param($Message)
    if ($Debug) {
        $logPath = "C:\Logs\CitrixLoginScript.log"
        $logEntry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - $Message"
        
        try {
            if (!(Test-Path "C:\Logs")) {
                New-Item -ItemType Directory -Path "C:\Logs" -Force -ErrorAction SilentlyContinue
            }
            Add-Content -Path $logPath -Value $logEntry -ErrorAction SilentlyContinue
            Write-Host "DEBUG: $Message"
        } catch {
            Write-Host "DEBUG: Failed to write to log - $($_.Exception.Message)"
        }
    }
}

# Main script execution
Write-DebugLog "Script started - User: $currentUser - Session: $sessionType"

try {
    # Check if network exception file exists
    if (!(Test-Path $networkExceptionFile)) {
        Write-DebugLog "ERROR: Network exception file not found: $networkExceptionFile"
        Exit 1
    }
    
    Write-DebugLog "Reading network exception file: $networkExceptionFile"
    
    # Read network exception file
    $networkExceptions = Get-Content -Path $networkExceptionFile -ErrorAction Stop
    Write-DebugLog "Found $($networkExceptions.Count) entries in network exception file"
    
    # Create local Java security directory if it doesn't exist
    $localSecurityDir = Split-Path $localExceptionFile -Parent
    if (!(Test-Path $localSecurityDir)) {
        Write-DebugLog "Creating local security directory: $localSecurityDir"
        New-Item -ItemType Directory -Path $localSecurityDir -Force -ErrorAction Stop
    }
    
    # Read existing local exception file (if it exists)
    $localExceptions = @()
    if (Test-Path $localExceptionFile) {
        $localExceptions = Get-Content -Path $localExceptionFile -ErrorAction Stop
        Write-DebugLog "Found $($localExceptions.Count) existing entries in local exception file"
    } else {
        Write-DebugLog "Local exception file does not exist, will create new one"
    }
    
    # Find entries that don't exist locally
    $newEntries = @()
    foreach ($networkEntry in $networkExceptions) {
        # Skip empty lines and comments
        if ([string]::IsNullOrWhiteSpace($networkEntry) -or $networkEntry.StartsWith("#")) {
            continue
        }
        
        # Check if entry already exists locally (case-insensitive)
        $entryExists = $false
        foreach ($localEntry in $localExceptions) {
            if ($localEntry.Trim() -eq $networkEntry.Trim()) {
                $entryExists = $true
                break
            }
        }
        
        if (!$entryExists) {
            $newEntries += $networkEntry
        }
    }
    
    # Append new entries to local file
    if ($newEntries.Count -gt 0) {
        Write-DebugLog "Adding $($newEntries.Count) new entries to local exception file"
        Add-Content -Path $localExceptionFile -Value $newEntries -ErrorAction Stop
        Write-DebugLog "Successfully updated local exception file"
    } else {
        Write-DebugLog "No new entries to add - local file is up to date"
    }
    
    Write-DebugLog "Script completed successfully"
    
} catch {
    Write-DebugLog "ERROR: $($_.Exception.Message)"
    if ($Debug) {
        Write-Host "Error occurred: $($_.Exception.Message)"
    }
    Exit 1
}

Exit 0