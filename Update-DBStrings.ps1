<#
.SYNOPSIS
    Updates Citrix Virtual Apps and Desktops (CVAD) database connection strings.

.DESCRIPTION
    Prompts for a SQL Server FQDN and three database names (Site, Logging, Monitor),
    clears all existing DB connection strings, then configures new ones for all CVAD
    services using Integrated Security (Windows Authentication).

.NOTES
    Author  : Jacob Wilson (jwilson@agsi.us)
    Requires: CVAD PowerShell SDK Snap-ins
    Run As  : CVAD Administrator with DB permissions
#>

$ErrorActionPreference = "Continue"

$sqlServer  = Read-Host "SQL Server (FQDN)"
$siteDBName = Read-Host "Site Database Name"
$logDBName  = Read-Host "Logging Database Name"
$monDBName  = Read-Host "Monitoring Database Name"

$cs    = "Server=$sqlServer;Initial Catalog=$siteDBName;Integrated Security=True"
$csLog = "Server=$sqlServer;Initial Catalog=$logDBName;Integrated Security=True"
$csMon = "Server=$sqlServer;Initial Catalog=$monDBName;Integrated Security=True"

Add-PSSnapin Citrix* -ErrorAction SilentlyContinue

function Clear-DBConnections {
    Write-Host "Clearing all DB connection strings..."
    try {
        Set-AdminDBConnection      -DBConnection $null
        Set-ConfigDBConnection     -DBConnection $null
        Set-AcctDBConnection       -DBConnection $null
        Set-AnalyticsDBConnection  -DBConnection $null
        Set-AppLibDBConnection     -DBConnection $null
        Set-BrokerDBConnection     -DBConnection $null
        Set-EnvTestDBConnection    -DBConnection $null
        Set-HypDBConnection        -DBConnection $null
        Set-OrchDBConnection       -DBConnection $null
        Set-ProvDBConnection       -DBConnection $null
        Set-SfDBConnection         -DBConnection $null
        Set-TrustDBConnection      -DBConnection $null
        # --- Logging DB ---
        Set-LogDBConnection     -DataStore Logging -DBConnection $null
        # --- Monitor DB ---
        Set-MonitorDBConnection -DataStore Monitor -DBConnection $null
    }
    catch {
        Write-Error $_.Exception.Message -ErrorAction Continue
    }
    Write-Host "DB connection strings cleared."
}

function Set-DBConnections {
    Write-Host "Setting DB connection strings..."
    try {
        # --- Site DB ---
        Set-AdminDBConnection      -DBConnection $cs
        Set-ConfigDBConnection     -DBConnection $cs
        Set-AcctDBConnection       -DBConnection $cs
        Set-AnalyticsDBConnection  -DBConnection $cs
        Set-AppLibDBConnection     -DBConnection $cs
        Set-BrokerDBConnection     -DBConnection $cs
        Set-EnvTestDBConnection    -DBConnection $cs
        Set-HypDBConnection        -DBConnection $cs
        Set-OrchDBConnection       -DBConnection $cs
        Set-ProvDBConnection       -DBConnection $cs
        Set-SfDBConnection         -DBConnection $cs
        Set-TrustDBConnection      -DBConnection $cs
        # --- Logging DB ---
        Set-LogDBConnection     -DataStore Logging -DBConnection $csLog
        # --- Monitor DB ---
        Set-MonitorDBConnection -DataStore Monitor -DBConnection $csMon
    }
    catch {
        Write-Error $_.Exception.Message -ErrorAction Continue
    }
    Write-Host "DB connection strings updated."
}

Clear-DBConnections
Set-DBConnections

Write-Host "Script Execution Complete"
