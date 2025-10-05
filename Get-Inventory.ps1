#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Complete Windows 10 System Inventory Script
.DESCRIPTION
    Gathers comprehensive system information and exports to CSV files
.NOTES
    Requires Administrator privileges
    Author: Jacob Wilson
    Email: jwilson@agsi.us
    Date: 2025-10-05
#>

# Create output directory with timestamp
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$outputDir = "C:\SystemInventory_$timestamp"
New-Item -Path $outputDir -ItemType Directory -Force | Out-Null

Write-Host "Starting system inventory collection..." -ForegroundColor Green
Write-Host "Output directory: $outputDir" -ForegroundColor Cyan

# 1. Computer System Information
Write-Host "`nCollecting Computer System Information..." -ForegroundColor Yellow
$computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object Name, Domain, Manufacturer, Model, 
    NumberOfProcessors, NumberOfLogicalProcessors, TotalPhysicalMemory, UserName, DNSHostName, DomainRole, 
    PartOfDomain, Workgroup, SystemType, PCSystemType
$computerSystem | Export-Csv "$outputDir\01_ComputerSystem.csv" -NoTypeInformation

# 2. Operating System Information
Write-Host "Collecting Operating System Information..." -ForegroundColor Yellow
$os = Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber, 
    OSArchitecture, InstallDate, LastBootUpTime, LocalDateTime, RegisteredUser, Organization, SerialNumber, 
    CountryCode, CurrentTimeZone, FreePhysicalMemory, TotalVisibleMemorySize, FreeVirtualMemory, 
    TotalVirtualMemorySize, SystemDrive, WindowsDirectory
$os | Export-Csv "$outputDir\02_OperatingSystem.csv" -NoTypeInformation

# 3. BIOS Information
Write-Host "Collecting BIOS Information..." -ForegroundColor Yellow
$bios = Get-CimInstance -ClassName Win32_BIOS | Select-Object Manufacturer, Name, SerialNumber, Version, 
    ReleaseDate, SMBIOSBIOSVersion, SMBIOSMajorVersion, SMBIOSMinorVersion
$bios | Export-Csv "$outputDir\03_BIOS.csv" -NoTypeInformation

# 4. Processor Information
Write-Host "Collecting Processor Information..." -ForegroundColor Yellow
$processors = Get-CimInstance -ClassName Win32_Processor | Select-Object Name, Manufacturer, Description, 
    MaxClockSpeed, CurrentClockSpeed, NumberOfCores, NumberOfLogicalProcessors, AddressWidth, DataWidth, 
    Architecture, Family, L2CacheSize, L3CacheSize, ProcessorId, SocketDesignation, Status
$processors | Export-Csv "$outputDir\04_Processors.csv" -NoTypeInformation

# 5. Memory/RAM Information
Write-Host "Collecting Memory Information..." -ForegroundColor Yellow
$memory = Get-CimInstance -ClassName Win32_PhysicalMemory | Select-Object BankLabel, Capacity, Speed, 
    Manufacturer, PartNumber, SerialNumber, DeviceLocator, MemoryType, FormFactor, DataWidth, ConfiguredClockSpeed
$memory | Export-Csv "$outputDir\05_Memory.csv" -NoTypeInformation

# 6. Disk Drive Information
Write-Host "Collecting Disk Drive Information..." -ForegroundColor Yellow
$disks = Get-CimInstance -ClassName Win32_DiskDrive | Select-Object DeviceID, Model, Size, MediaType, 
    InterfaceType, Partitions, SerialNumber, Status, FirmwareRevision, BytesPerSector, TotalCylinders, 
    TotalHeads, TotalSectors, TotalTracks, TracksPerCylinder
$disks | Export-Csv "$outputDir\06_DiskDrives.csv" -NoTypeInformation

# 7. Logical Disk/Volume Information
Write-Host "Collecting Logical Disk Information..." -ForegroundColor Yellow
$logicalDisks = Get-CimInstance -ClassName Win32_LogicalDisk | Select-Object DeviceID, DriveType, FileSystem, 
    Size, FreeSpace, VolumeName, VolumeSerialNumber, Compressed, Description
$logicalDisks | Export-Csv "$outputDir\07_LogicalDisks.csv" -NoTypeInformation

# 8. Network Adapter Information
Write-Host "Collecting Network Adapter Information..." -ForegroundColor Yellow
$networkAdapters = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration | Where-Object {$_.IPEnabled -eq $true} | 
    Select-Object Description, MACAddress, IPAddress, IPSubnet, DefaultIPGateway, DNSDomain, DNSServerSearchOrder, 
    DHCPEnabled, DHCPServer, WINSPrimaryServer, WINSSecondaryServer, Index, InterfaceIndex
$networkAdapters | Export-Csv "$outputDir\08_NetworkAdapters.csv" -NoTypeInformation

# 9. Network Adapter Details (Physical)
Write-Host "Collecting Physical Network Adapter Details..." -ForegroundColor Yellow
$physicalAdapters = Get-CimInstance -ClassName Win32_NetworkAdapter | Where-Object {$_.PhysicalAdapter -eq $true} | 
    Select-Object Name, Manufacturer, Description, MACAddress, AdapterType, Speed, NetConnectionID, 
    NetConnectionStatus, DeviceID, GUID, PNPDeviceID
$physicalAdapters | Export-Csv "$outputDir\09_PhysicalNetworkAdapters.csv" -NoTypeInformation

# 10. Video Controller/GPU Information
Write-Host "Collecting Video Controller Information..." -ForegroundColor Yellow
$videoControllers = Get-CimInstance -ClassName Win32_VideoController | Select-Object Name, AdapterCompatibility, 
    AdapterRAM, DriverVersion, DriverDate, VideoProcessor, VideoModeDescription, CurrentRefreshRate, 
    MaxRefreshRate, MinRefreshRate, VideoArchitecture, CurrentHorizontalResolution, CurrentVerticalResolution, 
    CurrentBitsPerPixel, Status
$videoControllers | Export-Csv "$outputDir\10_VideoControllers.csv" -NoTypeInformation

# 11. Installed Software (64-bit)
Write-Host "Collecting Installed Software (64-bit)..." -ForegroundColor Yellow
$software64 = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | 
    Select-Object DisplayName, DisplayVersion, Publisher, InstallDate, InstallLocation, UninstallString, 
    EstimatedSize, HelpLink, URLInfoAbout | Where-Object {$_.DisplayName -ne $null}
$software64 | Export-Csv "$outputDir\11_InstalledSoftware_64bit.csv" -NoTypeInformation

# 12. Installed Software (32-bit on 64-bit OS)
Write-Host "Collecting Installed Software (32-bit)..." -ForegroundColor Yellow
$software32 = Get-ItemProperty HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | 
    Select-Object DisplayName, DisplayVersion, Publisher, InstallDate, InstallLocation, UninstallString, 
    EstimatedSize, HelpLink, URLInfoAbout | Where-Object {$_.DisplayName -ne $null}
$software32 | Export-Csv "$outputDir\12_InstalledSoftware_32bit.csv" -NoTypeInformation

# 13. Windows Updates/Hotfixes
Write-Host "Collecting Windows Updates..." -ForegroundColor Yellow
$hotfixes = Get-HotFix | Select-Object HotFixID, Description, InstalledBy, InstalledOn, Caption
$hotfixes | Export-Csv "$outputDir\13_WindowsUpdates.csv" -NoTypeInformation

# 14. Windows Features
Write-Host "Collecting Windows Features..." -ForegroundColor Yellow
$features = Get-WindowsOptionalFeature -Online | Select-Object FeatureName, State, RestartRequired
$features | Export-Csv "$outputDir\14_WindowsFeatures.csv" -NoTypeInformation

# 15. Services
Write-Host "Collecting Services..." -ForegroundColor Yellow
$services = Get-Service | Select-Object Name, DisplayName, Status, StartType, ServiceType, DependentServices, 
    RequiredServices, CanPauseAndContinue, CanShutdown, CanStop | Sort-Object DisplayName
$services | Export-Csv "$outputDir\15_Services.csv" -NoTypeInformation

# 16. Running Processes
Write-Host "Collecting Running Processes..." -ForegroundColor Yellow
$processes = Get-Process | Select-Object ProcessName, Id, CPU, WorkingSet, VirtualMemorySize, 
    StartTime, Path, Company, ProductVersion, FileVersion, Description, Handles, Threads | Sort-Object CPU -Descending
$processes | Export-Csv "$outputDir\16_RunningProcesses.csv" -NoTypeInformation

# 17. Startup Programs
Write-Host "Collecting Startup Programs..." -ForegroundColor Yellow
$startupPrograms = Get-CimInstance -ClassName Win32_StartupCommand | Select-Object Name, Command, Location, User
$startupPrograms | Export-Csv "$outputDir\17_StartupPrograms.csv" -NoTypeInformation

# 18. Local Users
Write-Host "Collecting Local User Accounts..." -ForegroundColor Yellow
$localUsers = Get-LocalUser | Select-Object Name, Enabled, Description, PasswordRequired, PasswordLastSet, 
    LastLogon, PasswordExpires, UserMayChangePassword, PasswordChangeableDate, AccountExpires, SID, PrincipalSource
$localUsers | Export-Csv "$outputDir\18_LocalUsers.csv" -NoTypeInformation

# 19. Local Groups
Write-Host "Collecting Local Groups..." -ForegroundColor Yellow
$localGroups = Get-LocalGroup | Select-Object Name, Description, SID, PrincipalSource, ObjectClass
$localGroups | Export-Csv "$outputDir\19_LocalGroups.csv" -NoTypeInformation

# 20. Shares
Write-Host "Collecting Network Shares..." -ForegroundColor Yellow
$shares = Get-SmbShare | Select-Object Name, Path, Description, ShareState, ScopeName, CurrentUsers, 
    EncryptData, FolderEnumerationMode, CachingMode, ContinuouslyAvailable
$shares | Export-Csv "$outputDir\20_NetworkShares.csv" -NoTypeInformation

# 21. Printers
Write-Host "Collecting Printer Information..." -ForegroundColor Yellow
$printers = Get-Printer | Select-Object Name, ComputerName, Type, DriverName, PortName, Shared, Published, 
    ShareName, Location, Comment, PrinterStatus, DeviceType
$printers | Export-Csv "$outputDir\21_Printers.csv" -NoTypeInformation

# 22. Scheduled Tasks
Write-Host "Collecting Scheduled Tasks..." -ForegroundColor Yellow
$scheduledTasks = Get-ScheduledTask | Select-Object TaskName, TaskPath, State, Author, Description, 
    @{Name='LastRunTime';Expression={$_.LastRunTime}}, @{Name='NextRunTime';Expression={$_.NextRunTime}}, 
    @{Name='Actions';Expression={$_.Actions | ForEach-Object {$_.Execute + " " + $_.Arguments}}}
$scheduledTasks | Export-Csv "$outputDir\22_ScheduledTasks.csv" -NoTypeInformation

# 23. Installed Drivers
Write-Host "Collecting Installed Drivers..." -ForegroundColor Yellow
$drivers = Get-WindowsDriver -Online | Select-Object Driver, OriginalFileName, ProviderName, Date, Version, 
    ClassName, ClassDescription, BootCritical
$drivers | Export-Csv "$outputDir\23_InstalledDrivers.csv" -NoTypeInformation

# 24. USB Devices
Write-Host "Collecting USB Device History..." -ForegroundColor Yellow
$usbDevices = Get-CimInstance -ClassName Win32_PnPEntity | Where-Object {$_.DeviceID -like "USB*"} | 
    Select-Object Name, DeviceID, Manufacturer, Status, PNPDeviceID, Description, Service
$usbDevices | Export-Csv "$outputDir\24_USBDevices.csv" -NoTypeInformation

# 25. Windows Defender Status
Write-Host "Collecting Windows Defender Status..." -ForegroundColor Yellow
try {
    $defenderStatus = Get-MpComputerStatus | Select-Object AMEngineVersion, AMProductVersion, AMServiceEnabled, 
        AntispywareEnabled, AntispywareSignatureLastUpdated, AntivirusEnabled, AntivirusSignatureLastUpdated, 
        BehaviorMonitorEnabled, ComputerState, FullScanAge, IoavProtectionEnabled, IsTamperProtected, 
        NISEnabled, NISSignatureLastUpdated, OnAccessProtectionEnabled, QuickScanAge, RealTimeProtectionEnabled
    $defenderStatus | Export-Csv "$outputDir\25_WindowsDefender.csv" -NoTypeInformation
} catch {
    Write-Host "Windows Defender information not available" -ForegroundColor Red
}

# 26. Firewall Status
Write-Host "Collecting Firewall Status..." -ForegroundColor Yellow
$firewallProfiles = Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, 
    DefaultOutboundAction, AllowInboundRules, AllowLocalFirewallRules, AllowLocalIPsecRules, 
    AllowUserApps, AllowUserPorts, AllowUnicastResponseToMulticast, NotifyOnListen, LogAllowed, 
    LogBlocked, LogIgnored, LogMaxSizeKilobytes, LogFileName
$firewallProfiles | Export-Csv "$outputDir\26_FirewallProfiles.csv" -NoTypeInformation

# 27. Environment Variables
Write-Host "Collecting Environment Variables..." -ForegroundColor Yellow
$envVars = Get-ChildItem Env: | Select-Object Name, Value
$envVars | Export-Csv "$outputDir\27_EnvironmentVariables.csv" -NoTypeInformation

# 28. Event Log Summary (System - Last 30 days)
Write-Host "Collecting System Event Log Summary..." -ForegroundColor Yellow
$systemEvents = Get-EventLog -LogName System -After (Get-Date).AddDays(-30) -EntryType Error,Warning | 
    Select-Object TimeGenerated, EntryType, Source, EventID, Message -First 1000
$systemEvents | Export-Csv "$outputDir\28_SystemEventLog_Recent.csv" -NoTypeInformation

# 29. Event Log Summary (Application - Last 30 days)
Write-Host "Collecting Application Event Log Summary..." -ForegroundColor Yellow
$appEvents = Get-EventLog -LogName Application -After (Get-Date).AddDays(-30) -EntryType Error,Warning | 
    Select-Object TimeGenerated, EntryType, Source, EventID, Message -First 1000
$appEvents | Export-Csv "$outputDir\29_ApplicationEventLog_Recent.csv" -NoTypeInformation

# 30. Windows Activation Status
Write-Host "Collecting Windows Activation Status..." -ForegroundColor Yellow
$activation = Get-CimInstance -ClassName SoftwareLicensingProduct | Where-Object {$_.PartialProductKey} | 
    Select-Object Name, Description, LicenseStatus, PartialProductKey, ProductKeyID
$activation | Export-Csv "$outputDir\30_WindowsActivation.csv" -NoTypeInformation

# 31. TPM Information
Write-Host "Collecting TPM Information..." -ForegroundColor Yellow
try {
    $tpm = Get-Tpm | Select-Object TpmPresent, TpmReady, TpmEnabled, TpmActivated, TpmOwned, 
        ManufacturerId, ManufacturerIdTxt, ManufacturerVersion, ManagedAuthLevel, OwnerAuth
    $tpm | Export-Csv "$outputDir\31_TPM.csv" -NoTypeInformation
} catch {
    Write-Host "TPM information not available" -ForegroundColor Red
}

# 32. BitLocker Status
Write-Host "Collecting BitLocker Status..." -ForegroundColor Yellow
try {
    $bitlocker = Get-BitLockerVolume | Select-Object MountPoint, VolumeType, VolumeStatus, EncryptionMethod, 
        AutoUnlockEnabled, AutoUnlockKeyStored, MetadataVersion, EncryptionPercentage, ProtectionStatus, 
        LockStatus, CapacityGB
    $bitlocker | Export-Csv "$outputDir\32_BitLocker.csv" -NoTypeInformation
} catch {
    Write-Host "BitLocker information not available" -ForegroundColor Red
}

# 33. Disk Partitions
Write-Host "Collecting Disk Partition Information..." -ForegroundColor Yellow
$partitions = Get-Partition | Select-Object DiskNumber, PartitionNumber, DriveLetter, Type, Size, Offset, 
    IsReadOnly, IsOffline, IsSystem, IsBoot, IsHidden, IsActive, IsShadowCopy, MbrType, GptType
$partitions | Export-Csv "$outputDir\33_DiskPartitions.csv" -NoTypeInformation

# 34. Volume Information (Detailed)
Write-Host "Collecting Volume Details..." -ForegroundColor Yellow
$volumes = Get-Volume | Select-Object DriveLetter, FileSystemLabel, FileSystem, DriveType, HealthStatus, 
    OperationalStatus, SizeRemaining, Size, DedupMode, AllocationUnitSize
$volumes | Export-Csv "$outputDir\34_Volumes.csv" -NoTypeInformation

# 35. Storage Controllers
Write-Host "Collecting Storage Controller Information..." -ForegroundColor Yellow
$storageControllers = Get-CimInstance -ClassName Win32_SCSIController | Select-Object Name, Manufacturer, 
    DeviceID, Status, DriverName, DriverVersion, HardwareVersion
$storageControllers | Export-Csv "$outputDir\35_StorageControllers.csv" -NoTypeInformation

# 36. Virtual Machine Detection
Write-Host "Collecting Virtualization Information..." -ForegroundColor Yellow
$vmDetection = Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object Manufacturer, Model, 
    @{Name='IsVirtualMachine';Expression={$_.Model -match 'Virtual|VMware|VBox|Hyper-V|KVM|Xen'}},
    @{Name='VirtualizationType';Expression={
        if ($_.Model -match 'VMware') {'VMware'}
        elseif ($_.Model -match 'Virtual') {'Hyper-V'}
        elseif ($_.Model -match 'VirtualBox|VBox') {'VirtualBox'}
        elseif ($_.Model -match 'KVM') {'KVM'}
        elseif ($_.Model -match 'Xen') {'Xen'}
        else {'Physical or Unknown'}
    }}
$vmDetection | Export-Csv "$outputDir\36_VirtualizationDetection.csv" -NoTypeInformation

# 37. Hyper-V Status (if applicable)
Write-Host "Collecting Hyper-V Status..." -ForegroundColor Yellow
try {
    $hyperv = Get-WindowsOptionalFeature -FeatureName Microsoft-Hyper-V-All -Online | 
        Select-Object FeatureName, State, RestartRequired
    $hyperv | Export-Csv "$outputDir\37_HyperV.csv" -NoTypeInformation
} catch {
    Write-Host "Hyper-V information not available" -ForegroundColor Red
}

# 38. Power Configuration
Write-Host "Collecting Power Configuration..." -ForegroundColor Yellow
$powerPlan = Get-CimInstance -Namespace root\cimv2\power -ClassName Win32_PowerPlan | Where-Object {$_.IsActive} | 
    Select-Object ElementName, Description, IsActive
$powerPlan | Export-Csv "$outputDir\38_PowerPlan.csv" -NoTypeInformation

# 39. Time Zone Configuration
Write-Host "Collecting Time Zone Information..." -ForegroundColor Yellow
$timezone = Get-TimeZone | Select-Object Id, DisplayName, StandardName, DaylightName, BaseUtcOffset, 
    SupportsDaylightSavingTime
$timezone | Export-Csv "$outputDir\39_TimeZone.csv" -NoTypeInformation

# 40. Regional Settings
Write-Host "Collecting Regional Settings..." -ForegroundColor Yellow
$culture = Get-Culture | Select-Object Name, DisplayName, EnglishName, TwoLetterISOLanguageName, 
    ThreeLetterISOLanguageName, KeyboardLayoutId, @{Name='DateFormat';Expression={$_.DateTimeFormat.ShortDatePattern}},
    @{Name='TimeFormat';Expression={$_.DateTimeFormat.ShortTimePattern}}
$culture | Export-Csv "$outputDir\40_RegionalSettings.csv" -NoTypeInformation

# 41. Windows Roles and Features (Detailed)
Write-Host "Collecting Windows Capabilities..." -ForegroundColor Yellow
$capabilities = Get-WindowsCapability -Online | Select-Object Name, State, Description
$capabilities | Export-Csv "$outputDir\41_WindowsCapabilities.csv" -NoTypeInformation

# 42. Network Binding Order
Write-Host "Collecting Network Binding Information..." -ForegroundColor Yellow
$networkBindings = Get-NetAdapterBinding | Select-Object Name, DisplayName, ComponentID, Enabled, 
    BindingType, InterfaceDescription
$networkBindings | Export-Csv "$outputDir\42_NetworkBindings.csv" -NoTypeInformation

# 43. DNS Client Configuration
Write-Host "Collecting DNS Client Settings..." -ForegroundColor Yellow
$dnsClient = Get-DnsClientServerAddress | Select-Object InterfaceAlias, InterfaceIndex, AddressFamily, 
    ServerAddresses
$dnsClient | Export-Csv "$outputDir\43_DNSClientSettings.csv" -NoTypeInformation

# 44. Routing Table
Write-Host "Collecting Routing Table..." -ForegroundColor Yellow
$routes = Get-NetRoute | Select-Object DestinationPrefix, NextHop, InterfaceIndex, InterfaceAlias, 
    RouteMetric, Protocol, AddressFamily, State, PreferredLifetime
$routes | Export-Csv "$outputDir\44_RoutingTable.csv" -NoTypeInformation

# 45. Installed Certificates
Write-Host "Collecting Certificate Information..." -ForegroundColor Yellow
$certs = Get-ChildItem -Path Cert:\LocalMachine\My | Select-Object Subject, Issuer, Thumbprint, 
    NotBefore, NotAfter, FriendlyName, HasPrivateKey, SerialNumber, EnhancedKeyUsageList
$certs | Export-Csv "$outputDir\45_Certificates.csv" -NoTypeInformation

# 46. Windows Update Configuration
Write-Host "Collecting Windows Update Configuration..." -ForegroundColor Yellow
try {
    $wuSettings = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -ErrorAction SilentlyContinue |
        Select-Object PSPath, PSChildName, *
    if ($wuSettings) {
        $wuSettings | Export-Csv "$outputDir\46_WindowsUpdateConfig.csv" -NoTypeInformation
    }
} catch {
    Write-Host "Windows Update policy settings not configured" -ForegroundColor Red
}

# 47. Page File Configuration
Write-Host "Collecting Page File Configuration..." -ForegroundColor Yellow
$pageFile = Get-CimInstance -ClassName Win32_PageFileUsage | Select-Object Name, AllocatedBaseSize, 
    CurrentUsage, PeakUsage, TempPageFile
$pageFile | Export-Csv "$outputDir\47_PageFile.csv" -NoTypeInformation

# 48. Boot Configuration
Write-Host "Collecting Boot Configuration..." -ForegroundColor Yellow
try {
    $bootConfig = bcdedit /enum | Out-String
    $bootConfig | Out-File "$outputDir\48_BootConfiguration.txt" -Encoding UTF8
} catch {
    Write-Host "Boot configuration not available" -ForegroundColor Red
}

# 49. System PATH Variable
Write-Host "Collecting System PATH..." -ForegroundColor Yellow
$systemPath = [Environment]::GetEnvironmentVariable("Path", "Machine") -split ";"
$pathObjects = $systemPath | ForEach-Object { [PSCustomObject]@{PathEntry = $_} }
$pathObjects | Export-Csv "$outputDir\49_SystemPath.csv" -NoTypeInformation

# 50. User PATH Variable
Write-Host "Collecting User PATH..." -ForegroundColor Yellow
$userPath = [Environment]::GetEnvironmentVariable("Path", "User") -split ";"
$userPathObjects = $userPath | ForEach-Object { [PSCustomObject]@{PathEntry = $_} }
$userPathObjects | Export-Csv "$outputDir\50_UserPath.csv" -NoTypeInformation

# 51. Windows Edition and Licensing Details
Write-Host "Collecting Windows Edition Details..." -ForegroundColor Yellow
$editionDetails = Get-ComputerInfo | Select-Object WindowsProductName, WindowsVersion, WindowsEditionId, 
    WindowsInstallationType, WindowsInstallDateFromRegistry, WindowsRegisteredOwner, WindowsRegisteredOrganization,
    WindowsSystemRoot, WindowsCurrentVersion, WindowsBuildLabEx, OsHardwareAbstractionLayer, OsProductType,
    OsServerLevel, OsType
$editionDetails | Export-Csv "$outputDir\51_WindowsEdition.csv" -NoTypeInformation

# 52. Network Adapter Advanced Properties
Write-Host "Collecting Network Adapter Advanced Properties..." -ForegroundColor Yellow
$adapterProperties = Get-NetAdapterAdvancedProperty | Select-Object Name, DisplayName, DisplayValue, 
    RegistryKeyword, RegistryValue, ValidDisplayValues
$adapterProperties | Export-Csv "$outputDir\52_NetworkAdapterProperties.csv" -NoTypeInformation

# 53. Windows Defender Exclusions
Write-Host "Collecting Windows Defender Exclusions..." -ForegroundColor Yellow
try {
    $defenderPrefs = Get-MpPreference | Select-Object ExclusionPath, ExclusionExtension, ExclusionProcess,
        DisableRealtimeMonitoring, DisableBehaviorMonitoring, DisableBlockAtFirstSeen, DisableIOAVProtection,
        DisablePrivacyMode, DisableScriptScanning, SubmitSamplesConsent, MAPSReporting
    $defenderPrefs | Export-Csv "$outputDir\53_WindowsDefenderExclusions.csv" -NoTypeInformation
} catch {
    Write-Host "Windows Defender preferences not available" -ForegroundColor Red
}

# 54. Installed .NET Versions
Write-Host "Collecting .NET Framework Versions..." -ForegroundColor Yellow
$dotnetVersions = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP' -Recurse | 
    Get-ItemProperty -Name Version, Release -ErrorAction SilentlyContinue | 
    Where-Object { $_.PSChildName -match '^(?!S)\p{L}'} | 
    Select-Object @{Name='Framework';Expression={$_.PSChildName}}, Version, Release
$dotnetVersions | Export-Csv "$outputDir\54_DotNetVersions.csv" -NoTypeInformation

# 55. COM+ Applications
Write-Host "Collecting COM+ Applications..." -ForegroundColor Yellow
try {
    $comApps = Get-CimInstance -Namespace "root/cimv2" -ClassName Win32_COMApplication -ErrorAction SilentlyContinue |
        Select-Object Name, Description, AppID, LocalService
    if ($comApps) {
        $comApps | Export-Csv "$outputDir\55_COMApplications.csv" -NoTypeInformation
    }
} catch {
    Write-Host "COM+ applications not available" -ForegroundColor Red
}

# Create Summary Report
Write-Host "`nCreating Summary Report..." -ForegroundColor Yellow
$summary = [PSCustomObject]@{
    ComputerName = $computerSystem.Name
    Domain = $computerSystem.Domain
    Manufacturer = $computerSystem.Manufacturer
    Model = $computerSystem.Model
    OS = $os.Caption
    OSVersion = $os.Version
    OSBuild = $os.BuildNumber
    InstallDate = $os.InstallDate
    LastBoot = $os.LastBootUpTime
    Processor = $processors[0].Name
    ProcessorCores = $processors[0].NumberOfCores
    TotalMemoryGB = [math]::Round($computerSystem.TotalPhysicalMemory / 1GB, 2)
    TotalDiskSpaceGB = [math]::Round(($disks | Measure-Object -Property Size -Sum).Sum / 1GB, 2)
    TotalInstalledPrograms = ($software64.Count + $software32.Count)
    TotalServices = $services.Count
    RunningProcesses = $processes.Count
    LocalUsers = $localUsers.Count
    InstalledUpdates = $hotfixes.Count
    InventoryDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
}

$summary | Export-Csv "$outputDir\00_Summary.csv" -NoTypeInformation
Write-Host "`n========================================" -ForegroundColor Green
Write-Host "Inventory Collection Complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green

$csvCount = (Get-ChildItem $outputDir -Filter *.csv | Measure-Object).Count
Write-Host "Total CSV files created: $csvCount" -ForegroundColor Cyan
Write-Host "Output location: $outputDir" -ForegroundColor Cyan

# Compress all files into a zip archive
Write-Host "`nCompressing inventory files..." -ForegroundColor Yellow
$zipFileName = "$env:COMPUTERNAME`_SystemInventory_$timestamp.zip"
$zipFilePath = "C:\$zipFileName"

try {
    Compress-Archive -Path "$outputDir\*" -DestinationPath $zipFilePath -CompressionLevel Optimal -Force
    Write-Host "Archive created successfully!" -ForegroundColor Green
    Write-Host "Zip file location: $zipFilePath" -ForegroundColor Cyan
    
    $zipSize = [math]::Round((Get-Item $zipFilePath).Length / 1MB, 2)
    Write-Host "Zip file size: $zipSize MB" -ForegroundColor Cyan
    
    Write-Host "`nOpening zip file location..." -ForegroundColor Yellow
    Invoke-Item "C:\"
} catch {
    Write-Host "Error creating zip file: $_" -ForegroundColor Red
    Write-Host "Opening CSV directory instead..." -ForegroundColor Yellow
    Invoke-Item $outputDir
}

Write-Host "`n========================================" -ForegroundColor Green
Write-Host "Summary:" -ForegroundColor Green
Write-Host "  CSV Files: $csvCount" -ForegroundColor White
Write-Host "  CSV Directory: $outputDir" -ForegroundColor White
Write-Host "  Zip Archive: $zipFilePath" -ForegroundColor White
Write-Host "========================================" -ForegroundColor Green