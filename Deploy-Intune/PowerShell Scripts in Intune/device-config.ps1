    #requires -version 2
    <#
    .SYNOPSIS
      Sets all config for a new build
    
    .DESCRIPTION
      Sets the following:
      Configured MS OneDrive
      Allows Printer installs
      Disable FastBoot
      Set OneDrive Known Folder Move
      Configures background image
    
    
    .INPUTS
     $regpath - The full registry path
     $regname - The name of the key
     $regvalue - The value of the key
     $regtype - either STRING or DWORD
    
    .OUTPUTS
      Log file stored in C:\Windows\Temp\build-device.log>
    
    .NOTES
      Version:        1.0
      Author:         Andrew Taylor
      Creation Date:  11/08/2022
      Purpose/Change: Initial script development
      
    .EXAMPLE
      addregkey($path, "Test", "1", "DWORD")
    #>
    
    #---------------------------------------------------------[Initialisations]--------------------------------------------------------
    
    #Set Error Action to Silently Continue
    $ErrorActionPreference = "SilentlyContinue"
    
    
    #----------------------------------------------------------[Declarations]----------------------------------------------------------
    
    #Script Version
    $sScriptVersion = "1.0"
    
    #Log File Info
    $sLogPath = "C:\Windows\Temp\build-device.log"
    
    #----------------------------------------------------------[Configurables]----------------------------------------------------------
    ################################################## SET THESE FOR EACH CLIENT ###############################################
    
    
    ##No special characters
    $clientname = "AndrewSTaylor.com"
        
    
    ####################### DO NOT EDIT BELOW HERE WITHOUT COMMENTING AND GIT CHANGE################################################
    #-----------------------------------------------------------[Functions]------------------------------------------------------------
    
    start-transcript -path $sLogPath
    
    
    
    #-----------------------------------------------------------[Execution]------------------------------------------------------------
    
    ## Configure OneDrive
    write-host "Configuring OneDrive"
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\OneDrive"
    $Name = "SilentAccountConfig"
    $value = "1"
    $Type = "DWORD"
    IF(!(Test-Path $registryPath))
    {
    New-Item -Path $registryPath -Force | Out-Null
    New-ItemProperty -Path $registryPath -Name $Name -Value $value `
    -PropertyType $Type -Force | Out-Null}
    ELSE {
    New-ItemProperty -Path $registryPath -Name $Name -Value $value `
    -PropertyType $Type -Force | Out-Null}
    
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\OneDrive"
    $Name = "FilesOnDemandEnabled"
    $value = "1"
    $Type = "DWORD"
    IF(!(Test-Path $registryPath))
    {
    New-Item -Path $registryPath -Force | Out-Null
    New-ItemProperty -Path $registryPath -Name $Name -Value $value `
    -PropertyType $Type -Force | Out-Null}
    ELSE {
    New-ItemProperty -Path $registryPath -Name $Name -Value $value `
    -PropertyType $Type -Force | Out-Null}
    #-----------------------------------------------------------------------------------------------------------------------------------
    
    
    ## Allow Printer Installs
    
    write-host "Configuring Printers"
    $registryPath = "HKLM:\Software\Policies\Microsoft\Windows\DriverInstall\Restrictions"
    $Name = "AllowUserDeviceClasses"
    $value = "1"
    $Type = "DWORD"
    IF(!(Test-Path $registryPath))
    {
    New-Item -Path $registryPath -Force | Out-Null
    New-ItemProperty -Path $registryPath -Name $Name -Value $value `
    -PropertyType $Type -Force | Out-Null}
    ELSE {
    New-ItemProperty -Path $registryPath -Name $Name -Value $value `
    -PropertyType $Type -Force | Out-Null}
    
    
    $registryPath = "HKLM:\Software\Policies\Microsoft\Windows\DriverInstall\Restrictions\AllowUserDeviceClasses"
    $Name = "{4658ee7e-f050-11d1-b6bd-00c04fa372a7}"
    $value = ""
    $Type = "String"
    IF(!(Test-Path $registryPath))
    {
    New-Item -Path $registryPath -Force | Out-Null
    New-ItemProperty -Path $registryPath -Name $Name -Value $value `
    -PropertyType $Type -Force | Out-Null}
    ELSE {
    New-ItemProperty -Path $registryPath -Name $Name -Value $value `
    -PropertyType $Type -Force | Out-Null}
    
    
    $registryPath = "HKLM:\Software\Policies\Microsoft\Windows\DriverInstall\Restrictions\AllowUserDeviceClasses"
    $Name = "{4d36e979-e325-11ce-bfc1-08002be10318}"
    $value = ""
    $Type = "String"
    IF(!(Test-Path $registryPath))
    {
    New-Item -Path $registryPath -Force | Out-Null
    New-ItemProperty -Path $registryPath -Name $Name -Value $value `
    -PropertyType $Type -Force | Out-Null}
    ELSE {
    New-ItemProperty -Path $registryPath -Name $Name -Value $value `
    -PropertyType $Type -Force | Out-Null}
    
    #-----------------------------------------------------------------------------------------------------------------------------------
    
    
    ## Disable FastBoot
    write-host "Disable FastBoot"
    $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power"
    $Name = "HiberbootEnabled"
    $value = "0"
    $Type = "DWORD"
    IF(!(Test-Path $registryPath))
    {
    New-Item -Path $registryPath -Force | Out-Null
    New-ItemProperty -Path $registryPath -Name $Name -Value $value `
    -PropertyType $Type -Force | Out-Null}
    ELSE {
    New-ItemProperty -Path $registryPath -Name $Name -Value $value `
    -PropertyType $Type -Force | Out-Null}
    
    #-----------------------------------------------------------------------------------------------------------------------------------
    
    #-----------------------------------------------------------------------------------------------------------------------------------
    ###Additional Security Keys
    
    ## Set Login Cache to One
    write-host "Configuring Cached Count"
    $registryPath = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
    $Name = "CachedLogonsCount"
    $value = "1"
    $Type = "string"
    IF(!(Test-Path $registryPath))
    {
    New-Item -Path $registryPath -Force | Out-Null
    New-ItemProperty -Path $registryPath -Name $Name -Value $value `
    -PropertyType $Type -Force | Out-Null}
    ELSE {
    New-ItemProperty -Path $registryPath -Name $Name -Value $value `
    -PropertyType $Type -Force | Out-Null}
    
    
    ## Set DLLSearch to value of 1
    write-host "Configuring DLL Search"
    $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"
    $Name = "CWDIllegalInDllSearch"
    $value = "1"
    $Type = "DWORD"
    IF(!(Test-Path $registryPath))
    {
    New-Item -Path $registryPath -Force | Out-Null
    New-ItemProperty -Path $registryPath -Name $Name -Value $value `
    -PropertyType $Type -Force | Out-Null}
    ELSE {
    New-ItemProperty -Path $registryPath -Name $Name -Value $value `
    -PropertyType $Type -Force | Out-Null}
    
    ## Enable Cert Padding Check for Wintrust 64-bit key
    write-host "Enable Cert Padding Check for Wintrust 64-bit key"
    $registryPath = "HKLM:\Software\Microsoft\Cryptography\Wintrust\Config"
    $Name = "EnableCertPaddingCheck"
    $value = "1"
    $Type = "DWORD"
    IF(!(Test-Path $registryPath))
    {
    New-Item -Path $registryPath -Force | Out-Null
    New-ItemProperty -Path $registryPath -Name $Name -Value $value `
    -PropertyType $Type -Force | Out-Null}
    ELSE {
    New-ItemProperty -Path $registryPath -Name $Name -Value $value `
    -PropertyType $Type -Force | Out-Null}
    
    ## Enable Cert Padding Check for Wintrust 32-bit key
    write-host "Enable Cert Padding Check for Wintrust 32-bit key"
    $registryPath = "HKLM:\Software\Wow6432Node\Microsoft\Cryptography\Wintrust\Config"
    $Name = "EnableCertPaddingCheck"
    $value = "1"
    $Type = "DWORD"
    IF(!(Test-Path $registryPath))
    {
    New-Item -Path $registryPath -Force | Out-Null
    New-ItemProperty -Path $registryPath -Name $Name -Value $value `
    -PropertyType $Type -Force | Out-Null}
    ELSE {
    New-ItemProperty -Path $registryPath -Name $Name -Value $value `
    -PropertyType $Type -Force | Out-Null}
    
    #-----------------------------------------------------------------------------------------------------------------------------------
    
    
    ##Add Build Reg Keys
    write-host "Adding Reg Keys"
    $registryPath = "HKLM:\Software\BuildDetails"
    
    $CurrentComputerName = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName").ComputerName
    $major = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").CurrentMajorVersionNumber
    $version = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").ReleaseId
    $build = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").CurrentBuildNumber
    $release = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").UBR
    $edition = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").EditionID
    $installationtype = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").InstallationType
    $productname = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").ProductName
    
    $fullversion = $major + ".0." + $build + "." + $release
    $fulledition = $productname + " " + $edition
    
    
    $Name1 = "WinVersion"
    $value1 = $fullversion
    $Name2 = "OS"
    $value2 = $fulledition
    $Name4 = "Client"
    $value4 = $clientname
    $Name6 = "DatePCBuilt"
    $value6 = get-date
    $Name7 = "Serial"
    $serial = Get-WmiObject win32_bios
    $value7 = $serial.SerialNumber
    $Name8 = "PCName"
    $value8 = $CurrentComputerName
    
    
    IF(!(Test-Path $registryPath))
    
      {
    
        New-Item -Path $registryPath -Force | Out-Null
    
        New-ItemProperty -Path $registryPath -Name $Name1 -Value $value1 -PropertyType String -Force | Out-Null
        New-ItemProperty -Path $registryPath -Name $Name2 -Value $value2 -PropertyType String -Force | Out-Null
        New-ItemProperty -Path $registryPath -Name $Name4 -Value $value4 -PropertyType String -Force | Out-Null
        New-ItemProperty -Path $registryPath -Name $Name6 -Value $value6 -PropertyType String -Force | Out-Null
        New-ItemProperty -Path $registryPath -Name $Name7 -Value $value7 -PropertyType String -Force | Out-Null
        New-ItemProperty -Path $registryPath -Name $Name8 -Value $value8 -PropertyType String -Force | Out-Null
        }
    
     ELSE {
    
        New-ItemProperty -Path $registryPath -Name $Name1 -Value $value1 -PropertyType String -Force | Out-Null
        New-ItemProperty -Path $registryPath -Name $Name2 -Value $value2 -PropertyType String -Force | Out-Null
        New-ItemProperty -Path $registryPath -Name $Name4 -Value $value4 -PropertyType String -Force | Out-Null
        New-ItemProperty -Path $registryPath -Name $Name6 -Value $value6 -PropertyType String -Force | Out-Null
        New-ItemProperty -Path $registryPath -Name $Name7 -Value $value7 -PropertyType String -Force | Out-Null
        New-ItemProperty -Path $registryPath -Name $Name8 -Value $value8 -PropertyType String -Force | Out-Null
    
        }
    
    
    
    #-----------------------------------------------------------------------------------------------------------------------------------
    
    ##Set Background
    ##Include File Extension:
    
    
    write-host "Download Desktop Images"
    #Open the folder en Windows Explorer under C:\Users\USERNAME\AppData\Roaming\CustomerXXXX
    ########################################################################################
    $path = [Environment]::GetFolderPath('ApplicationData') + "\" + $clientname
    
    If(!(test-path $path))
    {
          New-Item -ItemType Directory -Force -Path $path
    }
    ########################################################################################
    
    $newpath = "c:\Windows\Web\Wallpaper"
    
    #Save the bas64 to image file
    ########################################################################################
    $bytes = [System.Convert]::FromBase64String("")
    $file = "C:\Windows\Web\wallpaper\custombackground.jpg"

    [System.IO.File]::WriteAllBytes($file, $bytes)
    
    ########################################################################################
    
    
    write-host "Set Lockscreen"
    
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization"
    $img =  "C:\Windows\Web\Wallpaper\custombackground.jpg"
    $Name = "LockScreenImage"
    $value = "1"
    $Type = "String"
    IF(!(Test-Path $registryPath))
    {
    New-Item -Path $registryPath -Force | Out-Null
    New-ItemProperty -Path $registryPath -Name $Name -Value $img `
    -PropertyType $Type -Force | Out-Null}
    ELSE {
    New-ItemProperty -Path $registryPath -Name $Name -Value $img `
    -PropertyType $Type -Force | Out-Null}
    $RegKeyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP"
    $DesktopPath = "DesktopImagePath"
    $DesktopStatus = "DesktopImageStatus"
    $DesktopUrl = "DesktopImageUrl"
    
    $StatusValue = "1"
    
    New-ItemProperty -Path $RegKeyPath -Name $DesktopStatus -Value $StatusValue -PropertyType DWORD -Force
    New-ItemProperty -Path $RegKeyPath -Name $DesktopPath -Value $img -PropertyType STRING -Force
    New-ItemProperty -Path $RegKeyPath -Name $DesktopUrl -Value $img -PropertyType STRING -Force
    
    #-----------------------------------------------------------------------------------------------------------------------------------
    
    ## Stop Logging
    stop-transcript
    