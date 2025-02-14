    #requires -version 2
    <#
    .SYNOPSIS
      Configures User Settings
    
    .DESCRIPTION
      Configures:
      ADAL for OneDrive
      Unpins MS Store
      Sets background
    
    
    
    .INPUTS
     $regpath - The full registry path
     $regname - The name of the key
     $regvalue - The value of the key
     $regtype - either STRING or DWORD
    
    .OUTPUTS
      Log file stored in C:\Windows\Temp\build-user.log>
    
    .NOTES
      Version:        1.0
      Author:         Andrew S Taylor
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
    $sLogPath = "C:\Windows\Temp\build-user.log"
    
    #----------------------------------------------------------[Configurables]----------------------------------------------------------

    ####################### DO NOT EDIT BELOW HERE WITHOUT COMMENTING AND GIT CHANGE################################################
    
    ##-----------------------------------------------------------[Functions]------------------------------------------------------------
    
    Start-Transcript -Path $sLogPath
    
    #-----------------------------------------------------------[Execution]------------------------------------------------------------
    
    
    ## Enable OneDrive ADAL
    write-host "Enable ADAL"
    $registryPath = "HKCU:\SOFTWARE\Microsoft\OneDrive"
    $Name = "EnableADAL"
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
    
    
    #----------------------------------------------------------------------------------------------------------------------------------
    
    ##Set Desktop Background
    write-host "Setting Background"
    Set-ItemProperty -path 'HKCU:\Control Panel\Desktop\' -name wallpaper -value "c:\Windows\Web\Wallpaper\custombackground.jpg"
    
    rundll32.exe user32.dll, UpdatePerUserSystemParameters
    
    #----------------------------------------------------------------------------------------------------------------------------------
    
    Stop-Transcript