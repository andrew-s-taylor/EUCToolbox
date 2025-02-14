#Advanced Settings
Set-MpPreference -DisableTlsParsing $False
Set-MpPreference -AllowSwitchToAsyncInspection $true
Set-MpPreference -DisableBlockAtFirstSeen $False
Set-MpPreference -EnableDnsSinkhole $true 
Set-MpPreference -EnableFileHashComputation $true
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Value 1 -Force
