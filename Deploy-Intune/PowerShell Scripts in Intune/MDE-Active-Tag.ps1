$registryPath = "HKLM:SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection\DeviceTagging"

$Name = "Group"
$value = "MDE-Active"

IF(!(Test-Path $registryPath))

  {
    New-Item -Path $registryPath -Force | Out-Null
    New-ItemProperty -Path $registryPath -Name $name -Value $value -PropertyType String -Force | Out-Null}

 ELSE {
    New-ItemProperty -Path $registryPath -Name $name -Value $value -PropertyType string -Force | Out-Null}