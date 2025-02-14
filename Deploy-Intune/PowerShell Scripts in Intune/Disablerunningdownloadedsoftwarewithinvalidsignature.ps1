$registryPath = "HKLM:SOFTWARE\Policies\Microsoft\Internet Explorer\Download"

$Name = "RunInvalidSignatures"
$value = "0"

IF(!(Test-Path $registryPath))

  {
    New-Item -Path $registryPath -Force | Out-Null
    New-ItemProperty -Path $registryPath -Name $name -Value $value -PropertyType String -Force | Out-Null}

 ELSE {
    New-ItemProperty -Path $registryPath -Name $name -Value $value -PropertyType string -Force | Out-Null}