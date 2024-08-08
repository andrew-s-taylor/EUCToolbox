<#PSScriptInfo
.VERSION 2.3
.AUTHOR AndrewTaylor
.DESCRIPTION Creates an Intune application from a Winget Manifest
.GUID e5188412-edee-421f-b1b3-ba9612de3f0f
.COMPANYNAME 
.COPYRIGHT GPL
.TAGS intune aad
.LICENSEURI https://github.com/andrew-s-taylor/public/blob/main/LICENSE
.PROJECTURI https://github.com/andrew-s-taylor/public
.ICONURI 
.EXTERNALMODULEDEPENDENCIES powershell-yaml AzureADPreview IntuneWin32App
.REQUIREDSCRIPTS 
.EXTERNALSCRIPTDEPENDENCIES
.RELEASENOTES
#>
<#
.SYNOPSIS
  Creates an Intune application from a Winget Manifest
.DESCRIPTION
Complete end-end creation of application in Intune.
Creates AzureAD group for Install and Uninstall
Extracts information from Winget custom manifest

.INPUTS
Winget YAML URL
.OUTPUTS
None
.NOTES
  Version:        2.3
  Author:         Andrew Taylor
  Twitter:        @AndrewTaylor_2
  WWW:            andrewstaylor.com
  Creation Date:  12/11/2021
  Modified Date:  30/10/2022
  Purpose/Change: Initial script development
  Change:   Switched AAD to Graph Module
  
.EXAMPLE
N/A
#>
<#
  __ _  _ __    __| | _ __   ___ __      __ ___ | |_   __ _  _   _ | |  ___   _ __      ___   ___   _ __ ___
 / _` || '_ \  / _` || '__| / _ \\ \ /\ / // __|| __| / _` || | | || | / _ \ | '__|    / __| / _ \ | '_ ` _ \
| (_| || | | || (_| || |   |  __/ \ V  V / \__ \| |_ | (_| || |_| || || (_) || |    _ | (__ | (_) || | | | | |
 \__,_||_| |_| \__,_||_|    \___|  \_/\_/  |___/ \__| \__,_| \__, ||_| \___/ |_|   (_) \___| \___/ |_| |_| |_|

#>
####################################################


[CmdletBinding()]
param (
    [Parameter()]
    [String]$yamlFile,
    [string]$tenant #Tenant ID (optional) for when automating and you want to use across tenants instead of hard-coded
    ,
    [string]$clientid #ClientID is the type of Azure AD App Reg ID
    ,
    [string]$clientsecret #ClientSecret is the type of Azure AD App Reg Secret
    ,
    [string]$email #Email for confirmation
    ,
    [string]$sendgridtoken #Token for SendGrid
    ,
    [object] $WebHookData #Webhook data for Azure Automation
)

###############################################################################################################
######                                         Install Modules                                           ######
###############################################################################################################
Write-Host "Installing Intune modules if required (current user scope)"

#Install MS Graph if not available
if (Get-Module -ListAvailable -Name powershell-yaml) {
    Write-Host "PowerShell YAML Already Installed"
} 
else {
    try {
        Install-Module -Name powershell-yaml -Scope CurrentUser -Repository PSGallery -Force 
    }
    catch [Exception] {
        $_.message 
    }
}

Write-Host "Installing Microsoft Graph modules if required (current user scope)"

#Install MS Graph if not available
if (Get-Module -ListAvailable -Name Microsoft.Graph.authentication) {
    Write-Host "Microsoft Graph Already Installed"
} 
else {
    try {
        Install-Module -Name Microsoft.Graph.authentication -Scope CurrentUser -Repository PSGallery -Force 
    }
    catch [Exception] {
        $_.message 
    }
}

#Install MS Graph if not available
if (Get-Module -ListAvailable -Name Microsoft.Graph.groups) {
    Write-Host "Microsoft Graph Already Installed"
} 
else {
    try {
        Install-Module -Name Microsoft.Graph.groups -Scope CurrentUser -Repository PSGallery -Force 
    }
    catch [Exception] {
        $_.message 
    }
}


#Install IntuneWin32App  if not available
if (Get-Module -ListAvailable -Name IntuneWin32App ) {
    Write-Host "IntuneWin32App Module Already Installed"
} 
else {
    try {
        Install-Module -Name IntuneWin32App  -Scope CurrentUser -Repository PSGallery -Force -AllowClobber -AcceptLicense
    }
    catch [Exception] {
        $_.message 
    }
}

if (Get-Module -ListAvailable -Name SvRooij.ContentPrep.Cmdlet ) {
    Write-Host "ContentPrep Installed"

} 
else {

        Install-Module -Name SvRooij.ContentPrep.Cmdlet  -Scope CurrentUser -Repository PSGallery -Force 
    }


#Importing Modules
Import-Module -Name SvRooij.ContentPrep.Cmdlet

#Importing Modules
Import-Module powershell-yaml
import-module IntuneWin32App 
Import-Module microsoft.graph.authentication
import-module microsoft.graph.groups


###############################################################################################################
######                                         Add functions                                             ######
###############################################################################################################

function checkforgroup() {

    [cmdletbinding()]
        
    param
    (
        $groupname
    )

    $url = "https://graph.microsoft.com/beta/groups?`$filter=displayName eq '$groupname'"
    $group = ((Invoke-MgGraphRequest -Uri $url -Method GET -OutputType PSObject -SkipHttpErrorCheck).value) | Sort-Object createdDateTime -Descending | Select-Object -First 1
        return $group.id
}

Function Connect-ToGraph {
    <#
.SYNOPSIS
Authenticates to the Graph API via the Microsoft.Graph.Authentication module.
 
.DESCRIPTION
The Connect-ToGraph cmdlet is a wrapper cmdlet that helps authenticate to the Intune Graph API using the Microsoft.Graph.Authentication module. It leverages an Azure AD app ID and app secret for authentication or user-based auth.
 
.PARAMETER Tenant
Specifies the tenant (e.g. contoso.onmicrosoft.com) to which to authenticate.
 
.PARAMETER AppId
Specifies the Azure AD app ID (GUID) for the application that will be used to authenticate.
 
.PARAMETER AppSecret
Specifies the Azure AD app secret corresponding to the app ID that will be used to authenticate.

.PARAMETER Scopes
Specifies the user scopes for interactive authentication.
 
.EXAMPLE
Connect-ToGraph -TenantId $tenantID -AppId $app -AppSecret $secret
 
-#>
    [cmdletbinding()]
    param
    (
        [Parameter(Mandatory = $false)] [string]$Tenant,
        [Parameter(Mandatory = $false)] [string]$AppId,
        [Parameter(Mandatory = $false)] [string]$AppSecret,
        [Parameter(Mandatory = $false)] [string]$scopes
    )

    Process {
        Import-Module Microsoft.Graph.Authentication
        $version = (get-module microsoft.graph.authentication | Select-Object -expandproperty Version).major

        if ($AppId -ne "") {
            $body = @{
                grant_type    = "client_credentials";
                client_id     = $AppId;
                client_secret = $AppSecret;
                scope         = "https://graph.microsoft.com/.default";
            }
     
            $response = Invoke-RestMethod -Method Post -Uri https://login.microsoftonline.com/$Tenant/oauth2/v2.0/token -Body $body
            $accessToken = $response.access_token
     
            $accessToken
            if ($version -eq 2) {
                write-host "Version 2 module detected"
                $accesstokenfinal = ConvertTo-SecureString -String $accessToken -AsPlainText -Force
            }
            else {
                write-host "Version 1 Module Detected"
                Select-MgProfile -Name Beta
                $accesstokenfinal = $accessToken
            }
            $graph = Connect-MgGraph  -AccessToken $accesstokenfinal 
            Write-Host "Connected to Intune tenant $TenantId using app-based authentication (Azure AD authentication not supported)"
        }
        else {
            if ($version -eq 2) {
                write-host "Version 2 module detected"
            }
            else {
                write-host "Version 1 Module Detected"
                Select-MgProfile -Name Beta
            }
            $graph = Connect-MgGraph -scopes $scopes
            Write-Host "Connected to Intune tenant $($graph.TenantId)"
        }
    }
}    


function new-detectionscript {
    param
    (
        $appid,
        $appname,
        $yaml
    )
    $remediate = @'

    Invoke-WebRequest `
   -Uri SETYAML `
   -OutFile $templateFilePath `
   -UseBasicParsing `
   -Headers @{"Cache-Control"="no-cache"}

$ResolveWingetPath = Resolve-Path "C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller_*_x64__8wekyb3d8bbwe"
    if ($ResolveWingetPath){
        $WingetPath = $ResolveWingetPath[-1].Path
    }
        
    $Winget = $WingetPath + "\winget.exe"
    Start-Process -NoNewWindow -FilePath $winget -ArgumentList "settings --enable LocalManifestFiles"
    Start-Process -NoNewWindow -FilePath $winget -ArgumentList "upgrade --silent --manifest $templatefilepath"
'@
    $remediate2 = $remediate -replace "SETAPPID", $appid
    $remediate2 = $remediate -replace "SETYAML", $yaml

    return $remediate2

}

function new-proac {
    param
    (
        $appid,
        $appname,
        $groupid,
        $yaml
    )
    $detectscriptcontent = new-detectionscript -appid $appid -appname $appname -yaml $yaml
    $detect = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($detectscriptcontent))

    $DisplayName = $appname + " Upgrade"
    $Description = "Upgrade $appname application"
    ##RunAs can be "system" or "user"
    $RunAs = "system"
    ##True for 32-bit, false for 64-bit
    $RunAs32 = $false
    ##Daily or Hourly
    #$ScheduleType = "Hourly"
    ##How Often
    $ScheduleFrequency = "1"
    ##Start Time (if daily)
    #$StartTime = "01:00"
    
    $proacparams = @{
        publisher                = "Microsoft"
        displayName              = $DisplayName
        description              = $Description
        detectionScriptContent   = $detect
        remediationScriptContent = ""
        runAs32Bit               = $RunAs32
        enforceSignatureCheck    = $false
        runAsAccount             = $RunAs
        roleScopeTagIds          = @(
            "0"
        )
        isGlobalScript           = "false"
    }
    $paramsjson = $proacparams | convertto-json
    $graphApiVersion = "beta"
    $Resource = "deviceManagement/deviceHealthScripts"
    $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"

    $proactive = Invoke-MgGraphRequest -Uri $uri -Method POST -Body $paramsjson -ContentType "application/json"


    $assignparams = @{
        DeviceHealthScriptAssignments = @(
            @{
                target               = @{
                    "@odata.type" = "#microsoft.graph.groupAssignmentTarget"
                    groupId       = $groupid
                }
                runRemediationScript = $true
                runSchedule          = @{
                    "@odata.type" = "#microsoft.graph.deviceHealthScriptHourlySchedule"
                    interval      = $scheduleFrequency
                }
            }
        )
    }
    $assignparamsjson = $assignparams | convertto-json -Depth 10
    $remediationID = $proactive.ID
        
        
    $graphApiVersion = "beta"
    $Resource = "deviceManagement/deviceHealthScripts"
    $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource/$remediationID/assign"
        
    Invoke-MgGraphRequest -Uri $uri -Method POST -Body $assignparamsjson -ContentType "application/json"

    return "Success"

}

###############################################################################################################
######                                        Pre-Requisite Work                                         ######
###############################################################################################################


if ($WebHookData){
    $rawdata = $WebHookData.RequestBody
    $bodyData = ConvertFrom-Json -InputObject ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($rawdata)))
     $tenant = ((($bodyData.tenant) | out-string).trim())
    $clientid = ((($bodyData.clientid) | out-string).trim())
    $clientsecret = ((($bodyData.clientsecret) | out-string).trim())
    $yamlFile1 = ((($bodyData.yamlFile) | out-string).trim())
    $email = ((($bodyData.email) | out-string).trim())
    $sendgridtoken = ((($bodyData.sendgridtoken) | out-string).trim())
    ##Convert $yamlFile1 from base64 and store in $yamlFile
    $yamlFile = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($yamlFile1))

    write-output $bodyData

}
#Get Creds and connect
#Connect to Graph
if ($clientid -and $clientsecret -and $tenant) {

    Connect-ToGraph -Tenant $tenant -AppId $clientid -AppSecret $clientsecret
    write-output "Graph Connection Established"
    
    }
    else {
    
Connect-ToGraph -Scopes "RoleAssignmentSchedule.ReadWrite.Directory, Domain.Read.All, Domain.ReadWrite.All, Directory.Read.All, Policy.ReadWrite.ConditionalAccess, DeviceManagementApps.ReadWrite.All, DeviceManagementConfiguration.ReadWrite.All, DeviceManagementManagedDevices.ReadWrite.All, openid, profile, email, offline_access"
write-output "Graph Connection Established"

    }

#Get Tenant ID
write-output "Grabbing Tenant ID"
$uri = "https://graph.microsoft.com/beta/organization"
$tenantdetails = (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).value
$tenantid = $tenantdetails.id
write-output "Tenant ID is $tenantid"
write-output "Connecting to App Module"
if ($clientid -and $clientsecret -and $tenant) {
Connect-MSIntuneGraph -TenantID $tenantId -ClientID $clientid -ClientSecret $clientsecret
}
else {
    Connect-MSIntuneGraph -TenantID $tenantId 
}
write-output "Connected"

##Set Download Directory

$directory = $env:TEMP
#Create Temp location
$random = Get-Random -Maximum 1000 
$random = $random.ToString()
$date =get-date -format yyMMddmmss
$date = $date.ToString()
$path2 = $random + "-"  + $date
$path = $directory + "\" + $path2 + "\"
new-item -ItemType Directory -Path $path




$filename = $yamlFile.Substring($yamlFile.LastIndexOf("/") + 1)

##File Name
$templateFilePath = $path + $filename

###############################################################################################################
######                                          Download YAML                                            ######
###############################################################################################################
write-output "Downloading YAML from $yamlFile"
Invoke-WebRequest `
   -Uri $yamlFile `
   -OutFile $templateFilePath `
   -UseBasicParsing `
   -Headers @{"Cache-Control"="no-cache"}

   write-output "YAML Downloaded, manipulating"
[string[]]$fileContent = Get-Content $templateFilePath
$content = ''
foreach ($line in $fileContent) { $content = $content + "`n" + $line }
$obj = ConvertFrom-Yaml $content
$tags = $obj.Tags
foreach ($tag in $tags) {
    if ($tag -like '*ICON*') {
        $icon = $tag
    }
    if ($tag -like '*DETECTION*') {
        $detection = $tag
    }
    if ($tag -like 'UNINSTALLCOMMAND*') {
        $uninstall = $tag
    }
    if ($tag -like '*ADGROUPI*') {
        $adgroupi = $tag
    }
    if ($tag -like '*ADGROUPU*') {
        $adgroupu = $tag
    }
}

write-output "Fields grabbed"
$icon2 = $icon -split '='
$iconpath = $icon2[1]
$iconname = $iconpath.Substring($iconpath.LastIndexOf("/") + 1)
$icondownload = $path + $iconname

write-output "Downloading icon"
##Download Icon
Invoke-WebRequest `
   -Uri $iconpath `
   -OutFile $icondownload `
   -UseBasicParsing `
   -Headers @{"Cache-Control"="no-cache"}

   write-output "Icon Downloaded"

$detection2 = $detection -split '='
$detectionrule = $detection2[1]

$uninstall2 = $uninstall -split '='
$uninstallcommand = $uninstall2[1]

$adgroupi2 = $adgroupi -split '='
$adgroupinstall = $adgroupi2[1]

$adgroupu2 = $adgroupu -split '='
$adgroupuninstall = $adgroupu2[1]

$publisher = $obj.publisher
$name = $obj.packagename
$description = $obj.shortdescription
$appversion = $obj.PackageVersion
$infourl = $obj.PackageUrl

write-output "Publisher is $publisher"
write-output "App name is $name"
write-output "App version is $appversion"
    ##Strip spaces and special characters into $nameid
    $nameid = $name -replace '[^a-zA-Z0-9]', ''

$apppath = "$path\$nameid"
new-item -Path $apppath -ItemType Directory -Force

write-output "Checking for groups"
$groupname1 = $name + "-INSTALL"
    ##Check if groups exist
    $installgrptest = checkforgroup -groupname $adgroupinstall
    if ($installgrptest) {
        write-output "Install group exists, continuing"
        $installid = $installgrptest
    }
    else {
#Create Install Group
write-output "Install group does not exist, creating group"
$installgroup = New-MgGroup -DisplayName $adgroupinstall -Description "Install group for $name" -SecurityEnabled -MailEnabled:$false -MailNickName "group" 
$installid = $installgroup.id
write-output "Install group created"
    }

$groupname2 = $name + "-UNINSTALL"
#Create Uninstall Group
$uninstallgrptest = checkforgroup -groupname $adgroupuninstall
if ($uninstallgrptest) {
    write-output "Uninstall group exists, continuing"

    $uninstallid = $uninstallgrptest
}
else {
    write-output "Uninstall group does not exist, creating group"

$uninstallgroup = New-MgGroup -DisplayName $adgroupuninstall -Description "Uninstall group for $name" -SecurityEnabled -MailEnabled:$false -MailNickName "group" 
$uninstallid = $uninstallgroup.id
write-output "Uninstall group created"

}

write-output "Creating Setup file"
$setupfile = "$apppath\$name-Install.ps1"
$setupfilename = "$name-Install.ps1"
##Create Install File
Set-Content $setupfile @'

$filename2 = 
'@ -NoNewline
add-Content $setupfile @"
"$filename"
"@
add-Content $setupfile @'
$filename = $filename2.Substring($filename2.LastIndexOf("/") + 1)
   $curDir = Get-Location
   $filebase = Join-Path $curDir $filename
   $Winget = Get-ChildItem -Path (Join-Path -Path (Join-Path -Path $env:ProgramFiles -ChildPath "WindowsApps") -ChildPath "Microsoft.DesktopAppInstaller*_x64*\Winget.exe")
   Start-Process -NoNewWindow -FilePath $winget -ArgumentList "settings --enable LocalManifestFiles"
   Start-Process -NoNewWindow -FilePath $winget -ArgumentList "install --silent  --manifest $filename"

'@
write-output "File created"

write-output "Creating Detection fule"
$path4 = $detectionrule
$fname = $path4.Substring($path4.LastIndexOf("\") + 1)
$fpath = Split-Path -Path $path4

write-output "Rule created"

write-output "Creating intunewin"

    # Package as .intunewin file
    #New-IntuneWin32AppPackage -SourceFolder $SourceFolder -SetupFile $setupfilename -OutputFolder $OutputFolder -Verbose
    $intunewinpath = $path + "\install$nameid.intunewin"
    New-IntuneWinPackage -SourcePath "$apppath" -SetupFile "$setupfilename" -DestinationPath "$path" 
    Write-Host "Intunewin $intunewinpath Created"
    $sleep = 10
    foreach ($i in 0..$sleep) {
        Write-Progress -Activity "Sleeping for $($sleep-$i) seconds" -PercentComplete ($i / $sleep * 100) -SecondsRemaining ($sleep - $i)
        Start-Sleep -s 1
    }

    $IntuneWinFile = Get-ChildItem -Path  $path | Where-Object Name -Like "*.intunewin"
    $IntuneWinFile.Name

    # Create custom display name like 'Name' and 'Version'
    $DisplayName = $name

    # Create detection rule
    $DetectionRule = New-IntuneWin32AppDetectionRuleFile -Existence -Path "$fpath" -FileOrFolder $fname -Check32BitOn64System $false -DetectionType "exists"

write-output "Created"

    # Add new EXE Win32 app
    $InstallationScriptFile = Get-ChildItem -Path $path | Where-Object Name -Like "*-Install.ps1"
    $InstallCommandLine = "powershell.exe -ExecutionPolicy Bypass -File .\$($InstallationScriptFile.Name)"
    $UninstallCommandLine = $uninstallcommand
    $ImageFile = $icondownload
    $Icon = New-IntuneWin32AppIcon -FilePath $ImageFile

    write-output "Adding app to Intune"
    Add-IntuneWin32App -FilePath $IntuneWinFile.FullName -DisplayName $DisplayName -Description $description -Publisher $publisher -AppVersion $appversion -InformationURL $infourl -Icon $Icon -InstallExperience "system" -RestartBehavior "suppress" -DetectionRule $DetectionRule -InstallCommandLine $InstallCommandLine -UninstallCommandLine $UninstallCommandLine -Verbose
    write-output "App added"

    ##Assignments
    $Win32App = (Get-IntuneWin32App -DisplayName $DisplayName -Verbose)  | Sort-Object createdDateTime -Descending | Select-Object -First 1



    #Install
    write-output "Assigning install group"
Add-IntuneWin32AppAssignmentGroup -Include -ID $Win32App.id -GroupID $installid -Intent "available" -Notification "showAll" -Verbose
write-output "Install group assigned"


#Uninstall
write-output "Assigning uninstall group"
Add-IntuneWin32AppAssignmentGroup -Include -ID $Win32App.id -GroupID $uninstallid -Intent "uninstall" -Notification "showAll" -Verbose
write-output "Uninstall group assigned"

##Create Remediation
    ##Create Detection Script
    write-output "Creating Detection Script for $name"

    new-proac -appid $nameid -appname $name -groupid $installid -yaml $yamlFile

    write-output "Proac created"

    write-output "Complete"
    

#######################################################################################################################################
#########                                            Send Email                                ########################################
#######################################################################################################################################

if ($email) {

        ##Grab footer details using the API
        $footeruri = "https://euctoolbox.com/api?action=sponsors"
        $footer  = Invoke-RestMethod -Method GET -Uri $footeruri
    
        $footerhtml = @()
    
        foreach ($sponsor in $footer) {
            $sponsorurl = $sponsor.url
            $sponsorname = $sponsor.Name
            $sponsorlogo = $sponsor.logo
            $footerhtml += "<a href='$sponsorurl'><img src='$sponsorlogo' alt='$sponsorname' class='responsive-image'></a>"
    
        }
    $emailhtml = @"
<html>
<head>
<style>
table, td, div, h1, p {font-family: Roboto, sans-serif;}
h1 {color: #EB5D2F}
table#t01{
     border-collapse: collapse;
     border-width: 1px;
     border-color: black;
     border-style: solid;
}
table#t01 th{
     color: white;
     background-color: #EB5D2F;
     padding: 3px;
     border-width: 1px;
     border-color: black;
     border-style: solid;
}
table#t01 td{
     border-width: 1px;
     border-color: black;
     border-style: solid;
}
         .responsive-image {
  height: 50px; /* Set the desired height */
  width: auto;   /* Automatically adjust the width to maintain aspect ratio */
  padding:5px;
}
</style>
</head>
</head>
<body>
<body style="margin:0;padding:0;">
     <table role="presentation" style="width:100%;border-collapse:collapse;border:0;border-spacing:0;background:#ffffff;">
          <tr>
               <td align="center" style="padding:0;">
                    <table role="presentation" style="width:602px;border-collapse:collapse;border-spacing:0;text-align:left;">
                         <tr>
                              <td align="center" style="padding:30px 0;background:#EB5D2F;">
                                   <img src="https://baselinepolicy.blob.core.windows.net/images/combined.png" alt="" width="300" style="height:auto;display:block;" />
                              </td>
                         </tr>
                         <tr>
                              <td style="padding:30px 10px;background:#FFFFFF;">
                                   <h1>App Completed</h1>
                                   <p>Application $name has been successfully deployed to tenant $tenant
                                   <br>
                                   Thank you for using <a href="https://euctoolbox.com">EUC Toolbox</a></p>
                              </td>
                         </tr>
                         </table>
                                                      <p>Sponsored by: $footerhtml

</body>
"@

#Send Mail    
$Header = @{
    "authorization" = "Bearer $sendgridtoken"
}

##Email it
write-output "Sending Email"
$Body = @{
    "personalizations" = @(
        @{
            "to"      = @(
                @{
                    "email" = $email
                }
            )
            "subject" = " App $name deployed "
        }
    )
    "content"          = @(
        @{
            "type"  = "text/html"
            "value" = $emailhtml
        }
    )
    "from"             = @{
        "email" = "info@euctoolbox.com"
        "name"  = "EUC Toolbox"
    }
    
}

$bodytest = $body | ConvertTo-Json -Depth 4

#send the mail through Sendgrid
$Parameters = @{
    Method      = "POST"
    Uri         = "https://api.sendgrid.com/v3/mail/send"
    Headers     = $Header
    ContentType = "application/json"
    Body        = $bodytest
}
Invoke-RestMethod @Parameters
write-output "Email Sent"


}