<#PSScriptInfo
.VERSION 1.0.0
.GUID 992177a9-f4a4-443e-b871-ea071d5baae8
.AUTHOR AndrewTaylor
.DESCRIPTION Creates Win32 apps, AAD groups and Proactive Remediations to keep apps updated
.COMPANYNAME 
.COPYRIGHT GPL
.TAGS intune endpoint MEM environment winget win32
.LICENSEURI https://github.com/andrew-s-taylor/public/blob/main/LICENSE
.PROJECTURI https://github.com/andrew-s-taylor/public
.ICONURI 
.EXTERNALMODULEDEPENDENCIES
.REQUIREDSCRIPTS 
.EXTERNALSCRIPTDEPENDENCIES 
.RELEASENOTES
#>
<#
.SYNOPSIS
  Creates and uploads a win32 app from Winget
.DESCRIPTION
.Receives app details via webhook
.Creates Intunewin
.Creates AAD Groups
.Creates Proactive Remediations (for auto updates)
.Uploads and assigns everything
.Special thanks to Nick Brown (https://twitter.com/techienickb) for re-writing functions to use MG.graph

.INPUTS
App ID and App name 
.OUTPUTS

.NOTES
  Version:        1.0.0
  Author:         Andrew Taylor
  Twitter:        @AndrewTaylor_2
  WWW:            andrewstaylor.com
  Creation Date:  07/08/2024
.EXAMPLE
N/A
#>

<#
  __ _  _ __    __| | _ __   ___ __      __ ___ | |_   __ _  _   _ | |  ___   _ __      ___   ___   _ __ ___
 / _` || '_ \  / _` || '__| / _ \\ \ /\ / // __|| __| / _` || | | || | / _ \ | '__|    / __| / _ \ | '_ ` _ \
| (_| || | | || (_| || |   |  __/ \ V  V / \__ \| |_ | (_| || |_| || || (_) || |    _ | (__ | (_) || | | | | |
 \__,_||_| |_| \__,_||_|    \___|  \_/\_/  |___/ \__| \__,_| \__, ||_| \___/ |_|   (_) \___| \___/ |_| |_| |_|

#>


##########################################################################################

##################################################################################################################################
#################                                                  PARAMS                                        #################
##################################################################################################################################

[cmdletbinding()]
    
param
(
    [string]$appid #The Winget App ID
    ,  
    [string]$appname #The exact Winget Name
    , 
    [string]$tenant #Tenant ID (optional) for when automating and you want to use across tenants instead of hard-coded
    ,
    [string]$clientid #ClientID is the type of Azure AD App Reg ID
    ,
    [string]$clientsecret #ClientSecret is the type of Azure AD App Reg Secret
    ,
    [string]$installgroupname #Group Name for Installation
    ,
    [string]$uninstallgroupname #Uninstall group name
    ,
    [string]$availableinstall #Make available as well, can be Users, Devices, Both or None - default is None
    ,
    [string]$email #Email for confirmation
    ,
    [string]$appversion #App version
    ,
    [string]$sendgridtoken #Sendgrid token for emails
    ,
    [object] $WebHookData #Webhook data for Azure Automation

    )

##WebHook Data

if ($WebHookData){

    $rawdata = $WebHookData.RequestBody
    $bodyData = ConvertFrom-Json -InputObject ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($rawdata)))
$appid = ((($bodyData.appid) | out-string).trim())
$appname = ((($bodyData.appname) | out-string).trim())
$tenant = ((($bodyData.tenant) | out-string).trim())
$clientid = ((($bodyData.clientid) | out-string).trim())
$clientsecret = ((($bodyData.clientsecret) | out-string).trim())
$installgroupname = ((($bodyData.installgroupname) | out-string).trim())
$uninstallgroupname = ((($bodyData.uninstallgroupname) | out-string).trim())
$reponame = ((($bodyData.reponame) | out-string).trim())
$ownername = ((($bodyData.ownername) | out-string).trim())
$token = ((($bodyData.token) | out-string).trim())
$project = ((($bodyData.project) | out-string).trim())
$repotype = ((($bodyData.repotype) | out-string).trim())
$availableinstall = ((($bodyData.availableinstall) | out-string).trim())
$email = ((($bodyData.email) | out-string).trim())
$appversion = ((($bodyData.appversion) | out-string).trim())
$sendgridtoken = ((($bodyData.sendgridtoken) | out-string).trim())

$keycheck = ((($bodyData.webhooksecret) | out-string).trim())

##Lets add some security, check if a password has been sent in the header

##Set my password
$webhooksecret = ""

##Check if the password is correct
if ($keycheck -ne $webhooksecret) {
    write-output "Webhook password incorrect, exiting"
    exit
}

}

##Check if Available Install is set, if not set to None
if ((!$availableinstall)) {
    write-output "Available Not Set"
$availableinstall = "None"
}

write-output $availableinstall
$ErrorActionPreference = "Continue"
##Start Logging to %TEMP%\intune.log
$date = get-date -format ddMMyyyy
Start-Transcript -Path $env:TEMP\intune-$date.log

##Add custom logging for runbook
$Logfile = "$env:TEMP\intuneauto-$date.log"
function WriteLog
{
Param ([string]$LogString)
$Stamp = (Get-Date).toString("yyyy/MM/dd HH:mm:ss")
$LogMessage = "$Stamp $LogString \n"
Add-content $LogFile -value $LogMessage
}

###############################################################################################################
######                                         Install Modules                                           ######
###############################################################################################################
Write-Host "Installing Intune modules if required (current user scope)"
writelog "Installing Intune modules if required (current user scope)"

Write-Host "Installing Intune modules if required (current user scope)"
writelog "Installing Intune modules if required (current user scope)"

#Install MS Graph if not available
if (Get-Module -ListAvailable -Name powershell-yaml) {
    Write-Host "PowerShell YAML Already Installed"
    writelog "PowerShell YAML Already Installed"

} 
else {

        Install-Module -Name powershell-yaml -Scope CurrentUser -Repository PSGallery -Force 

}

Write-Host "Installing Microsoft Graph modules if required (current user scope)"
writelog "Installing Microsoft Graph modules if required (current user scope)"


#Install MS Graph if not available
if (Get-Module -ListAvailable -Name Microsoft.Graph.Groups) {
    Write-Host "Microsoft Graph Already Installed"
    writelog "Microsoft Graph Already Installed"

} 
else {

        Install-Module -Name Microsoft.Graph.Groups -Scope CurrentUser -Repository PSGallery -Force 

}

#Install MS Graph if not available
if (Get-Module -ListAvailable -Name Microsoft.Graph.DeviceManagement) {
    Write-Host "Microsoft Graph Already Installed"
    writelog "Microsoft Graph Already Installed"

} 
else {

        Install-Module -Name Microsoft.Graph.DeviceManagement -Scope CurrentUser -Repository PSGallery -Force 

}

#Install MS Graph if not available
if (Get-Module -ListAvailable -Name Microsoft.Graph.Intune) {
    Write-Host "Microsoft Graph Already Installed"
    writelog "Microsoft Graph Already Installed"

} 
else {

        Install-Module -Name Microsoft.Graph.Intune -Scope CurrentUser -Repository PSGallery -Force 

}

#Install MS Graph if not available
if (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication) {
    Write-Host "Microsoft Graph Already Installed"
    writelog "Microsoft Graph Already Installed"

} 
else {

        Install-Module -Name Microsoft.Graph.Authentication -Scope CurrentUser -Repository PSGallery -Force 

}

#Install MS Graph if not available
if (Get-Module -ListAvailable -Name microsoft.graph.devices.corporatemanagement ) {
    Write-Host "Microsoft Graph Already Installed"
    writelog "Microsoft Graph Already Installed"

} 
else {

        Install-Module -Name microsoft.graph.devices.corporatemanagement  -Scope CurrentUser -Repository PSGallery -Force 
    }


    if (Get-Module -ListAvailable -Name SvRooij.ContentPrep.Cmdlet ) {
        Write-Host "Microsoft Graph Already Installed"
        writelog "Microsoft Graph Already Installed"
    
    } 
    else {
    
            Install-Module -Name SvRooij.ContentPrep.Cmdlet  -Scope CurrentUser -Repository PSGallery -Force 
        }


#Importing Modules
Import-Module -Name SvRooij.ContentPrep.Cmdlet
Import-Module powershell-yaml
Import-Module microsoft.graph.groups
import-module microsoft.graph.intune
import-module microsoft.graph.devicemanagement
import-module microsoft.graph.authentication
import-module microsoft.graph.devices.corporatemanagement 


###############################################################################################################
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



###############################################################################################################
######                                          Create Dir                                               ######
###############################################################################################################

#Create path for files
$DirectoryToCreate = "c:\temp"
if (-not (Test-Path -LiteralPath $DirectoryToCreate)) {
    
    try {
        New-Item -Path $DirectoryToCreate -ItemType Directory -ErrorAction Stop | Out-Null #-Force
    }
    catch {
        Write-Error -Message "Unable to create directory '$DirectoryToCreate'. Error was: $_" -ErrorAction Stop
    }
    "Successfully created directory '$DirectoryToCreate'."

}
else {
    "Directory already existed"
}


$random = Get-Random -Maximum 1000 
$random = $random.ToString()
$date =get-date -format yyMMddmmss
$date = $date.ToString()
$path2 = $random + "-"  + $date
$path = "c:\temp\" + $path2 + "\"

New-Item -ItemType Directory -Path $path


###############################################################################################################
######                                          Add Functions                                            ######
###############################################################################################################
       
####################################################
        
function getallpagination () {
    <#
.SYNOPSIS
This function is used to grab all items from Graph API that are paginated
.DESCRIPTION
The function connects to the Graph API Interface and gets all items from the API that are paginated
.EXAMPLE
getallpagination -url "https://graph.microsoft.com/v1.0/groups"
 Returns all items
.NOTES
 NAME: getallpagination
#>
[cmdletbinding()]
    
param
(
    $url
)
    $response = (Invoke-MgGraphRequest -uri $url -Method Get -OutputType PSObject)
    $alloutput = $response.value
    
    $alloutputNextLink = $response."@odata.nextLink"
    
    while ($null -ne $alloutputNextLink) {
        $alloutputResponse = (Invoke-MGGraphRequest -Uri $alloutputNextLink -Method Get -outputType PSObject)
        $alloutputNextLink = $alloutputResponse."@odata.nextLink"
        $alloutput += $alloutputResponse.value
    }
    
    return $alloutput
    }
        
function CloneObject($object) {
        
    $stream = New-Object IO.MemoryStream
    $formatter = New-Object Runtime.Serialization.Formatters.Binary.BinaryFormatter
    $formatter.Serialize($stream, $object)
    $stream.Position = 0
    $formatter.Deserialize($stream)
}
        
####################################################
        
function UploadAzureStorageChunk($sasUri, $id, $body) {
        
    $uri = "$sasUri&comp=block&blockid=$id"
    $request = "PUT $uri"
        
    $iso = [System.Text.Encoding]::GetEncoding("iso-8859-1")
    $encodedBody = $iso.GetString($body)
    $headers = @{
        "x-ms-blob-type" = "BlockBlob"
    }
        
    if ($logRequestUris) { Write-Verbose $request }
    if ($logHeaders) { WriteHeaders $headers }
        
    try {
        Invoke-WebRequest $uri -Method Put -Headers $headers -Body $encodedBody -UseBasicParsing
    }
    catch {
        Write-Error $request
        Write-Error $_.Exception.Message
        throw
    }
        
}
        
####################################################
        
function FinalizeAzureStorageUpload($sasUri, $ids) {
        
    $uri = "$sasUri&comp=blocklist"
    $request = "PUT $uri"
        
    $xml = '<?xml version="1.0" encoding="utf-8"?><BlockList>'
    foreach ($id in $ids) {
        $xml += "<Latest>$id</Latest>"
    }
    $xml += '</BlockList>'
        
    if ($logRequestUris) { Write-Verbose $request }
    if ($logContent) { Write-Verbose $xml }
        
    try {
        Invoke-RestMethod $uri -Method Put -Body $xml
    }
    catch {
        Write-Error $request
        Write-Error $_.Exception.Message
        throw
    }
}
        
####################################################
        
function UploadFileToAzureStorage($sasUri, $filepath, $fileUri) {
        
    try {
        
        $chunkSizeInBytes = 1024l * 1024l * $azureStorageUploadChunkSizeInMb
                
        # Start the timer for SAS URI renewal.
        $sasRenewalTimer = [System.Diagnostics.Stopwatch]::StartNew()
                
        # Find the file size and open the file.
        $fileSize = (Get-Item $filepath).length
        $chunks = [Math]::Ceiling($fileSize / $chunkSizeInBytes)
        $reader = New-Object System.IO.BinaryReader([System.IO.File]::Open($filepath, [System.IO.FileMode]::Open))
        $reader.BaseStream.Seek(0, [System.IO.SeekOrigin]::Begin)
                
        # Upload each chunk. Check whether a SAS URI renewal is required after each chunk is uploaded and renew if needed.
        $ids = @()
        
        for ($chunk = 0; $chunk -lt $chunks; $chunk++) {
        
            $id = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($chunk.ToString("0000")))
            $ids += $id
        
            $start = $chunk * $chunkSizeInBytes
            $length = [Math]::Min($chunkSizeInBytes, $fileSize - $start)
            $bytes = $reader.ReadBytes($length)
                    
            $currentChunk = $chunk + 1			
        
            Write-Progress -Activity "Uploading File to Azure Storage" -status "Uploading chunk $currentChunk of $chunks" `
                -percentComplete ($currentChunk / $chunks * 100)
        
            UploadAzureStorageChunk $sasUri $id $bytes
                    
            # Renew the SAS URI if 7 minutes have elapsed since the upload started or was renewed last.
            if ($currentChunk -lt $chunks -and $sasRenewalTimer.ElapsedMilliseconds -ge 450000) {
        
                RenewAzureStorageUpload $fileUri
                $sasRenewalTimer.Restart()
                    
            }
        
        }
        
        Write-Progress -Completed -Activity "Uploading File to Azure Storage"
        
        $reader.Close()
        
    }
        
    finally {
        
        if ($null -ne $reader) { $reader.Dispose() }
            
    }
            
    # Finalize the upload.
    FinalizeAzureStorageUpload $sasUri $ids
        
}
        
####################################################
        
function RenewAzureStorageUpload($fileUri) {
        
    $renewalUri = "$fileUri/renewUpload"
    $actionBody = ""
    Invoke-MgGraphRequest -method POST -Uri $renewalUri -Body $actionBody
            
    Start-WaitForFileProcessing $fileUri "AzureStorageUriRenewal" $azureStorageRenewSasUriBackOffTimeInSeconds
        
}
        
####################################################
        
function Start-WaitForFileProcessing($fileUri, $stage) {
    
    $attempts = 600
    $waitTimeInSeconds = 10
        
    $successState = "$($stage)Success"
    $pendingState = "$($stage)Pending"
        
    $file = $null
    while ($attempts -gt 0) {
        $file = Invoke-MgGraphRequest -Method GET -Uri $fileUri
        
        if ($file.uploadState -eq $successState) {
            break
        }
        elseif ($file.uploadState -ne $pendingState) {
            Write-Error $_.Exception.Message
            throw "File upload state is not success: $($file.uploadState)"
        }
        
        Start-Sleep $waitTimeInSeconds
        $attempts--
    }
        
    if ($null -eq $file -or $file.uploadState -ne $successState) {
        throw "File request did not complete in the allotted time."
    }
        
    $file
}
        
####################################################
        
function Get-Win32AppBody() {
        
    param
    (
        
        [parameter(Mandatory = $true, ParameterSetName = "MSI", Position = 1)]
        [Switch]$MSI,
        
        [parameter(Mandatory = $true, ParameterSetName = "EXE", Position = 1)]
        [Switch]$EXE,
        
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$displayName,
        
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$publisher,
        
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$description,
        
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$filename,
        
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$SetupFileName,
        
        [parameter(Mandatory = $true)]
        [ValidateSet('system', 'user')]
        $installExperience,
        
        [parameter(Mandatory = $true, ParameterSetName = "EXE")]
        [ValidateNotNullOrEmpty()]
        $installCommandLine,
        
        [parameter(Mandatory = $true, ParameterSetName = "EXE")]
        [ValidateNotNullOrEmpty()]
        $uninstallCommandLine,
        
        [parameter(Mandatory = $true, ParameterSetName = "MSI")]
        [ValidateNotNullOrEmpty()]
        $MsiPackageType,
        
        [parameter(Mandatory = $true, ParameterSetName = "MSI")]
        [ValidateNotNullOrEmpty()]
        $MsiProductCode,
        
        [parameter(Mandatory = $false, ParameterSetName = "MSI")]
        $MsiProductName,
        
        [parameter(Mandatory = $true, ParameterSetName = "MSI")]
        [ValidateNotNullOrEmpty()]
        $MsiProductVersion,
        
        [parameter(Mandatory = $false, ParameterSetName = "MSI")]
        $MsiPublisher,
        
        [parameter(Mandatory = $true, ParameterSetName = "MSI")]
        [ValidateNotNullOrEmpty()]
        $MsiRequiresReboot,
        
        [parameter(Mandatory = $true, ParameterSetName = "MSI")]
        [ValidateNotNullOrEmpty()]
        $MsiUpgradeCode
        
    )
        
    if ($MSI) {
        
        $body = @{ "@odata.type" = "#microsoft.graph.win32LobApp" }
        $body.applicableArchitectures = "x64,x86"
        $body.description = $description
        $body.developer = ""
        $body.displayName = $displayName
        $body.fileName = $filename
        $body.installCommandLine = "msiexec /i `"$SetupFileName`""
        $body.installExperience = @{"runAsAccount" = "$installExperience" }
        $body.informationUrl = $null
        $body.isFeatured = $false
        $body.minimumSupportedOperatingSystem = @{"v10_1607" = $true }
        $body.msiInformation = @{
            "packageType"    = "$MsiPackageType"
            "productCode"    = "$MsiProductCode"
            "productName"    = "$MsiProductName"
            "productVersion" = "$MsiProductVersion"
            "publisher"      = "$MsiPublisher"
            "requiresReboot" = "$MsiRequiresReboot"
            "upgradeCode"    = "$MsiUpgradeCode"
        }
        $body.notes = ""
        $body.owner = ""
        $body.privacyInformationUrl = $null
        $body.publisher = $publisher
        $body.runAs32bit = $false
        $body.setupFilePath = $SetupFileName
        $body.uninstallCommandLine = "msiexec /x `"$MsiProductCode`""
        
    }
        
    elseif ($EXE) {
        
        $body = @{ "@odata.type" = "#microsoft.graph.win32LobApp" }
        $body.description = $description
        $body.developer = ""
        $body.displayName = $displayName
        $body.fileName = $filename
        $body.installCommandLine = "$installCommandLine"
        $body.installExperience = @{"runAsAccount" = "$installExperience" }
        $body.informationUrl = $null
        $body.isFeatured = $false
        $body.minimumSupportedOperatingSystem = @{"v10_1607" = $true }
        $body.msiInformation = $null
        $body.notes = ""
        $body.owner = ""
        $body.privacyInformationUrl = $null
        $body.publisher = $publisher
        $body.runAs32bit = $false
        $body.setupFilePath = $SetupFileName
        $body.uninstallCommandLine = "$uninstallCommandLine"
        
    }
        
    $body
}
        
####################################################
        
function GetAppFileBody($name, $size, $sizeEncrypted, $manifest) {
        
    $body = @{ "@odata.type" = "#microsoft.graph.mobileAppContentFile" }
    $body.name = $name
    $body.size = $size
    $body.sizeEncrypted = $sizeEncrypted
    $body.manifest = $manifest
    $body.isDependency = $false
        
    $body
}
        
####################################################
        
function GetAppCommitBody($contentVersionId, $LobType) {
        
    $body = @{ "@odata.type" = "#$LobType" }
    $body.committedContentVersion = $contentVersionId
        
    $body
        
}
        
####################################################
        
Function Test-SourceFile() {
        
    param
    (
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        $SourceFile
    )
        
    try {
        
        if (!(test-path "$SourceFile")) {
        
            Write-Error "Source File '$sourceFile' doesn't exist..."
            throw
        
        }
        
    }
        
    catch {
        
        Write-Error $_.Exception.Message
        break
        
    }
        
}
        
####################################################
        
Function New-DetectionRule() {
        
    [cmdletbinding()]
        
    param
    (
        [parameter(Mandatory = $true, ParameterSetName = "PowerShell", Position = 1)]
        [Switch]$PowerShell,
        
        [parameter(Mandatory = $true, ParameterSetName = "MSI", Position = 1)]
        [Switch]$MSI,
        
        [parameter(Mandatory = $true, ParameterSetName = "File", Position = 1)]
        [Switch]$File,
        
        [parameter(Mandatory = $true, ParameterSetName = "Registry", Position = 1)]
        [Switch]$Registry,
        
        [parameter(Mandatory = $true, ParameterSetName = "PowerShell")]
        [ValidateNotNullOrEmpty()]
        [String]$ScriptFile,
        
        [parameter(Mandatory = $true, ParameterSetName = "PowerShell")]
        [ValidateNotNullOrEmpty()]
        $enforceSignatureCheck,
        
        [parameter(Mandatory = $true, ParameterSetName = "PowerShell")]
        [ValidateNotNullOrEmpty()]
        $runAs32Bit,
        
        [parameter(Mandatory = $true, ParameterSetName = "MSI")]
        [ValidateNotNullOrEmpty()]
        [String]$MSIproductCode,
           
        [parameter(Mandatory = $true, ParameterSetName = "File")]
        [ValidateNotNullOrEmpty()]
        [String]$Path,
         
        [parameter(Mandatory = $true, ParameterSetName = "File")]
        [ValidateNotNullOrEmpty()]
        [string]$FileOrFolderName,
        
        [parameter(Mandatory = $true, ParameterSetName = "File")]
        [ValidateSet("notConfigured", "exists", "modifiedDate", "createdDate", "version", "sizeInMB")]
        [string]$FileDetectionType,
        
        [parameter(Mandatory = $false, ParameterSetName = "File")]
        $FileDetectionValue = $null,
        
        [parameter(Mandatory = $true, ParameterSetName = "File")]
        [ValidateSet("True", "False")]
        [string]$check32BitOn64System = "False",
        
        [parameter(Mandatory = $true, ParameterSetName = "Registry")]
        [ValidateNotNullOrEmpty()]
        [String]$RegistryKeyPath,
        
        [parameter(Mandatory = $true, ParameterSetName = "Registry")]
        [ValidateSet("notConfigured", "exists", "doesNotExist", "string", "integer", "version")]
        [string]$RegistryDetectionType,
        
        [parameter(Mandatory = $false, ParameterSetName = "Registry")]
        [ValidateNotNullOrEmpty()]
        [String]$RegistryValue,
        
        [parameter(Mandatory = $true, ParameterSetName = "Registry")]
        [ValidateSet("True", "False")]
        [string]$check32BitRegOn64System = "False"
        
    )
        
    if ($PowerShell) {
        
        if (!(Test-Path "$ScriptFile")) {
                    
            Write-Error "Could not find file '$ScriptFile'..."
            Write-Error "Script can't continue..."
            break
        
        }
                
        $ScriptContent = [System.Convert]::ToBase64String([System.IO.File]::ReadAllBytes("$ScriptFile"))
                
        $DR = @{ "@odata.type" = "#microsoft.graph.win32LobAppPowerShellScriptDetection" }
        $DR.enforceSignatureCheck = $false
        $DR.runAs32Bit = $false
        $DR.scriptContent = "$ScriptContent"
        
    }
            
    elseif ($MSI) {
            
        $DR = @{ "@odata.type" = "#microsoft.graph.win32LobAppProductCodeDetection" }
        $DR.productVersionOperator = "notConfigured"
        $DR.productCode = "$MsiProductCode"
        $DR.productVersion = $null
        
    }
        
    elseif ($File) {
            
        $DR = @{ "@odata.type" = "#microsoft.graph.win32LobAppFileSystemDetection" }
        $DR.check32BitOn64System = "$check32BitOn64System"
        $DR.detectionType = "$FileDetectionType"
        $DR.detectionValue = $FileDetectionValue
        $DR.fileOrFolderName = "$FileOrFolderName"
        $DR.operator = "notConfigured"
        $DR.path = "$Path"
        
    }
        
    elseif ($Registry) {
            
        $DR = @{ "@odata.type" = "#microsoft.graph.win32LobAppRegistryDetection" }
        $DR.check32BitOn64System = "$check32BitRegOn64System"
        $DR.detectionType = "$RegistryDetectionType"
        $DR.detectionValue = ""
        $DR.keyPath = "$RegistryKeyPath"
        $DR.operator = "notConfigured"
        $DR.valueName = "$RegistryValue"
        
    }
        
    return $DR
        
}
        
####################################################
        
function Get-DefaultReturnCodes() {
        
    @{"returnCode" = 0; "type" = "success" }, `
    @{"returnCode" = 1707; "type" = "success" }, `
    @{"returnCode" = 3010; "type" = "softReboot" }, `
    @{"returnCode" = 1641; "type" = "hardReboot" }, `
    @{"returnCode" = 1618; "type" = "retry" }
        
}
        
####################################################
        
function New-ReturnCode() {
        
    param
    (
        [parameter(Mandatory = $true)]
        [int]$returnCode,
        [parameter(Mandatory = $true)]
        [ValidateSet('success', 'softReboot', 'hardReboot', 'retry')]
        $type
    )
        
    @{"returnCode" = $returnCode; "type" = "$type" }
        
}
        
####################################################
        
Function Get-IntuneWinXML() {
        
    param
    (
        [Parameter(Mandatory = $true)]
        $SourceFile,
        
        [Parameter(Mandatory = $true)]
        $fileName,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("false", "true")]
        [string]$removeitem = "true"
    )
        
    Test-SourceFile "$SourceFile"
        
    $Directory = [System.IO.Path]::GetDirectoryName("$SourceFile")
        
    Add-Type -Assembly System.IO.Compression.FileSystem
    $zip = [IO.Compression.ZipFile]::OpenRead("$SourceFile")
        
    $zip.Entries | where-object { $_.Name -like "$filename" } | foreach-object {
        
        [System.IO.Compression.ZipFileExtensions]::ExtractToFile($_, "$Directory\$filename", $true)
        
    }
        
    $zip.Dispose()
        
    [xml]$IntuneWinXML = Get-Content "$Directory\$filename"
        
    return $IntuneWinXML
        
    if ($removeitem -eq "true") { remove-item "$Directory\$filename" }
        
}
        
####################################################
        
Function Get-IntuneWinFile() {
        
    param
    (
        [Parameter(Mandatory = $true)]
        $SourceFile,
        
        [Parameter(Mandatory = $true)]
        $fileName,
        
        [Parameter(Mandatory = $false)]
        [string]$Folder = "win32"
    )
        
    $Directory = [System.IO.Path]::GetDirectoryName("$SourceFile")
        
    if (!(Test-Path "$Directory\$folder")) {
        
        New-Item -ItemType Directory -Path "$Directory" -Name "$folder" | Out-Null
        
    }
        
    Add-Type -Assembly System.IO.Compression.FileSystem
    $zip = [IO.Compression.ZipFile]::OpenRead("$SourceFile")
        
    $zip.Entries | Where-Object { $_.Name -like "$filename" } | ForEach-Object {
        
        [System.IO.Compression.ZipFileExtensions]::ExtractToFile($_, "$Directory\$folder\$filename", $true)
        
    }
        
    $zip.Dispose()
        
    return "$Directory\$folder\$filename"
        
    if ($removeitem -eq "true") { remove-item "$Directory\$filename" }
        
}
        
####################################################
        
function Invoke-UploadWin32Lob() {
        
    <#
        .SYNOPSIS
        This function is used to upload a Win32 Application to the Intune Service
        .DESCRIPTION
        This function is used to upload a Win32 Application to the Intune Service
        .EXAMPLE
        Invoke-UploadWin32Lob "C:\Packages\package.intunewin" -publisher "Microsoft" -description "Package"
        This example uses all parameters required to add an intunewin File into the Intune Service
        .NOTES
        NAME: Invoke-UploadWin32Lob
        #>
        
    [cmdletbinding()]
        
    param
    (
        [parameter(Mandatory = $true, Position = 1)]
        [ValidateNotNullOrEmpty()]
        [string]$SourceFile,
        
        [parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$displayName,
        
        [parameter(Mandatory = $true, Position = 2)]
        [ValidateNotNullOrEmpty()]
        [string]$publisher,
        
        [parameter(Mandatory = $true, Position = 3)]
        [ValidateNotNullOrEmpty()]
        [string]$description,
        
        [parameter(Mandatory = $true, Position = 4)]
        [ValidateNotNullOrEmpty()]
        $detectionRules,
        
        [parameter(Mandatory = $true, Position = 5)]
        [ValidateNotNullOrEmpty()]
        $returnCodes,
        
        [parameter(Mandatory = $false, Position = 6)]
        [ValidateNotNullOrEmpty()]
        [string]$installCmdLine,
        
        [parameter(Mandatory = $false, Position = 7)]
        [ValidateNotNullOrEmpty()]
        [string]$uninstallCmdLine,
        
        [parameter(Mandatory = $false, Position = 8)]
        [ValidateSet('system', 'user')]
        $installExperience = "system"
    )
        
    try	{
        
        $LOBType = "microsoft.graph.win32LobApp"
        
        Write-Verbose "Testing if SourceFile '$SourceFile' Path is valid..."
        Test-SourceFile "$SourceFile"
                
        Write-Verbose "Creating JSON data to pass to the service..."
        
        # Funciton to read Win32LOB file
        $DetectionXML = Get-IntuneWinXML "$SourceFile" -fileName "detection.xml"
        
        # If displayName input don't use Name from detection.xml file
        if ($displayName) { $DisplayName = $displayName }
        else { $DisplayName = $DetectionXML.ApplicationInfo.Name }
                
        $FileName = $DetectionXML.ApplicationInfo.FileName
        
        $SetupFileName = $DetectionXML.ApplicationInfo.SetupFile
        
        $Ext = [System.IO.Path]::GetExtension($SetupFileName)
        
        if ((($Ext).contains("msi") -or ($Ext).contains("Msi")) -and (!$installCmdLine -or !$uninstallCmdLine)) {
        
            # MSI
            $MsiExecutionContext = $DetectionXML.ApplicationInfo.MsiInfo.MsiExecutionContext
            $MsiPackageType = "DualPurpose"
            if ($MsiExecutionContext -eq "System") { $MsiPackageType = "PerMachine" }
            elseif ($MsiExecutionContext -eq "User") { $MsiPackageType = "PerUser" }
        
            $MsiProductCode = $DetectionXML.ApplicationInfo.MsiInfo.MsiProductCode
            $MsiProductVersion = $DetectionXML.ApplicationInfo.MsiInfo.MsiProductVersion
            $MsiPublisher = $DetectionXML.ApplicationInfo.MsiInfo.MsiPublisher
            $MsiRequiresReboot = $DetectionXML.ApplicationInfo.MsiInfo.MsiRequiresReboot
            $MsiUpgradeCode = $DetectionXML.ApplicationInfo.MsiInfo.MsiUpgradeCode
                    
            if ($MsiRequiresReboot -eq "false") { $MsiRequiresReboot = $false }
            elseif ($MsiRequiresReboot -eq "true") { $MsiRequiresReboot = $true }
        
            $mobileAppBody = Get-Win32AppBody `
                -MSI `
                -displayName "$DisplayName" `
                -publisher "$publisher" `
                -description $description `
                -filename $FileName `
                -SetupFileName "$SetupFileName" `
                -installExperience $installExperience `
                -MsiPackageType $MsiPackageType `
                -MsiProductCode $MsiProductCode `
                -MsiProductName $displayName `
                -MsiProductVersion $MsiProductVersion `
                -MsiPublisher $MsiPublisher `
                -MsiRequiresReboot $MsiRequiresReboot `
                -MsiUpgradeCode $MsiUpgradeCode
        
        }
        
        else {
        
            $mobileAppBody = Get-Win32AppBody -EXE -displayName "$DisplayName" -publisher "$publisher" `
                -description $description -filename $FileName -SetupFileName "$SetupFileName" `
                -installExperience $installExperience -installCommandLine $installCmdLine `
                -uninstallCommandLine $uninstallcmdline
        
        }
        
        if ($DetectionRules.'@odata.type' -contains "#microsoft.graph.win32LobAppPowerShellScriptDetection" -and @($DetectionRules).'@odata.type'.Count -gt 1) {
        
            Write-Warning "A Detection Rule can either be 'Manually configure detection rules' or 'Use a custom detection script'"
            Write-Warning "It can't include both..."
            break
        
        }
        
        else {
        
            $mobileAppBody | Add-Member -MemberType NoteProperty -Name 'detectionRules' -Value $detectionRules
        
        }
        
        #ReturnCodes
        
        if ($returnCodes) {
                
            $mobileAppBody | Add-Member -MemberType NoteProperty -Name 'returnCodes' -Value @($returnCodes)
        
        }
        
        else {
            Write-Warning "Intunewin file requires ReturnCodes to be specified"
            Write-Warning "If you want to use the default ReturnCode run 'Get-DefaultReturnCodes'"
            break
        }
        
        Write-Verbose "Creating application in Intune..."
        writelog "Creating application in Intune..."

        $mobileApp = Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/" -Body ($mobileAppBody | ConvertTo-Json) -ContentType "application/json" -OutputType PSObject
        #$mobileApp = New-MgDeviceAppMgtMobileApp -BodyParameter ($mobileAppBody | ConvertTo-Json)
        
        # Get the content version for the new app (this will always be 1 until the new app is committed).
        Write-Verbose "Creating Content Version in the service for the application..."
        writelog "Creating Content Version in the service for the application..."

        $appId = $mobileApp.id
        $contentVersionUri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/$appId/$LOBType/contentVersions"
        $contentVersion = Invoke-MgGraphRequest -method POST -Uri $contentVersionUri -Body "{}"
        
        # Encrypt file and Get File Information
        Write-Verbose "Getting Encryption Information for '$SourceFile'..."
        writelog "Getting Encryption Information for '$SourceFile'..."

        
        $encryptionInfo = @{}
        $encryptionInfo.encryptionKey = $DetectionXML.ApplicationInfo.EncryptionInfo.EncryptionKey
        $encryptionInfo.macKey = $DetectionXML.ApplicationInfo.EncryptionInfo.macKey
        $encryptionInfo.initializationVector = $DetectionXML.ApplicationInfo.EncryptionInfo.initializationVector
        $encryptionInfo.mac = $DetectionXML.ApplicationInfo.EncryptionInfo.mac
        $encryptionInfo.profileIdentifier = "ProfileVersion1"
        $encryptionInfo.fileDigest = $DetectionXML.ApplicationInfo.EncryptionInfo.fileDigest
        $encryptionInfo.fileDigestAlgorithm = $DetectionXML.ApplicationInfo.EncryptionInfo.fileDigestAlgorithm
        
        $fileEncryptionInfo = @{}
        $fileEncryptionInfo.fileEncryptionInfo = $encryptionInfo
        
        # Extracting encrypted file
        $IntuneWinFile = Get-IntuneWinFile "$SourceFile" -fileName "$filename"
        
        [int64]$Size = $DetectionXML.ApplicationInfo.UnencryptedContentSize
        $EncrySize = (Get-Item "$IntuneWinFile").Length
        
        # Create a new file for the app.
        Write-Verbose "Creating a new file entry in Azure for the upload..."
        writelog "Creating a new file entry in Azure for the upload..."

        $contentVersionId = $contentVersion.id
        $fileBody = GetAppFileBody "$FileName" $Size $EncrySize $null
        $filesUri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/$appId/$LOBType/contentVersions/$contentVersionId/files"
        $file = Invoke-MgGraphRequest -Method POST -Uri $filesUri -Body ($fileBody | ConvertTo-Json)
            
        # Wait for the service to process the new file request.
        Write-Verbose "Waiting for the file entry URI to be created..."
        writelog "Waiting for the file entry URI to be created..."

        $fileId = $file.id
        $fileUri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/$appId/$LOBType/contentVersions/$contentVersionId/files/$fileId"
        $file = Start-WaitForFileProcessing $fileUri "AzureStorageUriRequest"
        
        # Upload the content to Azure Storage.
        Write-Verbose "Uploading file to Azure Storage..."
        writelog "Uploading file to Azure Storage..."

        
        UploadFileToAzureStorage $file.azureStorageUri "$IntuneWinFile" $fileUri
        
        # Need to Add removal of IntuneWin file
        Remove-Item "$IntuneWinFile" -Force
        
        # Commit the file.
        Write-Verbose "Committing the file into Azure Storage..."
        writelog "Committing the file into Azure Storage..."

        $commitFileUri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/$appId/$LOBType/contentVersions/$contentVersionId/files/$fileId/commit"
        Invoke-MgGraphRequest -Uri $commitFileUri -Method POST -Body ($fileEncryptionInfo | ConvertTo-Json)
        
        # Wait for the service to process the commit file request.
        Write-Verbose "Waiting for the service to process the commit file request..."
        writelog "Waiting for the service to process the commit file request..."

        $file = Start-WaitForFileProcessing $fileUri "CommitFile"
        
        # Commit the app.
        Write-Verbose "Committing the file into Azure Storage..."
        writelog "Committing the file into Azure Storage..."

        $commitAppUri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/$appId"
        $commitAppBody = GetAppCommitBody $contentVersionId $LOBType
        Invoke-MgGraphRequest -Method PATCH -Uri $commitAppUri -Body ($commitAppBody | ConvertTo-Json)
        
        foreach ($i in 0..$sleep) {
            Write-Progress -Activity "Sleeping for $($sleep-$i) seconds" -PercentComplete ($i / $sleep * 100) -SecondsRemaining ($sleep - $i)
            Start-Sleep -s 1
        }            
    }
            
    catch {
        Write-Error "Aborting with exception: $($_.Exception.ToString())"
            
    }
}
        
$logRequestUris = $true
$logHeaders = $false
$logContent = $true
        
$azureStorageUploadChunkSizeInMb = 6l
        
$sleep = 30
        
Function Get-IntuneApplication() {
        
    <#
        .SYNOPSIS
        This function is used to get applications from the Graph API REST interface
        .DESCRIPTION
        The function connects to the Graph API Interface and gets any applications added
        .EXAMPLE
        Get-IntuneApplication
        Returns any applications configured in Intune
        .NOTES
        NAME: Get-IntuneApplication
        #>            
    try {

        return getallpagination -url "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/"
        
    }
            
    catch {
        
        $ex = $_.Exception
        Write-Verbose "Request to $Uri failed with HTTP Status $([int]$ex.Response.StatusCode) $($ex.Response.StatusDescription)"
        $errorResponse = $ex.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($errorResponse)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd();
        Write-Verbose "Response content:`n$responseBody"
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
        break
        
    }
        
}
        


function new-aadgroups {
    [cmdletbinding()]
        
    param
    (
        $appid,
        $appname,
        $grouptype
    )
    switch ($grouptype) {
        "install" {
            $groupname = $appname + " Install Group"
            $nickname = $appid + "install"
            $groupdescription = "Group for installation and updating of $appname application"
        }
        "uninstall" {
            $groupname = $appname + " Uninstall Group"
            $nickname = $appid + "uninstall"
            $groupdescription = "Group for uninstallation of $appname application"
        }
    }

    $grp = New-MgGroup -DisplayName $groupname -Description $groupdescription -MailEnabled:$False -MailNickName $nickname -SecurityEnabled:$True

    return $grp.id

}

function new-aadgroupsspecific {
    [cmdletbinding()]
        
    param
    (
        $appid,
        $appname,
        $grouptype,
        $groupname
    )
    switch ($grouptype) {
        "install" {
            $nickname = $appid + "install"
            $groupdescription = "Group for installation and updating of $appname application"
        }
        "uninstall" {
            $nickname = $appid + "uninstall"
            $groupdescription = "Group for uninstallation of $appname application"
        }
    }

    $grp = New-MgGroup -DisplayName $groupname -Description $groupdescription -MailEnabled:$False -MailNickName $nickname -SecurityEnabled:$True

    return $grp.id

}

function new-detectionscript {
    param
    (
        $appid,
        $appname
    )
    $detect = @'
$ResolveWingetPath = Resolve-Path "C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller_*_x64__8wekyb3d8bbwe"
    if ($ResolveWingetPath){
           $WingetPath = $ResolveWingetPath[-1].Path
    }
$Winget = $WingetPath + "\winget.exe"
$upgrades = &$winget upgrade
if ($upgrades -match "SETAPPID") {
    Write-Host "Upgrade available for: SETAPPNAME"
    exit 1
}
else {
        Write-Host "No Upgrade available"
        exit 0
}
'@
    $detect2 = $detect -replace "SETAPPID", $appid
    $detect3 = $detect2 -replace "SETAPPNAME", $appname

    return $detect3
}

function new-remediationscript {
    param
    (
        $appid,
        $appname
    )
    $remediate = @'
$ResolveWingetPath = Resolve-Path "C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller_*_x64__8wekyb3d8bbwe"
    if ($ResolveWingetPath){
        $WingetPath = $ResolveWingetPath[-1].Path
    }
        
    $Winget = $WingetPath + "\winget.exe"
    &$winget upgrade --id "SETAPPID" --silent --force --accept-package-agreements --accept-source-agreements
'@
    $remediate2 = $remediate -replace "SETAPPID", $appid
    return $remediate2

}

function new-proac {
    param
    (
        $appid,
        $appname,
        $groupid
    )
    $detectscriptcontent = new-detectionscript -appid $appid -appname $appname
    $detect = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($detectscriptcontent))
    $remediatecriptcontent = new-remediationscript -appid $appid -appname $appname
    $remediate = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($remediatecriptcontent))

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
        remediationScriptContent = $remediate
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

function new-intunewinfile {
    param
    (
        $appid,
        $appname,
        $apppath,
        $setupfilename,
        $destpath
    )
    #. $intuneapputiloutput -c "$apppath" -s "$setupfilename" -o "$apppath" -q
    New-IntuneWinPackage -SourcePath "$apppath" -SetupFile "$setupfilename" -DestinationPath "$destpath" 
}

function new-detectionscriptinstall {
    param
    (
        $appid,
        $appname,
        $appversion
    )
    $detection = @"
    `$ResolveWingetPath = Resolve-Path "C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller_*_x64__8wekyb3d8bbwe"
        if (`$ResolveWingetPath){
               `$WingetPath = `$ResolveWingetPath[-1].Path
        }
       
    `$Winget = `$WingetPath + "\winget.exe"
    `$wingettest = &`$winget list --id $appid
    if ((`$wingettest -like "*$appid*") -and (`$wingettest -like "*$appversion*")){
        Write-Host "Found it!"
        exit 0
    }
    else {
        write-host "Not Found"
        exit 1
    }
"@
    return $detection

}


function new-installscript {
    param
    (
        $appid,
        $appname,
        $appversion
    )
    $install = @"
    `$ResolveWingetPath = Resolve-Path "C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller_*_x64__8wekyb3d8bbwe"
        if (`$ResolveWingetPath){
               `$WingetPath = `$ResolveWingetPath[-1].Path
        }
    
    `$Winget = `$WingetPath + "\winget.exe"
    &`$winget install --id "$appid" --version $appversion --silent --force --accept-package-agreements --accept-source-agreements --scope machine --exact | out-null
"@
    return $install

}

function new-uninstallscript {
    param
    (
        $appid,
        $appname,
        $appversion
    )
    $uninstall = @"
    `$ResolveWingetPath = Resolve-Path "C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller_*_x64__8wekyb3d8bbwe"
        if (`$ResolveWingetPath){
               `$WingetPath = `$ResolveWingetPath[-1].Path
        }
    
    `$Winget = `$WingetPath + "\winget.exe"
    &`$winget uninstall --id "$appid" --version $appversion --silent --force --accept-source-agreements
"@
    return $uninstall

}

function grant-win32app {
    param
    (
        $appname,
        $installgroup,
        $uninstallgroup,
        $availableinstall
    )
    $Application = Get-IntuneApplication | where-object { $_.displayName -eq "$appname" -and $_.description -like "*Winget*" }
    #Install
    $ApplicationId = $Application.id
    $TargetGroupId1 = $installgroup
    $InstallIntent1 = "required"
    
    
    #Uninstall
    $ApplicationId = $Application.id
    $TargetGroupId = $uninstallgroup
    $InstallIntent = "uninstall"

    $JSON1 = @"
    
    {
        "mobileAppAssignments": [
          {
            "@odata.type": "#microsoft.graph.mobileAppAssignment",
            "target": {
            "@odata.type": "#microsoft.graph.groupAssignmentTarget",
            "groupId": "$TargetGroupId1"
            },
            "intent": "$InstallIntent1"
        },
        {
            "@odata.type": "#microsoft.graph.mobileAppAssignment",
            "target": {
            "@odata.type": "#microsoft.graph.groupAssignmentTarget",
            "groupId": "$TargetGroupId"
            },
            "intent": "$InstallIntent"
        }
    
"@

##Switch on available install for Devices, Users, Both or None
switch ($availableinstall) {
    "Device" {
        write-output "Making available for devices"
       $JSON2 = @"
       ,{
        "@odata.type": "#microsoft.graph.mobileAppAssignment",
        "intent": "Available",
        "settings": {
            "@odata.type": "#microsoft.graph.win32LobAppAssignmentSettings",
            "deliveryOptimizationPriority": "foreground",
            "installTimeSettings": null,
            "notifications": "showAll",
            "restartSettings": null
        },
        "target": {
            "@odata.type": "#microsoft.graph.allDevicesAssignmentTarget"
        }
    }
"@
break;
    }
    "User" {
        write-output "Making Available for Users"
        $JSON2 = @"
        ,{
			"@odata.type": "#microsoft.graph.mobileAppAssignment",
			"intent": "Available",
			"settings": {
				"@odata.type": "#microsoft.graph.win32LobAppAssignmentSettings",
				"deliveryOptimizationPriority": "foreground",
				"installTimeSettings": null,
				"notifications": "showAll",
				"restartSettings": null
			},
			"target": {
				"@odata.type": "#microsoft.graph.allLicensedUsersAssignmentTarget"
			}
		}
"@
break;
    }
    "Both" {
        write-output "Making Available for Users and Devices"
       $JSON2 = @"
       ,{
        "@odata.type": "#microsoft.graph.mobileAppAssignment",
        "intent": "Available",
        "settings": {
            "@odata.type": "#microsoft.graph.win32LobAppAssignmentSettings",
            "deliveryOptimizationPriority": "foreground",
            "installTimeSettings": null,
            "notifications": "showAll",
            "restartSettings": null
        },
        "target": {
            "@odata.type": "#microsoft.graph.allLicensedUsersAssignmentTarget"
        }
    },
    {
        "@odata.type": "#microsoft.graph.mobileAppAssignment",
        "intent": "Available",
        "settings": {
            "@odata.type": "#microsoft.graph.win32LobAppAssignmentSettings",
            "deliveryOptimizationPriority": "foreground",
            "installTimeSettings": null,
            "notifications": "showAll",
            "restartSettings": null
        },
        "target": {
            "@odata.type": "#microsoft.graph.allDevicesAssignmentTarget"
        }
    }
"@
break;
    }
    "None" {
        write-output "No Available Intent"
       $JSON2 = ""
       break;
    }
    Default {
        $JSON2 = ""
    }
}
    $JSON3 = @"
    ]
}

"@

$JSON = $JSON1 + $JSON2 + $JSON3
    Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/$ApplicationId/assign" -Method POST -Body $JSON
    
}

function new-win32app {
    [cmdletbinding()]
        
    param
    (
        $appid,
        $appname,
        $appfile,
        $installcmd,
        $uninstallcmd,
        $detectionfile
    )
    # Defining Intunewin32 detectionRules
    $PSRule = New-DetectionRule -PowerShell -ScriptFile $detectionfile -enforceSignatureCheck $false -runAs32Bit $false


    # Creating Array for detection Rule
    $DetectionRule = @($PSRule)

    $ReturnCodes = Get-DefaultReturnCodes

    # Win32 Application Upload
    $appupload = Invoke-UploadWin32Lob -SourceFile "$appfile" -DisplayName "$appname" -publisher "Winget" `
        -description "$appname Winget Package" -detectionRules $DetectionRule -returnCodes $ReturnCodes `
        -installCmdLine "$installcmd" `
        -uninstallCmdLine "$uninstallcmd"

    return $appupload

}

function checkforgroup() {

        [cmdletbinding()]
            
        param
        (
            $groupname
        )

        $url = "https://graph.microsoft.com/beta/groups?`$filter=displayName eq '$groupname'"
        $group = (Invoke-MgGraphRequest -Uri $url -Method GET -OutputType PSObject -SkipHttpErrorCheck).value
        return $group.id
}

############################################################################################################
######                          END FUNCTIONS SECTION                                               ########
############################################################################################################

if ($clientid -and $clientsecret -and $tenant) {

Connect-ToGraph -Tenant $tenant -AppId $clientid -AppSecret $clientsecret
write-output "Graph Connection Established"
writelog "Graph Connection Established"

}
else {
##Connect to Graph

Connect-ToGraph -Scopes "DeviceManagementApps.ReadWrite.All, DeviceManagementConfiguration.ReadWrite.All, Group.ReadWrite.All, GroupMember.ReadWrite.All, openid, profile, email, offline_access"
}
Write-Verbose "Graph connection established"
writelog "Graph connection established"


    $VerbosePreference="Continue"



    ##Create a custom object to store app details in
    $packs = [pscustomobject]@{
        Id = $appid
        Name = $appname
        Version = $appversion
    }

foreach ($pack in $packs) {
    $appid = $pack.Id.Trim()
    $appname = $pack.Name.Trim()
    $appversion = $pack.Version.Trim()

    Write-Verbose "$appname Selected with ID of $appid"
    writelog "$appname Selected with ID of $appid"



    ##Create Directory
    Write-Verbose "Creating Directory for $appname"
    writelog "Creating Directory for $appname"

    $apppath = "$path\$appid-$appversion"
    new-item -Path $apppath -ItemType Directory -Force
    Write-Host "Directory $apppath Created"
    writelog "Directory $apppath Created"


    ##Create Groups
    Write-Verbose "Creating AAD Groups for $appname"
    writelog "Creating AAD Groups for $appname"


    ##Check if Groups have been specified 

    if ($installgroupname) {
        $installgrouptest = checkforgroup -groupname $installgroupname
        if ($installgrouptest) {
            $installgroup = $installgrouptest
        }
        else {
            $installgroup = new-aadgroupsspecific -appid $appid -appname $appname -grouptype "Install" -groupname $installgroupname
        }

    }
    else {
        $installgroup = new-aadgroups -appid $appid -appname $appname -grouptype "Install"
    }
    Write-Host "Created $installgroup for installing $appname"
    writelog "Created $installgroup for installing $appname"

    if ($uninstallgroupname) {
        if ($uninstallgrouptest) {
            $uninstallgroup = $uninstallgrouptest
        }
        else {
            $uninstallgroup = new-aadgroupsspecific -appid $appid -appname $appname -grouptype "Uninstall" -groupname $uninstallgroupname
        }    }
    else {
        $uninstallgroup = new-aadgroups -appid $appid -appname $appname -grouptype "Uninstall"
    }
    Write-Host "Created $uninstallgroup for uninstalling $appname"
    writelog "Created $uninstallgroup for uninstalling $appname"


    ##Create Install Script
    Write-Verbose "Creating Install Script for $appname"
    writelog "Creating Install Script for $appname"

    $installscript = new-installscript -appid $appid -appname $appname -appversion $appversion
    $installfilename = "install$appid-$appversion.ps1"
    $installscriptfile = $apppath + "\" + $installfilename
    $installscript | Out-File $installscriptfile -Encoding utf8
    Write-Host "Script created at $installscriptfile"
    writelog "Script created at $installscriptfile"


    ##Create Uninstall Script
    Write-Verbose "Creating Uninstall Script for $appname"
    writelog "Creating Uninstall Script for $appname"

    $uninstallscript = new-uninstallscript -appid $appid -appname $appname -appversion $appversion
    $uninstallfilename = "uninstall$appid-$appversion.ps1"
    $uninstallscriptfile = $apppath + "\" + $uninstallfilename
    $uninstallscript | Out-File $uninstallscriptfile -Encoding utf8
    Write-Host "Script created at $uninstallscriptfile"
    writelog "Script created at $uninstallscriptfile"


    ##Create Detection Script
    Write-Verbose "Creating Detection Script for $appname"
    writelog "Creating Detection Script for $appname"

    $detectionscript = new-detectionscriptinstall -appid $appid -appname $appname -appversion $appversion
    $detectionscriptfile = $apppath + "\detection$appid-$appversion.ps1"
    $detectionscript | Out-File $detectionscriptfile -Encoding utf8
    Write-Host "Script created at $detectionscriptfile"
    writelog "Script created at $detectionscriptfile"


    ##Create Proac
    Write-Verbose "Creation Proactive Remediation for $appname"
    writelog "Creation Proactive Remediation for $appname"
    new-proac -appid $appid -appname $appname -groupid $installgroup
    Write-Host "Proactive Remediation Created and Assigned for $appname"
    writelog "Proactive Remediation Created and Assigned for $appname"

    ##Create IntuneWin
    Write-Verbose "Creating Intunewin File for $appname"
    writelog "Creating Intunewin File for $appname"
    $intunewinpath = $path + "\install$appid-$appversion.intunewin"
    new-intunewinfile -appid $appid -appname $appname -apppath $apppath -setupfilename $installscriptfile -destpath $path
    Write-Host "Intunewin $intunewinpath Created"
    writelog "Intunewin $intunewinpath Created"
    $sleep = 10
    foreach ($i in 0..$sleep) {
        Write-Progress -Activity "Sleeping for $($sleep-$i) seconds" -PercentComplete ($i / $sleep * 100) -SecondsRemaining ($sleep - $i)
        Start-Sleep -s 1
    }
    ##Create and upload Win32
    Write-Verbose "Uploading $appname to Intune"
    writelog "Uploading $appname to Intune"
    $installcmd = "powershell.exe -ExecutionPolicy Bypass -File $installfilename"
    $uninstallcmd = "powershell.exe -ExecutionPolicy Bypass -File $uninstallfilename"
    new-win32app -appid $appid -appname $appname -appfile $intunewinpath -installcmd $installcmd -uninstallcmd $uninstallcmd -detectionfile $detectionscriptfile
    Write-Host "$appname Created and uploaded"
    writelog "$appname Created and uploaded"

    ##Assign Win32
    Write-Verbose "Assigning Groups"
    writelog "Assigning Groups"
    grant-win32app -appname $appname -installgroup $installgroup -uninstallgroup $uninstallgroup -availableinstall $availableinstall
    Write-Host "Assigned $installgroup as Required Install to $appname"
    writelog "Assigned $installgroup as Required Install to $appname"
    Write-Host "Assigned $uninstallgroup as Required Uninstall to $appname"
    writelog "Assigned $uninstallgroup as Required Uninstall to $appname"

    ##Done
    Write-Host "$appname packaged and deployed"
    writelog "$appname packaged and deployed"

}
Disconnect-MgGraph
if ($question -eq 0) {
    $VerbosePreference="SilentlyContinue"
}
Write-Host "Selected apps have been deployed to Intune" -ForegroundColor Green


if (!$WebHookData) {
    Stop-Transcript  
}
          

    if ($WebHookData -and $repotype -and $ownername -and $reponame -and $token -and $project) {
        $backupreason = "Log on $tenant"

        ##Ingest it
        $logcontent = Get-Content -Path $Logfile      
        ##Encode profiles to base64
        $logencoded =[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($logcontent))
        ##Upload Logs
        writelog "Uploading log to Git Repo"
        if ($repotype -eq "github") {
            writelog "Uploading to Github"
        ##Upload to GitHub
        $date =get-date -format yyMMddHHmmss
        $date = $date.ToString()
        $readabledate = get-date -format dd-MM-yyyy-HH-mm-ss
        $filename = $tenant+"-log-"+$date+".json"
        $uri = "https://api.github.com/repos/$ownername/$reponame/contents/$filename"
        $message = "$backupreason - $readabledate"
        $body = '{{"message": "{0}", "content": "{1}" }}' -f $message, $logencoded
        (Invoke-RestMethod -Uri $uri -Method put -Headers @{'Authorization'='bearer '+$token; 'Accept'='Accept: application/vnd.github+json'} -Body $body -ContentType "application/json")
        }
        if ($repotype -eq "gitlab") {
            writelog "Uploading to GitLab"
        ##Upload to GitLab
        $date = Get-Date -Format yyMMddHHmmss
        $date = $date.ToString()
        $readabledate = Get-Date -Format dd-MM-yyyy-HH-mm-ss
        $filename = $tenant + "-log-" + $date + ".json"
        $GitLabUrl = "https://gitlab.com/api/v4"
        
        # Create a new file in the repository
        $CommitMessage = $backupreason
        $BranchName = "main"
        $FileContent = @{
            "branch" = $BranchName
            "commit_message" = $CommitMessage
            "actions" = @(
                @{
                    "action" = "create"
                    "file_path" = $filename
                    "content" = $logencoded
                }
            )
        }
        $FileContentJson = $FileContent | ConvertTo-Json -Depth 10
        $CreateFileUrl = "$GitLabUrl/projects/$project/repository/commits"
        $Headers = @{
            "PRIVATE-TOKEN" = $token
        }
        Invoke-RestMethod -Uri $CreateFileUrl -Method Post -Headers $Headers -Body $FileContentJson -ContentType "application/json"
        }
        if ($repotype -eq "azuredevops") {
            $date =get-date -format yyMMddHHmmss
        $date = $date.ToString()
        
            $filename = $tenant+"-log-"+$date+".json"
            writelog "Uploading to Azure DevOps"
            Add-DevopsFile -repo $reponame -project $project -organization $ownername -filename $filename -filecontent $logcontent -token $token -comment $backupreason
        
        }
        }


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
            "subject" = " App $appname deployed "
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