<#PSScriptInfo
.VERSION 1.0.0
.GUID 66b58c98-d81c-45e6-a97a-1d1074592f35
.AUTHOR AndrewTaylor
.DESCRIPTION Creates a daily report of expiring app registrations, apple certs and much more
.COMPANYNAME 
.COPYRIGHT GPL
.TAGS intune endpoint MEM
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
.Creates a daily report of expiring app registrations, apple certs and much more
.DESCRIPTION
.Creates a daily report of expiring app registrations, apple certs and much more

.INPUTS
Tenant, AppID, Secret, Email and Sendgrid token
.OUTPUTS
Sends an email
.NOTES
  Version:        1.0.0
  Author:         Andrew Taylor
  Twitter:        @AndrewTaylor_2
  WWW:            andrewstaylor.com
  Creation Date:  08/08/2024
  Purpose/Change: Initial script development
.EXAMPLE
N/A
#>
<#
  __ _  _ __    __| | _ __   ___ __      __ ___ | |_   __ _  _   _ | |  ___   _ __      ___   ___   _ __ ___
 / _` || '_ \  / _` || '__| / _ \\ \ /\ / // __|| __| / _` || | | || | / _ \ | '__|    / __| / _ \ | '_ ` _ \
| (_| || | | || (_| || |   |  __/ \ V  V / \__ \| |_ | (_| || |_| || || (_) || |    _ | (__ | (_) || | | | | |
 \__,_||_| |_| \__,_||_|    \___|  \_/\_/  |___/ \__| \__,_| \__, ||_| \___/ |_|   (_) \___| \___/ |_| |_| |_|

#>
[cmdletbinding()]
    
param
(
    [string]$tenant #Tenant ID (optional) for when automating and you want to use across tenants instead of hard-coded
    ,
    [string]$clientid #ClientID is the type of Azure AD App Reg ID
    ,
    [string]$clientsecret #ClientSecret is the type of Azure AD App Reg Secret
    ,
    [string]$EmailAddress #Email address for report
    , 
    [string]$sendgridtoken #Sendgrid API token
    ,
    [string]$PathToHTMLTemplate #HTML Template for email
    ,
    [object] $WebHookData #Webhook data for Azure Automation
    )

##WebHook Data

$clientidcheck = $PSBoundParameters.ContainsKey('clientid')
##Check if parameters have been set
if (($clientidcheck -eq $true)) {
##AAD Secret passed, use to login
$aadlogin = "yes"

}
if ($WebHookData){
$rawdata = $WebHookData.RequestBody
    $bodyData = ConvertFrom-Json -InputObject ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($rawdata)))
    $tenant = ((($bodyData.tenant) | out-string).trim())
$clientid = ((($bodyData.clientid) | out-string).trim())
$clientsecret = ((($bodyData.clientsecret) | out-string).trim())
$EmailAddress = ((($bodyData.EmailAddress) | out-string).trim())
$sendgridtoken = ((($bodyData.sendgridtoken) | out-string).trim())
$PathToHTMLTemplate = ((($bodyData.htmltemplate) | out-string).trim())

##Using a webhook so use app reg
$aadlogin = "yes"

}

###############################################################################################################
######                                         Install Modules                                           ######
###############################################################################################################
Write-Host "Installing Intune modules if required (current user scope)"


Write-Host "Installing Microsoft Graph Groups modules if required (current user scope)"

#Install Graph Groups module if not available
if (Get-Module -ListAvailable -Name microsoft.graph.groups) {
    Write-Host "Microsoft Graph Groups Module Already Installed"
} 
else {
    try {
        Install-Module -Name microsoft.graph.groups -Scope CurrentUser -Repository PSGallery -Force -AllowClobber 
    }
    catch [Exception] {
        $_.message 
    }
}

#Install Graph Device Management module if not available
if (Get-Module -ListAvailable -Name microsoft.graph.DeviceManagement.Enrollment) {
    Write-Host "Microsoft Graph Device Management Module Already Installed"
} 
else {
    try {
        Install-Module -Name microsoft.graph.DeviceManagement.Enrollment -Scope CurrentUser -Repository PSGallery -Force -AllowClobber 
    }
    catch [Exception] {
        $_.message 
    }
}

#Install MS Graph if not available
if (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication) {
    Write-Host "Microsoft Graph Already Installed"
} 
else {
    try {
        Install-Module -Name Microsoft.Graph.Authentication -Scope CurrentUser -Repository PSGallery -Force 
    }
    catch [Exception] {
        $_.message 
    }
}

#Install MS Graph if not available
if (Get-Module -ListAvailable -Name microsoft.graph.devices.corporatemanagement ) {
    Write-Host "Microsoft Graph Already Installed"
} 
else {
    try {
        Install-Module -Name microsoft.graph.devices.corporatemanagement  -Scope CurrentUser -Repository PSGallery -Force 
    }
    catch [Exception] {
        $_.message 
    }
}

#Install MS Graph if not available
if (Get-Module -ListAvailable -Name Microsoft.Graph.Identity.Governance ) {
    Write-Host "Microsoft Graph Already Installed"
} 
else {
    try {
        Install-Module -Name Microsoft.Graph.Identity.Governance  -Scope CurrentUser -Repository PSGallery -Force 
    }
    catch [Exception] {
        $_.message 
    }
}



#Importing Modules
Import-Module Microsoft.Graph.Groups
Import-Module Microsoft.Graph.DeviceManagement.Enrollment
import-module microsoft.graph.authentication
import-module microsoft.graph.devices.corporatemanagement
import-module Microsoft.Graph.Identity.Governance


###############################################################################################################
######                                          Add Functions                                            ######
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
function Get-RandomPassword {
    param (
        [Parameter(Mandatory)]
        [int] $length,
        [int] $amountOfNonAlphanumeric = 1
    )
    Add-Type -AssemblyName 'System.Web'
    return [System.Web.Security.Membership]::GeneratePassword($length, $amountOfNonAlphanumeric)
}

###############################################################

function getwindowsdevicesandusers() {
    $alldevices = getallpagination -url "https://graph.microsoft.com/beta/devicemanagement/manageddevices?`$filter=operatingSystem eq 'Windows'"
    $outputarray = @()
    foreach ($value in $alldevices) {
        $objectdetails = [pscustomobject]@{
            DeviceID = $value.id
            DeviceName = $value.deviceName
            OSVersion = $value.osVersion
            PrimaryUser = $value.userPrincipalName
        }
    
    
        $outputarray += $objectdetails
    
    }
    return $outputarray
}


<#
.SYNOPSIS
wraps a string or an array of strings at the console width without breaking within a word
.PARAMETER chunk
a string or an array of strings
.EXAMPLE
word-wrap -chunk $string
.EXAMPLE
$string | word-wrap
#>
function word-wrap {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory=1,ValueFromPipeline=1,ValueFromPipelineByPropertyName=1)]
        [Object[]]$chunk
    )
    PROCESS {
        $Lines = @()
        foreach ($line in $chunk) {
            $str = ''
            $counter = 0
            $line -split '\s+' | %{
                $counter += $_.Length + 1
                if ($counter -gt $Host.UI.RawUI.BufferSize.Width) {
                    $Lines += ,$str.trim()
                    $str = ''
                    $counter = $_.Length + 1
                }
                $str = "$str$_ "
            }
            $Lines += ,$str.trim()
        }
        $Lines
    }
}
###############################################################################################################
######                                     Graph Connection                                              ######
###############################################################################################################
##Connect using Secret
$tenantId = $tenant
write-output "Connecting to Graph"
if (($aadlogin -eq "yes")) {
 
    Connect-ToGraph -Tenant $tenant -AppId $clientId -AppSecret $clientSecret
    write-output "Graph Connection Established"
    }
    else {
    ##Connect to Graph
    Connect-ToGraph -Scopes "Policy.ReadWrite.ConditionalAccess, CloudPC.ReadWrite.All, DeviceManagementServiceConfig.ReadWrite.All, RoleAssignmentSchedule.ReadWrite.Directory, Domain.Read.All, Domain.ReadWrite.All, Directory.Read.All, Policy.ReadWrite.ConditionalAccess, DeviceManagementApps.ReadWrite.All, DeviceManagementConfiguration.ReadWrite.All, DeviceManagementManagedDevices.ReadWrite.All, openid, profile, email, offline_access, DeviceManagementRBAC.Read.All, DeviceManagementRBAC.ReadWrite.All, Policy.ReadWrite.MobilityManagement, SecurityEvents.Read.All, User.ReadWrite.All, AuditLog.Read.All"
    }
write-output "Graph Connection Established"


##Create an array to store JSON data
$jsonoutput = [pscustomobject]@{
}





##################################################################################################################################
#################                                        Updated Applications                                    #################
##################################################################################################################################
write-host "Detecting updated applications in the last week"
$updatedappoutput = @()
$uri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps"
$eightDaysAgo = (Get-Date).AddDays(-1).ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
$updatedapps = (getallpagination -url $uri) | where-object '@odata.type' -eq '#microsoft.graph.win32LobApp'| Where-Object { $_.lastModifiedDateTime -gt $eightDaysAgo }

##If it's empty, return that
if (!$updatedapps) {
    $updatedappoutput = "No apps have been updated in the last 24 hours"
}
else{
foreach ($app in $updatedapps) {
    $updatedappoutput += "App: $($app.displayName) was last updated on $($app.lastModifiedDateTime)"
}
}

##Count the updated apps
$updatedappcount = $updatedapps.count
$jsonoutput | Add-Member -NotePropertyName "UpdatedApps" -NotePropertyValue "$updatedappcount"


##################################################################################################################################
#################                                            Check Admin Alerts                                  #################
##################################################################################################################################

##Get all events
write-host "Getting all events from Intune"
$yesterday = (Get-Date).AddDays(-1).ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
$uri = "https://graph.microsoft.com/beta/deviceManagement/auditEvents?`$filter= activityDateTime gt $yesterday"
##Select the value
$eventsvalues = getallpagination -url $uri
##Expand nested array
$eventsvalues =  $eventsvalues | select-object * -ExpandProperty Actor

write-host "Audit Events Grabbed"
##Create an array to store tweaked output
$listofevents = @()
##Select specific values from the array
$eventsvalues =  $eventsvalues | select-object resources, userPrincipalName, displayName, category, activityType, activityDateTime, activityOperationType, id 
##Loop through the array and create a new object with the values we want
foreach ($event in $eventsvalues)
{
    $id = $event.id
    $eventobject = [pscustomobject]@{
        changedItem = $event.Resources.displayName
        changedBy = $event.userPrincipalName
        change = $event.displayName
        changeCategory = $event.category
        activityType = $event.activityType
        activityDateTime = $event.activityDateTime
        id = $event.id
    }
    $listofevents += $eventobject
}

$selected = $listofevents


##### DEAL WITH EACH EVENT SELECTED

write-host "Getting details for each event selected"

$excludedEvents = @(
    "Win32LobApp",
    "Microsoft.Management.Services.CertVNextCommonLibrary.ClientCertificate",
    "MobileApp",
    "Microsoft.Management.Services.Api.ManagedDevice",
    "AndroidManagedStoreApp",
    "ImportedWindowsAutopilotDeviceIdentity"
)

##Create array to store it
$selectedevents = @()

##Loop through
foreach ($item in $selected) {
    ##Grab the details
    $selectedid = $item.id
    $resourcetype = $changedcontent.resource.type
    if ($excludedEvents -notcontains $resourceType) {
$uri = "https://graph.microsoft.com/beta/deviceManagement/auditEvents/$selectedid"
write-host "Getting details for $selectedid"
$changedcontent = (Invoke-MgGraphRequest -Uri $uri -Method GET -ContentType "application/json" -OutputType PSObject)

##Create a new object with the values we want
$eventobject = [pscustomobject]@{
    change = $changedcontent.displayName
    activityDateTime = $changedcontent.activityDateTime
    activityResult = $changedcontent.activityResult
    type = $changedcontent.actor.type
    applicationId = $changedcontent.actor.applicationId
    applicationDisplayName = $changedcontent.actor.applicationDisplayName
    userPrincipalName = $changedcontent.actor.userPrincipalName
}

$selectedevents += $eventobject
}
}

##Check if it's not empty
if (!$selectedevents) {
    $eventscontent = "No events have been detected in the last 24 hours"
}
else {
    $eventscontent = $selectedevents | ConvertTo-Html -Fragment
}


##Count the admin alerts
$updatedeventcount = $eventsvalues.count
$jsonoutput | Add-Member -NotePropertyName "AdminEvents" -NotePropertyValue "$updatedeventcount"

##################################################################################################################################
#################                                            Check Licenses                                      #################
##################################################################################################################################

##Get the domain name
$uri = "https://graph.microsoft.com/beta/organization"
$tenantdetails = (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).value
$domain = ($tenantdetails.VerifiedDomains | Where-Object isDefault -eq $true).name

if (!$tenant) {
    $tenant = $tenantdetails.id
}

## Check unused licenses
write-output "Checking Unused Licenses"

$graphurl = "https://graph.microsoft.com/v1.0/subscribedSkus"

$licenses = getallpagination -url $graphurl


$translationTable = Invoke-RestMethod -Method Get -Uri "https://download.microsoft.com/download/e/3/e/e3e9faf2-f28b-490a-9ada-c6089a1fc5b0/Product%20names%20and%20service%20plan%20identifiers%20for%20licensing.csv" | ConvertFrom-Csv
$unused = @()
$total = @()
foreach ($license in $licenses) {
$skuNamePretty = ($translationTable | Where-Object {$_.GUID -eq $license.skuId} | Sort-Object Product_Display_Name -Unique)."ï»¿Product_Display_Name"

$available = (($license.prepaidUnits.enabled) - ($license.consumedUnits))
if (($skuNamePretty -notmatch "free") -and ($skuNamePretty -notmatch "trial")) {
$objectdetailstotal = [pscustomobject]@{
    name = $skuNamePretty
    total = $license.prepaidUnits.enabled
    used = $license.consumedUnits
    unused = $available
}
$total += $objectdetailstotal
}

if (($available -gt 0) -and ($skuNamePretty -notmatch "free") -and ($skuNamePretty -notmatch "trial")) {

$licensename = $skuNamePretty
Write-Output "$licensename has $available unused licenses"
$objectdetails = [pscustomobject]@{
    name = $licensename
    unused = $available
}
$unused += $objectdetails
}
}
$total = $total | Sort-Object Unused -Descending

##Count the unused licenses
$totalunused = $total.count
$jsonoutput | Add-Member -NotePropertyName "UnusedLicenses" -NotePropertyValue "$totalunused"


$totaloutput = $total | ConvertTo-Html -Fragment

Write-Output "Unused Licenses Checked"
##Check Unused users with licenses

Write-Output "Checking Unused Users"

##Unused Users first
$usersuri = "https://graph.microsoft.com/v1.0/users?`$select=displayName,signInActivity, userPrincipalName, id"

$users = getallpagination -url $usersuri

$oldusers = @()

##Find users who haven't signed in for 90 days
foreach ($user in $users) {
$userid = $user.id
$userupn = $user.userPrincipalName
$lastsignin = $user.signInActivity.lastSignInDateTime
if ([string]::IsNullOrEmpty($lastsignin) -or ([datetime]::UtcNow - [datetime]$lastsignin).TotalDays -gt 90) {
        $objectdetails = [pscustomobject]@{
            name = $userupn
            userid = $userid
        }
        $oldusers += $objectdetails
        write-output "$userupn has not been seen for 90 days or more"


}
else {
    ##Ignore these
}
}


write-output "Unused Users Checked"

##Check each old user for licenses

write-output "Checking Unused Licenses for Unused Users"

$licensestorelease = @()
foreach ($olduser in $oldusers) {
    $olduserid = $olduser.userid
    $olduserupn = $olduser.name
$licenseuricheck = "https://graph.microsoft.com/v1.0/users/$olduserid/licenseDetails"
$userlicence = getallpagination -url $licenseuricheck
    if ($userlicence.Count -gt 0) {
        Write-Output "$olduserupn has a license assigned"
        foreach ($individuallicense in $userlicence) {
            $skuNamePretty = ($translationTable | Where-Object {$_.GUID -eq $individuallicense.skuId} | Sort-Object Product_Display_Name -Unique)."ï»¿Product_Display_Name"
        $objectdetails = [pscustomobject]@{
            name = $olduserupn
            license = $skuNamePretty
        }
        $licensestorelease += $objectdetails
    }
    }
    else {
        write-output "$olduserupn has no license assigned"
    }


}

##Check if it has content
if (!$licensestorelease) {
    $licensesoutput = "No licenses to release"
}
else {

$licensesoutput = $licensestorelease | convertto-html -Fragment
}

Write-Output "Unused Licenses for Unused Users Checked"

##Count the unused licenses
$oldrelease = $licensestorelease.count
$jsonoutput | Add-Member -NotePropertyName "LicensesonOldUsers" -NotePropertyValue "$oldrelease"

##################################################################################################################################
#################                                            Check Secure Score                                  #################
##################################################################################################################################
$uri = "https://graph.microsoft.com/v1.0/security/secureScores"

$scores = (Invoke-MgGraphRequest -Uri $uri -Method GET -OutputType PSObject).value | Select-Object -First 1
$currentscore = $scores.currentScore
$maxscore = $scores.maxScore

$scoreoutput = "Secure score is $currentscore / $maxscore"


$jsonoutput | Add-Member -NotePropertyName "SecureScore" -NotePropertyValue "$currentscore"


##################################################################################################################################
#################                                     Check Non-Compliant Devices                                #################
##################################################################################################################################

##Get all devices and check their compliance

$graphApiVersion = "beta"
$Resource = "deviceManagement/managedDevices"
$uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"

$alldevices = getallpagination -url $uri

$listofissues = @()

foreach ($device in $alldevices) {
    $deviceid = $device.id
    $uri = "https://graph.microsoft.com/beta/deviceManagement/managedDevices/$deviceid/deviceCompliancePolicyStates"
    $allcompliance = getallpagination -url $uri
    foreach ($compliance in $allcompliance) {
        $compliancestate = $compliance.state
        $policyid = $compliance.id
    if ($compliancestate -eq "noncompliant") {
        ##Get Details
        $furi = "https://graph.microsoft.com/beta/deviceManagement/managedDevices/$deviceid/deviceCompliancePolicyStates/$policyid/settingStates"
        $noncompliance = (Invoke-MgGraphRequest -Uri $furi -Method Get -OutputType PSObject).value | Where-Object {$_.state -eq "noncompliant"}
        write-host "Device $deviceid is noncompliant" -ForegroundColor Red
        $username = $device.userPrincipalName
        $pcname = $device.deviceName    
        $eventobject = [pscustomobject]@{
            UserName = $username
            DeviceName = $pcname
        }
        $i = 0
        foreach ($resource in $noncompliance) {
            $name = "Non-CompliantSetting-" + $i        
            $eventobject | Add-Member -MemberType NoteProperty -Name $name -Value $resource.setting
            $i++
        }
        $listofissues += $eventobject
    
    }
    }
}

##Check if there is content
if (!$listofissues) {
    $noncompliantoutput = "No non-compliant devices"
}
else {

$noncompliantoutput = $listofissues | ConvertTo-Html -Fragment
}

##Count the unused licenses
$noncompliantcount = $listofissues.count
$jsonoutput | Add-Member -NotePropertyName "NonCompliantDevices" -NotePropertyValue "$noncompliantcount"

##################################################################################################################################
#################                                     Check Win365 Unused Devices                                #################
##################################################################################################################################

$checkurl = "https://graph.microsoft.com/beta/deviceManagement/virtualEndpoint/reports/getTotalAggregatedRemoteConnectionReports"

$clouddevices = (Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/deviceManagement/virtualEndpoint/cloudPCs" -OutputType PSObject).value

$outputarray = @()

foreach ($clouddevice in $clouddevices) {

$clouddevicename = $clouddevice.displayName
$clouddeviceid = $clouddevice.id
$clouddeviceuser = $clouddevice.userPrincipalName

$json = @"
{
    "filter": "CloudPcId eq '$clouddeviceid'",
    "select": [
        "TotalUsageInHour"
    ]
}
"@
$filepath = "c:\temp\report" + $clouddeviceid + ".txt"

Invoke-MgGraphRequest -Method POST -Uri $checkurl -Body $json -ContentType "application/json" -OutputFilePath $filepath
$parsedData = get-content $filepath | ConvertFrom-Json
$rawtime = ($parsedData.Values)[0] | out-string
$monthlyuptime = (New-TimeSpan -minutes $rawtime).ToString("mm")
remove-item $filepath
if (([decimal]$rawtime) -le 10) {
write-host $monthlyuptime
        $objectdetails = [pscustomobject]@{
            name = $clouddevicename
            user = $clouddeviceuser
            uptime = $monthlyuptime
        }
        $outputarray += $objectdetails
}

}
if (!$outputarray) {
 $w365output = "No unused W365 machines"
}
else {
    $w365output = $outputarray | convertto-html -Fragment
}

##################################################################################################################################
#################                                            Check Failed Sign-Ins                               #################
##################################################################################################################################
$startDate = (Get-Date).AddDays(-1).ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
$endDate = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
$uri = "https://graph.microsoft.com/beta/auditLogs/signIns?api-version=beta&`$filter=(createdDateTime ge $startDate and createdDateTime lt $endDate)&`$orderby=createdDateTime desc&source=kds"

$signins = (getallpagination -url $uri) | select-object * -ExpandProperty status | where-object errorcode -ne 0

$signinsoutputarray = @()

foreach ($signin in $signins) {
    $objectdetails = [pscustomobject]@{
        name = $signin.userDisplayName
        UPN = $signin.userPrincipalName
        DateTime = $signin.createdDateTime
        Location = $signin.location.city
        App = $signin.clientAppUsed
        Failure = $signin.status.failureReason
    }
    $signinsoutputarray += $objectdetails
}

##Check for output
if (!$signinsoutputarray) {
    $signinsoutput = "No failed sign-ins"
}
else {

$signinsoutput = $signinsoutputarray | convertto-html -Fragment
}

##Count the unused licenses
$failedcount = $signinsoutputarray.count
$jsonoutput | Add-Member -NotePropertyName "FailedSignIns" -NotePropertyValue "$failedcount"

##################################################################################################################################
#################                                            Check App Installs                                  #################
##################################################################################################################################
$uri = "https://graph.microsoft.com/beta/deviceManagement/reports/getAppsInstallSummaryReport"

$json = @"
{
	"filter": "(FailedDeviceCount gt '0')",
	"orderBy": [
		"FailedDeviceCount desc"
	],
	"select": [
		"DisplayName",
		"Publisher",
		"Platform",
		"AppVersion",
		"FailedDevicePercentage",
		"FailedDeviceCount",
		"FailedUserCount",
		"ApplicationId"
	],
	"skip": 0,
	"top": 10
}
"@

$tempfilepath = $env:TEMP + "\appreport.txt"

Invoke-MgGraphRequest -Method POST -Uri $uri -Body $json -ContentType "application/json" -OutputFilePath $tempfilepath

$parsedData = get-content $tempfilepath | ConvertFrom-Json
$fullvalues = $parsedData.Values

$appsoutputarray = @()
foreach ($value in $fullvalues) {
    $objectdetails = [pscustomobject]@{
        AppName = $value[2]
        DeviceFailures = $value[3]
        FailureRate = [Math]::Round($value[4], 0)
        UserFailures = $value[5]
        Platform = $value[7]
        Publisher = $value[8]
    }


    $appsoutputarray += $objectdetails

}


remove-item $tempfilepath

##Check for app installs
if (!$appsoutputarray) {
$appsoutput = "No failed app installs"
}
else {
$appsoutput = $appsoutputarray | convertto-html -Fragment
}

##Count the unused licenses
$failedappinstalls = $appsoutputarray.count
$jsonoutput | Add-Member -NotePropertyName "FailedAppInstalls" -NotePropertyValue "$failedappinstalls"


##################################################################################################################################
#################                                            Check App Protection                                #################
##################################################################################################################################
$uri = "https://graph.microsoft.com/beta/deviceAppManagement/managedAppRegistrations/getUserIdsWithFlaggedAppRegistration"
$flaggedusers = getallpagination -url $uri
if (!$flaggedusers) {
    $output = "None"
}
else {
    $output = $flaggedusers
}

##################################################################################################################################
#################                                     VPP Cert Expiry                                            #################
##################################################################################################################################
#MDM Push
$pushuri = "https://graph.microsoft.com/beta/deviceManagement/applePushNotificationCertificate"
$pushcert = Invoke-MgGraphRequest -Uri $pushuri -Method Get -OutputType PSObject
$pushexpiryplaintext = $pushcert.expirationDateTime
##Check it exists
if ($pushcert) {
$pushexpiry = ($pushcert.expirationDateTime).ToString("yyyy-MM-dd")
}
else {
    $pushexpiry = "No Push certificate detected"
}

$jsonoutput | Add-Member -NotePropertyName "Push-Expiry" -NotePropertyValue "$pushexpiry"


#VPP
$vppuri = "https://graph.microsoft.com/beta/deviceAppManagement/vppTokens"
$vppcert = Invoke-MgGraphRequest -Uri $vppuri -Method Get -OutputType PSObject
$vppexpiryvalue = $vppcert.value
$vppexpiryplaintext = $vppexpiryvalue.expirationDateTime
##Check it exists
if ($vppcert) {
    $vppexpiry = ($vppexpiryvalue.expirationDateTime).ToString("yyyy-MM-dd")
    }
    else {
    $vppexpiry = "No VPP certificate detected"
    }

    $jsonoutput | Add-Member -NotePropertyName "VPP-Expiry" -NotePropertyValue "$vppexpiry"
    

#DEP
$depuri = "https://graph.microsoft.com/beta/deviceManagement/depOnboardingSettings"
$depcert = Invoke-MgGraphRequest -Uri $depuri -Method Get -OutputType PSObject
$depexpiryvalue = $depcert.value
$depexpiryplaintext = $depexpiryvalue.tokenexpirationDateTime
##Check it exists
if ($depcert) {
    $depexpiry = ($depexpiryvalue.tokenExpirationDateTime).ToString("yyyy-MM-dd")
    }
    else {
    $depexpiry = "No DEP certificate detected"
    }

    $jsonoutput | Add-Member -NotePropertyName "DEPExpiry" -NotePropertyValue "$depexpiry"
    


$dateTime = Get-Date
$formattedDateTime = $dateTime.ToString("dddd MMMM d' 'yyyy hh:mmtt")

##################################################################################################################################
#################                                    Unsupported Versions                                        #################
##################################################################################################################################

$supportedversions = @()

    ##Windows 11
    ##Scrape the release information to find latest supported versions
    $url = "https://learn.microsoft.com/en-us/windows/release-health/windows11-release-information"
    $content = (Invoke-WebRequest -Uri $url -UseBasicParsing).content
    [regex]$regex = "(?s)<tr class=.*?</tr>"
    $tables = $regex.matches($content).groups.value
    $tables = $tables.replace("<td>","")
    $tables = $tables.replace("</td>","")
    $tables = $tables.replace('<td align="left">',"")
    $tables = $tables.replace('<tr class="highlight">',"")
    $tables = $tables.replace("</tr>","")
    
    ##Add each found version for array
    $availableversions = @()
    foreach ($table in $tables) {
        [array]$toArray = $table.Split("`n") | Where-Object {$_.Trim("")}
        $availableversions += ($toArray[4]).Trim()
    }
    
    ##We want n-1 so grab the first two objects
    $supportedversions += $availableversions | select-object -first 2

    
    

        ##Windows 10
        ##Scrape the release information to find latest supported versions
        $url = "https://learn.microsoft.com/en-us/windows/release-health/release-information"
        $content = (Invoke-WebRequest -Uri $url -UseBasicParsing).content
        [regex]$regex = "(?s)<tr class=.*?</tr>"
        $tables = $regex.matches($content).groups.value
        $tables = $tables.replace("<td>","")
        $tables = $tables.replace("</td>","")
        $tables = $tables.replace('<td align="left">',"")
        $tables = $tables.replace('<tr class="highlight">',"")
        $tables = $tables.replace("</tr>","")
        
        ##Add each found version for array
        $availableversions = @()
        foreach ($table in $tables) {
            [array]$toArray = $table.Split("`n") | Where-Object {$_.Trim("")}
            $availableversions += ($toArray[4]).Trim()
        }
    
        ##We want n-1 so grab the first two objects
        $supportedversions += $availableversions | select-object -first 2

$windowsdevices = getwindowsdevicesandusers
$outdateddevices = @()
foreach ($windowsdevice in $windowsdevices) {
    $osversion = $windowsdevice.osVersion
    $devicename = $windowsdevice.DeviceName
    $deviceuser = $windowsdevice.PrimaryUser
##Check if OS version is in $supportedversions array
if ($supportedversions -contains $osversion) {
    # Code to execute if OS version is supported
    Write-Host "OS version is supported on device $devicename."
} else {
    # Create a new PS Object
    $objectdetails = [pscustomobject]@{
        Devicename = $devicename
        OSVersion = $osversion
        User = $deviceuser
    }


    $outdateddevices += $objectdetails
}

}
if ($outdateddevices) {
    $outdatedreport = $outdateddevices | ConvertTo-Html -Fragment
}
else {
    $outdatedreport = "All devices are up to date"
}

##################################################################################################################################
#################                                        AV and Malware Checks                                   #################
##################################################################################################################################
$malware = @()

$uri = "https://graph.microsoft.com/beta/deviceManagement/windowsMalwareOverview"
$malwarecheck = Invoke-MgGraphRequest -Method GET -uri $uri -outputType PSObject
$infecteddevices = $malwarecheck.malwareDetectedDeviceCount
$totalmalware = $malwarecheck.totalMalwareCount
$uri = "https://graph.microsoft.com/beta/deviceManagement/deviceProtectionOverview"
$avchecks = Invoke-MgGraphRequest -uri $uri -method GET -outputType PSObject
$inactive = $avchecks.inactiveThreatAgentDeviceCount
$unknown = $avchecks.unknownStateThreatAgentDeviceCount
$pendingsig = $avchecks.pendingSignatureUpdateDeviceCount
$totaldevices = ($avchecks.totalReportedDeviceCount).ToString()
$cleandevices = ($avchecks.cleanDeviceCount).ToString()
$cleancount = $cleandevices + "/" + $totaldevices
$pendingscan = $avchecks.pendingFullScanDeviceCount
$pendingrestart = $avchecks.pendingRestartDeviceCount
$pendinginteraction = $avchecks.pendingManualStepsDeviceCount
$pendingofflinescan = $avchecks.pendingOfflineScanDeviceCount
$critfailure = $avchecks.criticalFailuresDeviceCount
$pendingquickscan = $avchecks.pendingQuickScanDeviceCount

$objectdetails = [pscustomobject]@{
    InfectedDevicesCount = $infecteddevices
    MalwareCount = $totalmalware
    InactiveAVCount = $inactive
    UnknownAVCount = $unknown
    OutdatedSignatureCount = $pendingsig
    CleanDevices = $cleancount
    PendingFullScan = $pendingscan
    PendingRestart = $pendingrestart
    RequiresManualInteraction = $pendinginteraction
    PendingOfflineScan = $pendingofflinescan
    CriticalFailure = $critfailure
    PendingQuickScan = $pendingquickscan
}
$malware += $objectdetails

$malwareoutput = $malware | convertto-html -Fragment

##Do a count
$avcount = $infecteddevices + $totalmalware + $inactive + $pendingsig + $pendingscan + $pendingrestart + $pendinginteraction + $pendingofflinescan + $pendingquickscan + $critfailure

$jsonoutput | Add-Member -NotePropertyName "AV-Issues" -NotePropertyValue "$avcount"


##################################################################################################################################
#################                                       Firewall Checks                                          #################
##################################################################################################################################

$uri = "https://graph.microsoft.com/beta/deviceManagement/reports/getUnhealthyFirewallSummaryReport"

$json = @"
{
    "{}": ""
}
"@

$tempfilepath = $env:TEMP + "\fwreport.txt"

Invoke-MgGraphRequest -Method POST -Uri $uri -Body $json -ContentType "application/json" -OutputFilePath $tempfilepath

$parsedData = get-content $tempfilepath | ConvertFrom-Json
$fullvalues = $parsedData.Values

$totaldevices = ($fullvalues[0][0]).ToString()
$firewalloff = ($fullvalues[0][1]).tostring()

$firewallstatus = $firewalloff + "/" + $totaldevices

remove-item $tempfilepath

$jsonoutput | Add-Member -NotePropertyName "FirewallOff" -NotePropertyValue "$firewalloff"



##################################################################################################################################
#################                                  Security Tasks                                                #################
##################################################################################################################################
$uri = "https://graph.microsoft.com/beta/DeviceAppManagement/deviceAppManagementTasks"
$securitytasks = getallpagination -url $uri
if ($securitytasks) 
{
    $securityoutput = $securitytasks
}
else {
    $securityoutput = "No security tasks outstanding"
}

$pendingsecurity = $securityoutput.count
$jsonoutput | Add-Member -NotePropertyName "Security Tasks" -NotePropertyValue "$pendingsecurity"


##################################################################################################################################
#################                                 Check Feature Update Policies                                  #################
##################################################################################################################################

##Grab all feature updates
$url = "https://graph.microsoft.com/beta/deviceManagement/windowsFeatureUpdateProfiles/"
$featureupdates  = getallpagination -url $url
##Get the latest feature update
$allupdatesurl = "https://graph.microsoft.com/beta/deviceManagement/windowsUpdateCatalogItems/microsoft.graph.windowsFeatureUpdateCatalogItem"
$availablefeatures = (Invoke-MgGraphRequest -Uri $allupdatesurl -Method GET -OutputType PSObject).value
$latest = $availablefeatures | Sort-Object -Property endOfSupportDate -Descending | Select-Object -First 1
$newversion = $latest.version


$winupdates = $featureupdates| Select-Object * -ExcludeProperty createdDateTime, lastModifiedDateTime, endOfSupportDate
$featurearray = @()
foreach ($winupdate in $winupdates) {
    $currentfeature = $winupdate.featureUpdateVersion
    $displaynamef = $winupdate.displayName
##Compare what we have to what is live
if ($currentfeature -eq $newversion) {
    write-output "Already running the latest, do nothing"
    }
    else {
        write-output "Updating to latest feature version"
    $status = "Outdated, configured version is $currentfeature, latest is $newversion"
    $objectdetails = [pscustomobject]@{
        PolicyName = $displaynamef
        Status = $status
    }
    $featurearray += $objectdetails
    }
}

##Check if array has content
if ($featurearray) {
$featureupdatecheck = $featurearray | convertto-html -Fragment
}
else {
    $featureupdatecheck = "All feature update profiles are running the latest version: $newversion"
}

$outdatedfeaturepolicy = $featurearray.count
$jsonoutput | Add-Member -NotePropertyName "OutdatedFeatureUpdatePolicy" -NotePropertyValue "$outdatedfeaturepolicy"

##################################################################################################################################
#################                                 Check App Registrations                                         #################
##################################################################################################################################

##Get app registrations
$Applications = getallpagination -url "https://graph.microsoft.com/v1.0/applications"
$array = @()
foreach ($app in $Applications) {
  $app.passwordCredentials | foreach-object {
      #If there is a secret with a enddatetime, we need to get the expiration of each one
      if ($_.endDateTime -ne $null) {
          [system.string]$secretdisplayName = $_.displayName
          [system.string]$id = $app.id
          [system.string]$displayname = $app.displayName
          $Date = [TimeZoneInfo]::ConvertTimeBySystemTimeZoneId($_.endDateTime, 'Central Standard Time')
          [int32]$daysUntilExpiration = (New-TimeSpan -Start ([System.TimeZoneInfo]::ConvertTimeBySystemTimeZoneId([DateTime]::Now, "Central Standard Time")) -End $Date).Days
          
          if (($daysUntilExpiration -ne $null) -and ($daysUntilExpiration -le $expirationDays)) {
              $array += $_ | Select-Object @{
                  name = "id"; 
                  expr = { $id } 
              }, 
              @{
                  name = "displayName"; 
                  expr = { $displayName } 
              }, 
              @{
                  name = "secretName"; 
                  expr = { $secretdisplayName } 
              },
              @{
                  name = "daysUntil"; 
                  expr = { $daysUntilExpiration } 
              }
          }
          $daysUntilExpiration = $null
          $secretdisplayName = $null
      }
  }
}

##Check if $array is empty
if ($array -ne 0) {
$textTable = $array | Sort-Object daysUntil | Select-Object displayName, secretName, daysUntil | ConvertTo-Html -Fragment
}
else {
    $textTable = "No expiring app secrets"
}

$expiringsecrets = $array.count
$jsonoutput | Add-Member -NotePropertyName "ExpiringSecrets" -NotePropertyValue "$expiringsecrets"


##################################################################################################################################
#################                                      Stale Devices                                             #################
##################################################################################################################################

[datetime]$scriptStartTime = Get-Date
[string]$disableDate = "$(($scriptStartTime).AddDays(-60).ToString("yyyy-MM-dd"))T00:00:00z"
$uri = "https://graph.microsoft.com/beta/devices?`$filter=approximateLastSignInDateTime le $disabledate"
$staledevices = getallpagination -url $uri

if ($staledevices) {
    $staleoutput = $staledevices | Select-Object deviceId, displayName, approximateLastSignInDateTime | ConvertTo-Html -Fragment
}
else {
    $staleoutput = "No stale devices"
}

$staledevicecount = $staledevices.count
$jsonoutput | Add-Member -NotePropertyName "StaleDevices" -NotePropertyValue "$staledevicecount"


##################################################################################################################################
#################                                Service Health Issues                                           #################
##################################################################################################################################

$yesterday = (Get-Date).AddDays(-1).ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
$uri = "https://graph.microsoft.com/beta/admin/serviceAnnouncement/issues?`$filter= startDateTime gt $yesterday"

$healthissues = getallpagination -url $uri

if ($healthissues = getallpagination -url $uri
) {
    $healthissueoutput = $healthissues | Select-Object startDateTime, endDateTime, title, impactDescription, classification, status, service | ConvertTo-Html -Fragment
}
else {
    $healthissueoutput = "No service health Issues"
}


##################################################################################################################################
#################                                Service Health Messages                                         #################
##################################################################################################################################

$yesterday = (Get-Date).AddDays(-1).ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
$uri = "https://graph.microsoft.com/beta/admin/serviceAnnouncement/messages?`$filter= startDateTime gt $yesterday"

$healthmessages = getallpagination -url $uri

if ($healthmessages = getallpagination -url $uri
) {
    $healthoutput = $healthmessages | Select-Object startDateTime, endDateTime, title | ConvertTo-Html -Fragment
}
else {
    $healthoutput = "No service health messages"
}


##################################################################################################################################
#################                                Service Health Overview                                         #################
##################################################################################################################################

$uri = "https://graph.microsoft.com/beta/admin/serviceAnnouncement/healthOverviews?`$filter=id eq 'Intune'"
$servicehealth = (Invoke-MgGraphRequest -Uri $uri -Method GET -OutputType PSObject).value.status
$serviceoutput = $servicehealth.ToString()

$jsonoutput | Add-Member -NotePropertyName "ServiceHealth" -NotePropertyValue "$serviceoutput"

##################################################################################################################################
#################                                Feature Update Checks                                           #################
##################################################################################################################################

$uri = "https://graph.microsoft.com/beta/deviceManagement/reports/getWindowsUpdateAlertSummaryReport"

$json = @"
{
    "select": [
        "PolicyId",
        "NumberOfDevicesWithErrors"
    ]
}
"@

$tempfilepath = $env:TEMP + "\featureupdates.txt"

Invoke-MgGraphRequest -Method POST -Uri $uri -Body $json -ContentType "application/json" -OutputFilePath $tempfilepath

$parsedData = get-content $tempfilepath | ConvertFrom-Json
$fullvalues = $parsedData.Values

$sumerrors = 0
$policieswitherrors = @()

foreach ($value in $values) {
    $policyid = $value[1]
    $errorcount = $value[0]

    $sumerrors += $errorcount

    if ($errorcount -gt 0) {
        $policieswitherrors += $policyid
    }
}

if ($sumerrors -gt 0) {
    $featureupdateoutput = "There are $sumerrors devices with errors in the following policies: $policieswitherrors"
}
else {
    $featureupdateoutput = "There are no devices with errors"
}

$jsonoutput | Add-Member -NotePropertyName "FeatureUpdateErrors" -NotePropertyValue "$errorcount"

Remove-Item $tempfilepath -Force


##################################################################################################################################
#################                                Expedited Update Checks                                         #################
##################################################################################################################################

$uri = "https://graph.microsoft.com/beta/deviceManagement/reports/getWindowsQualityUpdateAlertSummaryReport"

$json = @"
{
    "select": [
        "PolicyId",
        "NumberOfDevicesWithErrors"
    ]
}
"@

$tempfilepath = $env:TEMP + "\expeditedupdates.txt"

Invoke-MgGraphRequest -Method POST -Uri $uri -Body $json -ContentType "application/json" -OutputFilePath $tempfilepath

$parsedData = get-content $tempfilepath | ConvertFrom-Json
$fullvalues = $parsedData.Values

$sumerrors = 0
$policieswitherrors = @()

foreach ($value in $values) {
    $policyid = $value[1]
    $errorcount = $value[0]

    $sumerrors += $errorcount

    if ($errorcount -gt 0) {
        $policieswitherrors += $policyid
    }
}

if ($sumerrors -gt 0) {
    $expeditedupdateoutput = "There are $sumerrors devices with errors in the following policies: $policieswitherrors"
}
else {
    $expeditedupdateoutput = "There are no devices with errors"
}

$jsonoutput | Add-Member -NotePropertyName "expeditedUpdateErrors" -NotePropertyValue "$errorcount"

Remove-Item $tempfilepath -Force

##################################################################################################################################
#################                                Driver Update Checks                                            #################
##################################################################################################################################

$uri = "https://graph.microsoft.com/beta/deviceManagement/reports/getWindowsDriverUpdateAlertSummaryReport"

$json = @"
{
    "select": [
        "PolicyName",
        "NumberOfDevicesWithErrors"
    ]
}
"@

$tempfilepath = $env:TEMP + "\driverupdates.txt"

Invoke-MgGraphRequest -Method POST -Uri $uri -Body $json -ContentType "application/json" -OutputFilePath $tempfilepath

$parsedData = get-content $tempfilepath | ConvertFrom-Json
$fullvalues = $parsedData.Values

$sumerrors = 0
$policieswitherrors = @()

foreach ($value in $values) {
    $policyid = $value[1]
    $errorcount = $value[0]

    $sumerrors += $errorcount

    if ($errorcount -gt 0) {
        $policieswitherrors += $policyid
    }
}

if ($sumerrors -gt 0) {
    $driverupdateoutput = "There are $sumerrors devices with errors in the following policies: $policieswitherrors"
}
else {
    $driverupdateoutput = "There are no devices with errors"
}

$jsonoutput | Add-Member -NotePropertyName "DriverUpdateErrors" -NotePropertyValue "$errorcount"

Remove-Item $tempfilepath -Force


##################################################################################################################################
#################                                 Deployment Status                                              #################
##################################################################################################################################

$uri = "https://graph.microsoft.com/beta//deviceManagement/softwareUpdateStatusSummary?`$select=conflictDeviceCount,errorDeviceCount"

$deploymentstatus = Invoke-MgGraphRequest -Method GET -Uri $uri -OutputType PSObject
$conflictdevices = $deploymentstatus.conflictDeviceCount
$errordevices = $deploymentstatus.errorDeviceCount
$deploymentoutput = $deploymentstatus | Select-Object * -ExcludeProperty '@odata.context' | ConvertTo-Html -Fragment

$jsonoutput | Add-Member -NotePropertyName "UpdateConflictDevices" -NotePropertyValue "$conflictdevices"
$jsonoutput | Add-Member -NotePropertyName "UpdateErrorDevices" -NotePropertyValue "$errordevices"

##################################################################################################################################
#################                                               Create HTML                                      #################
##################################################################################################################################

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
$readabledate = get-date -format dd-MM-yyyy-HH-mm-ss

##Download it
Invoke-WebRequest -Uri $PathToHTMLTemplate -OutFile "$env:temp\email-template.html"
$EmailContent = Get-Content "$env:temp\email-template.html" | Out-String

$Section1Head = "Report generated for $domain at $formattedDateTime"
$Section1Body = "Here is your daily Intune report"
$Section2Head = 'Updated apps'
$updatedapps_HTML = $updatedappoutput.Replace('<table>','<table id="t01">')
$Section2Body = 'These apps have been updated in your tenant:<br>' + $updatedapps_HTML
$section3Head = 'Admin Alerts'
$eventscontent_HTML = $eventscontent.Replace('<table>','<table id="t01">')
$Section3Body = @"
These are your admin alerts from the last 24 hours:<br>'
$eventscontent_HTML
"@
$section4Head = "License Count"
$licensecount_HTML = $totaloutput.Replace('<table>','<table id="t01">')
$Section4Body = 'Here is your tenant license count:<br>' + $licensecount_HTML
$section5Head = "Licenses on old users"
$licensesoutput_HTML = $licensesoutput.Replace('<table>','<table id="t01">')
$Section5Body = 'These users have not been seen for 90 days and have active licenses:<br>' + $licensesoutput_HTML
$section6Head = "Secure Score"
$scoreoutput_HTML = $scoreoutput.Replace('<table>','<table id="t01">')
$Section6Body = 'Your secure score is:<br>' + $scoreoutput_HTML
$section7Head = "Non-compliant Devices"
$noncompliantoutput_HTML = $noncompliantoutput.Replace('<table>','<table id="t01">')
$Section7Body = 'These devices are non-compliant:<br>' + $noncompliantoutput_HTML
$section8Head = "Unused W365 devices"
$w365output_HTML = $w365output.Replace('<table>','<table id="t01">')
$Section8Body = 'These W365 machines are unused:<br>' + $w365output_HTML
$section9Head = "AV and Malware"
$malwareoutput_HTML = $malwareoutput.Replace('<table>','<table id="t01">')
$Section9Body = 'These devices have AV issues:<br>' + $malwareoutput_HTML
$section10Head = "Devices with Firewall off"
$firewallstatus_HTML = $firewallstatus.Replace('<table>','<table id="t01">')
$Section10Body = 'These devices have the firewall off:<br>' + $firewallstatus_HTML
$section11Head = "Outdated Windows devices"
$outdatedreport_HTML = $outdatedreport.Replace('<table>','<table id="t01">')
$Section11Body = 'These devices are running an outdated version of Windows:<br>' + $outdatedreport_HTML
$section12Head = "Feature Update Policies"
$featureupdatecheck_HTML = $featureupdatecheck.Replace('<table>','<table id="t01">')
$Section12Body = 'These feature update profiles are not set to the latest OS version:<br>' + $featureupdatecheck_HTML
$section13Head = "Failed Signins"
$signinsoutput_HTML = $signinsoutput.Replace('<table>','<table id="t01">')
$Section13Body = 'Here are your Entra failed sign-ins in the last 24 hours:<br>' + $signinsoutput_HTML
$section14Head = "Failed App Installs"
$appsoutput_HTML = $appsoutput.Replace('<table>','<table id="t01">')
$Section14Body = 'These apps have failed installations:<br>' + $appsoutput_HTML
$section15Head = "App Protection Issues"
$output_HTML = $output.Replace('<table>','<table id="t01">')
$Section15Body = 'Here are your reported MAM issues:<br>' + $output_HTML
$section16Head = "Security Tasks"
$securityoutput_HTML = $securityoutput.Replace('<table>','<table id="t01">')
$Section16Body = 'These security tasks are required on your devices:<br>' + $securityoutput_HTML
$section17Head = "Apple Certificate Expiry"
$section17Body = "MDM Push: $pushexpiryplaintext <br> VPP: $vppexpiryplaintext <br> DEP: $depexpiryplaintext"
$section18Head = "App Registrations"
$texttable_HTML = $texttable.Replace('<table>','<table id="t01">')
$section18Body = 'These are your expiring app registrations:<br>' + $texttable_HTML
$section19Head = "Stale Devices"
$staleoutput_HTML = $staleoutput.Replace('<table>','<table id="t01">')
$section19Body = 'These devices have not been seen for 60 days:<br>' + $staleoutput_HTML
$section20Head = "Service Health Overview"
$section20Body = "Intune service health is: $serviceoutput"
$section21Head = "Service Health Issues"
$section21Body = $healthissueoutput.Replace('<table>','<table id="t01">')
$section22Head = "Service Health Messages"
$section22Body = $healthoutput.Replace('<table>','<table id="t01">')
$section23Head = "Feature Update Policy Errors"
$section23Body = $featureupdateoutput
$section24Head = "Quality Update Policy Errors"
$section24Body = $expeditedupdateoutput
$section25Head = "Driver Update Policy Errors"
$section25Body = $driverupdateoutput
$section26Head = "Windows Update Deployment Status"
$section26Body = $deploymentoutput
$unsubscribe = "To unsubscribe, please click <a href='https://dailychecks.euctoolbox.com/unsubscribe.php?tenantid=$tenant'>here</a>"
$EmailContent = $EmailContent.Replace('$Section1Head',$Section1Head)
$EmailContent = $EmailContent.Replace('$Section1Body',$Section1Body)
$EmailContent = $EmailContent.Replace('$Section2Head',$Section2Head)
$EmailContent = $EmailContent.Replace('$Section2Body',$Section2Body)
$EmailContent = $EmailContent.Replace('$Section3Head',$section3Head)
$EmailContent = $EmailContent.Replace('$Section3Body',$Section3Body)
$EmailContent = $EmailContent.Replace('$Section4Head',$section4Head)
$EmailContent = $EmailContent.Replace('$Section4Body',$Section4Body)
$EmailContent = $EmailContent.Replace('$Section5Head',$section5Head)
$EmailContent = $EmailContent.Replace('$Section5Body',$Section5Body)
$EmailContent = $EmailContent.Replace('$Section6Head',$section6Head)
$EmailContent = $EmailContent.Replace('$Section6Body',$Section6Body)
$EmailContent = $EmailContent.Replace('$Section7Head',$section7Head)
$EmailContent = $EmailContent.Replace('$Section7Body',$Section7Body)
$EmailContent = $EmailContent.Replace('$Section8Head',$section8Head)
$EmailContent = $EmailContent.Replace('$Section8Body',$Section8Body)
$EmailContent = $EmailContent.Replace('$Section9Head',$section9Head)
$EmailContent = $EmailContent.Replace('$Section9Body',$Section9Body)
$EmailContent = $EmailContent.Replace('$Section10Head',$section10Head)
$EmailContent = $EmailContent.Replace('$Section10Body',$Section10Body)
$EmailContent = $EmailContent.Replace('$Section11Head',$section11Head)
$EmailContent = $EmailContent.Replace('$Section11Body',$Section11Body)
$EmailContent = $EmailContent.Replace('$Section12Head',$section12Head)
$EmailContent = $EmailContent.Replace('$Section12Body',$Section12Body)
$EmailContent = $EmailContent.Replace('$Section13Head',$section13Head)
$EmailContent = $EmailContent.Replace('$Section13Body',$Section13Body)
$EmailContent = $EmailContent.Replace('$Section14Head',$section14Head)
$EmailContent = $EmailContent.Replace('$Section14Body',$Section14Body)
$EmailContent = $EmailContent.Replace('$Section15Head',$section15Head)
$EmailContent = $EmailContent.Replace('$Section15Body',$Section15Body)
$EmailContent = $EmailContent.Replace('$Section16Head',$section16Head)
$EmailContent = $EmailContent.Replace('$Section16Body',$Section16Body)
$EmailContent = $EmailContent.Replace('$Section17Head',$section17Head)
$EmailContent = $EmailContent.Replace('$Section17Body',$Section17Body)
$EmailContent = $EmailContent.Replace('$Section18Head',$section18Head)
$EmailContent = $EmailContent.Replace('$Section18Body',$Section18Body)
$EmailContent = $EmailContent.Replace('$Section19Head',$section19Head)
$EmailContent = $EmailContent.Replace('$Section19Body',$Section19Body)
$EmailContent = $EmailContent.Replace('$Section20Head',$section20Head)
$EmailContent = $EmailContent.Replace('$Section20Body',$Section20Body)
$EmailContent = $EmailContent.Replace('$Section21Head',$section21Head)
$EmailContent = $EmailContent.Replace('$Section21Body',$Section21Body)
$EmailContent = $EmailContent.Replace('$Section22Head',$section22Head)
$EmailContent = $EmailContent.Replace('$Section22Body',$Section22Body)
$EmailContent = $EmailContent.Replace('$Section23Head',$section23Head)
$EmailContent = $EmailContent.Replace('$Section23Body',$Section23Body)
$EmailContent = $EmailContent.Replace('$Section24Head',$section24Head)
$EmailContent = $EmailContent.Replace('$Section24Body',$Section24Body)
$EmailContent = $EmailContent.Replace('$Section25Head',$section25Head)
$EmailContent = $EmailContent.Replace('$Section25Body',$Section25Body)
$EmailContent = $EmailContent.Replace('$Section26Head',$section26Head)
$EmailContent = $EmailContent.Replace('$Section26Body',$Section26Body)
$EmailContent = $EmailContent.Replace('$LinkSponsors',$footerhtml)

if ($portal -ne "yes") {
$EmailContent = $EmailContent.Replace('$Unsubscribe', $unsubscribe)
}
else {
$EmailContent = $EmailContent.Replace('$Unsubscribe', "")
}
#Send Mail    

 

$tempemail = word-wrap -chunk $emailcontent
$tempemail | out-file "$env:temp\finalemail.html"

$EmailContent2 = Get-Content "$env:temp\finalemail.html" | Out-String

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
                    "email" = $EmailAddress
                }
            )
            "subject" = " Daily Intune Report for $domain at $readabledate "
        }
    )
    "content"          = @(
        @{
            "type"  = "text/html"
            "value" = $EmailContent2
        }
    )
    "from"             = @{
        "email" = "info@euctoolbox.com"
        "name"  = "Daily Report"
    }
    
}

$bodytest = $body | ConvertTo-Json -Depth 10

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



