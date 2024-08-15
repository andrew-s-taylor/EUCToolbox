<#PSScriptInfo
.VERSION 1.0.0
.GUID f98cf547-178a-4824-8308-9b9b0e18f9c4
.AUTHOR AndrewTaylor
.DESCRIPTION Creates a daily report of expiring app registrations and Apple certificates
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
.Creates a daily report of expiring app registrations and Apple certificates
.DESCRIPTION
.Creates a daily report of expiring app registrations and Apple certificates

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
    [string]$EmailAddress #Email address for report
    ,
    [string]$clientid #ClientID is the type of Azure AD App Reg ID
    ,
    [string]$clientsecret #ClientSecret is the type of Azure AD App Reg Secret
    ,
    [string]$sendgridtoken #For emailing results
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
$EmailAddress = ((($bodyData.EmailAddress) | out-string).trim())
$clientid = ((($bodyData.clientid) | out-string).trim())
$clientsecret = ((($bodyData.clientsecret) | out-string).trim())
$sendgridtoken = ((($bodyData.sendgridtoken) | out-string).trim())
$PathToHTMLTemplate = ((($bodyData.htmltemplate) | out-string).trim())


##Using a webhook so use app reg
$aadlogin = "yes"

}

$PathToHTMLTemplate = "https://baselinepolicy.blob.core.windows.net/images/email-template-alert.html"

###############################################################################################################
######                                         Install Modules                                           ######
###############################################################################################################
write-output "Installing Intune modules if required (current user scope)"


write-output "Installing Microsoft Graph Groups modules if required (current user scope)"

#Install Graph Groups module if not available
if (Get-Module -ListAvailable -Name microsoft.graph.groups) {
    write-output "Microsoft Graph Groups Module Already Installed"
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
    write-output "Microsoft Graph Device Management Module Already Installed"
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
    write-output "Microsoft Graph Already Installed"
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
    write-output "Microsoft Graph Already Installed"
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
    write-output "Microsoft Graph Already Installed"
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


##Set a counter to check
$counter = 0

##Get the domain name
$uri = "https://graph.microsoft.com/beta/organization"
$tenantdetails = (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).value
$domain = ($tenantdetails.VerifiedDomains | Where-Object isDefault -eq $true).name


##################################################################################################################################
#################                                     VPP Cert Expiry                                            #################
##################################################################################################################################
#MDM Push
write-output "Checking MDM Push Expiry"
$pushuri = "https://graph.microsoft.com/beta/deviceManagement/applePushNotificationCertificate"
$pushcert = Invoke-MgGraphRequest -Uri $pushuri -Method Get -OutputType PSObject
$pushexpiryplaintext = $pushcert.expirationDateTime
$pushexpiry = ($pushcert.expirationDateTime).ToString("yyyy-MM-dd")

write-output "MDM push expiry is $pushexpiry"


#VPP
write-output "Checking VPP Expiry"
$vppuri = "https://graph.microsoft.com/beta/deviceAppManagement/vppTokens"
$vppcert = Invoke-MgGraphRequest -Uri $vppuri -Method Get -OutputType PSObject
$vppexpiryvalue = $vppcert.value
$vppexpiryplaintext = $vppexpiryvalue.expirationDateTime
$vppexpiry = ($vppexpiryvalue.expirationDateTime).ToString("yyyy-MM-dd")
write-output "Push expiry is $vppexpiry"

#DEP
write-output "Checking DEP expiry"
$depuri = "https://graph.microsoft.com/beta/deviceManagement/depOnboardingSettings"
$depcert = Invoke-MgGraphRequest -Uri $depuri -Method Get -OutputType PSObject
$depexpiryvalue = $depcert.value
$depexpiryplaintext = $depexpiryvalue.tokenexpirationDateTime
$depexpiry = ($depexpiryvalue.tokenExpirationDateTime).ToString("yyyy-MM-dd")
write-output "DEP expiry is $depexpiry"


$dateTime = Get-Date
$formattedDateTime = $dateTime.ToString("dddd MMMM d' 'yyyy hh:mmtt")

##Check if any of the certs are expiring in the next 30 days
$expirationDays = 30
if (($pushexpiry -lt $dateTime.AddDays($expirationDays)) -or ($vppexpiry -lt $dateTime.AddDays($expirationDays)) -or ($depexpiry -lt $dateTime.AddDays($expirationDays))) {
    $counter++
    $expiry = "Yes"
    $applehtml = @"
    MDM Push: $pushexpiryplaintext <br>
    VPP: $vppexpiryplaintext <br>
    DEP: $depexpiryplaintext
"@
}
else {
    $expiry = "No"
    $applehtml = "No expiring Apple Certificates"
}

##################################################################################################################################
#################                                 Check App Registrations                                         #################
##################################################################################################################################

##Get app registrations
write-output "Checking app secret expiry"
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

write-output "Checks complete"

##Check if $array is empty
if ($array -ne 0) {
$counter++
$textTable = $array | Sort-Object daysUntil | Select-Object displayName, secretName, daysUntil | ConvertTo-Html -Fragment
}
else {
    $textTable = "No expiring app secrets"
}

##################################################################################################################################
#################                                      Stale Devices                                             #################
##################################################################################################################################

write-output "Checking stale devices"
[datetime]$scriptStartTime = Get-Date
[string]$disableDate = "$(($scriptStartTime).AddDays(-60).ToString("yyyy-MM-dd"))T00:00:00z"
$uri = "https://graph.microsoft.com/beta/devices?`$filter=approximateLastSignInDateTime le $disabledate"
$staledevices = getallpagination -url $uri

if ($staledevices) {
    $counter++
    $staleoutput = $staledevices | Select-Object deviceId, displayName, approximateLastSignInDateTime | ConvertTo-Html -Fragment
}
else {
    $staleoutput = "No stale devices"
}
write-output "Stale checks complete"
##################################################################################################################################
#################                                               Create HTML                                      #################
##################################################################################################################################


if ($counter -gt 0) {

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


write-output "Creating html report"
##Download it
Invoke-WebRequest -Uri $PathToHTMLTemplate -OutFile "$env:temp\email-template.html"
$EmailContent = Get-Content "$env:temp\email-template.html" | Out-String

$Section1Head = "Report generated for $domain at $formattedDateTime"
$Section1Body = "Here is your daily Intune report"
$section2Head = "Apple Certificate Expiry"
$section2Body = "MDM Push: $pushexpiryplaintext <br> VPP: $vppexpiryplaintext <br> DEP: $depexpiryplaintext"
$section3Head = "App Registrations"
$texttable_HTML = $texttable.Replace('<table>','<table id="t01">')
$section3Body = 'These are your expiring app registrations:<br>' + $texttable_HTML
$section4Head = "Stale Devices"
$staleoutput_HTML = $staleoutput.Replace('<table>','<table id="t01">')
$section4Body = 'These devices have not been seen for 60 days:<br>' + $staleoutput_HTML
$EmailContent = $EmailContent.Replace('$Section1Head',$Section1Head)
$EmailContent = $EmailContent.Replace('$Section1Body',$Section1Body)
$EmailContent = $EmailContent.Replace('$Section2Head',$Section2Head)
$EmailContent = $EmailContent.Replace('$Section2Body',$Section2Body)
$EmailContent = $EmailContent.Replace('$Section3Head',$section3Head)
$EmailContent = $EmailContent.Replace('$Section3Body',$Section3Body)
$EmailContent = $EmailContent.Replace('$Section4Head',$section4Head)
$EmailContent = $EmailContent.Replace('$Section4Body',$Section4Body)
$EmailContent = $EmailContent.Replace('$LinkSponsors',$footerhtml)


write-output "Report Created"

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
                    "email" = $EmailAddress
                }
            )
            "subject" = " EUC Toolbox Expiry Alert "
        }
    )
    "content"          = @(
        @{
            "type"  = "text/html"
            "value" = $EmailContent
        }
    )
    "from"             = @{
        "email" = "info@euctoolbox.com"
        "name"  = "Daily Report"
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

else {
    write-output "Nothing expiring"
}