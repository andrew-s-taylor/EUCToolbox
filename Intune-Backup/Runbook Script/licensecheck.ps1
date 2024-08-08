<#
.SYNOPSIS
Reviews M365 Licensing and produces an html report on unused items and excess licenses
.DESCRIPTION
Reviews M365 Licensing and produces an html report on unused items and excess licenses
.PARAMETER Path
    The path to the .
.PARAMETER LiteralPath
    Specifies a path to one or more locations. Unlike Path, the value of 
    LiteralPath is used exactly as it is typed. No characters are interpreted 
    as wildcards. If the path includes escape characters, enclose it in single
    quotation marks. Single quotation marks tell Windows PowerShell not to 
    interpret any characters as escape sequences.
.INPUTS
None
.OUTPUTS
N/A
.NOTES
  Version:        1.0.0
  Author:         Andrew Taylor
  WWW:            andrewstaylor.com
  Creation Date:  13/01/2024
  Purpose/Change: Initial script development
  .EXAMPLE
N/A
#>

<#PSScriptInfo
.VERSION 1.0.0
.GUID 5695622e-ee7a-43f7-bbcb-ecdf1a2ee03e
.AUTHOR AndrewTaylor
.COMPANYNAME 
.COPYRIGHT GPL
.TAGS intune endpoint MEM environment
.LICENSEURI https://github.com/andrew-s-taylor/public/blob/main/LICENSE
.PROJECTURI https://github.com/andrew-s-taylor/public
.ICONURI 
.EXTERNALMODULEDEPENDENCIES
.REQUIREDSCRIPTS 
.EXTERNALSCRIPTDEPENDENCIES 
.RELEASENOTES
#>

<#
  __ _  _ __    __| | _ __   ___ __      __ ___ | |_   __ _  _   _ | |  ___   _ __      ___   ___   _ __ ___
 / _` || '_ \  / _` || '__| / _ \\ \ /\ / // __|| __| / _` || | | || | / _ \ | '__|    / __| / _ \ | '_ ` _ \
| (_| || | | || (_| || |   |  __/ \ V  V / \__ \| |_ | (_| || |_| || || (_) || |    _ | (__ | (_) || | | | | |
 \__,_||_| |_| \__,_||_|    \___|  \_/\_/  |___/ \__| \__,_| \__, ||_| \___/ |_|   (_) \___| \___/ |_| |_| |_|

#>



##################################################################################################################################
#################                                                  PARAMS                                        #################
##################################################################################################################################

[cmdletbinding()]
    
param
(

    [string]$tenant #Tenant ID (optional) for when automating and you want to use across tenants instead of hard-coded
    ,
    [string]$clientid #ClientID is the type of Azure AD App Reg ID
    ,
    [string]$clientsecret #ClientSecret is the type of Azure AD App Reg Secret
    ,
    [string]$email #Email address to send report to
    ,
    [string]$recipient #Email address to send report to
    ,
    [string]$branding #Sets to use logo from Intune
    ,
    [object] $WebHookData #Webhook data for Azure Automation

    )

##WebHook Data

if ($WebHookData){

    $rawdata = $WebHookData.RequestBody
    $bodyData = ConvertFrom-Json -InputObject ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($rawdata)))

$tenant = ((($bodyData.tenant) | out-string).trim())
$clientid = ((($bodyData.clientid) | out-string).trim())
$clientsecret = ((($bodyData.clientsecret) | out-string).trim())
$email = ((($bodyData.email) | out-string).trim())
$recipient = ((($bodyData.recipient) | out-string).trim())
$branding = ((($bodyData.branding) | out-string).trim())




##Check if parameters have been set

$clientidcheck = $PSBoundParameters.ContainsKey('clientid')
$clientsecretcheck = $PSBoundParameters.ContainsKey('clientsecret')

if (($clientidcheck -eq $true) -and ($clientsecretcheck -eq $true)) {
##AAD Secret passed, use to login
$aadlogin = "yes"

}



}

$sendgridtoken = ""


###############################################################################################################
######                                  Create GUI for Tenant Details                                    ######
###############################################################################################################
if (!$tenant) {
##Prompt for tenant ID in a GUI window
Add-Type -AssemblyName System.Windows.Forms

# Create a new form
$form = New-Object System.Windows.Forms.Form
$form.Text = "Enter the Tenant ID"
$form.Width = 300
$form.Height = 150
$form.StartPosition = "CenterScreen"

# Create a label to display instructions
$label = New-Object System.Windows.Forms.Label
$label.Location = New-Object System.Drawing.Point(10, 20)
$label.Size = New-Object System.Drawing.Size(280, 20)
$label.Text = "Please enter the Tenant ID:"
$form.Controls.Add($label)

# Create a text box for user input
$textbox = New-Object System.Windows.Forms.TextBox
$textbox.Location = New-Object System.Drawing.Point(10, 50)
$textbox.Size = New-Object System.Drawing.Size(280, 20)
$form.Controls.Add($textbox)

# Create a button to submit the input
$button = New-Object System.Windows.Forms.Button
$button.Location = New-Object System.Drawing.Point(100, 80)
$button.Size = New-Object System.Drawing.Size(100, 30)
$button.Text = "Submit"
$button.DialogResult = [System.Windows.Forms.DialogResult]::OK
$form.AcceptButton = $button
$form.Controls.Add($button)

# Show the form and wait for user input
$result = $form.ShowDialog()

# Get the user input from the text box
if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
    $tenantid = $textbox.Text
}
}
else {
    $tenantid = $tenant
}
###############################################################################################################
######                                           Output Folder Creation                                  ######
###############################################################################################################
write-output "Creating Folder for Reports"
##Create a folder to store the output
$folder = "$env:temp\Reports"
if (!(Test-Path $folder)) {
    New-Item -ItemType Directory -Path $folder
}

write-output "Folder Created"


##################################################################################################################################
#################                                                  INITIALIZATION                                #################
##################################################################################################################################
$ErrorActionPreference = "Continue"
$date = Get-Date -Format "dd-MM-yyyy"
$logpath = "$env:temp\Reports\licensecheck_$tenantid" + "_$date.log"
Start-Transcript -Path $logpath -Append


###############################################################################################################
######                                         Install Modules                                           ######
###############################################################################################################


##Install and Import MgGraph Authentication Module
Write-Host "Installing Intune modules if required (current user scope)"


Write-Host "Installing Microsoft Graph Groups modules if required (current user scope)"

#Install MS Graph if not available
if (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication) {
    Write-Host "Microsoft Graph Already Installed"
} 
else {
    try {
        Install-Module -Name Microsoft.Graph.Authentication -Scope CurrentUser -Repository PSGallery -Force 
        Write-Host "Microsoft Graph Installed"
    }
    catch [Exception] {
        $_.message 
    }
}

if (Get-Module -ListAvailable -Name Microsoft.Graph.Applications) {
    Write-Host "Microsoft Graph Applications Already Installed"
} 
else {
    try {
        Install-Module -Name Microsoft.Graph.Applications -Scope CurrentUser -Repository PSGallery -Force 
        Write-Host "Microsoft Graph Applications Installed"
    }
    catch [Exception] {
        $_.message 
    }
}


#Importing Modules
Write-Host "Importing Microsoft Graph Authentication Module"
import-module microsoft.graph.authentication
write-host "Imported Microsoft Graph Authentication"

Write-Host "Importing Microsoft Graph Applications Module"
import-module microsoft.graph.Applications
write-host "Imported Microsoft Graph Applications"

##Add custom logging for runbook
$Logfile = "$env:TEMP\licensereview-$date.log"
function WriteLog
{
Param ([string]$LogString)
$Stamp = (Get-Date).toString("yyyy/MM/dd HH:mm:ss")
$LogMessage = "$Stamp $LogString \n"
Add-content $LogFile -value $LogMessage
}

Function Connect-ToGraph {
    <#
.SYNOPSIS
Authenticates to the Graph API via the Microsoft.Graph.Authentication module.
 
.DESCRIPTION
The Connect-ToGraph cmdlet is a wrapper cmdlet that helps authenticate to the Intune Graph API using the Microsoft.Graph.Authentication module. It leverages an Entra ID app ID and app secret for authentication or user-based auth.
 
.PARAMETER Tenant
Specifies the tenant (e.g. contoso.onmicrosoft.com) to which to authenticate.
 
.PARAMETER AppId
Specifies the Entra ID app ID (GUID) for the application that will be used to authenticate.
 
.PARAMETER AppSecret
Specifies the Entra ID app secret corresponding to the app ID that will be used to authenticate.

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
            Write-Host "Connected to Intune tenant $TenantId using app-based authentication (Entra ID authentication not supported)"
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
###############################################################################################################
######                                            Connect                                                ######
###############################################################################################################
##Authenticate to Graph
if (($WebHookData) -or ($aadlogin -eq "yes")) {
 
    Connect-ToGraph -Tenant $tenant -AppId $clientId -AppSecret $clientSecret
    write-output "Graph Connection Established"
    writelog "Graph Connection Established"
    
    }
    else {
write-host "Authenticating to Microsoft Graph"
Connect-ToGraph -Scopes "User.ReadWrite.All, AuditLog.Read.All, Reports.Read.All, Group.Read.All, ReportSettings.ReadWrite.All"
write-host "Authenticated to Microsoft Graph"
    }



###############################################################################################################
######                                            Query                                                  ######
###############################################################################################################

##Get the domain name
$uri = "https://graph.microsoft.com/beta/organization"
$tenantdetails = (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).value
$domain = ($tenantdetails.VerifiedDomains | Where-Object isDefault -eq $true).name

if ($branding -eq "true") {
$brandingprofilesurl = "https://graph.microsoft.com/beta/deviceManagement/intuneBrandingProfiles/"
$allbrandingprofiles = getallpagination -url $brandingprofilesurl
$brandingid = $allbrandingprofiles.Id
$brandinglogourl = "https://graph.microsoft.com/beta/deviceManagement/intuneBrandingProfiles/$brandingid/?`$select=landingPageCustomizedImage"
$imgdetails = (Invoke-MgGraphRequest -Uri $brandinglogourl -Method GET -OutputType PSObject)
$imgtype = $imgdetails.landingPageCustomizedImage.type
$imgbase64 = $imgdetails.landingPageCustomizedImage.value
$imgsrc = @"
<img src="data:$imgtype;base64, iVBORw0KGgoAAAANSUhEUgAAAAUA
AAAFCAYAAACNbyblAAAAHElEQVQI12P4//8/w38GIAXDIBKE0DHxgljNBAAO
    9TXL0Y4OHwAAAABJRU5ErkJggg==$imgbase64" alt="EUCToolbox" width="50% height="50%">
"@
}
else {
    $imgsrc = @"
<img src="https://baselinepolicy.blob.core.windows.net/templates/combined.png?sp=r&st=2024-04-22T16:52:28Z&se=2044-04-23T00:52:28Z&spr=https&sv=2022-11-02&sr=b&sig=auEM7hk0UhzrNgElb91nmfADzYk1BcGMtGnMNkTp7lE%3D" alt="EUCToolbox" width="50% height="50%">
"@

}

## Check unused licenses
write-output "Checking Unused Licenses"
writelog "Checking Unused Licenses"

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
writelog "$licensename has $available unused licenses"
$objectdetails = [pscustomobject]@{
    name = $licensename
    unused = $available
}
$unused += $objectdetails
}
}
$total = $total | Sort-Object Unused -Descending
Write-Output "Unused Licenses Checked"
writelog "Unused Licenses Checked"
##Check Unused users with licenses

Write-Output "Checking Unused Users"
writelog "Checking Unused Users"

##Unused Users first
$usersuri = "https://graph.microsoft.com/v1.0/users?`$select=displayName,signInActivity, userPrincipalName, id"

$users = getallpagination -url $usersuri

$90daysago = (Get-Date).AddDays(-90).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")

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
        writelog "$userupn has not been seen for 90 days or more"


}
else {
    ##Ignore these
}
}


write-output "Unused Users Checked"
writelog "Unused Users Checked"

##Check each old user for licenses

write-output "Checking Unused Licenses for Unused Users"
writelog "Checking Unused Licenses for Unused Users"

$licensestorelease = @()
foreach ($olduser in $oldusers) {
    $olduserid = $olduser.userid
    $olduserupn = $olduser.name
$licenseuricheck = "https://graph.microsoft.com/v1.0/users/$olduserid/licenseDetails"
$userlicence = getallpagination -url $licenseuricheck
    if ($userlicence.Count -gt 0) {
        Write-Output "$olduserupn has a license assigned"
        writelog "$olduserupn has a license assigned"
        foreach ($individuallicense in $userlicence) {
            $skuNamePretty = ($translationTable | Where-Object {$_.GUID -eq $individuallicense.skuId} | Sort-Object Product_Display_Name -Unique).Product_Display_Name
        $objectdetails = [pscustomobject]@{
            name = $olduserupn
            license = $skuNamePretty
        }
        $licensestorelease += $objectdetails
    }
    }
    else {
        write-output "$olduserupn has no license assigned"
        writelog "$olduserupn has no license assigned"
    }


}

Write-Output "Unused Licenses for Unused Users Checked"
writelog "Unused Licenses for Unused Users Checked"

##Check for Intune Corporate devices

write-output "Checking Intune Corporate Devices"
writelog "Checking Intune Corporate Devices"

$devicecheckuri = "https://graph.microsoft.com/beta/deviceManagement/managedDevices?`$filter=ownerType eq 'company'"
$devices = (Invoke-MgGraphRequest -uri $devicecheckuri -Method GET -OutputType PSObject)."@odata.count"

if ($devices -le 5) {
    write-output "There are $devices Intune Corporate devices, assuming unused"
    writelog "There are $devices Intune Corporate devices, assuming unused"
    $intuneusage = "Intune only has $devices devices, assuming unused"
}
else {
    write-output "There are $devices Intune Corporate devices, assuming used"
    writelog "There are $devices Intune Corporate devices, assuming used"
    $intuneusage = "Intune is used with $devices devices enrolled"
}

write-output "Intune Corporate Devices Checked"
writelog "Intune Corporate Devices Checked"

##Check for unused or old Sharepoint sites

##Display obfuscated values
write-output "Checking if values are obfuscated"
WriteLog "Checking if values are obfuscated"
$Display = Invoke-MgGraphRequest -Method Get -Uri 'https://graph.microsoft.com/beta/admin/reportSettings'
$obfuscated = $Display.displayConcealedNames

if ($obfuscated -eq $true) {
    $reset = $true
    write-output "Values are obfuscated, changing value"
    WriteLog "Values are obfuscated, changing value"
    # Set reports to use clear values
    Invoke-MgGraphRequest -Method PATCH -Uri 'https://graph.microsoft.com/beta/admin/reportSettings' -Body (@{"displayConcealedNames"= $false} | ConvertTo-Json)

}
else {
    $reset = $false
    write-output "Values are not obfuscated"
    WriteLog "Values are not obfuscated"
}



write-output "Checking Sharepoint Sites"
writelog "Checking Sharepoint Sites"
$filepath = "$env:temp\sharepoint.csv"
$sharepointuri = "https://graph.microsoft.com/v1.0/reports/getSharePointSiteUsageDetail(period='d90')"
(Invoke-MgGraphRequest -uri $sharepointuri -Method GET -OutputFilePath $filepath)
##import the CSV
$sharepoint = Import-Csv $filepath
$sharepointsites = @()
$activitydates = @()


foreach ($site in $sharepoint) {
    $siteurl = $site."Site URL"
    $lastactivity = $site."Last Activity Date"
    $activitydates += $lastactivity
    $objectdetails = [pscustomobject]@{
        SiteID = $siteurl
        LastActivity = $lastactivity
    }
    $sharepointsites += $objectdetails
}

$totalsites = $sharepointsites.count
if ($totalsites -le 5) {
    write-output "There are $totalsites SharePoint sites, assuming unused"
    writelog "There are $totalsites SharePoint sites, assuming unused"
    $sharepointusage = "SharePoint has $totalsites sites, assuming unused"
    $sharepointdata = ""
    
}
else {
    write-output "There are $totalsites SharePoint sites, assuming used"
    writelog "There are $totalsites SharePoint sites, assuming used"
    $sharepointusage = "SharePoint is used with $totalsites sites"
    $sharepointdata = $sharepointsites | ConvertTo-Html -Fragment
}
$totallastactivity = $activitydates | Sort-Object | Select-Object -Last 1
write-output "There are $totalsites SharePoint sites with the most recent activity date of $totallastactivity"
writelog "There are $totalsites SharePoint sites with the most recent activity date of $totallastactivity"
Remove-Item $filepath

write-output "Sharepoint Sites Checked"
writelog "Sharepoint Sites Checked"

##Reset obfuscation
if ($reset -eq $true) {
    write-output "Resetting"
    WriteLog "Resetting"
    Invoke-MgGraphRequest -Method PATCH -Uri 'https://graph.microsoft.com/beta/admin/reportSettings' -Body (@{"displayConcealedNames"= $true} | ConvertTo-Json)

}
else {
    write-output "Values were not obfuscated before, ignoring"
    WriteLog "Values were not obfuscated before, ignoring"
}



##Check for unused or old Teams

write-output "Checking Teams Usage"
writelog "Checking Teams Usage"

$teamsuri = "https://graph.microsoft.com/beta//reports/getTeamsTeamActivityCounts(period='d90')"
$teams = (Invoke-MgGraphRequest -uri $teamsuri -Method GET -OutputType PSObject).value
$activechannels = 0
$channelmessages = 0
$activeusers = 0
$postmessages = 0
$guests = 0

foreach ($team in $teams) {
    $activechannels += $team.activeChannels
    $channelmessages += $team.channelMessages
    $activeusers += $team.activeUsers
    $postmessages += $team.postMessages
    $guests += $team.guests
}

##Check if any are greater than 5
if ($activechannels -gt 5 -or $channelmessages -gt 5 -or $activeusers -gt 5 -or $postmessages -gt 5 -or $guests -gt 5) {
    write-output "Teams usage is greater than 5, assuming used"
    writelog "Teams usage is greater than 5, assuming used"
    $teamsusage = "Teams is used with $activechannels active channels, $channelmessages channel messages, $activeusers active users, $postmessages post messages and $guests guests"
} else {
    write-output "Teams usage is less than 5, assuming unused"
    writelog "Teams usage is less than 5, assuming unused"
    $teamsusage = "Teams is unused"
}

write-output "Teams Usage Checked"
writelog "Teams Usage Checked"

##Check for Conditional Access

write-output "Checking Conditional Access"
writelog "Checking Conditional Access"

$conditionalaccessuri = "https://graph.microsoft.com/beta//identity/conditionalAccess/policies?`$select=id,displayname,state&`$count=true"
$conditionalaccess = ((Invoke-MgGraphRequest -uri $conditionalaccessuri -Method GET -OutputType PSObject).value | where-object {$_.state -eq "enabled"}).count
if ($conditionalaccess -gt 0) {
    write-output "There are $conditionalaccess Conditional Access policies, assuming used"
    writelog "There are $conditionalaccess Conditional Access policies, assuming used"
    $conditionalaccessstate = "Conditional Access is used with $conditionalaccess policies"
}
else {
    write-output "There are $conditionalaccess Conditional Access policies, assuming unused"
    writelog "There are $conditionalaccess Conditional Access policies, assuming unused"
    $conditionalaccessstate = "Conditional Access is unused"
}

write-output "Conditional Access Checked"
writelog "Conditional Access Checked"

##Check for security defaults

write-output "Checking Security Defaults"
writelog "Checking Security Defaults"

$securitydefaulturi = "https://graph.microsoft.com/beta/policies/identitySecurityDefaultsEnforcementPolicy"
$securitydefault = (Invoke-MgGraphRequest -uri $securitydefaulturi -Method GET -OutputType PSObject).isEnabled

if ($securitydefault -eq $true) {
    write-output "Security defaults are enabled"
    writelog "Security defaults are enabled"
    $securitydefaultstate = "Security defaults are enabled"
}
else {
    write-output "Security defaults are disabled"
    writelog "Security defaults are disabled"
    $securitydefaultstate = "Security defaults are disabled"
}

write-output "Security Defaults Checked"
writelog "Security Defaults Checked"


##Check for SSPR

write-output "Checking SSPR"
writelog "Checking SSPR"
$sspruri = "https://graph.microsoft.com/beta/policies/authorizationPolicy"
$sspr = (getallpagination -url $sspruri).allowedToUseSSPR
if ($sspr -eq $false) {
    write-output "SSPR is disabled"
    writelog "SSPR is disabled"
    $ssprstate = "SSPR is disabled"
}
else {
    write-output "SSPR is enabled"
    writelog "SSPR is enabled"
    $ssprstate = "SSPR is enabled"
}

write-output "SSPR Checked"
writelog "SSPR Checked"

##Check for Defender for Endpoint

write-output "Checking Defender for Endpoint"
writelog "Checking Defender for Endpoint"

##Get all security templates
$templatesuri = "https://graph.microsoft.com/beta/deviceManagement/templates?`$filter=templateType eq 'SecurityTemplate'"
$templatesid = ((Invoke-MgGraphRequest -uri $templatesuri -Method GET -OutputType PSObject).value | Where-Object {$_.displayName -like "Endpoint detection and response"}).Id
$policyuri = "https://graph.microsoft.com/beta/deviceManagement/intents?`$filter=templateId+eq+'$templatesid'"
$policycheck = ((Invoke-MgGraphRequest -uri $policyuri -Method GET -OutputType PSObject).value)

if ($policycheck) {
    write-output "Defender for Endpoint is enabled"
    writelog "Defender for Endpoint is enabled"
    $defenderstate = "Defender for Endpoint is enabled via Intune"
}
else {
    write-output "Defender for Endpoint is disabled"
    writelog "Defender for Endpoint is disabled"
    $defenderstate = "Defender for Endpoint is disabled via Intune"
}

write-output "Defender for Endpoint Checked"
writelog "Defender for Endpoint Checked"

##Check if Planner is being used

    $uri = "https://graph.microsoft.com/v1.0/groups"

    # Fetch all groups
    
    $groupsRequest = Invoke-MgGraphRequest -Uri $uri -Method GET -OutputType PSObject
    
    $groups = @()
    $groups+=$groupsRequest.value
    
    while($groupsRequest.'@odata.nextLink' -ne $null){
        $groupsRequest = Invoke-MgGraphRequest -Uri $groupsRequest.'@odata.nextLink' -Method GET -OutputType PSObject
        $groups+=$groupsRequest.value
        }  

        $plannercount = 0
        $plannerdates = @()
foreach ($group in $groups) {
    if ($group.securityEnabled -eq $false -and $group.mailEnabled -eq $true) {
        $groupid = $group.id
        $planuri = "https://graph.microsoft.com/v1.0/groups/$groupid/planner/plans"
        $plannercheck = (Invoke-MgGraphRequest -uri $planuri -Method GET -OutputType PSObject)
        $plannercountcheck = $plannercheck."@odata.count"
        $plannercount += $plannercountcheck
        $plannerdate = $plannercheck.value.createdDateTime
        $plannerdates += $plannerdate
    }

}
if ($plannercount -gt 0) {
    $lastused = $plannerdates | Sort-Object | Select-Object -last 1
    write-output "Planner is being used and was last used on $lastused"
    writelog "Planner is being used and was last used on $lastused"
    $plannerstate = "Planner is being used and was last used on $lastused"
}
else {
    write-output "Planner is not being used"
    writelog "Planner is not being used"
    $plannerstate = "Planner is not being used"
}

write-output "Checks completed, creating output file"
writelog "Checks completed, creating output file"

###############################################################################################################
######                                            Reporting                                              ######
###############################################################################################################

$html = @"
<html>
<head>
<title>License Report</title>
<style type="text/css">
/* Set default font family and color for entire page */
body {
    font-family: Arial, sans-serif;
    color: #333;
  }
  
  /* Center all headings */
  h1, h2, h3 {
    text-align: center;
  }
  
  /* Style for main heading */
  h1 {
    font-size: 2.5rem;
    margin: 2rem 0;
    color: #ff6633; /* blue */
  }
  
  /* Style for subheadings */
  h2 {
    font-size: 2rem;
    margin: 1.5rem 0;
    color: #cc3399; /* orange */
  }
  
  /* Style for sub-subheadings */
  h3 {
    font-size: 1.5rem;
    margin: 1rem 0;
    color: #ff6633; /* blue */
  }
  
  /* Style for tables */
  table {
    border-collapse: collapse;
    width: 100%;
    margin-bottom: 2rem;
  }
  
  /* Style for table headers */
  th {
    text-align: left;
    background-color: #0066ff;
    padding: 0.5rem;
    border: 1px solid #ddd;
    color: #ffffff;
  }
  
  /* Style for table cells */
  td {
    border: 1px solid #ddd;
    padding: 0.5rem;
  }
  
  /* Alternate row background color */
  tr:nth-child(even) {
    background-color: #ffffff;
    color: #000000;
  }

   /* Alternate row background color */
   tr:nth-child(odd) {
    background-color: #eeeeee;
    color: #000000;
  }

  /* Blue link color */
  a {
    color: #0066ff;
  }
  
  #container {
    width: 80%;
    margin: 0 auto;
  }
  
  #header {
    background-color: #eee;
    padding: 1rem;
  }
  #contents {
    padding: 1rem;
  }
</style>
</head>
<body>
<div id="container">
<div id="header">
$imgsrc
</div>
<div id="contents">
<a id="top"></a>
<a href="#total">Total Licenses</a> | <a href="#unused">Unused Licenses</a> | <a href="#oldusers">Old Users with Licenses</a> | <a href="#intune">Intune Usage</a> | <a href="#sharepoint">Sharepoint Usage</a> | <a href="#teams">Teams Usage</a> | <a href="#conditionalaccess">Conditional Access</a> | <a href="#securitydefaults">Security Defaults</a> | <a href="#sspr">SSPR</a> | <a href="#defender">Defender for Endpoint</a> | <a href="#planner">Planner Usage</a> 
</div>
"@
##Add a header
$html += "<h1>License Report for $domain</h1>"
$html += "<h2>Report Generated on $(Get-Date)</h2>"
$html += '<h2 id="total">Total Licenses</h2>'
$totalhtml = $total | ConvertTo-Html -Fragment
$html += $totalhtml
$html += '<h2 id="unused">Unused Licenses</h2>'
$unusedhtml = $unused | ConvertTo-Html -Fragment
$html += $unusedhtml
$html += '<h2 id="oldusers">Old Users (not seen in 90 days)</h2>'
$usedhtml = $licensestorelease | ConvertTo-Html -Fragment
$html += $usedhtml
$html += '<h2 id="intune">Intune Usage</h2>'
$html += "<p>$intuneusage</p>"
$html += '<h2 id="sharepoint">Sharepoint Usage</h2>'
$html += "<p>$sharepointusage</p>"
$html += $sharepointdata
$html += '<h2 id="teams">Teams Usage</h2>'
$html += "<p>$teamsusage</p>"
$html += '<h2 id="conditionalaccess">Conditional Access Usage</h2>'
$html += "<p>$conditionalaccessstate</p>"
$html += '<h2 id="securitydefaults">Security Defaults</h2>'
$html += "<p>$securitydefaultstate</p>"
$html += '<h2 id="sspr">SSPR</h2>'
$html += "<p>$ssprstate</p>"
$html += '<h2 id="defender">Defender for Endpoint</h2>'
$html += "<p>$defenderstate</p>"
$html += '<h2 id="planner">Planner</h2>'
$html += "<p>$plannerstate</p>"

##Close the HTML
$html += @"
</div>
</body>
</html>
"@

$outputfile = "$folder\license_report_$tenantid" + "_$date.html"

write-output "Generating HTML Report"
writelog "Generating HTML Report"
#The command below will generate the report to an HTML file
$html | Out-File $outputfile

##Confirm where report is saved
write-output "Report saved to $outputfile"
writelog "Report saved to $outputfile"

###############################################################################################################
######                                            PROCESS REPORTS                                        ######
###############################################################################################################

$bodycontent = @"   
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
</style>
</head>
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
                                   <h1>License Report</h1>
                                   <p>Please find your license report attached
                                   <br><br>
                                   With thanks
                                   <br><br>
                                   EUC Toolbox from AndrewSTaylor.com</p>
                              </td>
                         </tr>

</body>
</html>
"@ 
$FileName=Split-Path $outputfile -leaf
$base64string = [Convert]::ToBase64String([IO.File]::ReadAllBytes($outputfile))

##Email it
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
                    "email" = $recipient
                }
            )
            "subject" = " License Report"
        }
    )
    "content"          = @(
        @{
            "type"  = "text/html"
            "value" = $bodycontent
        }
    )
    "from"             = @{
        "email" = "security@euctoolbox.com"
        "name"  = "AndrewSTaylor.com"
    }
    "attachments" = @(
        @{
            "content"=$base64string
            "filename"=$filename
            "type"= "text/plain"
            "disposition"="attachment"
         }
)
    
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
writelog "Email Sent"

Stop-Transcript
# SIG # Begin signature block
# MIIoGQYJKoZIhvcNAQcCoIIoCjCCKAYCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBZ4h0fJbpENNe4
# BDgLIrxA8dDyKPyxGqHk+z30u+ZzXaCCIRwwggWNMIIEdaADAgECAhAOmxiO+dAt
# 5+/bUOIIQBhaMA0GCSqGSIb3DQEBDAUAMGUxCzAJBgNVBAYTAlVTMRUwEwYDVQQK
# EwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xJDAiBgNV
# BAMTG0RpZ2lDZXJ0IEFzc3VyZWQgSUQgUm9vdCBDQTAeFw0yMjA4MDEwMDAwMDBa
# Fw0zMTExMDkyMzU5NTlaMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2Vy
# dCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lD
# ZXJ0IFRydXN0ZWQgUm9vdCBHNDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoC
# ggIBAL/mkHNo3rvkXUo8MCIwaTPswqclLskhPfKK2FnC4SmnPVirdprNrnsbhA3E
# MB/zG6Q4FutWxpdtHauyefLKEdLkX9YFPFIPUh/GnhWlfr6fqVcWWVVyr2iTcMKy
# unWZanMylNEQRBAu34LzB4TmdDttceItDBvuINXJIB1jKS3O7F5OyJP4IWGbNOsF
# xl7sWxq868nPzaw0QF+xembud8hIqGZXV59UWI4MK7dPpzDZVu7Ke13jrclPXuU1
# 5zHL2pNe3I6PgNq2kZhAkHnDeMe2scS1ahg4AxCN2NQ3pC4FfYj1gj4QkXCrVYJB
# MtfbBHMqbpEBfCFM1LyuGwN1XXhm2ToxRJozQL8I11pJpMLmqaBn3aQnvKFPObUR
# WBf3JFxGj2T3wWmIdph2PVldQnaHiZdpekjw4KISG2aadMreSx7nDmOu5tTvkpI6
# nj3cAORFJYm2mkQZK37AlLTSYW3rM9nF30sEAMx9HJXDj/chsrIRt7t/8tWMcCxB
# YKqxYxhElRp2Yn72gLD76GSmM9GJB+G9t+ZDpBi4pncB4Q+UDCEdslQpJYls5Q5S
# UUd0viastkF13nqsX40/ybzTQRESW+UQUOsxxcpyFiIJ33xMdT9j7CFfxCBRa2+x
# q4aLT8LWRV+dIPyhHsXAj6KxfgommfXkaS+YHS312amyHeUbAgMBAAGjggE6MIIB
# NjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTs1+OC0nFdZEzfLmc/57qYrhwP
# TzAfBgNVHSMEGDAWgBRF66Kv9JLLgjEtUYunpyGd823IDzAOBgNVHQ8BAf8EBAMC
# AYYweQYIKwYBBQUHAQEEbTBrMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdp
# Y2VydC5jb20wQwYIKwYBBQUHMAKGN2h0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNv
# bS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcnQwRQYDVR0fBD4wPDA6oDigNoY0
# aHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENB
# LmNybDARBgNVHSAECjAIMAYGBFUdIAAwDQYJKoZIhvcNAQEMBQADggEBAHCgv0Nc
# Vec4X6CjdBs9thbX979XB72arKGHLOyFXqkauyL4hxppVCLtpIh3bb0aFPQTSnov
# Lbc47/T/gLn4offyct4kvFIDyE7QKt76LVbP+fT3rDB6mouyXtTP0UNEm0Mh65Zy
# oUi0mcudT6cGAxN3J0TU53/oWajwvy8LpunyNDzs9wPHh6jSTEAZNUZqaVSwuKFW
# juyk1T3osdz9HNj0d1pcVIxv76FQPfx2CWiEn2/K2yCNNWAcAgPLILCsWKAOQGPF
# mCLBsln1VWvPJ6tsds5vIy30fnFqI2si/xK4VC0nftg62fC2h5b9W9FcrBjDTZ9z
# twGpn1eqXijiuZQwggauMIIElqADAgECAhAHNje3JFR82Ees/ShmKl5bMA0GCSqG
# SIb3DQEBCwUAMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMx
# GTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lDZXJ0IFRy
# dXN0ZWQgUm9vdCBHNDAeFw0yMjAzMjMwMDAwMDBaFw0zNzAzMjIyMzU5NTlaMGMx
# CzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjE7MDkGA1UEAxMy
# RGlnaUNlcnQgVHJ1c3RlZCBHNCBSU0E0MDk2IFNIQTI1NiBUaW1lU3RhbXBpbmcg
# Q0EwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDGhjUGSbPBPXJJUVXH
# JQPE8pE3qZdRodbSg9GeTKJtoLDMg/la9hGhRBVCX6SI82j6ffOciQt/nR+eDzMf
# UBMLJnOWbfhXqAJ9/UO0hNoR8XOxs+4rgISKIhjf69o9xBd/qxkrPkLcZ47qUT3w
# 1lbU5ygt69OxtXXnHwZljZQp09nsad/ZkIdGAHvbREGJ3HxqV3rwN3mfXazL6IRk
# tFLydkf3YYMZ3V+0VAshaG43IbtArF+y3kp9zvU5EmfvDqVjbOSmxR3NNg1c1eYb
# qMFkdECnwHLFuk4fsbVYTXn+149zk6wsOeKlSNbwsDETqVcplicu9Yemj052FVUm
# cJgmf6AaRyBD40NjgHt1biclkJg6OBGz9vae5jtb7IHeIhTZgirHkr+g3uM+onP6
# 5x9abJTyUpURK1h0QCirc0PO30qhHGs4xSnzyqqWc0Jon7ZGs506o9UD4L/wojzK
# QtwYSH8UNM/STKvvmz3+DrhkKvp1KCRB7UK/BZxmSVJQ9FHzNklNiyDSLFc1eSuo
# 80VgvCONWPfcYd6T/jnA+bIwpUzX6ZhKWD7TA4j+s4/TXkt2ElGTyYwMO1uKIqjB
# Jgj5FBASA31fI7tk42PgpuE+9sJ0sj8eCXbsq11GdeJgo1gJASgADoRU7s7pXche
# MBK9Rp6103a50g5rmQzSM7TNsQIDAQABo4IBXTCCAVkwEgYDVR0TAQH/BAgwBgEB
# /wIBADAdBgNVHQ4EFgQUuhbZbU2FL3MpdpovdYxqII+eyG8wHwYDVR0jBBgwFoAU
# 7NfjgtJxXWRM3y5nP+e6mK4cD08wDgYDVR0PAQH/BAQDAgGGMBMGA1UdJQQMMAoG
# CCsGAQUFBwMIMHcGCCsGAQUFBwEBBGswaTAkBggrBgEFBQcwAYYYaHR0cDovL29j
# c3AuZGlnaWNlcnQuY29tMEEGCCsGAQUFBzAChjVodHRwOi8vY2FjZXJ0cy5kaWdp
# Y2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNydDBDBgNVHR8EPDA6MDig
# NqA0hjJodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9v
# dEc0LmNybDAgBgNVHSAEGTAXMAgGBmeBDAEEAjALBglghkgBhv1sBwEwDQYJKoZI
# hvcNAQELBQADggIBAH1ZjsCTtm+YqUQiAX5m1tghQuGwGC4QTRPPMFPOvxj7x1Bd
# 4ksp+3CKDaopafxpwc8dB+k+YMjYC+VcW9dth/qEICU0MWfNthKWb8RQTGIdDAiC
# qBa9qVbPFXONASIlzpVpP0d3+3J0FNf/q0+KLHqrhc1DX+1gtqpPkWaeLJ7giqzl
# /Yy8ZCaHbJK9nXzQcAp876i8dU+6WvepELJd6f8oVInw1YpxdmXazPByoyP6wCeC
# RK6ZJxurJB4mwbfeKuv2nrF5mYGjVoarCkXJ38SNoOeY+/umnXKvxMfBwWpx2cYT
# gAnEtp/Nh4cku0+jSbl3ZpHxcpzpSwJSpzd+k1OsOx0ISQ+UzTl63f8lY5knLD0/
# a6fxZsNBzU+2QJshIUDQtxMkzdwdeDrknq3lNHGS1yZr5Dhzq6YBT70/O3itTK37
# xJV77QpfMzmHQXh6OOmc4d0j/R0o08f56PGYX/sr2H7yRp11LB4nLCbbbxV7HhmL
# NriT1ObyF5lZynDwN7+YAN8gFk8n+2BnFqFmut1VwDophrCYoCvtlUG3OtUVmDG0
# YgkPCr2B2RP+v6TR81fZvAT6gt4y3wSJ8ADNXcL50CN/AAvkdgIm2fBldkKmKYcJ
# RyvmfxqkhQ/8mJb2VVQrH4D6wPIOK+XW+6kvRBVK5xMOHds3OBqhK/bt1nz8MIIG
# sDCCBJigAwIBAgIQCK1AsmDSnEyfXs2pvZOu2TANBgkqhkiG9w0BAQwFADBiMQsw
# CQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cu
# ZGlnaWNlcnQuY29tMSEwHwYDVQQDExhEaWdpQ2VydCBUcnVzdGVkIFJvb3QgRzQw
# HhcNMjEwNDI5MDAwMDAwWhcNMzYwNDI4MjM1OTU5WjBpMQswCQYDVQQGEwJVUzEX
# MBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRydXN0
# ZWQgRzQgQ29kZSBTaWduaW5nIFJTQTQwOTYgU0hBMzg0IDIwMjEgQ0ExMIICIjAN
# BgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA1bQvQtAorXi3XdU5WRuxiEL1M4zr
# PYGXcMW7xIUmMJ+kjmjYXPXrNCQH4UtP03hD9BfXHtr50tVnGlJPDqFX/IiZwZHM
# gQM+TXAkZLON4gh9NH1MgFcSa0OamfLFOx/y78tHWhOmTLMBICXzENOLsvsI8Irg
# nQnAZaf6mIBJNYc9URnokCF4RS6hnyzhGMIazMXuk0lwQjKP+8bqHPNlaJGiTUyC
# EUhSaN4QvRRXXegYE2XFf7JPhSxIpFaENdb5LpyqABXRN/4aBpTCfMjqGzLmysL0
# p6MDDnSlrzm2q2AS4+jWufcx4dyt5Big2MEjR0ezoQ9uo6ttmAaDG7dqZy3SvUQa
# khCBj7A7CdfHmzJawv9qYFSLScGT7eG0XOBv6yb5jNWy+TgQ5urOkfW+0/tvk2E0
# XLyTRSiDNipmKF+wc86LJiUGsoPUXPYVGUztYuBeM/Lo6OwKp7ADK5GyNnm+960I
# HnWmZcy740hQ83eRGv7bUKJGyGFYmPV8AhY8gyitOYbs1LcNU9D4R+Z1MI3sMJN2
# FKZbS110YU0/EpF23r9Yy3IQKUHw1cVtJnZoEUETWJrcJisB9IlNWdt4z4FKPkBH
# X8mBUHOFECMhWWCKZFTBzCEa6DgZfGYczXg4RTCZT/9jT0y7qg0IU0F8WD1Hs/q2
# 7IwyCQLMbDwMVhECAwEAAaOCAVkwggFVMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYD
# VR0OBBYEFGg34Ou2O/hfEYb7/mF7CIhl9E5CMB8GA1UdIwQYMBaAFOzX44LScV1k
# TN8uZz/nupiuHA9PMA4GA1UdDwEB/wQEAwIBhjATBgNVHSUEDDAKBggrBgEFBQcD
# AzB3BggrBgEFBQcBAQRrMGkwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2lj
# ZXJ0LmNvbTBBBggrBgEFBQcwAoY1aHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29t
# L0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5jcnQwQwYDVR0fBDwwOjA4oDagNIYyaHR0
# cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5jcmww
# HAYDVR0gBBUwEzAHBgVngQwBAzAIBgZngQwBBAEwDQYJKoZIhvcNAQEMBQADggIB
# ADojRD2NCHbuj7w6mdNW4AIapfhINPMstuZ0ZveUcrEAyq9sMCcTEp6QRJ9L/Z6j
# fCbVN7w6XUhtldU/SfQnuxaBRVD9nL22heB2fjdxyyL3WqqQz/WTauPrINHVUHmI
# moqKwba9oUgYftzYgBoRGRjNYZmBVvbJ43bnxOQbX0P4PpT/djk9ntSZz0rdKOtf
# JqGVWEjVGv7XJz/9kNF2ht0csGBc8w2o7uCJob054ThO2m67Np375SFTWsPK6Wrx
# oj7bQ7gzyE84FJKZ9d3OVG3ZXQIUH0AzfAPilbLCIXVzUstG2MQ0HKKlS43Nb3Y3
# LIU/Gs4m6Ri+kAewQ3+ViCCCcPDMyu/9KTVcH4k4Vfc3iosJocsL6TEa/y4ZXDlx
# 4b6cpwoG1iZnt5LmTl/eeqxJzy6kdJKt2zyknIYf48FWGysj/4+16oh7cGvmoLr9
# Oj9FpsToFpFSi0HASIRLlk2rREDjjfAVKM7t8RhWByovEMQMCGQ8M4+uKIw8y4+I
# Cw2/O/TOHnuO77Xry7fwdxPm5yg/rBKupS8ibEH5glwVZsxsDsrFhsP2JjMMB0ug
# 0wcCampAMEhLNKhRILutG4UI4lkNbcoFUCvqShyepf2gpx8GdOfy1lKQ/a+FSCH5
# Vzu0nAPthkX0tGFuv2jiJmCG6sivqf6UHedjGzqGVnhOMIIGwjCCBKqgAwIBAgIQ
# BUSv85SdCDmmv9s/X+VhFjANBgkqhkiG9w0BAQsFADBjMQswCQYDVQQGEwJVUzEX
# MBUGA1UEChMORGlnaUNlcnQsIEluYy4xOzA5BgNVBAMTMkRpZ2lDZXJ0IFRydXN0
# ZWQgRzQgUlNBNDA5NiBTSEEyNTYgVGltZVN0YW1waW5nIENBMB4XDTIzMDcxNDAw
# MDAwMFoXDTM0MTAxMzIzNTk1OVowSDELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRp
# Z2lDZXJ0LCBJbmMuMSAwHgYDVQQDExdEaWdpQ2VydCBUaW1lc3RhbXAgMjAyMzCC
# AiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAKNTRYcdg45brD5UsyPgz5/X
# 5dLnXaEOCdwvSKOXejsqnGfcYhVYwamTEafNqrJq3RApih5iY2nTWJw1cb86l+uU
# UI8cIOrHmjsvlmbjaedp/lvD1isgHMGXlLSlUIHyz8sHpjBoyoNC2vx/CSSUpIIa
# 2mq62DvKXd4ZGIX7ReoNYWyd/nFexAaaPPDFLnkPG2ZS48jWPl/aQ9OE9dDH9kgt
# XkV1lnX+3RChG4PBuOZSlbVH13gpOWvgeFmX40QrStWVzu8IF+qCZE3/I+PKhu60
# pCFkcOvV5aDaY7Mu6QXuqvYk9R28mxyyt1/f8O52fTGZZUdVnUokL6wrl76f5P17
# cz4y7lI0+9S769SgLDSb495uZBkHNwGRDxy1Uc2qTGaDiGhiu7xBG3gZbeTZD+BY
# QfvYsSzhUa+0rRUGFOpiCBPTaR58ZE2dD9/O0V6MqqtQFcmzyrzXxDtoRKOlO0L9
# c33u3Qr/eTQQfqZcClhMAD6FaXXHg2TWdc2PEnZWpST618RrIbroHzSYLzrqawGw
# 9/sqhux7UjipmAmhcbJsca8+uG+W1eEQE/5hRwqM/vC2x9XH3mwk8L9CgsqgcT2c
# kpMEtGlwJw1Pt7U20clfCKRwo+wK8REuZODLIivK8SgTIUlRfgZm0zu++uuRONhR
# B8qUt+JQofM604qDy0B7AgMBAAGjggGLMIIBhzAOBgNVHQ8BAf8EBAMCB4AwDAYD
# VR0TAQH/BAIwADAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDAgBgNVHSAEGTAXMAgG
# BmeBDAEEAjALBglghkgBhv1sBwEwHwYDVR0jBBgwFoAUuhbZbU2FL3MpdpovdYxq
# II+eyG8wHQYDVR0OBBYEFKW27xPn783QZKHVVqllMaPe1eNJMFoGA1UdHwRTMFEw
# T6BNoEuGSWh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRH
# NFJTQTQwOTZTSEEyNTZUaW1lU3RhbXBpbmdDQS5jcmwwgZAGCCsGAQUFBwEBBIGD
# MIGAMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wWAYIKwYB
# BQUHMAKGTGh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0
# ZWRHNFJTQTQwOTZTSEEyNTZUaW1lU3RhbXBpbmdDQS5jcnQwDQYJKoZIhvcNAQEL
# BQADggIBAIEa1t6gqbWYF7xwjU+KPGic2CX/yyzkzepdIpLsjCICqbjPgKjZ5+PF
# 7SaCinEvGN1Ott5s1+FgnCvt7T1IjrhrunxdvcJhN2hJd6PrkKoS1yeF844ektrC
# QDifXcigLiV4JZ0qBXqEKZi2V3mP2yZWK7Dzp703DNiYdk9WuVLCtp04qYHnbUFc
# jGnRuSvExnvPnPp44pMadqJpddNQ5EQSviANnqlE0PjlSXcIWiHFtM+YlRpUurm8
# wWkZus8W8oM3NG6wQSbd3lqXTzON1I13fXVFoaVYJmoDRd7ZULVQjK9WvUzF4UbF
# KNOt50MAcN7MmJ4ZiQPq1JE3701S88lgIcRWR+3aEUuMMsOI5ljitts++V+wQtaP
# 4xeR0arAVeOGv6wnLEHQmjNKqDbUuXKWfpd5OEhfysLcPTLfddY2Z1qJ+Panx+VP
# NTwAvb6cKmx5AdzaROY63jg7B145WPR8czFVoIARyxQMfq68/qTreWWqaNYiyjvr
# moI1VygWy2nyMpqy0tg6uLFGhmu6F/3Ed2wVbK6rr3M66ElGt9V/zLY4wNjsHPW2
# obhDLN9OTH0eaHDAdwrUAuBcYLso/zjlUlrWrBciI0707NMX+1Br/wd3H3GXREHJ
# uEbTbDJ8WC9nR2XlG3O2mflrLAZG70Ee8PBf4NvZrZCARK+AEEGKMIIHWzCCBUOg
# AwIBAgIQCLGfzbPa87AxVVgIAS8A6TANBgkqhkiG9w0BAQsFADBpMQswCQYDVQQG
# EwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0
# IFRydXN0ZWQgRzQgQ29kZSBTaWduaW5nIFJTQTQwOTYgU0hBMzg0IDIwMjEgQ0Ex
# MB4XDTIzMTExNTAwMDAwMFoXDTI2MTExNzIzNTk1OVowYzELMAkGA1UEBhMCR0Ix
# FDASBgNVBAcTC1doaXRsZXkgQmF5MR4wHAYDVQQKExVBTkRSRVdTVEFZTE9SLkNP
# TSBMVEQxHjAcBgNVBAMTFUFORFJFV1NUQVlMT1IuQ09NIExURDCCAiIwDQYJKoZI
# hvcNAQEBBQADggIPADCCAgoCggIBAMOkYkLpzNH4Y1gUXF799uF0CrwW/Lme676+
# C9aZOJYzpq3/DIa81oWv9b4b0WwLpJVu0fOkAmxI6ocu4uf613jDMW0GfV4dRodu
# tryfuDuit4rndvJA6DIs0YG5xNlKTkY8AIvBP3IwEzUD1f57J5GiAprHGeoc4Utt
# zEuGA3ySqlsGEg0gCehWJznUkh3yM8XbksC0LuBmnY/dZJ/8ktCwCd38gfZEO9UD
# DSkie4VTY3T7VFbTiaH0bw+AvfcQVy2CSwkwfnkfYagSFkKar+MYwu7gqVXxrh3V
# /Gjval6PdM0A7EcTqmzrCRtvkWIR6bpz+3AIH6Fr6yTuG3XiLIL6sK/iF/9d4U2P
# iH1vJ/xfdhGj0rQ3/NBRsUBC3l1w41L5q9UX1Oh1lT1OuJ6hV/uank6JY3jpm+Of
# Z7YCTF2Hkz5y6h9T7sY0LTi68Vmtxa/EgEtG6JVNVsqP7WwEkQRxu/30qtjyoX8n
# zSuF7TmsRgmZ1SB+ISclejuqTNdhcycDhi3/IISgVJNRS/F6Z+VQGf3fh6ObdQLV
# woT0JnJjbD8PzJ12OoKgViTQhndaZbkfpiVifJ1uzWJrTW5wErH+qvutHVt4/sEZ
# AVS4PNfOcJXR0s0/L5JHkjtM4aGl62fAHjHj9JsClusj47cT6jROIqQI4ejz1slO
# oclOetCNAgMBAAGjggIDMIIB/zAfBgNVHSMEGDAWgBRoN+Drtjv4XxGG+/5hewiI
# ZfROQjAdBgNVHQ4EFgQU0HdOFfPxa9Yeb5O5J9UEiJkrK98wPgYDVR0gBDcwNTAz
# BgZngQwBBAEwKTAnBggrBgEFBQcCARYbaHR0cDovL3d3dy5kaWdpY2VydC5jb20v
# Q1BTMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzCBtQYDVR0f
# BIGtMIGqMFOgUaBPhk1odHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRU
# cnVzdGVkRzRDb2RlU2lnbmluZ1JTQTQwOTZTSEEzODQyMDIxQ0ExLmNybDBToFGg
# T4ZNaHR0cDovL2NybDQuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0Q29k
# ZVNpZ25pbmdSU0E0MDk2U0hBMzg0MjAyMUNBMS5jcmwwgZQGCCsGAQUFBwEBBIGH
# MIGEMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wXAYIKwYB
# BQUHMAKGUGh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0
# ZWRHNENvZGVTaWduaW5nUlNBNDA5NlNIQTM4NDIwMjFDQTEuY3J0MAkGA1UdEwQC
# MAAwDQYJKoZIhvcNAQELBQADggIBAEkRh2PwMiyravr66Zww6Pjl24KzDcGYMSxU
# KOEU4bykcOKgvS6V2zeZIs0D/oqct3hBKTGESSQWSA/Jkr1EMC04qJHO/Twr/sBD
# CDBMtJ9XAtO75J+oqDccM+g8Po+jjhqYJzKvbisVUvdsPqFll55vSzRvHGAA6hjy
# DyakGLROcNaSFZGdgOK2AMhQ8EULrE8Riri3D1ROuqGmUWKqcO9aqPHBf5wUwia8
# g980sTXquO5g4TWkZqSvwt1BHMmu69MR6loRAK17HvFcSicK6Pm0zid1KS2z4ntG
# B4Cfcg88aFLog3ciP2tfMi2xTnqN1K+YmU894Pl1lCp1xFvT6prm10Bs6BViKXfD
# fVFxXTB0mHoDNqGi/B8+rxf2z7u5foXPCzBYT+Q3cxtopvZtk29MpTY88GHDVJsF
# MBjX7zM6aCNKsTKC2jb92F+jlkc8clCQQnl3U4jqwbj4ur1JBP5QxQprWhwde0+M
# ifDVp0vHZsVZ0pnYMCKSG5bUr3wOU7EP321DwvvEsTjCy/XDgvy8ipU6w3GjcQQF
# mgp/BX/0JCHX+04QJ0JkR9TTFZR1B+zh3CcK1ZEtTtvuZfjQ3viXwlwtNLy43vbe
# 1J5WNTs0HjJXsfdbhY5kE5RhyfaxFBr21KYx+b+evYyolIS0wR6New6FqLgcc4Ge
# 94yaYVTqMYIGUzCCBk8CAQEwfTBpMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGln
# aUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRydXN0ZWQgRzQgQ29kZSBT
# aWduaW5nIFJTQTQwOTYgU0hBMzg0IDIwMjEgQ0ExAhAIsZ/Ns9rzsDFVWAgBLwDp
# MA0GCWCGSAFlAwQCAQUAoIGEMBgGCisGAQQBgjcCAQwxCjAIoAKAAKECgAAwGQYJ
# KoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQB
# gjcCARUwLwYJKoZIhvcNAQkEMSIEIMhlphwWg3JkTIWwBeQsorzWshh8UZevuaTZ
# ncmo/b7vMA0GCSqGSIb3DQEBAQUABIICABV1QsrOtK78ABeDjizGlobuAwcEYuVH
# ECVIbiKJ2VVFetiOJEhyfBk6X4uCDj5HeiaGsxJaxfuWlIGZJob4I/xt4VjJ+Kue
# 91TtmAmNk6W9x3YZQeIlY3sALixjgCzRpQEHBUTr9LiKXjMvNC6Nq3f9FT0HLqWP
# TqvV+IihHcWdFOmdBS9Cyy+TIK3rHRM/DClYQAoe6GfwojW/IRcRoog7ueCbpIho
# jRwfNExADlbptr8oFLcWkSZcIAtSm2klTtzd0nTRd/WCQ36o0jLC1EcOY3fw45D5
# J9N4xr7iNfuOSZscn8KfX2KB2k3PzD2JY4PxXBJAU1m2Pzmp5bSVtlL+ihwj0fdk
# C5qYxfd3oQmRfCsf1idY/KqN3lKlp+dg/7hioJRo23DhdKwpmpn0TTOzJW4BoJzW
# TCsyj3GcVrYNkDm/HkCuAaX3nU7FgWHwUKxMlQzK9viGM2rIfJAM+d1iQif360mF
# yzVd3OUdemO9somwCBglTWLJXEZ5KA3dJVc982H1vS/7sqw4botH/kP9DDhwWYtw
# Lz2wEB1EgFn+dAXqPGN47GCmGMEyO1sLckhWAgiadt3LfjxEPCJO97BXi0+6YGXu
# CdFZqfxCk5g/FE4m0TBi0GHWG4tR87fQCSA6SmgCbNT7nxgdnMYwgNHLOPiH0n2+
# +w5S/fWTPm3loYIDIDCCAxwGCSqGSIb3DQEJBjGCAw0wggMJAgEBMHcwYzELMAkG
# A1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdp
# Q2VydCBUcnVzdGVkIEc0IFJTQTQwOTYgU0hBMjU2IFRpbWVTdGFtcGluZyBDQQIQ
# BUSv85SdCDmmv9s/X+VhFjANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJAzEL
# BgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTI0MDExMjE1NDYwNlowLwYJKoZI
# hvcNAQkEMSIEIOXtlEYipOypUq4qac6Q+VDnKiN4S26ZEHlTXLexVRGEMA0GCSqG
# SIb3DQEBAQUABIICAJhAIxHLIa7+9zBOdR+HIGdX8ufa6WrXWFibrCKTczxoH6Mi
# 5PX1Adchieb8hb8G72YQNH4G8LNcYVZLtmAR4pbNPHwNN8v80s7raV1vaXrywjqP
# IuDhm2e5cFs6V01DTFnu3uLat377vAe0Jc1DhNrAbnxSmzBvfK4OjnU8tGj1np0J
# 8IeWT4ETdRtYvS5Gre1aDbQ/MS4RGVTNgdWEmInfLZErYKOLHKkPEXYGXkeBO+co
# nbH/Cu5bY34geoEUIFBj8IIx0Di45yMFfToaYs7CU/UshTmkGZKV5mOwnQ4RGiu8
# 5OZGwHbMT+F6COQgH5nIzVDljwqkUiaqDfF55w4N/VBM+zXNyjeTwtYyY5wWSNbi
# hItJuI+4q3AzRq7Cy2EzZ8AWiwFllhfDUUoeuIle9xxwfg5KzHd9/PuNzs8bUmZZ
# gkuMftMo6boXVU1BjSD3OESRiZlNLO6mW5be0nSBGRoix6RdQ9PdsH045Vqyfjyx
# qj3F4jHMabiggvTcdLV8WL5PUjoODr91Qc/nvT8d6Ok7CWRGRMT4USUJhIdqFSMR
# 4GJLWfrD8YE/5myGs+cxygL1i7PrCWO+sNZArslXjAHDbfg1aRZ+gPPORsCT+6fR
# iK2MVHMPepR/Qv7bUyf03LB/f6kU+vfYDdVVfgNeSv7T1wQz0zEHb7vg9XEE
# SIG # End signature block
