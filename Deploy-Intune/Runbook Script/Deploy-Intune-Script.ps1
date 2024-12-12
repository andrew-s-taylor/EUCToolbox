<#
  __ _  _ __    __| | _ __   ___ __      __ ___ | |_   __ _  _   _ | |  ___   _ __      ___   ___   _ __ ___
 / _` || '_ \  / _` || '__| / _ \\ \ /\ / // __|| __| / _` || | | || | / _ \ | '__|    / __| / _ \ | '_ ` _ \
| (_| || | | || (_| || |   |  __/ \ V  V / \__ \| |_ | (_| || |_| || || (_) || |    _ | (__ | (_) || | | | | |
 \__,_||_| |_| \__,_||_|    \___|  \_/\_/  |___/ \__| \__,_| \__, ||_| \___/ |_|   (_) \___| \___/ |_| |_| |_|
                                                             |___/
.SYNOPSIS
  Builds an Intune Quick Start Environment
.DESCRIPTION
.Deploys Windows and Office update ring groups
.Configures an "Intune-Users" Group
.Deploys compliance policies for Android, iOS, Windows and MacOS
.Deploys base configuration profiles for Android, iOS, Windows and MacOS
.Deploys Security baselines for Windows
.Assigns everything as approproate
.Deploys Office 365 and Edge as required apps
.Deploys 7-Zip as available app
.Creates an Admins group with assignment on the Azure Joined Local Device Admins PIM role
.Creates a conditional access policy for compliant devices only
.Deploys MS Project and MS Visio with licensing groups
.Deploys DotNet 3.5 and Company Portal
.Deploys user backup script
.Deploys store apps using new Integration
.Runs silently in DevOps pipeline
.Queries GitHub Repo for customer details.

.INPUTS
Runmode:
silent (hides popups)
.OUTPUTS
Within Azure
.NOTES
  Version:        10.1
  Author:         Andrew Taylor
  Twitter:        @AndrewTaylor_2
  WWW:            andrewstaylor.com
  Creation Date:  14/02/2022
  Last Modified:  02/05/2024
  Purpose/Change: Initial script development
  Change: Added PIM Assignment and Conditional Access policy
  Change: Added Project and Visio (with groups)
  Change: Added VPP expiry check
  Change: Added environment backup
  Change: Added device backup script
  Change: Added options not to deploy CA and Azure parts (cost)
  Change: Added directory structure to store application Intunewin files
  Change: Various bug fixes
  Change: Added Android Enrollment
  Change: Added  Winget as Win32 App
  Change: Updated Autopilot Azure AD Group to include both Offline and Online devices (injected JSON)
  Change: Updated ESP to only install Company Portal and Winget
  Change: Added Windows Hello for Business Config
  Change: Added assignment for App Protection Policy
  Change: Configured ESP to be OOBE only
  Change: Tweaked modules to grab Autopilot information
  Change: Fixed script updates to encode into Base64 within the JSON
  Change: Amended Get- Functions to use where-object instead of URL filter (works better with special characters)
  Change: Added option to use MG.Graph.Groups instead of AzureAD for Group creation
  Change: Fixed Certificate login
  Change: Swapped M365 Apps from CSP to Win32 for better reliability
  Change: Transitioned away from AAD module
  Change: Added Store Integration
  Change: Silenced script for pipeline
  Change: Queries Github for CSV details
  Change: Removed form
  Change: Create and edit PowerShell scripts inline
  Change: Removed IntuneBackupAndRestore and 7zip modules
  Change: Changed to new Restore method using flat-file GitHub Repo
  Change: Removed Winget as now included
  Change: Added Store apps
  Change: Added Proactive Remediation for profile backup
  Change: Fixed assignments for scripts and Security policies
  Change: Added OneDrive and Browser config inline rather than find/replace
  Change: Fixed Breakglass details from hashtable to string
  Change: Added support for Azure Devops Repos as well as GitHub
  Change: Fixed DevOps repo to perform pull requests when adding files
  Change: Added option for non managed service which removes app reg and doesn't add to customer CSV
  Change: Support for SDK V2
  Change: Re-worked to run as runbook or manually rather than devops pipeline
  Change: Runbook Fixes
  Change: Re-written conditional access policies
  Change: Added Windows MAM
  Change: Added to run without file uploads
  Change: Added background image support inline using Base64 directly
  Change: Added Local Admin Entra settings
  Change: Switched to SendGrid for Email
  Change: Added prefix option to all policies and groups
  Change: Added fresh environment toggle

.EXAMPLE
N/A
#>
<#PSScriptInfo
.VERSION 10.1
.GUID 4bc67c81-0a03-4699-8313-3f31a9ec06ab
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
    [string]$importhomepage #Homepage URL
    ,
    [string]$importcompany #Company Name
    ,
    [string]$importcad #Conditional Access Checks ("Yes" or "No")
    ,
    [string]$imgbase64 #Base64 Image
    ,
    [string]$noupload #Don't upload files
    ,
    [string]$emailsend #Email address for files
    ,
    [string]$whitelabel #Prefix for whitelabelling
    ,
    [string]$fresh #Switch groups to dynamic for a fresh environment "Yes" or "No"
    ,
    [string]$sendgridtoken #Sendgrid API token
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
$importhomepage = ((($bodyData.homepage) | out-string).trim())
$importcompany = ((($bodyData.companyname) | out-string).trim())
$importcad = ((($bodyData.cad) | out-string).trim())
$imgbase64 = ((($bodyData.imagebase64) | out-string).trim())
$noupload = ((($bodyData.noupload) | out-string).trim())
$emailsend = ((($bodyData.emailsend) | out-string).trim())
$whitelabel = ((($bodyData.whitelabel) | out-string).trim())
$fresh = ((($bodyData.fresh) | out-string).trim())
$sendgridtoken = ((($bodyData.sendgridtoken) | out-string).trim())

$aadlogin = "yes"


}
else {
    write-output "No Webhook data, checking for parameters"


##Defaulting to github if nothing set above
$repocheck = $PSBoundParameters.ContainsKey('repotype')

if ($repocheck -ne $true) {
    write-output "No Repo Type set, defaulting to GitHub"
    $repoType = "github"
}
else {
    "Using $repotype for repo type"
}
$clientidcheck = $PSBoundParameters.ContainsKey('clientid')
$clientsecretcheck = $PSBoundParameters.ContainsKey('clientsecret')

if (($clientidcheck -eq $true) -and ($clientsecretcheck -eq $true)) {
##AAD Secret passed, use to login
$aadlogin = "yes"

}

}

$clientnameout = $importcompany
$clientnamelower = $clientnameout.ToLower()
$clientnamelower -replace '[^a-zA-Z0-9]', ''


if ($noupload) {
    $noupload = $noupload.Substring(0,1).ToUpper() + $noupload.Substring(1).ToLower()
}

if ($importcad) {
    $importcad = $importcad.Substring(0,1).ToUpper() + $importcad.Substring(1).ToLower()
}


write-output "whitelabel set to $whitelabel"

############################################################
############################################################
#############           AUTOMATION NOTES       #############
############################################################

## You need to add these modules to your Automation Account if using Azure Automation
## Don't use the V2 preview versions
## https://www.powershellgallery.com/packages/PackageManagement/
## https://www.powershellgallery.com/packages/Microsoft.Graph.Authentication/
## https://www.powershellgallery.com/packages/Microsoft.Graph.Devices.CorporateManagement/
## https://www.powershellgallery.com/packages/Microsoft.Graph.Groups/
## https://www.powershellgallery.com/packages/Microsoft.Graph.DeviceManagement/
## https://www.powershellgallery.com/packages/Microsoft.Graph.Identity.SignIns/
##Microsoft.Graph.Identity.Governance
################################################################################################################
################################################################################################################

$ErrorActionPreference = "Continue"
##Start Logging to %TEMP%\intune.log
$date = get-date -format ddMMyyyy
Start-Transcript -Path $env:TEMP\intune-$date.log


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

Function Add-DevopsFile(){
    
    <#
    .SYNOPSIS
    This function is used to add a file to an Azure Devops Repository
    .DESCRIPTION
    The function connects to the Azure Devops API and adds a file to a repository
    .EXAMPLE
    add-devopsfile -repo reponame -project projectname -organization orgname -filename filename -filecontent filecontent -token token
    .NOTES
    NAME: add-devopsfile
    #>
    
    [cmdletbinding()]
    
    param
    (
        $repo,
        $project,
        $organization,
        $filename,
        $filecontent,
        $token
    )
    

    $base64AuthInfo= [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes(":$($token)"))
    $encryptedcontent= [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes(":$($filecontent)"))

    $repoUrl = "https://dev.azure.com/$organization/$project/_apis/git/repositories/$repo"

    $repo = Invoke-RestMethod -Uri $repoUrl -Headers @{Authorization=("Basic {0}" -f $base64AuthInfo)} -Method Get
    $repoId = $repo.id

    ##Check for commits
    $pushiduri = "https://dev.azure.com/$organization/$project/_apis/git/repositories/$repoId/pushes?&`$top=1&searchCriteria.refName=refs/heads/master&api-version=6.0"
    $pushid = ((Invoke-RestMethod -Uri $pushiduri -Headers @{Authorization=("Basic {0}" -f $base64AuthInfo)} -Method Get).value).pushId
    $commituri = "https://dev.azure.com/$organization/$project/_apis/git/repositories/$repoID/pushes/$pushid`?api-version=6.0"
    $final = ((Invoke-RestMethod -Uri $commituri -Headers @{Authorization=("Basic {0}" -f $base64AuthInfo)} -Method Get).value).commitId



    if ($final) {
        $oldid = $final
    } else {
        $oldid = "0000000000000000000000000000000000000000"
    }


    # Push the commit
$pushUrl = "https://dev.azure.com/$organization/$project/_apis/git/repositories/$repoId/pushes?api-version=6.0"
$json = @"
{
    "refUpdates": [
      {
        "name": "refs/heads/master",
        "oldObjectId": "$oldid"
      }
    ],
    "commits": [
      {
        "comment": "Added new file.",
        "changes": [
          {
            "changeType": "add",
            "item": {
              "path": "/$filename"
            },
            "newContent": {
              "content": "$encryptedcontent",
              "contentType": "base64encoded"
            }
          }
        ]
      }
    ]
  }
"@
Invoke-RestMethod -Uri $pushUrl -Headers @{Authorization=("Basic {0}" -f $base64AuthInfo)} -Method Post -Body $json -ContentType "application/json"   

    ##Pull Request
    $pullurl = "https://dev.azure.com/$organization/$project/_apis/git/repositories/$repoId/pullrequests?api-version=6.0"
    $json = @"
    {
      "sourceRefName": "refs/heads/master",
      "targetRefName": "refs/heads/main",
      "title": "New File",
      "description": "New File"
    }
"@
    Invoke-RestMethod -Uri $pullurl -Headers @{Authorization=("Basic {0}" -f $base64AuthInfo)} -Method Post -Body $json -ContentType "application/json"   
    
    ##Get Pull Request
    $pullrequest = (Invoke-RestMethod -Uri $pullurl -Headers @{Authorization=("Basic {0}" -f $base64AuthInfo)} -Method GET)
    $pullrequestid = $pullrequest.value.pullRequestId
    $requestor = $pullrequest.value.createdBy.id
    
    
    ##Complete it
    $pullcompleteurl = "https://dev.azure.com/$organization/$project/_apis/git/repositories/$repoId/pullrequests/$pullrequestid" + "?api-version=6.0"
    $json = @"
    {
      "autoCompleteSetBy": {
        "id": "$requestor"
      },
      "completionOptions": {
        "deleteSourceBranch": "true",
        "mergeCommitMessage": "Updated File",
        "squashMerge": "false"
      }
    }
"@
    Invoke-RestMethod -Uri $pullcompleteurl -Headers @{Authorization=("Basic {0}" -f $base64AuthInfo)} -Method PATCH -Body $json -ContentType "application/json"   
        


}
Function Get-DevOpsCommits(){
    
    <#
    .SYNOPSIS
    This function is used to get commits from an Azure Devops Repository
    .DESCRIPTION
    The function connects to the Azure Devops API and gets commits from a repository
    .EXAMPLE
    Get-DevOpsCommits -repo reponame -project projectname -organization orgname -token token
    .NOTES
    NAME: Get-DevOpsCommits
    #>
    
    [cmdletbinding()]
    
    param
    (
        $repo,
        $project,
        $organization,
        $token
    )
    

    $base64AuthInfo= [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes(":$($token)"))
    $repoUrl = "https://dev.azure.com/$organization/$project/_apis/git/repositories/$repo"
    $repo = Invoke-RestMethod -Uri $repoUrl -Headers @{Authorization=("Basic {0}" -f $base64AuthInfo)} -Method Get
    $repoId = $repo.id

    # Get the commits
$ProjectUrl = "https://dev.azure.com/$organization/$project/_apis/git/repositories/$repoId/commits?api-version=7.0"
$CommitInfo = (Invoke-RestMethod -Uri $ProjectUrl -Method Get -UseDefaultCredential -Headers @{Authorization=("Basic {0}" -f $base64AuthInfo)}).value

return $CommitInfo
}



Function Get-DeviceConfigurationPolicy() {
    
    <#
        .SYNOPSIS
        This function is used to get device configuration policies from the Graph API REST interface
        .DESCRIPTION
        The function connects to the Graph API Interface and gets any device configuration policies
        .EXAMPLE
        Get-DeviceConfigurationPolicy
        Returns any device configuration policies configured in Intune
        .NOTES
        NAME: Get-DeviceConfigurationPolicy
        #>
        
    [cmdletbinding()]
        
    param
    (
        $name
    )
        
    $graphApiVersion = "beta"
    $DCP_resource = "deviceManagement/deviceConfigurations"
        
    try {
        
        if ($Name) {
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)"
                ((Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).value) | Where-Object DisplayName -EQ $name
        }
        
        else {
        
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)"
                (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).value
        
        }
        
    }
        
    catch {
        
        $ex = $_.Exception
        $errorResponse = $ex.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($errorResponse)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd();
        Write-Host "Response content:`n$responseBody" -f Red
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
        write-host
            
        
    }
        
}
        
####################################################
    
    
####################################################
        
Function Get-DeviceConfigurationPolicySC(){
    
    <#
    .SYNOPSIS
    This function is used to get device configuration policies from the Graph API REST interface - SETTINGS CATALOG
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any device configuration policies
    .EXAMPLE
    Get-DeviceConfigurationPolicySC
    Returns any device configuration policies configured in Intune
    .NOTES
    NAME: Get-DeviceConfigurationPolicySC
    #>
    
    [cmdletbinding()]
    
    param
    (
        $id
    )
    
    $graphApiVersion = "beta"
    $DCP_resource = "deviceManagement/configurationPolicies"
    try {
            if($id){
    
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)?`$filter=id eq '$id'"
            (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).value
    
            }
    
            else {

                $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)"
                $allconfigurationsettingscatalogpages = @()
                $configurationsettingscatalog = Invoke-MgGraphRequest -Uri $uri -Method Get
                $allconfigurationsettingscatalogpages += $configurationsettingscatalog.value
                        $policynextlink = $configurationsettingscatalog."@odata.nextlink"

                        while (($policynextlink -ne "") -and ($null -ne $policynextlink))
                        {
        $nextsettings = (Invoke-MgGraphRequest -Uri $policynextlink -Method Get -OutputType PSObject)
        $policynextlink = $nextsettings."@odata.nextLink"
        $allconfigurationsettingscatalogpages += $nextsettings.value
    }

        
                $configurationsettingscatalog = $allconfigurationsettingscatalogpages
                $configurationsettingscatalog
        
                }
        }
        catch {}
    
    
}

####################################################

Function Get-DeviceConfigurationPolicybyName(){
    
    <#
    .SYNOPSIS
    This function is used to get device configuration policies from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any device configuration policies
    .EXAMPLE
    Get-DeviceConfigurationPolicybyName
    Returns any device configuration policies configured in Intune
    .NOTES
    NAME: Get-DeviceConfigurationPolicybyName
    #>
    
    [cmdletbinding()]
    
    param
    (
        $name
    )
    
    $graphApiVersion = "beta"
    $Resource = "deviceManagement/deviceConfigurations"
    
    try {

    
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)?`$filter=displayName eq '$name'"
        $DC = (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value
    
        }
        catch {}
        $myid = $DC.id
        if ($null -ne $myid) {
            $fulluri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$myid"
            $type = "Configuration Policy"
            }
            else {
                $fulluri = ""
                $type = ""
            }
            $output = "" | Select-Object -Property id,fulluri, type    
            $output.id = $myid
            $output.fulluri = $fulluri
            $output.type = $type
            return $output
    }
    
    

Function Get-DeviceConfigurationPolicySCbyName(){
    
    <#
    .SYNOPSIS
    This function is used to get device configuration policies from the Graph API REST interface - SETTINGS CATALOG
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any device configuration policies
    .EXAMPLE
    Get-DeviceConfigurationPolicySCbyName
    Returns any device configuration policies configured in Intune
    .NOTES
    NAME: Get-DeviceConfigurationPolicySCbyName
    #>
    
    [cmdletbinding()]
    
    param
    (
        $name
    )
    
    $graphApiVersion = "beta"
    $Resource = "deviceManagement/configurationPolicies"
    try {


        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)?`$filter=name eq '$name'"
        $SC = (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value
    
        }
        catch {}
        $myid = $SC.id
        if ($null -ne $myid) {
            $fulluri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$myid"
            $type = "Settings Catalog"
            }
            else {
                $fulluri = ""
                $type = ""
            }
            $output = "" | Select-Object -Property id,fulluri, type    
            $output.id = $myid
            $output.fulluri = $fulluri
            $output.type = $type
            return $output
                        
}
                
####################################################
    
    
####################################################
        
Function Get-DeviceCompliancePolicy() {
        
    <#
                .SYNOPSIS
                This function is used to get device compliance policies from the Graph API REST interface
                .DESCRIPTION
                The function connects to the Graph API Interface and gets any device compliance policies
                .EXAMPLE
                Get-DeviceCompliancepolicy
                Returns any device compliance policies configured in Intune
                .NOTES
                NAME: Get-devicecompliancepolicy
                #>
                
    [cmdletbinding()]
                
    param
    (
        $name
    )
                
    $graphApiVersion = "beta"
    $DCP_resource = "deviceManagement/deviceCompliancePolicies"
                
    try {
                
        if ($Name) {
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)"
                            ((Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).value) | Where-Object Name -EQ $name
    
                
        }
                
        else {
                
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)"
                (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).value
                
        }
                
    }
                
    catch {
                
        $ex = $_.Exception
        $errorResponse = $ex.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($errorResponse)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd();
        Write-Host "Response content:`n$responseBody" -f Red
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
        write-host
                    
                
    }
                
}
                
Function Get-DeviceCompliancePolicyScripts(){
    
    <#
    .SYNOPSIS
    This function is used to get device custom compliance policy scripts from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any device compliance policies
    .EXAMPLE
    Get-DeviceCompliancePolicyScripts
    Returns any device compliance policy scripts configured in Intune
    .NOTES
    NAME: Get-DeviceCompliancePolicyScripts
    #>
    
    [cmdletbinding()]
    
    param
    (
        $id
    )
    
    $graphApiVersion = "beta"
    $DCP_resource = "deviceManagement/deviceComplianceScripts"
    try {
            if($id){
    
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)/$id"
            (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject)
    
            }
    
            else {
    
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)"
            (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value
    
            }
        }
        catch {}
    
}   
Function Get-DeviceSecurityPolicy() {
    
    <#
                    .SYNOPSIS
                    This function is used to get device security policies from the Graph API REST interface
                    .DESCRIPTION
                    The function connects to the Graph API Interface and gets any device security policies
                    .EXAMPLE
                    Get-DeviceSecurityPolicy
                    Returns any device compliance policies configured in Intune
                    .NOTES
                    NAME: Get-DeviceSecurityPolicy
                    #>
                    
    [cmdletbinding()]
                    
    param
    (
        $id
    )
                    
    $graphApiVersion = "beta"
    $DCP_resource = "deviceManagement/intents"
    try {
        if ($id) {
                    
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)/$id"
                            (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject)
                    
        }
                    
        else {
                    
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)"
                            (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value
                    
        }
    }
    catch {}
                   
}
    
Function Get-DeviceManagementScripts() {
        
    <#
                .SYNOPSIS
                This function is used to get device management scripts from the Graph API REST interface
                .DESCRIPTION
                The function connects to the Graph API Interface and gets any device management scripts
                .EXAMPLE
                Get-DeviceManagementScripts
                Returns any device management scripts configured in Intune
                .NOTES
                NAME: Get-DeviceManagementScripts
                #>
                
    [cmdletbinding()]
                
    param
    (
        $name
    )
                
    $graphApiVersion = "beta"
    $DCP_resource = "deviceManagement/deviceManagementScripts"
                
    try {
                
        if ($Name) {
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)"
                ((Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).value) | Where-Object displayName -EQ $name
    
        }
                
        else {
                
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)"
                (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).value
                
        }
                
    }
                
    catch {
                
        $ex = $_.Exception
        $errorResponse = $ex.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($errorResponse)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd();
        Write-Host "Response content:`n$responseBody" -f Red
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
        write-host
                    
                
    }
                
}
                
####################################################
        
    
    
Function Get-AutoPilotProfile() {
        
    <#
                    .SYNOPSIS
                    This function is used to get autopilot profiles from the Graph API REST interface 
                    .DESCRIPTION
                    The function connects to the Graph API Interface and gets any autopilot profiles
                    .EXAMPLE
                    Get-AutoPilotProfile
                    Returns any autopilot profiles configured in Intune
                    .NOTES
                    NAME: Get-AutoPilotProfile
                    #>
                    
    [cmdletbinding()]
                    
    param
    (
        $name
    )
                    
    $graphApiVersion = "beta"
    $DCP_resource = "deviceManagement/windowsAutopilotDeploymentProfiles"
                    
    try {
                    
        if ($Name) {
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)"
                ((Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).value) | Where-Object displayName -EQ $name
       
        }
                    
        else {
                    
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)"
                (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).value
                    
        }
                    
    }
                    
    catch {
                    
        $ex = $_.Exception
        $errorResponse = $ex.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($errorResponse)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd();
        Write-Host "Response content:`n$responseBody" -f Red
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
        write-host
                        
                    
    }
                    
}
                    
####################################################       
Function Get-DeviceConfigurationPolicyAssignment() {
    
    <#
    .SYNOPSIS
    This function is used to get device configuration policy assignment from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets a device configuration policy assignment
    .EXAMPLE
    Get-DeviceConfigurationPolicyAssignment $id guid
    Returns any device configuration policy assignment configured in Intune
    .NOTES
    NAME: Get-DeviceConfigurationPolicyAssignment
    #>
    
    [cmdletbinding()]
    
    param
    (
        [Parameter(Mandatory = $true, HelpMessage = "Enter id (guid) for the Device Configuration Policy you want to check assignment")]
        $id
    )
    
    $graphApiVersion = "Beta"
    $DCP_resource = "deviceManagement/deviceConfigurations"
    
    try {
    
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)/$id/groupAssignments"
        (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value
    
    }
    
    catch {
    
        $ex = $_.Exception
        $errorResponse = $ex.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($errorResponse)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd();
        Write-Host "Response content:`n$responseBody" -f Red
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
        write-host
        
    
    }
    
}

Function Get-DeviceConfigurationPolicyAssignmentSC() {
    
    <#
        .SYNOPSIS
        This function is used to get device configuration policy assignment from the Graph API REST interface - SETTINGS CATALOG Version
        .DESCRIPTION
        The function connects to the Graph API Interface and gets a device configuration policy assignment
        .EXAMPLE
        Get-DeviceConfigurationPolicyAssignmentSC $id guid
        Returns any device configuration policy assignment configured in Intune
        .NOTES
        NAME: Get-DeviceConfigurationPolicyAssignmentSC
        #>
        
    [cmdletbinding()]
        
    param
    (
        [Parameter(Mandatory = $true, HelpMessage = "Enter id (guid) for the Device Configuration Policy you want to check assignment")]
        $id
    )
        
    $graphApiVersion = "Beta"
    $DCP_resource = "deviceManagement/configurationPolicies"
        
    try {
        
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)/$id/Assignments"
            (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value
        
    }
        
    catch {
        
        $ex = $_.Exception
        $errorResponse = $ex.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($errorResponse)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd();
        Write-Host "Response content:`n$responseBody" -f Red
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
        write-host
            
        
    }
        
}

Function Add-DeviceManagementScriptAssignment() {
    <#
.SYNOPSIS
This function is used to add a device configuration policy assignment using the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and adds a device configuration policy assignment
.EXAMPLE
Add-DeviceConfigurationPolicyAssignment -ConfigurationPolicyId $ConfigurationPolicyId -TargetGroupId $TargetGroupId
Adds a device configuration policy assignment in Intune
.NOTES
NAME: Add-DeviceConfigurationPolicyAssignment
#>

    [cmdletbinding()]

    param
    (
        $ScriptId,
        $TargetGroupId
    )

    $graphApiVersion = "Beta"
    $Resource = "deviceManagement/deviceManagementScripts/$ScriptId/assign"

    try {

        if (!$ScriptId) {

            write-host "No Script Policy Id specified, specify a valid Script Policy Id" -f Red
            break

        }

        if (!$TargetGroupId) {

            write-host "No Target Group Id specified, specify a valid Target Group Id" -f Red
            break

        }

        $JSON = @"
{
    "deviceManagementScriptGroupAssignments":  [
        {
            "@odata.type":  "#microsoft.graph.deviceManagementScriptGroupAssignment",
            "targetGroupId": "$TargetGroupId",
            "id": "$ScriptId"
        }
    ]
}
"@

        $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"
        Invoke-MgGraphRequest -Uri $uri -Method POST -OutputType PSObject -Body $JSON -ContentType "application/json"

    }

    catch {

        $ex = $_.Exception
        $errorResponse = $ex.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($errorResponse)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd();
        Write-Host "Response content:`n$responseBody" -f Red
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
        write-host
        break

    }
}


Function Get-DeviceCompliancePolicyAssignment() {
    
    <#
        .SYNOPSIS
        This function is used to get device compliance policy assignment from the Graph API REST interface
        .DESCRIPTION
        The function connects to the Graph API Interface and gets a device compliance policy assignment
        .EXAMPLE
        Get-DeviceCompliancePolicyAssignment $id guid
        Returns any device compliance policy assignment configured in Intune
        .NOTES
        NAME: Get-DeviceCompliancePolicyAssignment
        #>
        
    [cmdletbinding()]
        
    param
    (
        [Parameter(Mandatory = $true, HelpMessage = "Enter id (guid) for the Device Configuration Policy you want to check assignment")]
        $id
    )
        
    $graphApiVersion = "Beta"
    $DCP_resource = "deviceManagement/devicecompliancePolicies"
        
    try {
        
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)/$id/assignments"
            (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value
        
    }
        
    catch {
        
        $ex = $_.Exception
        $errorResponse = $ex.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($errorResponse)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd();
        Write-Host "Response content:`n$responseBody" -f Red
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
        write-host
            
        
    }
        
}

Function Get-DeviceSecurityPolicyAssignment() {
    
    <#
        .SYNOPSIS
        This function is used to get device security policy assignment from the Graph API REST interface
        .DESCRIPTION
        The function connects to the Graph API Interface and gets a device compliance policy assignment
        .EXAMPLE
        Get-DeviceSecurityPolicyAssignment $id guid
        Returns any device security policy assignment configured in Intune
        .NOTES
        NAME: Get-DeviceSecurityPolicyAssignment
        #>
        
    [cmdletbinding()]
        
    param
    (
        [Parameter(Mandatory = $true, HelpMessage = "Enter id (guid) for the Device Security Policy you want to check assignment")]
        $id
    )
        
    $graphApiVersion = "Beta"
    $DCP_resource = "deviceManagement/intents"
        
    try {
        
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)/$id/Assignments"
            (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value
        
    }
        
    catch {
        
        $ex = $_.Exception
        $errorResponse = $ex.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($errorResponse)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd();
        Write-Host "Response content:`n$responseBody" -f Red
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
        write-host
            
        
    }
        
}
    
####################################################
Function Get-AutopilotProfile() {
    <#
    .SYNOPSIS
    Gets Windows Autopilot profile details.
     
    .DESCRIPTION
    The Get-AutopilotProfile cmdlet returns either a list of all Windows Autopilot profiles for the current Azure AD tenant, or information for the specific profile specified by its ID.
     
    .PARAMETER id
    Optionally, the ID (GUID) of the profile to be retrieved.
     
    .EXAMPLE
    Get a list of all Windows Autopilot profiles.
     
    Get-AutopilotProfile
    #>
    [cmdletbinding()]
    param
    (
        [Parameter(Mandatory = $false)] $id
    )
    
    # Defining Variables
    $graphApiVersion = "beta"
    $Resource = "deviceManagement/windowsAutopilotDeploymentProfiles"
    
    if ($id) {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource/$id"
    }
    else {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"
    }
    
    Write-Verbose "GET $uri"
    
    try {
        $response = Invoke-MGGraphRequest -Uri $uri -Method Get -OutputType PSObject
        if ($id) {
            $response
        }
        else {
            $devices = $response.value
        
            $devicesNextLink = $response."@odata.nextLink"
        
            while ($null -ne $devicesNextLink) {
                $devicesResponse = (Invoke-MGGraphRequest -Uri $devicesNextLink -Method Get -outputType PSObject)
                $devicesNextLink = $devicesResponse."@odata.nextLink"
                $devices += $devicesResponse.value
            }
        
            $devices
        }
    }
    catch {
        Write-Error $_.Exception 
        break
    }
    
}
Function ConvertTo-AutopilotConfigurationJSON() {
    <#
    .SYNOPSIS
    Converts the specified Windows Autopilot profile into a JSON format.
     
    .DESCRIPTION
    The ConvertTo-AutopilotConfigurationJSON cmdlet converts the specified Windows Autopilot profile, as represented by a Microsoft Graph API object, into a JSON format.
     
    .PARAMETER profile
    A Windows Autopilot profile object, typically returned by Get-AutopilotProfile
     
    .EXAMPLE
    Get the JSON representation of each Windows Autopilot profile in the current Azure AD tenant.
     
    Get-AutopilotProfile | ConvertTo-AutopilotConfigurationJSON
    #>
    [cmdletbinding()]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipeline = $True)]
        [Object] $profile
    )
    
    Begin {
    
        # Set the org-related info
        $script:TenantOrg = (Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/organization" -OutputType PSObject).value
        foreach ($domain in $script:TenantOrg.VerifiedDomains) {
            if ($domain.isDefault) {
                $script:TenantDomain = $domain.name
            }
        }
    }
    
    Process {
    
        $oobeSettings = $profile.outOfBoxExperienceSettings
    
        # Build up properties
        $json = @{}
        $json.Add("Comment_File", "Profile $($_.displayName)")
        $json.Add("Version", 2049)
        $json.Add("ZtdCorrelationId", $_.id)
        if ($profile."@odata.type" -eq "#microsoft.graph.activeDirectoryWindowsAutopilotDeploymentProfile") {
            $json.Add("CloudAssignedDomainJoinMethod", 1)
        }
        else {
            $json.Add("CloudAssignedDomainJoinMethod", 0)
        }
        if ($profile.deviceNameTemplate) {
            $json.Add("CloudAssignedDeviceName", $_.deviceNameTemplate)
        }
    
        # Figure out config value
        $oobeConfig = 8 + 256
        if ($oobeSettings.userType -eq 'standard') {
            $oobeConfig += 2
        }
        if ($oobeSettings.hidePrivacySettings -eq $true) {
            $oobeConfig += 4
        }
        if ($oobeSettings.hideEULA -eq $true) {
            $oobeConfig += 16
        }
        if ($oobeSettings.skipKeyboardSelectionPage -eq $true) {
            $oobeConfig += 1024
            if ($_.language) {
                $json.Add("CloudAssignedLanguage", $_.language)
            }
        }
        if ($oobeSettings.deviceUsageType -eq 'shared') {
            $oobeConfig += 32 + 64
        }
        $json.Add("CloudAssignedOobeConfig", $oobeConfig)
    
        # Set the forced enrollment setting
        if ($oobeSettings.hideEscapeLink -eq $true) {
            $json.Add("CloudAssignedForcedEnrollment", 1)
        }
        else {
            $json.Add("CloudAssignedForcedEnrollment", 0)
        }
    
        $json.Add("CloudAssignedTenantId", $script:TenantOrg.id)
        $json.Add("CloudAssignedTenantDomain", $script:TenantDomain)
        $embedded = @{}
        $embedded.Add("CloudAssignedTenantDomain", $script:TenantDomain)
        $embedded.Add("CloudAssignedTenantUpn", "")
        if ($oobeSettings.hideEscapeLink -eq $true) {
            $embedded.Add("ForcedEnrollment", 1)
        }
        else {
            $embedded.Add("ForcedEnrollment", 0)
        }
        $ztc = @{}
        $ztc.Add("ZeroTouchConfig", $embedded)
        $json.Add("CloudAssignedAadServerData", (ConvertTo-JSON $ztc -Compress))
    
        # Skip connectivity check
        if ($profile.hybridAzureADJoinSkipConnectivityCheck -eq $true) {
            $json.Add("HybridJoinSkipDCConnectivityCheck", 1)
        }
    
        # Hard-code properties not represented in Intune
        $json.Add("CloudAssignedAutopilotUpdateDisabled", 1)
        $json.Add("CloudAssignedAutopilotUpdateTimeout", 1800000)
    
        # Return the JSON
        ConvertTo-JSON $json
    }
    
}
    
        

Function Get-AutoPilotProfileAssignments() {
    
    <#
        .SYNOPSIS
        This function is used to get AutoPilot Profile assignment from the Graph API REST interface
        .DESCRIPTION
        The function connects to the Graph API Interface and gets an Autopilot profile assignment
        .EXAMPLE
        Get-AutoPilotProfileAssignments $id guid
        Returns any autopilot profile assignment configured in Intune
        .NOTES
        NAME: Get-AutoPilotProfileAssignments
        #>
        
    [cmdletbinding()]
        
    param
    (
        [Parameter(Mandatory = $true, HelpMessage = "Enter id (guid) for the Autopilot Profile you want to check assignment")]
        $id
    )
        
    $graphApiVersion = "Beta"
    $DCP_resource = "deviceManagement/windowsAutopilotDeploymentProfiles"
        
    try {
        
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)/$id/Assignments"
            (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value
        
    }
        
    catch {
        
        $ex = $_.Exception
        $errorResponse = $ex.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($errorResponse)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd();
        Write-Host "Response content:`n$responseBody" -f Red
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
        write-host
            
        
    }
        
}
    
####################################################
    
Function Add-DeviceConfigurationPolicyAssignment() {
    
    <#
    .SYNOPSIS
    This function is used to add a device configuration policy assignment using the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and adds a device configuration policy assignment
    .EXAMPLE
    Add-DeviceConfigurationPolicyAssignment -ConfigurationPolicyId $ConfigurationPolicyId -TargetGroupId $TargetGroupId
    Adds a device configuration policy assignment in Intune
    .NOTES
    NAME: Add-DeviceConfigurationPolicyAssignment
    #>
    
    [cmdletbinding()]
    
    param
    (
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        $ConfigurationPolicyId,
    
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        $TargetGroupId,
    
        [parameter(Mandatory = $true)]
        [ValidateSet("Included", "Excluded")]
        [ValidateNotNullOrEmpty()]
        [string]$AssignmentType
    )
    
    $graphApiVersion = "Beta"
    $Resource = "deviceManagement/deviceConfigurations/$ConfigurationPolicyId/assign"
        
    try {
    
        if (!$ConfigurationPolicyId) {
    
            write-host "No Configuration Policy Id specified, specify a valid Configuration Policy Id" -f Red
            break
    
        }
    
        if (!$TargetGroupId) {
    
            write-host "No Target Group Id specified, specify a valid Target Group Id" -f Red
            break
    
        }
    
        # Checking if there are Assignments already configured in the Policy
        $DCPA = Get-DeviceConfigurationPolicyAssignment -id $ConfigurationPolicyId
    
        $TargetGroups = @()
    
        if (@($DCPA).count -ge 1) {
                    
            if ($DCPA.targetGroupId -contains $TargetGroupId) {
    
                Write-Host "Group with Id '$TargetGroupId' already assigned to Policy..."
                Write-Host
                
    
            }
    
            # Looping through previously configured assignements
    
            $DCPA | ForEach-Object {
    
                $TargetGroup = New-Object -TypeName psobject
         
                if ($_.excludeGroup -eq $true) {
    
                    $TargetGroup | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value '#microsoft.graph.exclusionGroupAssignmentTarget'
         
                }
         
                else {
         
                    $TargetGroup | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value '#microsoft.graph.groupAssignmentTarget'
         
                }
    
                $TargetGroup | Add-Member -MemberType NoteProperty -Name 'groupId' -Value $_.targetGroupId
    
                $Target = New-Object -TypeName psobject
                $Target | Add-Member -MemberType NoteProperty -Name 'target' -Value $TargetGroup
    
                $TargetGroups += $Target
    
            }
    
            # Adding new group to psobject
            $TargetGroup = New-Object -TypeName psobject
    
            if ($AssignmentType -eq "Excluded") {
    
                $TargetGroup | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value '#microsoft.graph.exclusionGroupAssignmentTarget'
         
            }
         
            elseif ($AssignmentType -eq "Included") {
         
                $TargetGroup | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value '#microsoft.graph.groupAssignmentTarget'
         
            }
         
            $TargetGroup | Add-Member -MemberType NoteProperty -Name 'groupId' -Value "$TargetGroupId"
    
            $Target = New-Object -TypeName psobject
            $Target | Add-Member -MemberType NoteProperty -Name 'target' -Value $TargetGroup
    
            $TargetGroups += $Target
    
        }

        else {
    
            # No assignments configured creating new JSON object of group assigned
                
            $TargetGroup = New-Object -TypeName psobject
    
            if ($AssignmentType -eq "Excluded") {
    
                $TargetGroup | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value '#microsoft.graph.exclusionGroupAssignmentTarget'
         
            }
         
            elseif ($AssignmentType -eq "Included") {
         
                $TargetGroup | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value '#microsoft.graph.groupAssignmentTarget'
         
            }
         
            $TargetGroup | Add-Member -MemberType NoteProperty -Name 'groupId' -Value "$TargetGroupId"
    
            $Target = New-Object -TypeName psobject
            $Target | Add-Member -MemberType NoteProperty -Name 'target' -Value $TargetGroup
    
            $TargetGroups = $Target
    
        }
    
        # Creating JSON object to pass to Graph
        $Output = New-Object -TypeName psobject
    
        $Output | Add-Member -MemberType NoteProperty -Name 'assignments' -Value @($TargetGroups)
    
        $JSON = $Output | ConvertTo-Json -Depth 3
    
        # POST to Graph Service
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        #Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post -Body $JSON -ContentType "application/json"
        Invoke-MgGraphRequest -Uri $uri -Method Post -Body $JSON -ContentType "application/json"
    
    }
        
    catch {
    
        $ex = $_.Exception
        $errorResponse = $ex.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($errorResponse)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd();
        Write-Host "Response content:`n$responseBody" -f Red
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
        write-host
        
    
    }
    
}

Function Add-DeviceConfigurationPolicyAssignmentSC() {
    
    <#
        .SYNOPSIS
        This function is used to add a device configuration policy assignment using the Graph API REST interface  Settings Catalog
        .DESCRIPTION
        The function connects to the Graph API Interface and adds a device configuration policy assignment
        .EXAMPLE
        Add-DeviceConfigurationPolicyAssignment -ConfigurationPolicyId $ConfigurationPolicyId -TargetGroupId $TargetGroupId
        Adds a device configuration policy assignment in Intune
        .NOTES
        NAME: Add-DeviceConfigurationPolicyAssignment
        #>
            
    [cmdletbinding()]
            
    param
    (
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        $ConfigurationPolicyId,
            
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        $TargetGroupId,
            
        [parameter(Mandatory = $true)]
        [ValidateSet("Included", "Excluded")]
        [ValidateNotNullOrEmpty()]
        [string]$AssignmentType
    )
            
    $graphApiVersion = "Beta"
    $Resource = "deviceManagement/configurationPolicies/$ConfigurationPolicyId/assign"
                
    try {
            
        if (!$ConfigurationPolicyId) {
            
            write-host "No Configuration Policy Id specified, specify a valid Configuration Policy Id" -f Red
            break
            
        }
            
        if (!$TargetGroupId) {
            
            write-host "No Target Group Id specified, specify a valid Target Group Id" -f Red
            break
            
        }
            
        # Checking if there are Assignments already configured in the Policy
        $DCPA = Get-DeviceConfigurationPolicyAssignmentSC -id $ConfigurationPolicyId
            
        $TargetGroups = @()
            
        if (@($DCPA).count -ge 1) {
                        
            if ($DCPA.target.groupId -contains $TargetGroupId) {
            
                Write-Host "Group with Id '$TargetGroupId' already assigned to Policy..." 
                Write-Host
                break
            
            }
            
            # Looping through previously configured assignements
            
            $DCPA | ForEach-Object {
            
                $TargetGroup = New-Object -TypeName psobject
                 
                if ($_.excludeGroup -eq $true) {
                    $TargetGroup | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value '#microsoft.graph.exclusionGroupAssignmentTarget'
                 
                }
                 
                else {
                 
                    $TargetGroup | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value '#microsoft.graph.groupAssignmentTarget'
                 
                }
            
                $TargetGroup | Add-Member -MemberType NoteProperty -Name 'groupId' -Value $_.target.groupId

            
                $Target = New-Object -TypeName psobject
                $Target | Add-Member -MemberType NoteProperty -Name 'target' -Value $TargetGroup
            
                $TargetGroups += $Target
            
            }
            
            # Adding new group to psobject
            $TargetGroup = New-Object -TypeName psobject
            
            if ($AssignmentType -eq "Excluded") {
            
                $TargetGroup | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value '#microsoft.graph.exclusionGroupAssignmentTarget'
                 
            }
                 
            elseif ($AssignmentType -eq "Included") {
                 
                $TargetGroup | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value '#microsoft.graph.groupAssignmentTarget'
                 
            }
                 
            $TargetGroup | Add-Member -MemberType NoteProperty -Name 'groupId' -Value "$TargetGroupId"
            
            $Target = New-Object -TypeName psobject
            $Target | Add-Member -MemberType NoteProperty -Name 'target' -Value $TargetGroup
            
            $TargetGroups += $Target
            
        }
            
        else {
            
            # No assignments configured creating new JSON object of group assigned
                        
            $TargetGroup = New-Object -TypeName psobject
            
            if ($AssignmentType -eq "Excluded") {
            
                $TargetGroup | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value '#microsoft.graph.exclusionGroupAssignmentTarget'
                 
            }
                 
            elseif ($AssignmentType -eq "Included") {
                 
                $TargetGroup | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value '#microsoft.graph.groupAssignmentTarget'
                 
            }
                 
            $TargetGroup | Add-Member -MemberType NoteProperty -Name 'groupId' -Value "$TargetGroupId"
            
            $Target = New-Object -TypeName psobject
            $Target | Add-Member -MemberType NoteProperty -Name 'target' -Value $TargetGroup
            
            $TargetGroups = $Target
            
        }
            
        # Creating JSON object to pass to Graph
        $Output = New-Object -TypeName psobject
            
        $Output | Add-Member -MemberType NoteProperty -Name 'assignments' -Value @($TargetGroups)
            
        $JSON = $Output | ConvertTo-Json -Depth 3
            
        # POST to Graph Service
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Invoke-MgGraphRequest -Uri $uri -Method Post -Body $JSON -ContentType "application/json"
            
    }
                
    catch {
            
        $ex = $_.Exception
        $errorResponse = $ex.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($errorResponse)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd();
        Write-Host "Response content:`n$responseBody" -f Red
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
        write-host
        break
            
    }
            
}

Function Set-ManagedAppPolicy() {

    <#
            .SYNOPSIS
            This function is used to assign an AAD group to a Managed App Policy using the Graph API REST interface
            .DESCRIPTION
            The function connects to the Graph API Interface and assigns a Managed App Policy with an AAD Group
            .EXAMPLE
            Set-ManagedAppPolicy -Id $Id -TargetGroupId $TargetGroupId -OS Android
            Assigns an AAD Group assignment to an Android App Protection Policy in Intune
            .EXAMPLE
            Set-ManagedAppPolicy -Id $Id -TargetGroupId $TargetGroupId -OS iOS
            Assigns an AAD Group assignment to an iOS App Protection Policy in Intune
            .NOTES
            NAME: Set-ManagedAppPolicy
            #>
            
    [cmdletbinding()]
            
    param
    (
        $Id,
        $TargetGroupId,
        $OS
    )
            
    $graphApiVersion = "Beta"
                
    try {
            
        if (!$Id) {
            
            write-host "No Policy Id specified, specify a valid Application Id" -f Red
            break
            
        }
            
        if (!$TargetGroupId) {
            
            write-host "No Target Group Id specified, specify a valid Target Group Id" -f Red
            break
            
        }
            
        $JSON = @"
            
            {
                "assignments":[
                {
                    "target":
                    {
                        "groupId":"$TargetGroupId",
                        "@odata.type":"#microsoft.graph.groupAssignmentTarget"
                    }
                }
                ]
            }
            
"@
            
        if ($OS -eq "" -or $null -eq $OS) {
            
            write-host "No OS parameter specified, please provide an OS. Supported value Android or iOS..." -f Red
            Write-Host
            break
            
        }
            
        elseif ($OS -eq "Android") {
            
            $uri = "https://graph.microsoft.com/beta/deviceAppManagement/iosManagedAppProtections('$ID')/assign"
            Invoke-MgGraphRequest -Uri $uri -Method Post -ContentType "application/json" -Body $JSON
            
        }
            
        elseif ($OS -eq "iOS") {
            
            $uri = "https://graph.microsoft.com/$graphApiVersion/deviceAppManagement/iosManagedAppProtections('$ID')/assign"
            Invoke-MgGraphRequest -Uri $uri -Method Post -ContentType "application/json" -Body $JSON

            
        }
                
    }
                
    catch {
            
        $ex = $_.Exception
        $errorResponse = $ex.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($errorResponse)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd();
        Write-Host "Response content:`n$responseBody" -f Red
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
        write-host
        break
            
    }
            
}
            
####################################################    

Function Add-DeviceCompliancePolicyAssignment() {

    <#
.SYNOPSIS
This function is used to add a device compliance policy assignment using the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and adds a device compliance policy assignment
.EXAMPLE
Add-DeviceCompliancePolicyAssignment -CompliancePolicyId $CompliancePolicyId -TargetGroupId $TargetGroupId
Adds a device compliance policy assignment in Intune
.NOTES
NAME: Add-DeviceCompliancePolicyAssignment
#>

    [cmdletbinding()]

    param
    (
        $CompliancePolicyId,
        $TargetGroupId
    )

    $graphApiVersion = "v1.0"
    $Resource = "deviceManagement/deviceCompliancePolicies/$CompliancePolicyId/assign"
    
    try {

        if (!$CompliancePolicyId) {

            write-host "No Compliance Policy Id specified, specify a valid Compliance Policy Id" -f Red
            break

        }

        if (!$TargetGroupId) {

            write-host "No Target Group Id specified, specify a valid Target Group Id" -f Red
            break

        }

        $JSON = @"
    {
        "assignments": [
        {
            "target": {
            "@odata.type": "#microsoft.graph.groupAssignmentTarget",
            "groupId": "$TargetGroupId"
            }
        }
        ]
    }
    
"@

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Invoke-MgGraphRequest -Uri $uri -Method Post -Body $JSON -ContentType "application/json"


    }
    
    catch {

        $ex = $_.Exception
        $errorResponse = $ex.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($errorResponse)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd();
        Write-Host "Response content:`n$responseBody" -f Red
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
        write-host
    

    }

}

Function Add-DeviceSecurityPolicyAssignment() {
    
    <#
    .SYNOPSIS
    This function is used to add a device security policy assignment using the Graph API REST interface  
    .DESCRIPTION
    The function connects to the Graph API Interface and adds a device security policy assignment
    .EXAMPLE
    Add-DeviceSecurityPolicyAssignment -ConfigurationPolicyId $ConfigurationPolicyId -TargetGroupId $TargetGroupId
    Adds a device security policy assignment in Intune
    .NOTES
    NAME: Add-DeviceSecurityPolicyAssignment
    #>
    
    [cmdletbinding()]
    
    param
    (
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        $ConfigurationPolicyId,
    
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        $TargetGroupId,
    
        [parameter(Mandatory = $true)]
        [ValidateSet("Included", "Excluded")]
        [ValidateNotNullOrEmpty()]
        [string]$AssignmentType
    )
    
    $graphApiVersion = "Beta"
    $Resource = "deviceManagement/intents/$ConfigurationPolicyId/assign"
        
    try {
    
        if (!$ConfigurationPolicyId) {
    
            write-host "No Security Policy Id specified, specify a valid Security Policy Id"
            break
    
        }
    
        if (!$TargetGroupId) {
    
            write-host "No Target Group Id specified, specify a valid Target Group Id"
            break
    
        }
    
        # Checking if there are Assignments already configured in the Policy
        $DCPA = Get-DeviceSecurityPolicyAssignment -id $ConfigurationPolicyId
    
        $TargetGroups = @()
    
        if (@($DCPA).count -ge 1) {
                    
            if ($DCPA.targetGroupId -contains $TargetGroupId) {
    
                Write-Host "Group with Id '$TargetGroupId' already assigned to Policy..."
                Write-Host
                
    
            }
    
            # Looping through previously configured assignements
    
            $DCPA | ForEach-Object {
    
                $TargetGroup = New-Object -TypeName psobject
         
                if ($_.excludeGroup -eq $true) {
    
                    $TargetGroup | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value '#microsoft.graph.exclusionGroupAssignmentTarget'
         
                }
         
                else {
         
                    $TargetGroup | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value '#microsoft.graph.groupAssignmentTarget'
         
                }
    
                $TargetGroup | Add-Member -MemberType NoteProperty -Name 'groupId' -Value $_.targetGroupId
    
                $Target = New-Object -TypeName psobject
                $Target | Add-Member -MemberType NoteProperty -Name 'target' -Value $TargetGroup
    
                $TargetGroups += $Target
    
            }
    
            # Adding new group to psobject
            $TargetGroup = New-Object -TypeName psobject
    
            if ($AssignmentType -eq "Excluded") {
    
                $TargetGroup | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value '#microsoft.graph.exclusionGroupAssignmentTarget'
         
            }
         
            elseif ($AssignmentType -eq "Included") {
         
                $TargetGroup | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value '#microsoft.graph.groupAssignmentTarget'
         
            }
         
            $TargetGroup | Add-Member -MemberType NoteProperty -Name 'groupId' -Value "$TargetGroupId"
    
            $Target = New-Object -TypeName psobject
            $Target | Add-Member -MemberType NoteProperty -Name 'target' -Value $TargetGroup
    
            $TargetGroups += $Target
    
        }

        else {
    
            # No assignments configured creating new JSON object of group assigned
                
            $TargetGroup = New-Object -TypeName psobject
    
            if ($AssignmentType -eq "Excluded") {
    
                $TargetGroup | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value '#microsoft.graph.exclusionGroupAssignmentTarget'
         
            }
         
            elseif ($AssignmentType -eq "Included") {
         
                $TargetGroup | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value '#microsoft.graph.groupAssignmentTarget'
         
            }
         
            $TargetGroup | Add-Member -MemberType NoteProperty -Name 'groupId' -Value "$TargetGroupId"
    
            $Target = New-Object -TypeName psobject
            $Target | Add-Member -MemberType NoteProperty -Name 'target' -Value $TargetGroup
    
            $TargetGroups = $Target
    
        }
    
        # Creating JSON object to pass to Graph
        $Output = New-Object -TypeName psobject
    
        $Output | Add-Member -MemberType NoteProperty -Name 'assignments' -Value @($TargetGroups)
    
        $JSON = $Output | ConvertTo-Json -Depth 3
    
        # POST to Graph Service
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Invoke-MgGraphRequest -Uri $uri -Method Post -Body $JSON -ContentType "application/json"
    
    }
        
    catch {
    
        $ex = $_.Exception
        $errorResponse = $ex.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($errorResponse)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd();
        Write-Host "Response content:`n$responseBody" -f Red
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
        write-host
        
    
    }
    
}

        
Function Add-AutoPilotProfileAssignment() {
    
    <#
        .SYNOPSIS
        This function is used to add an autopilot profile assignment using the Graph API REST interface
        .DESCRIPTION
        The function connects to the Graph API Interface and adds an autopilot profile assignment
        .EXAMPLE
        Add-AutoPilotProfileAssignment -ConfigurationPolicyId $ConfigurationPolicyId -TargetGroupId $TargetGroupId
        Adds a device configuration policy assignment in Intune
        .NOTES
        NAME: Add-AutoPilotProfileAssignment
        #>
        
    [cmdletbinding()]
        
    param
    (
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        $ConfigurationPolicyId,
        
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        $TargetGroupId,
        
        [parameter(Mandatory = $true)]
        [ValidateSet("Included", "Excluded")]
        [ValidateNotNullOrEmpty()]
        [string]$AssignmentType
    )
        
    $graphApiVersion = "Beta"
    $Resource = "deviceManagement/windowsAutopilotDeploymentProfiles/$ConfigurationPolicyId/assignments"
            
    try {
        
        if (!$ConfigurationPolicyId) {
        
            write-host "No Configuration Policy Id specified, specify a valid Configuration Policy Id" -f Red
            break
        
        }
        
        if (!$TargetGroupId) {
        
            write-host "No Target Group Id specified, specify a valid Target Group Id" -f Red
            break
        
        }
        
        # Checking if there are Assignments already configured in the Policy
        $DCPA = Get-AutoPilotProfileAssignments -id $ConfigurationPolicyId
        
        $TargetGroups = @()
        
        if (@($DCPA).count -ge 1) {
                    
            if ($DCPA.targetGroupId -contains $TargetGroupId) {
        
                Write-Host "Group with Id '$TargetGroupId' already assigned to Policy..."
                Write-Host
                    
        
            }
        
            # Looping through previously configured assignements
        
            $DCPA | ForEach-Object {
        
                $TargetGroup = New-Object -TypeName psobject
             
                if ($_.excludeGroup -eq $true) {
        
                    $TargetGroup | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value '#microsoft.graph.exclusionGroupAssignmentTarget'
             
                }
             
                else {
             
                    $TargetGroup | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value '#microsoft.graph.groupAssignmentTarget'
             
                }
        
                $TargetGroup | Add-Member -MemberType NoteProperty -Name 'groupId' -Value $_.targetGroupId
        
                $Target = New-Object -TypeName psobject
                $Target | Add-Member -MemberType NoteProperty -Name 'target' -Value $TargetGroup
        
                $TargetGroups += $Target
        
            }
        
            # Adding new group to psobject
            $TargetGroup = New-Object -TypeName psobject
        
            if ($AssignmentType -eq "Excluded") {
        
                $TargetGroup | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value '#microsoft.graph.exclusionGroupAssignmentTarget'
             
            }
             
            elseif ($AssignmentType -eq "Included") {
             
                $TargetGroup | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value '#microsoft.graph.groupAssignmentTarget'
             
            }
             
            $TargetGroup | Add-Member -MemberType NoteProperty -Name 'groupId' -Value "$TargetGroupId"
        
            $Target = New-Object -TypeName psobject
            $Target | Add-Member -MemberType NoteProperty -Name 'target' -Value $TargetGroup
        
            $TargetGroups += $Target
        
        }
        
        else {
        
            # No assignments configured creating new JSON object of group assigned
                    
            $TargetGroup = New-Object -TypeName psobject
        
            if ($AssignmentType -eq "Excluded") {
        
                $TargetGroup | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value '#microsoft.graph.exclusionGroupAssignmentTarget'
             
            }
             
            elseif ($AssignmentType -eq "Included") {
             
                $TargetGroup | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value '#microsoft.graph.deviceAndAppManagementAssignmentTarget'
                $TargetGroup | Add-Member -MemberType NoteProperty -Name 'deviceAndAppManagementAssignmentFilterType' -Value 'include'
             
            }
             
            $TargetGroup | Add-Member -MemberType NoteProperty -Name 'deviceAndAppManagementAssignmentFilterId' -Value "$TargetGroupId"
        
            $Target = New-Object -TypeName psobject
            $Target | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value '#microsoft.graph.windowsAutopilotDeploymentProfileAssignment'
            $Target | Add-Member -MemberType NoteProperty -Name 'target' -Value $TargetGroup
            $Target | Add-Member -MemberType NoteProperty -Name 'sourceId' -Value $TargetGroupId
            $Target | Add-Member -MemberType NoteProperty -Name 'source' -Value "direct"
        
            $TargetGroups = $Target
        
        }
        
        # Creating JSON object to pass to Graph
        $Output = New-Object -TypeName psobject
        
        $Output | Add-Member -MemberType NoteProperty -Name 'assignments' -Value @($TargetGroups)
        
        $JSON = $Output | ConvertTo-Json -Depth 4
        
        # POST to Graph Service
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Invoke-MgGraphRequest -Uri $uri -Method Post -Body $JSON -ContentType "application/json"
        
    }
            
    catch {
        
        $ex = $_.Exception
        $errorResponse = $ex.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($errorResponse)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd();
        Write-Host "Response content:`n$responseBody" -f Red
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
        write-host
            
        
    }
        
}

function Add-MDMApplication() {

    <#
                .SYNOPSIS
                This function is used to add an MDM application using the Graph API REST interface
                .DESCRIPTION
                The function connects to the Graph API Interface and adds an MDM application from the itunes store
                .EXAMPLE
                Add-MDMApplication -JSON $JSON
                Adds an application into Intune
                .NOTES
                NAME: Add-MDMApplication
                #>
                
    [cmdletbinding()]
                
    param
    (
        $JSON
    )
                
    try {
                
        if (!$JSON) {
                
            Write-Error "No JSON was passed to the function, provide a JSON variable"
            break
                
        }
                
        Test-JSON -JSON $JSON
        
        New-MgDeviceAppMgtMobileApp -BodyParameter $JSON        
    }
                
    catch {
                
        $ex = $_.Exception
        $errorResponse = $ex.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($errorResponse)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd()
        Write-Debug "Response content:`n$responseBody"
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
        
        break
                
    }
                
}
        
####################################################

Function Add-ApplicationAssignment() {
        
    <#
        .SYNOPSIS
        This function is used to add an application assignment using the Graph API REST interface
        .DESCRIPTION
        The function connects to the Graph API Interface and adds a application assignment
        .EXAMPLE
        Add-ApplicationAssignment -ApplicationId $ApplicationId -TargetGroupId $TargetGroupId -InstallIntent $InstallIntent
        Adds an application assignment in Intune
        .NOTES
        NAME: Add-ApplicationAssignment
        #>
        
    [cmdletbinding()]
        
    param
    (
        $ApplicationId,
        $TargetGroupId,
        $InstallIntent
    )
            
    try {
        
        if (!$ApplicationId) {
        
            Write-Error "No Application Id specified, specify a valid Application Id"
            break
        
        }
        
        if (!$TargetGroupId) {
        
            Write-Error "No Target Group Id specified, specify a valid Target Group Id"
            break
        
        }
        
                
        if (!$InstallIntent) {
        
            Write-Error "No Install Intent specified, specify a valid Install Intent - available, notApplicable, required, uninstall, availableWithoutEnrollment"
            break
        
        }
        
        $JSON = @"
        {
            "mobileAppAssignments": [
            {
                "@odata.type": "#microsoft.graph.mobileAppAssignment",
                "target": {
                "@odata.type": "#microsoft.graph.groupAssignmentTarget",
                "groupId": "$TargetGroupId"
                },
                "intent": "$InstallIntent"
            }
            ]
        }
"@
        Set-MgDeviceAppMgtMobileApp -MobileAppId $ApplicationId -BodyParameter $JSON
        
    }
            
    catch {
        
        $ex = $_.Exception
        $errorResponse = $ex.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($errorResponse)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd()
        Write-Debug "Response content:`n$responseBody"
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
        break
        
    }
        
}


function CloneObject($object) {

    $stream = New-Object IO.MemoryStream;
    $formatter = New-Object Runtime.Serialization.Formatters.Binary.BinaryFormatter;
    $formatter.Serialize($stream, $object);
    $stream.Position = 0;
    $formatter.Deserialize($stream);
}

####################################################

function WriteHeaders($authToken) {

    foreach ($header in $authToken.GetEnumerator()) {
        if ($header.Name.ToLower() -eq "authorization") {
            continue;
        }

        Write-Host -ForegroundColor Gray "$($header.Name): $($header.Value)";
    }
}

####################################################

function MakeGetRequest($collectionPath) {

    $uri = "$baseUrl$collectionPath";
    $request = "GET $uri";
	
    if ($logRequestUris) { Write-Host $request; }
    if ($logHeaders) { WriteHeaders $authToken; }

    try {
        Test-AuthToken
        $response = Invoke-MgGraphRequest $uri -Method Get -OutputType PSObject;
        $response;
    }
    catch {
        Write-Host -ForegroundColor Red $request;
        Write-Host -ForegroundColor Red $_.Exception.Message;
        throw;
    }
}

####################################################

function MakePatchRequest($collectionPath, $body) {

    MakeRequest "PATCH" $collectionPath $body;

}

####################################################

function MakePostRequest($collectionPath, $body) {

    MakeRequest "POST" $collectionPath $body;

}

####################################################

function MakeRequest($verb, $collectionPath, $body) {

    $uri = "$baseUrl$collectionPath";
    $request = "$verb $uri";
	
    $clonedHeaders = CloneObject $authToken;
    $clonedHeaders["content-length"] = $body.Length;
    $clonedHeaders["content-type"] = "application/json";

    if ($logRequestUris) { Write-Host $request; }
    if ($logHeaders) { WriteHeaders $clonedHeaders; }
    if ($logContent) { Write-Host -ForegroundColor Gray $body; }

    try {
        Test-AuthToken
        $response = Invoke-MgGraphRequest $uri -Method $verb -Headers $clonedHeaders -Body $body;
        $response;
    }
    catch {
        Write-Host -ForegroundColor Red $request;
        Write-Host -ForegroundColor Red $_.Exception.Message;
        throw;
    }
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

    $body = @{ "@odata.type" = "#microsoft.graph.mobileAppContentFile" };
    $body.name = $name;
    $body.size = $size;
    $body.sizeEncrypted = $sizeEncrypted;
    $body.manifest = $manifest;
    $body.isDependency = $false;

    $body;
}

####################################################

function GetAppCommitBody($contentVersionId, $LobType) {

    $body = @{ "@odata.type" = "#$LobType" };
    $body.committedContentVersion = $contentVersionId;

    $body;

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
        $mobileApp = Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/" -Body ($mobileAppBody | ConvertTo-Json) -ContentType "application/json" -OutputType PSObject
        #$mobileApp = New-MgDeviceAppMgtMobileApp -BodyParameter ($mobileAppBody | ConvertTo-Json)
        
        # Get the content version for the new app (this will always be 1 until the new app is committed).
        Write-Verbose "Creating Content Version in the service for the application..."
        $appId = $mobileApp.id
        $contentVersionUri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/$appId/$LOBType/contentVersions"
        $contentVersion = Invoke-MgGraphRequest -method POST -Uri $contentVersionUri -Body "{}"
        
        # Encrypt file and Get File Information
        Write-Verbose "Getting Encryption Information for '$SourceFile'..."
        
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
        $contentVersionId = $contentVersion.id
        $fileBody = GetAppFileBody "$FileName" $Size $EncrySize $null
        $filesUri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/$appId/$LOBType/contentVersions/$contentVersionId/files"
        $file = Invoke-MgGraphRequest -Method POST -Uri $filesUri -Body ($fileBody | ConvertTo-Json)
            
        # Wait for the service to process the new file request.
        Write-Verbose "Waiting for the file entry URI to be created..."
        $fileId = $file.id
        $fileUri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/$appId/$LOBType/contentVersions/$contentVersionId/files/$fileId"
        $file = Start-WaitForFileProcessing $fileUri "AzureStorageUriRequest"
        
        # Upload the content to Azure Storage.
        Write-Verbose "Uploading file to Azure Storage..."
        
        UploadFileToAzureStorage $file.azureStorageUri "$IntuneWinFile" $fileUri
        
        # Need to Add removal of IntuneWin file
        Remove-Item "$IntuneWinFile" -Force
        
        # Commit the file.
        Write-Verbose "Committing the file into Azure Storage..."
        $commitFileUri = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/$appId/$LOBType/contentVersions/$contentVersionId/files/$fileId/commit"
        Invoke-MgGraphRequest -Uri $commitFileUri -Method POST -Body ($fileEncryptionInfo | ConvertTo-Json)
        
        # Wait for the service to process the commit file request.
        Write-Verbose "Waiting for the service to process the commit file request..."
        $file = Start-WaitForFileProcessing $fileUri "CommitFile"
        
        # Commit the app.
        Write-Verbose "Committing the file into Azure Storage..."
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


####################################################
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
##########################################################################################

Function Get-GroupPolicyConfigurationsDefinitionValues() {
	
    <#
    .SYNOPSIS
    This function is used to get device configuration policies from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any device configuration policies
    .EXAMPLE
    Get-DeviceConfigurationPolicy
    Returns any device configuration policies configured in Intune
    .NOTES
    NAME: Get-GroupPolicyConfigurations
    #>
	
    [cmdletbinding()]
    Param (
		
        [Parameter(Mandatory = $true)]
        [string]$GroupPolicyConfigurationID
		
    )
	
    $graphApiVersion = "Beta"
    #$DCP_resource = "deviceManagement/groupPolicyConfigurations/$GroupPolicyConfigurationID/definitionValues?`$filter=enabled eq true"
    $DCP_resource = "deviceManagement/groupPolicyConfigurations/$GroupPolicyConfigurationID/definitionValues"
	
    try {	
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)"
		(Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value
		
    }
    catch {}
	

	
}

####################################################
Function Get-GroupPolicyConfigurationsDefinitionValuesPresentationValues() {
	
    <#
    .SYNOPSIS
    This function is used to get device configuration policies from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any device configuration policies
    .EXAMPLE
    Get-DeviceConfigurationPolicy
    Returns any device configuration policies configured in Intune
    .NOTES
    NAME: Get-GroupPolicyConfigurations
    #>
	
    [cmdletbinding()]
    Param (
		
        [Parameter(Mandatory = $true)]
        [string]$GroupPolicyConfigurationID,
        [string]$GroupPolicyConfigurationsDefinitionValueID
		
    )
    $graphApiVersion = "Beta"
	
    $DCP_resource = "deviceManagement/groupPolicyConfigurations/$GroupPolicyConfigurationID/definitionValues/$GroupPolicyConfigurationsDefinitionValueID/presentationValues"
    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)"
		(Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value
    }
    catch {}
		
	
}

Function Get-GroupPolicyConfigurationsDefinitionValuesdefinition () {
    <#
    .SYNOPSIS
    This function is used to get device configuration policies from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any device configuration policies
    .EXAMPLE
    Get-DeviceConfigurationPolicy
    Returns any device configuration policies configured in Intune
    .NOTES
    NAME: Get-GroupPolicyConfigurations
    #>
	
    [cmdletbinding()]
    Param (
		
        [Parameter(Mandatory = $true)]
        [string]$GroupPolicyConfigurationID,
        [Parameter(Mandatory = $true)]
        [string]$GroupPolicyConfigurationsDefinitionValueID
		
    )
    $graphApiVersion = "Beta"
    $DCP_resource = "deviceManagement/groupPolicyConfigurations/$GroupPolicyConfigurationID/definitionValues/$GroupPolicyConfigurationsDefinitionValueID/definition"
    try {
		
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)"
		
        $responseBody = Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject
    }
    catch {}
		
		
    $responseBody
}


Function Get-GroupPolicyDefinitionsPresentations () {
    <#
    .SYNOPSIS
    This function is used to get device configuration policies from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any device configuration policies
    .EXAMPLE
    Get-DeviceConfigurationPolicy
    Returns any device configuration policies configured in Intune
    .NOTES
    NAME: Get-GroupPolicyConfigurations
    #>
	
    [cmdletbinding()]
    Param (
		
		
        [Parameter(Mandatory = $true)]
        [string]$groupPolicyDefinitionsID,
        [Parameter(Mandatory = $true)]
        [string]$GroupPolicyConfigurationsDefinitionValueID
		
    )
    $graphApiVersion = "Beta"
    $DCP_resource = "deviceManagement/groupPolicyConfigurations/$groupPolicyDefinitionsID/definitionValues/$GroupPolicyConfigurationsDefinitionValueID/presentationValues?`$expand=presentation"
    $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)"
    try {
		(Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value.presentation
    }
    catch {}
		
	
}


####################################################
##############################################################################################################

Function Add-MSStoreApp() {
        
    <#
    .SYNOPSIS
    This function adds Microsoft Store Apps using Winget
    .DESCRIPTION
    The function connects to the Graph API Interface and creates a Microsoft Store App using the new experience
    .EXAMPLE
    Add-MSStoreApp -name "WhatsApp"
    .NOTES
    NAME: Add-MSStoreApp
    #>
    
    [cmdletbinding()]
    
    param
    (
        $name
    )
    $appName = $name
    $storeSearchUrl = "https://storeedgefd.dsx.mp.microsoft.com/v9.0/manifestSearch"
    $body = @{
        Query = @{
            KeyWord   = $appName
            MatchType = "Substring"
        }
    } | ConvertTo-Json
    $appSearch = Invoke-RestMethod -Uri $storeSearchUrl -Method POST -ContentType 'application/json' -body $body
    $exactApp = $appSearch.Data | Where-Object { $_.PackageName -eq $appName }

    $appUrl = "https://storeedgefd.dsx.mp.microsoft.com/v9.0/packageManifests/{0}" -f $exactApp.PackageIdentifier
    $app = Invoke-RestMethod -Uri $appUrl -Method GET 
    $appId = $app.Data.PackageIdentifier
    $appInfo = $app.Data.Versions[-1].DefaultLocale
    $appInstaller = $app.Data.Versions[-1].Installers


    #$imageUrl = "https://apps.microsoft.com/store/api/ProductsDetails/GetProductDetailsById/{0}?hl=en-US&gl=US" -f $exactApp.PackageIdentifier
    #$image = Invoke-RestMethod -Uri $imageUrl -Method GET 
    #$wc = New-Object System.Net.WebClient
    #$wc.DownloadFile($image.IconUrl, "./temp.jpg")
    #$base64string = [Convert]::ToBase64String([IO.File]::ReadAllBytes('./temp.jpg'))

    $appdescription = ($appInfo.Shortdescription).ToString()
    $appdescription2 = $appdescription.replace("`n", " ").replace("`r", " ").replace("\n", " ").replace("\\n", " ")
    $appdeveloper = $appInfo.Publisher
    $appdisplayName = $appInfo.packageName
    $appinformationUrl = $appInfo.PublisherSupportUrl
    $apprunAsAccount = ($appInstaller.scope | select-object -First 1)
    $apppackageIdentifier = $appId
    $appprivacyInformationUrl = $appInfo.PrivacyUrl
    $apppublisher = $appInfo.publisher


    $deployUrl = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps"
    $json = @"
{
	"@odata.type": "#microsoft.graph.winGetApp",
	"categories": [],
	"description": "$appdescription2",
	"developer": "$appdeveloper",
	"displayName": "$appdisplayName",
	"informationUrl": "$appinformationUrl",
	"installExperience": {
		"runAsAccount": "$apprunAsAccount"
	},
	"isFeatured": false,
	"notes": "",
	"owner": "",
	"packageIdentifier": "$apppackageIdentifier",
	"privacyInformationUrl": "$appprivacyInformationUrl",
	"publisher": "$apppublisher",
	"repositoryType": "microsoftStore",
	"roleScopeTagIds": []
}
"@

    $appDeploy = Invoke-mggraphrequest -uri $deployUrl -Method POST -Body $json -ContentType "application/JSON"



    return $appDeploy
}

Function Add-StoreAppAssignment() {

    <#
    .SYNOPSIS
    This function is used to add a store app assignment using the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and adds a store app assignment
    .EXAMPLE
    Add-StoreAppAssignment -StoreAppID $StoreAppIdId -TargetGroupId $TargetGroupId
    Adds a Store app assignment in Intune
    .NOTES
    NAME: Add-SStoreAppAssignment
    #>
    
    [cmdletbinding()]
    
    param
    (
        $StoreAppID,
        $TargetGroupId
    )
    
    $graphApiVersion = "Beta"
    $Resource = "deviceAppManagement/mobileApps/$storeAppID/assign"
        
    try {
    
        if (!$StoreAppID) {
    
            write-host "No App Id specified, specify a valid Compliance Policy Id" -f Red
            break
    
        }
    
        if (!$TargetGroupId) {
    
            write-host "No Target Group Id specified, specify a valid Target Group Id" -f Red
            break
    
        }
    
        $JSON = @"
{
	"mobileAppAssignments": [
		{
			"@odata.type": "#microsoft.graph.mobileAppAssignment",
			"intent": "Required",
			"settings": {
				"@odata.type": "#microsoft.graph.winGetAppAssignmentSettings",
				"installTimeSettings": null,
				"notifications": "showAll",
				"restartSettings": null
			},
			"target": {
				"@odata.type": "#microsoft.graph.groupAssignmentTarget",
				"groupId": "$targetgroupid"
			}
		}
	]
}
"@
    
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Invoke-MgGraphRequest -Uri $uri -Method Post -Body $JSON -ContentType "application/json"
    
    
    }
        
    catch {
    
        $ex = $_.Exception
        $errorResponse = $ex.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($errorResponse)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd();
        Write-Host "Response content:`n$responseBody" -f Red
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
        write-host
        
    
    }
    
}

Function Get-MSStoreApps() {
        
    <#
        .SYNOPSIS
        This function is used to get MS Store Apps from the Graph API REST interface
        .DESCRIPTION
        The function connects to the Graph API Interface and gets any MS Store Apps
        .EXAMPLE
        Get-MSStoreApps
        Returns any MS Store Apps configured in Intune
        .NOTES
        NAME: Get-MSStoreApps
        #>
        
    [cmdletbinding()]
        
    param
    (
        $id
    )
        
    $graphApiVersion = "beta"
    $DCP_resource = "deviceAppManagement/MobileApps"
        
    try {
        
        if ($id) {
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)/$id"
        ((Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).value)

        }
        
        else {
        
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)?`$filter=(isof('microsoft.graph.winGetApp'))"
        (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).value
        
        }
        
    }
        
    catch {
        
        $ex = $_.Exception
        $errorResponse = $ex.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($errorResponse)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd();
        Write-Host "Response content:`n$responseBody" -f Red
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
        write-host
            
        
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
$date = get-date -format yyMMddmmss
$date = $date.ToString()
$path2 = $random + "-" + $date
$path = "c:\temp\" + $path2 + "\"

New-Item -ItemType Directory -Path $path


Write-Output "Directory Created"


###############################################################################################################
######                                          Deploy                                                   ######
###############################################################################################################



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
    Select-MgProfile -Name Beta
    Connect-ToGraph -Scopes "Policy.ReadWrite.ConditionalAccess, CloudPC.ReadWrite.All, DeviceManagementServiceConfig.ReadWrite.All, RoleAssignmentSchedule.ReadWrite.Directory, Domain.Read.All, Domain.ReadWrite.All, Directory.Read.All, Policy.ReadWrite.ConditionalAccess, DeviceManagementApps.ReadWrite.All, DeviceManagementConfiguration.ReadWrite.All, DeviceManagementManagedDevices.ReadWrite.All, openid, profile, email, offline_access, DeviceManagementRBAC.Read.All, DeviceManagementRBAC.ReadWrite.All, Policy.ReadWrite.MobilityManagement, Policy.ReadWrite.DeviceConfiguration"
    }
write-output "Graph Connection Established"


###############################################################################################################
######                                          Group Creation using MG.Graph Module                     ######
###############################################################################################################

    write-output "Creating Groups and users"
##Get Domain suffix
$domain = get-mgdomain | where-object IsDefault -eq $true

$suffix = $domain.Id
#
##Create Azure AD Groups
##Create Admins Groups
if ($whitelabel) {
    $displayname = $whitelabel + "Azure-Global-Admins"
}
else {
    $displayname = "Azure-Global-Admins"
}
$globaladmingrp = New-MgGroup -DisplayName "$displayname" -Description "Azure Global Admins (PIM Role)" -MailEnabled:$False -MailNickName "azureglobaladmins" -SecurityEnabled -IsAssignableToRole
#
##Create Azure AD Breakglass user

function GenerateRandomPassword {
    param (
        [Parameter(Mandatory)]
        [int] $length
    )
 
    $charSet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?'.ToCharArray()
 
    $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
    $bytes = New-Object byte[]($length)
  
    $rng.GetBytes($bytes)
  
    $result = New-Object char[]($length)
  
    for ($i = 0 ; $i -lt $length ; $i++) {
        $result[$i] = $charSet[$bytes[$i]%$charSet.Length]
    }
 
    return -join $result
}

$bgpassword = GenerateRandomPassword -length 20
$bglassname = "breakglass@$suffix"

$PasswordProfile = @{
    Password = $bgpassword
    ForceChangePasswordNextSignIn = $false
}
if ($whitelabel) {
    $displayname = $whitelabel + "Azure BreakGlass Account"
}
else {
    $displayname = "Azure BreakGlass Account"
}
$breakglass = New-MGUser -DisplayName "$displayname" -PasswordProfile $PasswordProfile -UserPrincipalName "breakglass@$suffix" -AccountEnabled:$true -MailNickName "BreakGlass" -PasswordPolicies "DisablePasswordExpiration"
#

##Set Breakglass never to expire
$bgid = $breakglass.Id

##Create Admins Groups
if ($whitelabel) {
    $displayname = $whitelabel + "Intune-Device-Admins"
}
else {
    $displayname = "Intune-Device-Admins"
}
$admingrp = New-MGGroup -DisplayName "$displayname" -Description "Azure AD Joined Device Admins (PIM Role)" -MailEnabled:$False -MailNickName "IntuneDeviceAdmins" -SecurityEnabled -IsAssignableToRole
#
##Pilot Group
if ($whitelabel) {
    $displayname = $whitelabel + "Intune-Pilot-Users"
}
else {
    $displayname = "Intune-Pilot-Users"
}
$pilotgrp = New-MGGroup -DisplayName "$displayname" -Description "Assigned group for Pilot Users" -MailEnabled:$False -MailNickName "IntunePilotUsers" -SecurityEnabled
#
##Preview Group
if ($whitelabel) {
    $displayname = $whitelabel + "Intune-Preview-Users"
}
else {
    $displayname = "Intune-Preview-Users"
}
$previewgrp = New-MGGroup -DisplayName "$displayname" -Description "Assigned group for Preview Users" -MailEnabled:$False -MailNickName "IntunePreviewUsers" -SecurityEnabled
#
##VIP Group
if ($whitelabel) {
    $displayname = $whitelabel + "Intune-VIP-Users"
}
else {
    $displayname = "Intune-VIP-Users"
}
$vipgrp = New-MGGroup -DisplayName "$displayname" -Description "Assigned group for VIP Users" -MailEnabled:$False -MailNickName "IntuneVIPUsers" -SecurityEnabled
#
##Intune Users Group
if ($fresh -eq "No") {
    if ($whitelabel) {
        $displayname = $whitelabel + "Intune-Users"
    }
    else {
        $displayname = "Intune-Users"
    }
    $intunemaingrp = New-MGGroup -DisplayName "$displayname" -Description "Dynamic group for Intune Users" -MailEnabled:$False -MailNickName "intuneusers" -SecurityEnabled -GroupTypes "DynamicMembership" -MembershipRule "(user.assignedPlans -any (assignedPlan.servicePlanId -eq ""c1ec4a95-1f05-45b3-a911-aa3fa01094f5"" -and assignedPlan.capabilityStatus -eq ""Enabled"")) and (user.accountEnabled -eq true)" -MembershipRuleProcessingState "On"
    if ($whitelabel) {
        $displayname = $whitelabel + "Intune Deploy Pilot Users"
    }
    else {
        $displayname = "Intune Deploy Pilot Users"
    }
    $intunegrp = New-MGGroup -DisplayName "$displayname" -Description "Assigned group for Intune Pilot Users" -MailEnabled:$False -MailNickName "intunedeploypilotusers" -SecurityEnabled

}
else {
#$intunegrp = New-MGGroup -DisplayName "Intune-Users" -Description "Assigned group for Intune Users" -MailEnabled:$False -MailNickName "intuneusers" -SecurityEnabled
if ($whitelabel) {
    $displayname = $whitelabel + "Intune-Users"
}
else {
    $displayname = "Intune-Users"
}
$intunegrp = New-MGGroup -DisplayName "$displayname" -Description "Dynamic group for Intune Users" -MailEnabled:$False -MailNickName "intuneusers" -SecurityEnabled -GroupTypes "DynamicMembership" -MembershipRule "(user.assignedPlans -any (assignedPlan.servicePlanId -eq ""c1ec4a95-1f05-45b3-a911-aa3fa01094f5"" -and assignedPlan.capabilityStatus -eq ""Enabled"")) and (user.accountEnabled -eq true)" -MembershipRuleProcessingState "On"

}
#
##Create Visio Install Group
if ($whitelabel) {
    $displayname = $whitelabel + "Visio-Install"
}
else {
    $displayname = "Visio-Install"
}
$visioinstall = New-MGGroup -DisplayName "$displayname" -Description "Dynamic group for Licensed Visio Users" -MailEnabled:$False -MailNickName "visiousers" -SecurityEnabled -GroupTypes "DynamicMembership" -MembershipRule "(user.assignedPlans -any (assignedPlan.servicePlanId -eq ""663a804f-1c30-4ff0-9915-9db84f0d1cea"" -and assignedPlan.capabilityStatus -eq ""Enabled""))" -MembershipRuleProcessingState "On"
#
##Create Visio Uninstall Group
if ($whitelabel) {
    $displayname = $whitelabel + "Visio-Uninstall"
}
else {
    $displayname = "Visio-Uninstall"
}
$visiouninstall = New-MGGroup -DisplayName "$displayname" -Description "Dynamic group for users without Visio license" -MailEnabled:$False -MailNickName "visiouninstall" -SecurityEnabled -GroupTypes "DynamicMembership" -MembershipRule "(user.assignedPlans -all (assignedPlan.servicePlanId -ne ""663a804f-1c30-4ff0-9915-9db84f0d1cea"" -and assignedPlan.capabilityStatus -ne ""Enabled""))" -MembershipRuleProcessingState "On"
#
##Create Project Install Group
if ($whitelabel) {
    $displayname = $whitelabel + "Project-Install"
}
else {
    $displayname = "Project-Install"
}
$projectinstall = New-MGGroup -DisplayName "$displayname" -Description "Dynamic group for Licensed Project Users" -MailEnabled:$False -MailNickName "projectinstall" -SecurityEnabled -GroupTypes "DynamicMembership" -MembershipRule "(user.assignedPlans -any (assignedPlan.servicePlanId -eq ""fafd7243-e5c1-4a3a-9e40-495efcb1d3c3"" -and assignedPlan.capabilityStatus -eq ""Enabled""))" -MembershipRuleProcessingState "On"
#
##Create Project Uninstall Group
if ($whitelabel) {
    $displayname = $whitelabel + "Project-Uninstall"
}
else {
    $displayname = "Project-Uninstall"
}
$projectuninstall = New-MGGroup -DisplayName "$displayname" -Description "Dynamic group for users without Project license" -MailEnabled:$False -MailNickName "projectuninstall" -SecurityEnabled -GroupTypes "DynamicMembership" -MembershipRule "(user.assignedPlans -all (assignedPlan.servicePlanId -ne ""fafd7243-e5c1-4a3a-9e40-495efcb1d3c3"" -and assignedPlan.capabilityStatus -ne ""Enabled""))" -MembershipRuleProcessingState "On"

###############################################################################################################
######                         End MG Graph Group Creation                                               ######
###############################################################################################################




write-output "Azure AD Groups Created, moving on to PIM Config"

###############################################################################################################
######                                          PIM Setup                                                ######
###############################################################################################################


##Add breakglass account to Azure global admins and Entra admins

$url = "https://graph.microsoft.com/beta/directoryRoles"
$garoleid = ((getallpagination -url $url) | where-object displayName -eq "Global Administrator").id

$roleuri = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments"
$rolejson = @"
{
    "@odata.type": "#microsoft.graph.unifiedRoleAssignment",
    "principalId": "$bgid",
    "roleDefinitionId": "$garoleid",
    "directoryScopeId": "/"
}
"@

Invoke-MgGraphRequest -Uri $roleuri -Method POST -Body $rolejson -ContentType "application/json"

##Grab Tenant ID
$uri = "https://graph.microsoft.com/beta/organization"
$tenantdetails = (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).value
$tenantid = $tenantdetails.id
$licensing = $tenantdetails.AssignedPlans
$islicensed = $licensing.ServicePlanId -contains "eec0eb4f-6444-4f95-aba0-50c24d67f998"

if (($islicensed -eq $True) -and (!$noupload)) {
    write-output "Azure AD P2 licensing in place, continuing"

    ##Device Admins
    ##Get the PIM Role
    $uri = "https://graph.microsoft.com/beta/roleManagement/directory/roleDefinitions"
    $roles = (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).value
    $PIMrole = $roles | where-object DisplayName -eq "Azure AD Joined Device Local Administrator"

    #This bombs out if group isn't fully created so lets wait 30 seconds
    start-sleep -s 30
    #Create PIM role
    $roleid = $PIMrole.id
    $principalId = $admingrp.id
    $starttime = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
    $params = @{
        Action           = "adminAssign"
        Justification    = "Local Admins"
        RoleDefinitionId = $roleid
        DirectoryScopeId = "/"
        PrincipalId      = $principalId
        ScheduleInfo     = @{
            StartDateTime = $starttime
            Expiration    = @{
                Type = "NoExpiration"
            }
        }
    }

    New-MgRoleManagementDirectoryRoleAssignmentScheduleRequest -BodyParameter $params

}
else {
    write-output "Not Licensed for Azure PIM, skipping"
}

    ###############################################################################################################
    ######                                          BASE Configuration                                      ######
    ###############################################################################################################
##Get Org ID
write-output "Getting Organisation ID"
$OrgId = (Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/organization" -Method Get -OutputType PSObject).value.id
write-output "Org ID is $orgid"
    #Check if Intune already is MDM Authority
write-output "Checking if Intune is MDM"
 $mdmAuth = (Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/organization('$OrgId')?`$select=mobiledevicemanagementauthority" -Method Get -OutputType PSObject).mobileDeviceManagementAuthority
 #Sets Intune as MDM Authority if not already set
 write-output "MDMAuth is $mdmAuth"
 if($mdmAuth -notlike "intune")
  {
  write-output "Setting MDM org to Intune"
  Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/v1.0/organization/$OrgID/setMobileDeviceManagementAuthority" -Method POST
 write-output "MDM set"
 } 


    ##Grab a token for Delegated access
    $ReqTokenBody = @{
        Grant_Type    = "Password"
        client_Id     = $clientID
        Client_Secret = $clientSecret
        Username      = $bglassname
        Password      = $bgpassword
        Scope         = "https://graph.microsoft.com/.default"
    } 
    
    $TokenResponse = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$suffix/oauth2/v2.0/token" -Method POST -Body $ReqTokenBody

    ##Sleep for 30 seconds to give role time to assign
    start-sleep -s 30

    ##Enable LAPS and setting admins
write-output "Enabling LAPS and setting admins"
$uri = "https://graph.microsoft.com/beta/policies/deviceRegistrationPolicy"
$json = @'
{
	"@odata.context": "https://graph.microsoft.com/beta/$metadata#policies/deviceRegistrationPolicy/$entity",
	"multiFactorAuthConfiguration": "notRequired",
	"id": "deviceRegistrationPolicy",
	"displayName": "Device Registration Policy",
	"description": "Tenant-wide policy that manages initial provisioning controls using quota restrictions, additional authentication and authorization checks",
	"userDeviceQuota": 50,
	"azureADRegistration": {
		"isAdminConfigurable": false,
		"allowedToRegister": {
			"@odata.type": "#microsoft.graph.allDeviceRegistrationMembership"
		}
	},
	"azureADJoin": {
		"isAdminConfigurable": true,
		"allowedToJoin": {
			"@odata.type": "#microsoft.graph.allDeviceRegistrationMembership"
		},
		"localAdmins": {
			"enableGlobalAdmins": true,
			"registeringUsers": {
				"@odata.type": "#microsoft.graph.noDeviceRegistrationMembership"
			}
		}
	},
	"localAdminPassword": {
		"isEnabled": true
	}
}
'@
Invoke-MgGraphRequest -Method PUT -Uri $uri -Body $json -ContentType "application/json"
#Invoke-RestMethod -Method Put -Uri $uri -UseBasicParsing -Body $json -ContentType "application/json" -Headers @{Authorization = "Bearer $($Tokenresponse.access_token)"}
Write-Output "LAPS Enabled and admins configured"

##Set enrollment types
##Get Policy ID
Write-Output "Getting Device Restrictions Policy ID"
$policyid = (((Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceEnrollmentConfigurations?`$filter=priority eq 0" -OutputType PSObject).value) | where-object '@odata.type' -eq "#microsoft.graph.deviceEnrollmentPlatformRestrictionsConfiguration").id
Write-Output "Policy ID: $policyid"

##Set URL
$url = "https://graph.microsoft.com/beta/deviceManagement/deviceEnrollmentConfigurations/$policyid"


##Populate JSON
$json = @"
{
	"@odata.type": "#microsoft.graph.deviceEnrollmentPlatformRestrictionsConfiguration",
	"androidForWorkRestriction": {
		"blockedManufacturers": [],
		"osMaximumVersion": "",
		"osMinimumVersion": "",
		"personalDeviceEnrollmentBlocked": true,
		"platformBlocked": false
	},
	"androidRestriction": {
		"blockedManufacturers": [],
		"osMaximumVersion": "",
		"osMinimumVersion": "",
		"personalDeviceEnrollmentBlocked": false,
		"platformBlocked": true
	},
	"macOSRestriction": {
		"blockedManufacturers": [],
		"osMaximumVersion": null,
		"osMinimumVersion": null,
		"personalDeviceEnrollmentBlocked": true,
		"platformBlocked": false
	},
	"windowsHomeSkuRestriction": {
		"blockedManufacturers": [],
		"osMaximumVersion": null,
		"osMinimumVersion": null,
		"personalDeviceEnrollmentBlocked": true,
		"platformBlocked": false
	},
	"windowsRestriction": {
		"blockedManufacturers": [],
		"osMaximumVersion": "",
		"osMinimumVersion": "",
		"personalDeviceEnrollmentBlocked": true,
		"platformBlocked": false
	}
}
"@

##Update Policy
write-output "Updating Device Restrictions Policy"
Invoke-MgGraphRequest -Uri $url -Method PATCH -Body $json -ContentType "application/json"
Write-Output "Device Restrictions Policy updated"

##Allow Entra MDM
write-output "Allowing MDM Entra Enrollment"
##Get policies
$policiesuri = "https://graph.microsoft.com/beta/policies/mobileDeviceManagementPolicies"
$policies = getallpagination -url $policiesuri
#$policies = (Invoke-RestMethod -Method GET -Uri $policiesuri -UseBasicParsing -Headers @{Authorization = "Bearer $($Tokenresponse.access_token)"}).value

##If only one, convert to array
if ($policies -isnot [System.Collections.ArrayList]) {
    $policies = @($policies)
}



foreach ($policy in $policies) {
    $policyid = $policy.Id
    $json = @"
    {
        "appliesTo":  "all"
    }
"@
    $uri = "https://graph.microsoft.com/beta/policies/mobileDeviceManagementPolicies/$policyid"
    Invoke-MgGraphRequest -Method PATCH -Uri $uri -Body $json -ContentType "application/json"
    #Invoke-RestMethod -Method PATCH -Uri $uri -UseBasicParsing -Body $json -ContentType "application/json" -Headers @{Authorization = "Bearer $($Tokenresponse.access_token)"}
}



##Only deploy if Selected
if ($importcad -eq "Yes") {

    ###############################################################################################################
    ######                                     Conditional Access                                            ######
    ###############################################################################################################

    $breakglassid = $breakglass.id

write-output "Creating Conditional Access Policy to block anything not protected"
$url = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"
if ($whitelabel) {
    $displayname = $whitelabel + "Block anything not protected"
}
else {
    $displayname = "Block anything not protected"
}
$json = @"
{
    "displayName":  "$displayname",
    "state@odata.type":  "#microsoft.graph.conditionalAccessPolicyState",
    "state":  "disabled",
    "sessionControls":  null,
    "conditions":  {
                       "@odata.type":  "#microsoft.graph.conditionalAccessConditionSet",
                       "userRiskLevels@odata.type":  "#Collection(microsoft.graph.riskLevel)",
                       "userRiskLevels":  [

                                          ],
                       "signInRiskLevels@odata.type":  "#Collection(microsoft.graph.riskLevel)",
                       "signInRiskLevels":  [

                                            ],
                       "clientAppTypes@odata.type":  "#Collection(microsoft.graph.conditionalAccessClientApp)",
                       "clientAppTypes":  [
                                              "all"
                                          ],
                       "locations":  null,
                       "times":  null,
                       "deviceStates":  null,
                       "clientApplications":  null,
                       "applications":  {
                                            "@odata.type":  "#microsoft.graph.conditionalAccessApplications",
                                            "includeApplications@odata.type":  "#Collection(String)",
                                            "includeApplications":  [
                                                                        "All"
                                                                    ],
                                            "excludeApplications@odata.type":  "#Collection(String)",
                                            "excludeApplications":  [

                                                                    ],
                                            "includeUserActions@odata.type":  "#Collection(String)",
                                            "includeUserActions":  [

                                                                   ],
                                            "includeAuthenticationContextClassReferences@odata.type":  "#Collection(String)",
                                            "includeAuthenticationContextClassReferences":  [

                                                                                            ],
                                            "applicationFilter":  null
                                        },
                       "users":  {
                                     "@odata.type":  "#microsoft.graph.conditionalAccessUsers",
                                     "includeUsers@odata.type":  "#Collection(String)",
                                     "includeUsers":  [
                                                          "All"
                                                      ],
                                     "excludeUsers@odata.type":  "#Collection(String)",
                                     "excludeUsers":  [
                                                          "$breakglassid"
                                                      ],
                                     "includeGroups@odata.type":  "#Collection(String)",
                                     "includeGroups":  [

                                                       ],
                                     "excludeGroups@odata.type":  "#Collection(String)",
                                     "excludeGroups":  [

                                                       ],
                                     "includeRoles@odata.type":  "#Collection(String)",
                                     "includeRoles":  [

                                                      ],
                                     "excludeRoles@odata.type":  "#Collection(String)",
                                     "excludeRoles":  [

                                                      ],
                                     "includeGuestsOrExternalUsers":  null,
                                     "excludeGuestsOrExternalUsers":  null
                                 },
                       "platforms":  {
                                         "@odata.type":  "#microsoft.graph.conditionalAccessPlatforms",
                                         "includePlatforms@odata.type":  "#Collection(microsoft.graph.conditionalAccessDevicePlatform)",
                                         "includePlatforms":  [
                                                                  "android",
                                                                  "iOS",
                                                                  "windowsPhone",
                                                                  "macOS",
                                                                  "linux"
                                                              ],
                                         "excludePlatforms@odata.type":  "#Collection(microsoft.graph.conditionalAccessDevicePlatform)",
                                         "excludePlatforms":  [

                                                              ]
                                     },
                       "devices":  {
                                       "@odata.type":  "#microsoft.graph.conditionalAccessDevices",
                                       "includeDeviceStates@odata.type":  "#Collection(String)",
                                       "includeDeviceStates":  [

                                                               ],
                                       "excludeDeviceStates@odata.type":  "#Collection(String)",
                                       "excludeDeviceStates":  [

                                                               ],
                                       "includeDevices@odata.type":  "#Collection(String)",
                                       "includeDevices":  [

                                                          ],
                                       "excludeDevices@odata.type":  "#Collection(String)",
                                       "excludeDevices":  [

                                                          ],
                                       "deviceFilter":  {
                                                            "@odata.type":  "#microsoft.graph.conditionalAccessFilter",
                                                            "mode@odata.type":  "#microsoft.graph.filterMode",
                                                            "mode":  "exclude",
                                                            "rule":  "device.deviceOwnership -eq \"Company\""
                                                        }
                                   }
                   },
    "grantControls":  {
                          "@odata.type":  "#microsoft.graph.conditionalAccessGrantControls",
                          "operator":  "OR",
                          "builtInControls@odata.type":  "#Collection(microsoft.graph.conditionalAccessGrantControl)",
                          "builtInControls":  [
                                                  "compliantDevice",
                                                  "domainJoinedDevice",
                                                  "compliantApplication"
                                              ],
                          "customAuthenticationFactors@odata.type":  "#Collection(String)",
                          "customAuthenticationFactors":  [

                                                          ],
                          "termsOfUse@odata.type":  "#Collection(String)",
                          "termsOfUse":  [

                                         ],
                          "authenticationStrength":  null
                      }
}
"@

Invoke-MgGraphRequest -Method POST -Uri $url -Body $json -ContentType "application/json" -OutputType PSObject

write-output "Created Conditional Access Policy to block anything not protected"


#######################################################################

write-output "Creating Conditional Access Policy - Block Legacy Auth"
$url = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"
if ($whitelabel) {
    $displayname = $whitelabel + "Block legacy authentication"
}
else {
    $displayname = "Block legacy authentication"
}
$json = @"
{
    "displayName":  "$displayname",
    "state@odata.type":  "#microsoft.graph.conditionalAccessPolicyState",
    "state":  "disabled",
    "sessionControls":  null,
    "conditions":  {
                       "@odata.type":  "#microsoft.graph.conditionalAccessConditionSet",
                       "userRiskLevels@odata.type":  "#Collection(microsoft.graph.riskLevel)",
                       "userRiskLevels":  [

                                          ],
                       "signInRiskLevels@odata.type":  "#Collection(microsoft.graph.riskLevel)",
                       "signInRiskLevels":  [

                                            ],
                       "clientAppTypes@odata.type":  "#Collection(microsoft.graph.conditionalAccessClientApp)",
                       "clientAppTypes":  [
                                              "exchangeActiveSync",
                                              "other"
                                          ],
                       "platforms":  null,
                       "locations":  null,
                       "times":  null,
                       "deviceStates":  null,
                       "devices":  null,
                       "clientApplications":  null,
                       "applications":  {
                                            "@odata.type":  "#microsoft.graph.conditionalAccessApplications",
                                            "includeApplications@odata.type":  "#Collection(String)",
                                            "includeApplications":  [
                                                                        "All"
                                                                    ],
                                            "excludeApplications@odata.type":  "#Collection(String)",
                                            "excludeApplications":  [

                                                                    ],
                                            "includeUserActions@odata.type":  "#Collection(String)",
                                            "includeUserActions":  [

                                                                   ],
                                            "includeAuthenticationContextClassReferences@odata.type":  "#Collection(String)",
                                            "includeAuthenticationContextClassReferences":  [

                                                                                            ],
                                            "applicationFilter":  null
                                        },
                       "users":  {
                                     "@odata.type":  "#microsoft.graph.conditionalAccessUsers",
                                     "includeUsers@odata.type":  "#Collection(String)",
                                     "includeUsers":  [
                                                          "All"
                                                      ],
                                     "excludeUsers@odata.type":  "#Collection(String)",
                                     "excludeUsers":  [
                                                          "$breakglassid"
                                                      ],
                                     "includeGroups@odata.type":  "#Collection(String)",
                                     "includeGroups":  [

                                                       ],
                                     "excludeGroups@odata.type":  "#Collection(String)",
                                     "excludeGroups":  [

                                                       ],
                                     "includeRoles@odata.type":  "#Collection(String)",
                                     "includeRoles":  [

                                                      ],
                                     "excludeRoles@odata.type":  "#Collection(String)",
                                     "excludeRoles":  [

                                                      ],
                                     "includeGuestsOrExternalUsers":  null,
                                     "excludeGuestsOrExternalUsers":  null
                                 }
                   },
    "grantControls":  {
                          "@odata.type":  "#microsoft.graph.conditionalAccessGrantControls",
                          "operator":  "OR",
                          "builtInControls@odata.type":  "#Collection(microsoft.graph.conditionalAccessGrantControl)",
                          "builtInControls":  [
                                                  "block"
                                              ],
                          "customAuthenticationFactors@odata.type":  "#Collection(String)",
                          "customAuthenticationFactors":  [

                                                          ],
                          "termsOfUse@odata.type":  "#Collection(String)",
                          "termsOfUse":  [

                                         ],
                          "authenticationStrength":  null
                      }
}

"@

Invoke-MgGraphRequest -Method POST -Uri $url -Body $json -ContentType "application/json" -OutputType PSObject

write-output "Created Conditional Access Policy to block legacy authentication"

#######################################################################

write-output "Creating Conditional Access Policy - Block Personal Windows without MAM"
$url = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"
if ($whitelabel) {
    $displayname = $whitelabel + "Block Personal Windows without App"
}
else {
    $displayname = "Block Personal Windows without App"
}
$json = @"
    {
        "displayName":  "$displayname",
        "state@odata.type":  "#microsoft.graph.conditionalAccessPolicyState",
        "state":  "disabled",
        "sessionControls":  null,
        "conditions":  {
                           "@odata.type":  "#microsoft.graph.conditionalAccessConditionSet",
                           "userRiskLevels@odata.type":  "#Collection(microsoft.graph.riskLevel)",
                           "userRiskLevels":  [
    
                                              ],
                           "signInRiskLevels@odata.type":  "#Collection(microsoft.graph.riskLevel)",
                           "signInRiskLevels":  [
    
                                                ],
                           "clientAppTypes@odata.type":  "#Collection(microsoft.graph.conditionalAccessClientApp)",
                           "clientAppTypes":  [
                                                  "exchangeActiveSync",
                                                  "mobileAppsAndDesktopClients",
                                                  "other"
                                              ],
                           "locations":  null,
                           "times":  null,
                           "deviceStates":  null,
                           "clientApplications":  null,
                           "applications":  {
                                                "@odata.type":  "#microsoft.graph.conditionalAccessApplications",
                                                "includeApplications@odata.type":  "#Collection(String)",
                                                "includeApplications": ["Office365"],
                                                "excludeApplications@odata.type":  "#Collection(String)",
                                                "excludeApplications":  [
    
                                                                        ],
                                                "includeUserActions@odata.type":  "#Collection(String)",
                                                "includeUserActions":  [
    
                                                                       ],
                                                "includeAuthenticationContextClassReferences@odata.type":  "#Collection(String)",
                                                "includeAuthenticationContextClassReferences":  [
    
                                                                                                ],
                                                "applicationFilter":  null
                                            },
                           "users":  {
                                         "@odata.type":  "#microsoft.graph.conditionalAccessUsers",
                                         "includeUsers@odata.type":  "#Collection(String)",
                                         "includeUsers":  [
                                                              "All"
                                                          ],
                                         "excludeUsers@odata.type":  "#Collection(String)",
                                         "excludeUsers":  [
                                                              "$breakglassid"
                                                          ],
                                         "includeGroups@odata.type":  "#Collection(String)",
                                         "includeGroups":  [
    
                                                           ],
                                         "excludeGroups@odata.type":  "#Collection(String)",
                                         "excludeGroups":  [
    
                                                           ],
                                         "includeRoles@odata.type":  "#Collection(String)",
                                         "includeRoles":  [
    
                                                          ],
                                         "excludeRoles@odata.type":  "#Collection(String)",
                                         "excludeRoles":  [
    
                                                          ],
                                         "includeGuestsOrExternalUsers":  null,
                                         "excludeGuestsOrExternalUsers":  null
                                     },
                           "platforms":  {
                                             "@odata.type":  "#microsoft.graph.conditionalAccessPlatforms",
                                             "includePlatforms@odata.type":  "#Collection(microsoft.graph.conditionalAccessDevicePlatform)",
                                             "includePlatforms":  [
                                                                      "windows"
                                                                  ],
                                             "excludePlatforms@odata.type":  "#Collection(microsoft.graph.conditionalAccessDevicePlatform)",
                                             "excludePlatforms":  [
    
                                                                  ]
                                         },
                           "devices":  {
                                           "@odata.type":  "#microsoft.graph.conditionalAccessDevices",
                                           "includeDeviceStates@odata.type":  "#Collection(String)",
                                           "includeDeviceStates":  [
    
                                                                   ],
                                           "excludeDeviceStates@odata.type":  "#Collection(String)",
                                           "excludeDeviceStates":  [
    
                                                                   ],
                                           "includeDevices@odata.type":  "#Collection(String)",
                                           "includeDevices":  [
    
                                                              ],
                                           "excludeDevices@odata.type":  "#Collection(String)",
                                           "excludeDevices":  [
    
                                                              ],
                                           "deviceFilter":  {
                                                                "@odata.type":  "#microsoft.graph.conditionalAccessFilter",
                                                                "mode@odata.type":  "#microsoft.graph.filterMode",
                                                                "mode":  "exclude",
                                                                "rule":  "device.deviceOwnership -eq \"Company\""
                                                            }
                                       }
                       },
        "grantControls":  {
                              "@odata.type":  "#microsoft.graph.conditionalAccessGrantControls",
                              "operator":  "OR",
                              "builtInControls@odata.type":  "#Collection(microsoft.graph.conditionalAccessGrantControl)",
                              "builtInControls":  [
                                                      "block"
                                                  ],
                              "customAuthenticationFactors@odata.type":  "#Collection(String)",
                              "customAuthenticationFactors":  [
    
                                                              ],
                              "termsOfUse@odata.type":  "#Collection(String)",
                              "termsOfUse":  [
    
                                             ],
                              "authenticationStrength":  null
                          }
    }
   
"@

Invoke-MgGraphRequest -Method POST -Uri $url -Body $json -ContentType "application/json" -OutputType PSObject

write-output "Created Conditional Access Policy to block personal windows without MAM"

#######################################################################

write-output "Creating Conditional Access Policy - Require App Protection for Mobile Devices"
$url = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"
if ($whitelabel) {
    $displayname = $whitelabel + "Require App Protection for Mobile Devices"
}
else {
    $displayname = "Require App Protection for Mobile Devices"
}
$json = @"
{
    "displayName":  "$displayname",
    "state@odata.type":  "#microsoft.graph.conditionalAccessPolicyState",
    "state":  "disabled",
    "sessionControls":  null,
    "conditions":  {
                       "@odata.type":  "#microsoft.graph.conditionalAccessConditionSet",
                       "userRiskLevels@odata.type":  "#Collection(microsoft.graph.riskLevel)",
                       "userRiskLevels":  [

                                          ],
                       "signInRiskLevels@odata.type":  "#Collection(microsoft.graph.riskLevel)",
                       "signInRiskLevels":  [

                                            ],
                       "clientAppTypes@odata.type":  "#Collection(microsoft.graph.conditionalAccessClientApp)",
                       "clientAppTypes":  [
                                              "all"
                                          ],
                       "locations":  null,
                       "times":  null,
                       "deviceStates":  null,
                       "clientApplications":  null,
                       "applications":  {
                                            "@odata.type":  "#microsoft.graph.conditionalAccessApplications",
                                            "includeApplications@odata.type":  "#Collection(String)",
                                            "includeApplications":  [
                                                                        "All"
                                                                    ],
                                            "excludeApplications@odata.type":  "#Collection(String)",
                                            "excludeApplications":  [

                                                                    ],
                                            "includeUserActions@odata.type":  "#Collection(String)",
                                            "includeUserActions":  [

                                                                   ],
                                            "includeAuthenticationContextClassReferences@odata.type":  "#Collection(String)",
                                            "includeAuthenticationContextClassReferences":  [

                                                                                            ],
                                            "applicationFilter":  null
                                        },
                       "users":  {
                                     "@odata.type":  "#microsoft.graph.conditionalAccessUsers",
                                     "includeUsers@odata.type":  "#Collection(String)",
                                     "includeUsers":  [
                                                          "All"
                                                      ],
                                     "excludeUsers@odata.type":  "#Collection(String)",
                                     "excludeUsers":  [
                                                          "$breakglassid"
                                                      ],
                                     "includeGroups@odata.type":  "#Collection(String)",
                                     "includeGroups":  [

                                                       ],
                                     "excludeGroups@odata.type":  "#Collection(String)",
                                     "excludeGroups":  [

                                                       ],
                                     "includeRoles@odata.type":  "#Collection(String)",
                                     "includeRoles":  [

                                                      ],
                                     "excludeRoles@odata.type":  "#Collection(String)",
                                     "excludeRoles":  [

                                                      ],
                                     "includeGuestsOrExternalUsers":  null,
                                     "excludeGuestsOrExternalUsers":  null
                                 },
                       "platforms":  {
                                         "@odata.type":  "#microsoft.graph.conditionalAccessPlatforms",
                                         "includePlatforms@odata.type":  "#Collection(microsoft.graph.conditionalAccessDevicePlatform)",
                                         "includePlatforms":  [
                                                                  "android",
                                                                  "iOS"
                                                              ],
                                         "excludePlatforms@odata.type":  "#Collection(microsoft.graph.conditionalAccessDevicePlatform)",
                                         "excludePlatforms":  [

                                                              ]
                                     },
                       "devices":  {
                                       "@odata.type":  "#microsoft.graph.conditionalAccessDevices",
                                       "includeDeviceStates@odata.type":  "#Collection(String)",
                                       "includeDeviceStates":  [

                                                               ],
                                       "excludeDeviceStates@odata.type":  "#Collection(String)",
                                       "excludeDeviceStates":  [

                                                               ],
                                       "includeDevices@odata.type":  "#Collection(String)",
                                       "includeDevices":  [

                                                          ],
                                       "excludeDevices@odata.type":  "#Collection(String)",
                                       "excludeDevices":  [

                                                          ],
                                       "deviceFilter":  {
                                                            "@odata.type":  "#microsoft.graph.conditionalAccessFilter",
                                                            "mode@odata.type":  "#microsoft.graph.filterMode",
                                                            "mode":  "exclude",
                                                            "rule":  "device.deviceOwnership -eq \"Company\""
                                                        }
                                   }
                   },
    "grantControls":  {
                          "@odata.type":  "#microsoft.graph.conditionalAccessGrantControls",
                          "operator":  "OR",
                          "builtInControls@odata.type":  "#Collection(microsoft.graph.conditionalAccessGrantControl)",
                          "builtInControls":  [
                                                  "compliantApplication"
                                              ],
                          "customAuthenticationFactors@odata.type":  "#Collection(String)",
                          "customAuthenticationFactors":  [

                                                          ],
                          "termsOfUse@odata.type":  "#Collection(String)",
                          "termsOfUse":  [

                                         ],
                          "authenticationStrength":  null
                      }
}

"@

Invoke-MgGraphRequest -Method POST -Uri $url -Body $json -ContentType "application/json" -OutputType PSObject

write-output "Created Conditional Access Policy to require app protection for mobile devices"

#######################################################################

write-output "Creating Conditional Access Policy - Require Device Compliance"
$url = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"
if ($whitelabel) {
    $displayname = $whitelabel + "Require Device Compliance"
}
else {
    $displayname = "Require Device Compliance"
}
$json = @"
    {
        "displayName":  "$displayname",
        "state@odata.type":  "#microsoft.graph.conditionalAccessPolicyState",
        "state":  "disabled",
        "sessionControls":  null,
        "conditions":  {
                           "@odata.type":  "#microsoft.graph.conditionalAccessConditionSet",
                           "userRiskLevels@odata.type":  "#Collection(microsoft.graph.riskLevel)",
                           "userRiskLevels":  [
    
                                              ],
                           "signInRiskLevels@odata.type":  "#Collection(microsoft.graph.riskLevel)",
                           "signInRiskLevels":  [
    
                                                ],
                           "clientAppTypes@odata.type":  "#Collection(microsoft.graph.conditionalAccessClientApp)",
                           "clientAppTypes":  [
                                                  "all"
                                              ],
                           "platforms":  null,
                           "locations":  null,
                           "times":  null,
                           "deviceStates":  null,
                           "clientApplications":  null,
                           "applications":  {
                                                "@odata.type":  "#microsoft.graph.conditionalAccessApplications",
                                                "includeApplications@odata.type":  "#Collection(String)",
                                                "includeApplications":  [
                                                                            "All"
                                                                        ],
                                                "excludeApplications@odata.type":  "#Collection(String)",
                                                "excludeApplications":  [
    
                                                                        ],
                                                "includeUserActions@odata.type":  "#Collection(String)",
                                                "includeUserActions":  [
    
                                                                       ],
                                                "includeAuthenticationContextClassReferences@odata.type":  "#Collection(String)",
                                                "includeAuthenticationContextClassReferences":  [
    
                                                                                                ],
                                                "applicationFilter":  null
                                            },
                           "users":  {
                                         "@odata.type":  "#microsoft.graph.conditionalAccessUsers",
                                         "includeUsers@odata.type":  "#Collection(String)",
                                         "includeUsers":  [
                                                              "All"
                                                          ],
                                         "excludeUsers@odata.type":  "#Collection(String)",
                                         "excludeUsers":  [
                                                              "$breakglassid"
                                                          ],
                                         "includeGroups@odata.type":  "#Collection(String)",
                                         "includeGroups":  [
    
                                                           ],
                                         "excludeGroups@odata.type":  "#Collection(String)",
                                         "excludeGroups":  [
    
                                                           ],
                                         "includeRoles@odata.type":  "#Collection(String)",
                                         "includeRoles":  [
    
                                                          ],
                                         "excludeRoles@odata.type":  "#Collection(String)",
                                         "excludeRoles":  [
    
                                                          ],
                                         "includeGuestsOrExternalUsers":  null,
                                         "excludeGuestsOrExternalUsers":  null
                                     },
                           "devices":  {
                                           "@odata.type":  "#microsoft.graph.conditionalAccessDevices",
                                           "includeDeviceStates@odata.type":  "#Collection(String)",
                                           "includeDeviceStates":  [
    
                                                                   ],
                                           "excludeDeviceStates@odata.type":  "#Collection(String)",
                                           "excludeDeviceStates":  [
    
                                                                   ],
                                           "includeDevices@odata.type":  "#Collection(String)",
                                           "includeDevices":  [
    
                                                              ],
                                           "excludeDevices@odata.type":  "#Collection(String)",
                                           "excludeDevices":  [
    
                                                              ],
                                           "deviceFilter":  {
                                                                "@odata.type":  "#microsoft.graph.conditionalAccessFilter",
                                                                "mode@odata.type":  "#microsoft.graph.filterMode",
                                                                "mode":  "include",
                                                                "rule":  "device.deviceOwnership -eq \"Company\""
                                                            }
                                       }
                       },
        "grantControls":  {
                              "@odata.type":  "#microsoft.graph.conditionalAccessGrantControls",
                              "operator":  "OR",
                              "builtInControls@odata.type":  "#Collection(microsoft.graph.conditionalAccessGrantControl)",
                              "builtInControls":  [
                                                      "compliantDevice",
                                                      "domainJoinedDevice"
                                                  ],
                              "customAuthenticationFactors@odata.type":  "#Collection(String)",
                              "customAuthenticationFactors":  [
    
                                                              ],
                              "termsOfUse@odata.type":  "#Collection(String)",
                              "termsOfUse":  [
    
                                             ],
                              "authenticationStrength":  null
                          }
    }
    
"@

Invoke-MgGraphRequest -Method POST -Uri $url -Body $json -ContentType "application/json" -OutputType PSObject

write-output "Created Conditional Access Policy to require device compliance"

#######################################################################


write-output "Creating Conditional Access Policy - Require MFA for guests"
$url = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"
if ($whitelabel) {
    $displayname = $whitelabel + "Require MFA for Guests"
}
else {
    $displayname = "Require MFA for Guests"
}
$json = @"
{
    "displayName":  "$displayname",
    "state@odata.type":  "#microsoft.graph.conditionalAccessPolicyState",
    "state":  "disabled",
    "sessionControls":  null,
    "conditions":  {
                       "@odata.type":  "#microsoft.graph.conditionalAccessConditionSet",
                       "userRiskLevels@odata.type":  "#Collection(microsoft.graph.riskLevel)",
                       "userRiskLevels":  [

                                          ],
                       "signInRiskLevels@odata.type":  "#Collection(microsoft.graph.riskLevel)",
                       "signInRiskLevels":  [

                                            ],
                       "clientAppTypes@odata.type":  "#Collection(microsoft.graph.conditionalAccessClientApp)",
                       "clientAppTypes":  [
                                              "all"
                                          ],
                       "platforms":  null,
                       "locations":  null,
                       "times":  null,
                       "deviceStates":  null,
                       "devices":  null,
                       "clientApplications":  null,
                       "applications":  {
                                            "@odata.type":  "#microsoft.graph.conditionalAccessApplications",
                                            "includeApplications@odata.type":  "#Collection(String)",
                                            "includeApplications":  [
                                                                        "All"
                                                                    ],
                                            "excludeApplications@odata.type":  "#Collection(String)",
                                            "excludeApplications":  [

                                                                    ],
                                            "includeUserActions@odata.type":  "#Collection(String)",
                                            "includeUserActions":  [

                                                                   ],
                                            "includeAuthenticationContextClassReferences@odata.type":  "#Collection(String)",
                                            "includeAuthenticationContextClassReferences":  [

                                                                                            ],
                                            "applicationFilter":  null
                                        },
                       "users":  {
                                     "@odata.type":  "#microsoft.graph.conditionalAccessUsers",
                                     "includeUsers@odata.type":  "#Collection(String)",
                                     "includeUsers":  [

                                                      ],
                                     "excludeUsers@odata.type":  "#Collection(String)",
                                     "excludeUsers":  [
                                                          "$breakglassid"
                                                      ],
                                     "includeGroups@odata.type":  "#Collection(String)",
                                     "includeGroups":  [

                                                       ],
                                     "excludeGroups@odata.type":  "#Collection(String)",
                                     "excludeGroups":  [

                                                       ],
                                     "includeRoles@odata.type":  "#Collection(String)",
                                     "includeRoles":  [

                                                      ],
                                     "excludeRoles@odata.type":  "#Collection(String)",
                                     "excludeRoles":  [

                                                      ],
                                     "excludeGuestsOrExternalUsers":  null,
                                     "includeGuestsOrExternalUsers":  {
                                                                          "@odata.type":  "#microsoft.graph.conditionalAccessGuestsOrExternalUsers",
                                                                          "guestOrExternalUserTypes@odata.type":  "#microsoft.graph.conditionalAccessGuestOrExternalUserTypes",
                                                                          "guestOrExternalUserTypes":  "internalGuest,b2bCollaborationGuest,b2bCollaborationMember,b2bDirectConnectUser,otherExternalUser,serviceProvider",
                                                                          "externalTenants":  {
                                                                                                  "@odata.type":  "#microsoft.graph.conditionalAccessAllExternalTenants",
                                                                                                  "membershipKind@odata.type":  "#microsoft.graph.conditionalAccessExternalTenantsMembershipKind",
                                                                                                  "membershipKind":  "all"
                                                                                              }
                                                                      }
                                 }
                   },
    "grantControls":  {
                          "@odata.type":  "#microsoft.graph.conditionalAccessGrantControls",
                          "operator":  "OR",
                          "builtInControls@odata.type":  "#Collection(microsoft.graph.conditionalAccessGrantControl)",
                          "builtInControls":  [
                                                  "mfa"
                                              ],
                          "customAuthenticationFactors@odata.type":  "#Collection(String)",
                          "customAuthenticationFactors":  [

                                                          ],
                          "termsOfUse@odata.type":  "#Collection(String)",
                          "termsOfUse":  [

                                         ],
                          "authenticationStrength":  null
                      }
}

"@

Invoke-MgGraphRequest -Method POST -Uri $url -Body $json -ContentType "application/json" -OutputType PSObject

write-output "Created Conditional Access Policy to require MFA for guests"

#######################################################################

write-output "Creating Conditional Access Policy - Require MFA for admins"
$url = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"
if ($whitelabel) {
    $displayname = $whitelabel + "Require multifactor authentication for admins"
}
else {
    $displayname = "Require multifactor authentication for admins"
}
$json = @"
{
    "displayName":  "$displayname",
    "state@odata.type":  "#microsoft.graph.conditionalAccessPolicyState",
    "state":  "disabled",
    "sessionControls":  null,
    "conditions":  {
                       "@odata.type":  "#microsoft.graph.conditionalAccessConditionSet",
                       "userRiskLevels@odata.type":  "#Collection(microsoft.graph.riskLevel)",
                       "userRiskLevels":  [

                                          ],
                       "signInRiskLevels@odata.type":  "#Collection(microsoft.graph.riskLevel)",
                       "signInRiskLevels":  [

                                            ],
                       "clientAppTypes@odata.type":  "#Collection(microsoft.graph.conditionalAccessClientApp)",
                       "clientAppTypes":  [
                                              "all"
                                          ],
                       "platforms":  null,
                       "locations":  null,
                       "times":  null,
                       "deviceStates":  null,
                       "devices":  null,
                       "clientApplications":  null,
                       "applications":  {
                                            "@odata.type":  "#microsoft.graph.conditionalAccessApplications",
                                            "includeApplications@odata.type":  "#Collection(String)",
                                            "includeApplications":  [
                                                                        "All"
                                                                    ],
                                            "excludeApplications@odata.type":  "#Collection(String)",
                                            "excludeApplications":  [

                                                                    ],
                                            "includeUserActions@odata.type":  "#Collection(String)",
                                            "includeUserActions":  [

                                                                   ],
                                            "includeAuthenticationContextClassReferences@odata.type":  "#Collection(String)",
                                            "includeAuthenticationContextClassReferences":  [

                                                                                            ],
                                            "applicationFilter":  null
                                        },
                       "users":  {
                                     "@odata.type":  "#microsoft.graph.conditionalAccessUsers",
                                     "includeUsers@odata.type":  "#Collection(String)",
                                     "includeUsers":  [

                                                      ],
                                     "excludeUsers@odata.type":  "#Collection(String)",
                                     "excludeUsers":  [
                                                          "$breakglassid"
                                                      ],
                                     "includeGroups@odata.type":  "#Collection(String)",
                                     "includeGroups":  [

                                                       ],
                                     "excludeGroups@odata.type":  "#Collection(String)",
                                     "excludeGroups":  [

                                                       ],
                                     "includeRoles@odata.type":  "#Collection(String)",
                                     "includeRoles":  [
                                                          "62e90394-69f5-4237-9190-012177145e10",
                                                          "194ae4cb-b126-40b2-bd5b-6091b380977d",
                                                          "f28a1f50-f6e7-4571-818b-6a12f2af6b6c",
                                                          "29232cdf-9323-42fd-ade2-1d097af3e4de",
                                                          "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9",
                                                          "729827e3-9c14-49f7-bb1b-9608f156bbb8",
                                                          "b0f54661-2d74-4c50-afa3-1ec803f12efe",
                                                          "fe930be7-5e62-47db-91af-98c3a49a38b1",
                                                          "c4e39bd9-1100-46d3-8c65-fb160da0071f",
                                                          "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3",
                                                          "158c047a-c907-4556-b7ef-446551a6b5f7",
                                                          "966707d0-3269-4727-9be2-8c3a10f19b9d",
                                                          "7be44c8a-adaf-4e2a-84d6-ab2649e08a13",
                                                          "e8611ab8-c189-46e8-94e1-60213ab1f814"
                                                      ],
                                     "excludeRoles@odata.type":  "#Collection(String)",
                                     "excludeRoles":  [

                                                      ],
                                     "includeGuestsOrExternalUsers":  null,
                                     "excludeGuestsOrExternalUsers":  null
                                 }
                   },
    "grantControls":  {
                          "@odata.type":  "#microsoft.graph.conditionalAccessGrantControls",
                          "operator":  "OR",
                          "builtInControls@odata.type":  "#Collection(microsoft.graph.conditionalAccessGrantControl)",
                          "builtInControls":  [
                                                  "mfa"
                                              ],
                          "customAuthenticationFactors@odata.type":  "#Collection(String)",
                          "customAuthenticationFactors":  [

                                                          ],
                          "termsOfUse@odata.type":  "#Collection(String)",
                          "termsOfUse":  [

                                         ],
                          "authenticationStrength":  null
                      }
}
"@

Invoke-MgGraphRequest -Method POST -Uri $url -Body $json -ContentType "application/json" -OutputType PSObject

write-output "Created Conditional Access Policy to require MFA for admins"

#######################################################################

write-output "Creating Conditional Access Policy - Require MFA for everyone"
$url = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"
if ($whitelabel) {
    $displayname = $whitelabel + "Require multifactor authentication for all users"
}
else {
    $displayname = "Require multifactor authentication for all users"
}
$json = @"
{
    "displayName":  "$displayname",
    "state@odata.type":  "#microsoft.graph.conditionalAccessPolicyState",
    "state":  "disabled",
    "sessionControls":  null,
    "conditions":  {
                       "@odata.type":  "#microsoft.graph.conditionalAccessConditionSet",
                       "userRiskLevels@odata.type":  "#Collection(microsoft.graph.riskLevel)",
                       "userRiskLevels":  [

                                          ],
                       "signInRiskLevels@odata.type":  "#Collection(microsoft.graph.riskLevel)",
                       "signInRiskLevels":  [

                                            ],
                       "clientAppTypes@odata.type":  "#Collection(microsoft.graph.conditionalAccessClientApp)",
                       "clientAppTypes":  [
                                              "all"
                                          ],
                       "platforms":  null,
                       "locations":  null,
                       "times":  null,
                       "deviceStates":  null,
                       "devices":  null,
                       "clientApplications":  null,
                       "applications":  {
                                            "@odata.type":  "#microsoft.graph.conditionalAccessApplications",
                                            "includeApplications@odata.type":  "#Collection(String)",
                                            "includeApplications":  [
                                                                        "All"
                                                                    ],
                                            "excludeApplications@odata.type":  "#Collection(String)",
                                            "excludeApplications":  [

                                                                    ],
                                            "includeUserActions@odata.type":  "#Collection(String)",
                                            "includeUserActions":  [

                                                                   ],
                                            "includeAuthenticationContextClassReferences@odata.type":  "#Collection(String)",
                                            "includeAuthenticationContextClassReferences":  [

                                                                                            ],
                                            "applicationFilter":  null
                                        },
                       "users":  {
                                     "@odata.type":  "#microsoft.graph.conditionalAccessUsers",
                                     "includeUsers@odata.type":  "#Collection(String)",
                                     "includeUsers":  [
                                                          "All"
                                                      ],
                                     "excludeUsers@odata.type":  "#Collection(String)",
                                     "excludeUsers":  [
                                                          "$breakglassid"
                                                      ],
                                     "includeGroups@odata.type":  "#Collection(String)",
                                     "includeGroups":  [

                                                       ],
                                     "excludeGroups@odata.type":  "#Collection(String)",
                                     "excludeGroups":  [

                                                       ],
                                     "includeRoles@odata.type":  "#Collection(String)",
                                     "includeRoles":  [

                                                      ],
                                     "excludeRoles@odata.type":  "#Collection(String)",
                                     "excludeRoles":  [

                                                      ],
                                     "includeGuestsOrExternalUsers":  null,
                                     "excludeGuestsOrExternalUsers":  null
                                 }
                   },
    "grantControls":  {
                          "@odata.type":  "#microsoft.graph.conditionalAccessGrantControls",
                          "operator":  "OR",
                          "builtInControls@odata.type":  "#Collection(microsoft.graph.conditionalAccessGrantControl)",
                          "builtInControls":  [
                                                  "mfa"
                                              ],
                          "customAuthenticationFactors@odata.type":  "#Collection(String)",
                          "customAuthenticationFactors":  [

                                                          ],
                          "termsOfUse@odata.type":  "#Collection(String)",
                          "termsOfUse":  [

                                         ],
                          "authenticationStrength":  null
                      }
}

"@

Invoke-MgGraphRequest -Method POST -Uri $url -Body $json -ContentType "application/json" -OutputType PSObject

write-output "Created Conditional Access Policy to require MFA for everyone"

#######################################################################


write-output "Creating Conditional Access Policy - Require Windows MAM"
$url = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"
if ($whitelabel) {
    $displayname = $whitelabel + "Require Windows MAM"
}
else {
    $displayname = "Require Windows MAM"
}
$json = @"
{
    "conditions": {
      "applications": {
        "includeApplications": ["All"],
        "excludeApplications": [],
        "includeUserActions": [],
        "includeAuthenticationContextClassReferences": [],
        "globalSecureAccess": null
      },
      "clients": null,
      "users": {
        "includeUsers": ["All"],
        "excludeUsers": ["$breakglassid"],
        "includeGroups": [],
        "excludeGroups": [],
        "includeRoles": [],
        "excludeRoles": [],
        "includeGuestsOrExternalUsers": null,
        "excludeGuestsOrExternalUsers": null
      },
      "clientApplications": null,
      "platforms": { "includePlatforms": ["windows"], "excludePlatforms": [] },
      "locations": null,
      "userRiskLevels": [],
      "signInRiskLevels": [],
      "signInRiskDetections": null,
      "clientAppTypes": ["browser"],
      "times": null,
      "devices": null,
      "servicePrincipalRiskLevels": [],
      "authenticationFlows": null
    },
    "displayName": "$displayname",
    "grantControls": {
      "operator": "OR",
      "builtInControls": ["compliantDevice", "compliantApplication"],
      "customAuthenticationFactors": [],
      "termsOfUse": [],
      "authenticationStrength": null
    },
    "sessionControls": null,
    "state": "disabled"
  }
"@

Invoke-MgGraphRequest -Method POST -Uri $url -Body $json -ContentType "application/json" -OutputType PSObject

write-output "Created Conditional Access Policy to require Windows MAM"

#######################################################################


    ####################################################################### END CREATE POLICIES ###############################################################################################


    write-output "Conditional Access Policy Created, moving on to Intune Build"


}








###############################################################################################################
######                                          Script Content                                           ######
###############################################################################################################


###############################################################################################################
######                                          Download JSON                                            ######
###############################################################################################################

$policiesuri = "https://deploy.euctoolbox.com/json/prefix-livepolicies.json"

$policytemp = Invoke-RestMethod -Uri $policiesuri

    $profilelist2 = $policytemp

###############################################################################################################
######                                         Restore Policies                                            ######
###############################################################################################################

$oneormore = $profilelist2.SyncRoot
if ($null -ne $oneormore) {
    $fullist = $profilelist2.SyncRoot
    $profilelist3 = $profilelist2.SyncRoot | select-object Value
    $looplist = $profilelist3
    $profilelist = @()
    foreach ($profiletemp in $fullist) {
        $value1 = ($profiletemp.value)[2]
        $profilelist += $value1
    }
}
else {
    $fulllist = $profilelist2.value
    $profilelist3 = $fulllist
    $looplist = $profilelist3 | Select-Object -First 1
    $profilelist = @()
    $value1 = ($profilelist3)[2]
    $profilelist += $value1
}
$temp = $profilelist
##Loop through array and create Profiles
foreach ($toupload in $looplist) {
    ##Count items in new array
    $tocheck = $toupload.value
    ##Multi Item
    if ($null -ne $tocheck) {
        $profilevalue = $toupload.value
    }
    else {
        #Single Item, just grab the whole thing
        $profilevalue = $profilelist3
    }

    foreach ($tname in $temp) {
        if ($tname -eq $profilevalue[2]) {
            $policyuri = $profilevalue[1]
            $policyjson = $profilevalue[0]
            $id = $profilevalue[3]
            write-host $profilevalue[1]
            $policy = $policyjson
            ##If policy is conditional access, we need special config
            if ($policyuri -eq "conditionalaccess") {
                write-host "Creating Conditional Access Policy"
                $uri = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"
                $oldname = $Policy.DisplayName
                $restoredate = get-date -format dd-MM-yyyy-HH-mm-ss
                $NewDisplayName = $oldname + "-restore-" + $restoredate        
                $Parameters = @{
                    displayName     = $NewDisplayName
                    state           = $policy.State
                    conditions      = $policy.Conditions
                    grantControls   = $policy.GrantControls
                    sessionControls = $policy.SessionControls
                }
                $body = $Parameters | ConvertTo-Json -depth 50
                $null = Invoke-MgGraphRequest -Method POST -uri $uri -Body $body -ContentType "application/json"
            }
            else {

                # Add the policy
                $body = ([System.Text.Encoding]::UTF8.GetBytes($policyjson.tostring()))
                try {
                    $copypolicy = Invoke-MgGraphRequest -Uri $policyuri -Method Post -Body $body  -ContentType "application/json; charset=utf-8"
                }
                catch {

                }



                ##If policy is an admin template, we need to loop through and add the settings
                if ($policyuri -eq "https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations") {
                    ##Now grab the JSON
                    $GroupPolicyConfigurationsDefinitionValues = Get-GroupPolicyConfigurationsDefinitionValues -GroupPolicyConfigurationID $id
                    $OutDefjson = @()
                    foreach ($GroupPolicyConfigurationsDefinitionValue in $GroupPolicyConfigurationsDefinitionValues) {
                        $GroupPolicyConfigurationsDefinitionValue
                        $DefinitionValuedefinition = Get-GroupPolicyConfigurationsDefinitionValuesdefinition -GroupPolicyConfigurationID $id -GroupPolicyConfigurationsDefinitionValueID $GroupPolicyConfigurationsDefinitionValue.id
                        $DefinitionValuedefinitionID = $DefinitionValuedefinition.id
                        $DefinitionValuedefinitionDisplayName = $DefinitionValuedefinition.displayName
                        $DefinitionValuedefinitionDisplayName = $DefinitionValuedefinitionDisplayName
                        $GroupPolicyDefinitionsPresentations = Get-GroupPolicyDefinitionsPresentations -groupPolicyDefinitionsID $id -GroupPolicyConfigurationsDefinitionValueID $GroupPolicyConfigurationsDefinitionValue.id
                        $DefinitionValuePresentationValues = Get-GroupPolicyConfigurationsDefinitionValuesPresentationValues -GroupPolicyConfigurationID $id -GroupPolicyConfigurationsDefinitionValueID $GroupPolicyConfigurationsDefinitionValue.id
                        $OutDef = New-Object -TypeName PSCustomObject
                        $OutDef | Add-Member -MemberType NoteProperty -Name "definition@odata.bind" -Value "https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions('$definitionValuedefinitionID')"
                        $OutDef | Add-Member -MemberType NoteProperty -Name "enabled" -value $($GroupPolicyConfigurationsDefinitionValue.enabled.tostring().tolower())
                        if ($DefinitionValuePresentationValues) {
                            $i = 0
                            $PresValues = @()
                            foreach ($Pres in $DefinitionValuePresentationValues) {
                                $P = $pres | Select-Object -Property * -ExcludeProperty id, createdDateTime, lastModifiedDateTime, version
                                $GPDPID = $groupPolicyDefinitionsPresentations[$i].id
                                $P | Add-Member -MemberType NoteProperty -Name "presentation@odata.bind" -Value "https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions('$definitionValuedefinitionID')/presentations('$GPDPID')"
                                $PresValues += $P
                                $i++
                            }
                            $OutDef | Add-Member -MemberType NoteProperty -Name "presentationValues" -Value $PresValues
                        }
                        $OutDefjson += ($OutDef | ConvertTo-Json -Depth 10).replace("\u0027", "'")
                        foreach ($json in $OutDefjson) {
                            $graphApiVersion = "beta"
                            $policyid = $copypolicy.id
                            $DCP_resource = "deviceManagement/groupPolicyConfigurations/$($policyid)/definitionValues"
                            $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)"
                            #Invoke-RestMethod -ErrorAction SilentlyContinue -Uri $uri -Headers $authToken -Method Post -Body $json -ContentType "application/json"
                            try {
                                Invoke-MgGraphRequest -Uri $uri -Method Post -Body $json -ContentType "application/json"
                            }
                            catch {}
                        }
                    }
                }
                if ($policyuri -like "https://graph.microsoft.com/beta/deviceManagement/templates*") {
                    write-host "It's a security intent, add the settings"
                    $policyid = $copypolicy.id
                    $uri = "https://graph.microsoft.com/beta/deviceManagement/intents/$policyid/updateSettings"
                    $values = ($policyjson | convertfrom-json).values[1]
                    $settingjson = @"
                    {
          "settings": [
"@
        $countarray = $values.Count
        $start = 0
        foreach ($value in $values) {
        $settingjson += $value | convertto-json
        $start++
        if ($start -ne $countarray) {
        $settingjson += ","
        }
        }
                    $settingjson += @"
          ]
        }
"@
                    $body = ([System.Text.Encoding]::UTF8.GetBytes($settingjson.tostring()))
        
        Invoke-MgGraphRequest -Uri $uri -Method POST -Body $body -ContentType "application/json; charset=utf-8" 
        
                    }
            }
    
        }


    }
}


write-output "Base Build Complete"

###############################################################################################################
######                                          Create Additional Policies                               ######
###############################################################################################################

##Default Compliance Settings
write-output "Setting Default Compliance Settings"
$uri = "https://graph.microsoft.com/beta/deviceManagement/"
$json = @"
{
    "settings": {
        "@odata.context": "https://graph.microsoft.com/beta/`$metadata#deviceManagement/settings",
        "androidDeviceAdministratorEnrollmentEnabled": false,
        "derivedCredentialProvider": "notConfigured",
        "derivedCredentialUrl": null,
        "deviceComplianceCheckinThresholdDays": 30,
        "deviceInactivityBeforeRetirementInDay": 0,
        "enableAutopilotDiagnostics": true,
        "enableDeviceGroupMembershipReport": false,
        "enableEnhancedTroubleshootingExperience": false,
        "enableLogCollection": true,
        "enhancedJailBreak": false,
        "ignoreDevicesForUnsupportedSettingsEnabled": false,
        "isScheduledActionEnabled": true,
        "secureByDefault": true
    }
}
"@
Invoke-MgGraphRequest -uri $uri -Method PATCH -Body $json -ContentType "application/json"

write-output "Default Compliance Settings Configured"


##Device Cleanup Rules

write-output "Setting device cleanup to 90 days"
$uri = "https://graph.microsoft.com/beta/deviceManagement/managedDeviceCleanupSettings"
$json = @"
{
    "DeviceInactivityBeforeRetirementInDays": "90"
}
"@
Invoke-MgGraphRequest -Uri $uri -Method PATCH -Body $json -ContentType "application/json"

write-output "Device Cleanup configured"

##Windows MAM
##Enable Connector
$byodgroupid = $intunegrp.id
write-output "Enabling Connector"
$url = "https://graph.microsoft.com/beta/deviceManagement/mobileThreatDefenseConnectors"
$threatjson = @"
{
	"allowPartnerToCollectIOSApplicationMetadata": false,
	"allowPartnerToCollectIOSPersonalApplicationMetadata": false,
	"androidDeviceBlockedOnMissingPartnerData": false,
	"androidEnabled": false,
	"androidMobileApplicationManagementEnabled": false,
	"id": "c2b688fe-48c0-464b-a89c-67041aa8fcb2",
	"iosDeviceBlockedOnMissingPartnerData": false,
	"iosEnabled": false,
	"iosMobileApplicationManagementEnabled": false,
	"macDeviceBlockedOnMissingPartnerData": false,
	"macEnabled": false,
	"microsoftDefenderForEndpointAttachEnabled": false,
	"partnerUnresponsivenessThresholdInDays": 7,
	"partnerUnsupportedOsVersionBlocked": false,
	"windowsDeviceBlockedOnMissingPartnerData": false,
	"windowsEnabled": false,
	"windowsMobileApplicationManagementEnabled": true
}
"@
Invoke-MgGraphRequest -Method POST -Uri $url -Body $threatjson -ContentType "application/json" -OutputType PSObject

write-output "Connector Enabled"

##Create MAM policy

write-output "Creating MAM Policy"
$url = "https://graph.microsoft.com/beta/deviceAppManagement/windowsManagedAppProtections"
if ($whitelabel) {
    $displayname = $whitelabel + "Windows MAM Edge Policy"
}
else {
    $displayname = "Windows MAM Edge Policy"
}
$json = @"
{
	"@odata.type": "#microsoft.graph.windowsManagedAppProtection",
	"allowedDataIngestionLocations": [
		"oneDriveForBusiness",
		"sharePoint",
		"camera",
		"photoLibrary"
	],
	"allowedDataStorageLocations": [],
	"allowedInboundDataTransferSources": "none",
	"allowedOutboundClipboardSharingExceptionLength": 0,
	"allowedOutboundClipboardSharingLevel": "none",
	"allowedOutboundDataTransferDestinations": "none",
	"appActionIfAccountIsClockedOut": null,
	"appActionIfDeviceComplianceRequired": "block",
	"appActionIfMaximumPinRetriesExceeded": "block",
	"appActionIfSamsungKnoxAttestationRequired": null,
	"appActionIfUnableToAuthenticateUser": "block",
	"apps": [
		{
			"mobileAppIdentifier": {
				"@odata.type": "#microsoft.graph.windowsAppIdentifier",
				"windowsAppId": "com.microsoft.edge"
			}
		}
	],
	"assignments": [
		{
			"target": {
				"@odata.type": "#microsoft.graph.groupAssignmentTarget",
				"deviceAndAppManagementAssignmentFilterId": null,
				"deviceAndAppManagementAssignmentFilterType": "none",
				"groupId": "$byodgroupid"
			}
		}
	],
	"blockAfterCompanyPortalUpdateDeferralInDays": 0,
	"blockDataIngestionIntoOrganizationDocuments": false,
	"contactSyncBlocked": false,
	"customBrowserDisplayName": "",
	"customBrowserPackageId": "",
	"customBrowserProtocol": "",
	"customDialerAppDisplayName": "",
	"customDialerAppPackageId": "",
	"customDialerAppProtocol": "",
	"dataBackupBlocked": false,
	"description": "",
	"deviceComplianceRequired": false,
	"dialerRestrictionLevel": "allApps",
	"disableAppPinIfDevicePinIsSet": false,
	"displayName": "$displayname",
	"exemptedAppPackages": [],
	"exemptedAppProtocols": [
		{
			"name": "Default",
			"value": "skype;app-settings;calshow;itms;itmss;itms-apps;itms-appss;itms-services;"
		}
	],
	"fingerprintBlocked": false,
	"gracePeriodToBlockAppsDuringOffClockHours": null,
	"managedBrowser": "notConfigured",
	"managedBrowserToOpenLinksRequired": false,
	"maximumAllowedDeviceThreatLevel": "notConfigured",
	"maximumPinRetries": 5,
	"maximumRequiredOsVersion": null,
	"maximumWarningOsVersion": null,
	"maximumWipeOsVersion": null,
	"minimumPinLength": 4,
	"minimumRequiredAppVersion": null,
	"minimumRequiredCompanyPortalVersion": null,
	"minimumRequiredOsVersion": null,
	"minimumRequiredSdkVersion": null,
	"minimumWarningAppVersion": null,
	"minimumWarningCompanyPortalVersion": null,
	"minimumWarningOsVersion": null,
	"minimumWipeAppVersion": null,
	"minimumWipeCompanyPortalVersion": null,
	"minimumWipeOsVersion": null,
	"minimumWipeSdkVersion": null,
	"mobileThreatDefensePartnerPriority": null,
	"mobileThreatDefenseRemediationAction": "block",
	"notificationRestriction": "allow",
	"organizationalCredentialsRequired": false,
	"periodBeforePinReset": "P0D",
	"periodBeforePinResetRequired": false,
	"periodOfflineBeforeAccessCheck": "PT720M",
	"periodOfflineBeforeWipeIsEnforced": "P90D",
	"periodOnlineBeforeAccessCheck": "PT30M",
	"pinCharacterSet": "numeric",
	"pinRequired": true,
	"pinRequiredInsteadOfBiometric": true,
	"pinRequiredInsteadOfBiometricTimeout": "PT30M",
	"previousPinBlockCount": 0,
	"printBlocked": true,
	"roleScopeTagIds": [
		"0"
	],
	"saveAsBlocked": false,
	"shareWithBrowserVirtualSetting": "anyApp",
	"simplePinBlocked": false,
	"targetedAppManagementLevels": "unspecified",
	"warnAfterCompanyPortalUpdateDeferralInDays": 0,
	"wipeAfterCompanyPortalUpdateDeferralInDays": 0
}
"@

Invoke-MgGraphRequest -Method POST -Uri $url -Body $json -ContentType "application/json" -OutputType PSObject


##LAPS
$lapspassword = GenerateRandomPassword -length 20
write-output "Configuring LAPS"
##Create Custom Policy for lapsadmin user
$customurl = "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations"
if ($whitelabel) {
    $displayname = $whitelabel + "Windows-LAPS-User"
}
else {
    $displayname = "Windows-LAPS-User"
}
$customjson = @"
{
	"@odata.type": "#microsoft.graph.windows10CustomConfiguration",
	"description": "Creates a new user to be used with LAPS",
	"displayName": "$displayname",
	"id": "00000000-0000-0000-0000-000000000000",
	"omaSettings": [
		{
			"@odata.type": "#microsoft.graph.omaSettingString",
			"description": "Create lapsadmin and set password",
			"displayName": "Create-User",
			"omaUri": "./Device/Vendor/MSFT/Accounts/Users/lapsadmin/Password",
			"value": "$lapspassword"
		},
		{
			"@odata.type": "#microsoft.graph.omaSettingInteger",
			"description": "Add to admins",
			"displayName": "Add-to-group",
			"omaUri": "./Device/Vendor/MSFT/Accounts/Users/lapsadmin/LocalUserGroup",
			"value": 2
		}
	],
	"roleScopeTagIds": [
		"0"
	]
}
"@

$policy = Invoke-MgGraphRequest -Method POST -Uri $customurl -Body $customjson -OutputType PSObject -ContentType "application/json"
write-output "LAPS policy created"
write-output "Assigning policy to all devices"

$policyid = $policy.id

$assignurl = "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations/$policyid/assign"

$assignjson = @"
{
	"assignments": [
		{
			"target": {
				"@odata.type": "#microsoft.graph.allDevicesAssignmentTarget"
			}
		}
	]
}
"@

Invoke-MgGraphRequest -Method POST -Uri $assignurl -Body $assignjson -ContentType "application/json" -OutputType PSObject

write-output "Policy created and assigned to all devices"


##Create LAPS policy to use new user account
write-output "Creating LAPS policy with new user account lapsadmin"
$lapsurl = "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies"
if ($whitelabel) {
    $displayname = $whitelabel + "LAPS Config"
}
else {
    $displayname = "LAPS Config"
}
$lapsjson = @"
{
	"description": "Uses lapsadmin created via custom OMA-URI policy",
	"name": "$displayname",
	"platforms": "windows10",
	"roleScopeTagIds": [
		"0"
	],
	"settings": [
		{
			"@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
			"settingInstance": {
				"@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
				"choiceSettingValue": {
					"@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
					"children": [
						{
							"@odata.type": "#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance",
							"settingDefinitionId": "device_vendor_msft_laps_policies_passwordagedays_aad",
							"simpleSettingValue": {
								"@odata.type": "#microsoft.graph.deviceManagementConfigurationIntegerSettingValue",
								"value": 30
							}
						}
					],
					"settingValueTemplateReference": {
						"settingValueTemplateId": "4d90f03d-e14c-43c4-86da-681da96a2f92"
					},
					"value": "device_vendor_msft_laps_policies_backupdirectory_1"
				},
				"settingDefinitionId": "device_vendor_msft_laps_policies_backupdirectory",
				"settingInstanceTemplateReference": {
					"settingInstanceTemplateId": "a3270f64-e493-499d-8900-90290f61ed8a"
				}
			}
		},
		{
			"@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
			"settingInstance": {
				"@odata.type": "#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance",
				"settingDefinitionId": "device_vendor_msft_laps_policies_administratoraccountname",
				"settingInstanceTemplateReference": {
					"settingInstanceTemplateId": "d3d7d492-0019-4f56-96f8-1967f7deabeb"
				},
				"simpleSettingValue": {
					"@odata.type": "#microsoft.graph.deviceManagementConfigurationStringSettingValue",
					"settingValueTemplateReference": {
						"settingValueTemplateId": "992c7fce-f9e4-46ab-ac11-e167398859ea"
					},
					"value": "lapsadmin"
				}
			}
		},
		{
			"@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
			"settingInstance": {
				"@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
				"choiceSettingValue": {
					"@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
					"children": [],
					"settingValueTemplateReference": {
						"settingValueTemplateId": "aa883ab5-625e-4e3b-b830-a37a4bb8ce01"
					},
					"value": "device_vendor_msft_laps_policies_passwordcomplexity_4"
				},
				"settingDefinitionId": "device_vendor_msft_laps_policies_passwordcomplexity",
				"settingInstanceTemplateReference": {
					"settingInstanceTemplateId": "8a7459e8-1d1c-458a-8906-7b27d216de52"
				}
			}
		},
		{
			"@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
			"settingInstance": {
				"@odata.type": "#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance",
				"settingDefinitionId": "device_vendor_msft_laps_policies_passwordlength",
				"settingInstanceTemplateReference": {
					"settingInstanceTemplateId": "da7a1dbd-caf7-4341-ab63-ece6f994ff02"
				},
				"simpleSettingValue": {
					"@odata.type": "#microsoft.graph.deviceManagementConfigurationIntegerSettingValue",
					"settingValueTemplateReference": {
						"settingValueTemplateId": "d08f1266-5345-4f53-8ae1-4c20e6cb5ec9"
					},
					"value": 20
				}
			}
		},
		{
			"@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
			"settingInstance": {
				"@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
				"choiceSettingValue": {
					"@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
					"children": [],
					"settingValueTemplateReference": {
						"settingValueTemplateId": "68ff4f78-baa8-4b32-bf3d-5ad5566d8142"
					},
					"value": "device_vendor_msft_laps_policies_postauthenticationactions_1"
				},
				"settingDefinitionId": "device_vendor_msft_laps_policies_postauthenticationactions",
				"settingInstanceTemplateReference": {
					"settingInstanceTemplateId": "d9282eb1-d187-42ae-b366-7081f32dcfff"
				}
			}
		}
	],
	"technologies": "mdm",
	"templateReference": {
		"templateId": "adc46e5a-f4aa-4ff6-aeff-4f27bc525796_1"
	}
}
"@

$lapspolicy = Invoke-MgGraphRequest -Method POST -Uri $lapsurl -Body $lapsjson -ContentType "application/json" -OutputType PSObject

write-output "LAPS Policy created, assigning to all devices"

$lapspolicyid = $lapspolicy.id

$lapsassignurl = "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies/$lapspolicyid/assign"

$lapsassignjson = @"
{
	"assignments": [
		{
			"target": {
				"@odata.type": "#microsoft.graph.allDevicesAssignmentTarget"
			}
		}
	]
}
"@

Invoke-MgGraphRequest -Method POST -Uri $lapsassignurl -Body $lapsassignjson -ContentType "application/json"

write-output "LAPS Policy assigned to all devices"


##OneDrive
$tenantid = $tenantdetails.id
##OneDrive Config
write-output "Creating OneDrive Config Policy"
$uri = "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies"
if ($whitelabel) {
    $displayname = $whitelabel + "OneDrive Config"
}
else {
    $displayname = "OneDrive Config"
}
$json = @"
{
    "description": "Enabled KFM, Files on Demand, Silent sign-in and excludes lnk files from synchronising",
    "name": "$displayname",
    "platforms": "windows10",
    "priorityMetaData": null,
    "roleScopeTagIds": [
        "0"
    ],
    "settingCount": 6,
    "technologies": "mdm",
    "templateReference": {
        "templateId": "",
        "templateFamily": "none",
        "templateDisplayName": null,
        "templateDisplayVersion": null
    },
    "settings": [
        {
            "id": "0",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_onedrivengscv4~policy~onedrivengsc_enableodignorelistfromgpo",
                "settingInstanceTemplateReference": null,
                "choiceSettingValue": {
                    "settingValueTemplateReference": null,
                    "value": "device_vendor_msft_policy_config_onedrivengscv4~policy~onedrivengsc_enableodignorelistfromgpo_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSimpleSettingCollectionInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_onedrivengscv4~policy~onedrivengsc_enableodignorelistfromgpo_enableodignorelistfromgpolistbox",
                            "settingInstanceTemplateReference": null,
                            "simpleSettingCollectionValue": [
                                {
                                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationStringSettingValue",
                                    "settingValueTemplateReference": null,
                                    "value": "*.lnk"
                                }
                            ]
                        }
                    ]
                }
            }
        },
        {
            "id": "1",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_onedrivengscv4~policy~onedrivengsc_disablefirstdeletedialog",
                "settingInstanceTemplateReference": null,
                "choiceSettingValue": {
                    "settingValueTemplateReference": null,
                    "value": "device_vendor_msft_policy_config_onedrivengscv4~policy~onedrivengsc_disablefirstdeletedialog_1",
                    "children": []
                }
            }
        },
        {
            "id": "2",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_onedrivengscv2~policy~onedrivengsc_kfmblockoptout",
                "settingInstanceTemplateReference": null,
                "choiceSettingValue": {
                    "settingValueTemplateReference": null,
                    "value": "device_vendor_msft_policy_config_onedrivengscv2~policy~onedrivengsc_kfmblockoptout_1",
                    "children": []
                }
            }
        },
        {
            "id": "3",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_onedrivengscv2~policy~onedrivengsc_kfmoptinnowizard",
                "settingInstanceTemplateReference": null,
                "choiceSettingValue": {
                    "settingValueTemplateReference": null,
                    "value": "device_vendor_msft_policy_config_onedrivengscv2~policy~onedrivengsc_kfmoptinnowizard_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_onedrivengscv2~policy~onedrivengsc_kfmoptinnowizard_kfmoptinnowizard_dropdown",
                            "settingInstanceTemplateReference": null,
                            "choiceSettingValue": {
                                "settingValueTemplateReference": null,
                                "value": "device_vendor_msft_policy_config_onedrivengscv2~policy~onedrivengsc_kfmoptinnowizard_kfmoptinnowizard_dropdown_0",
                                "children": []
                            }
                        },
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_onedrivengscv2~policy~onedrivengsc_kfmoptinnowizard_kfmoptinnowizard_textbox",
                            "settingInstanceTemplateReference": null,
                            "simpleSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationStringSettingValue",
                                "settingValueTemplateReference": null,
                                "value": "$tenantid"
                            }
                        }
                    ]
                }
            }
        },
        {
            "id": "4",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_onedrivengscv2~policy~onedrivengsc_silentaccountconfig",
                "settingInstanceTemplateReference": null,
                "choiceSettingValue": {
                    "settingValueTemplateReference": null,
                    "value": "device_vendor_msft_policy_config_onedrivengscv2~policy~onedrivengsc_silentaccountconfig_1",
                    "children": []
                }
            }
        },
        {
            "id": "5",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_onedrivengscv2~policy~onedrivengsc_filesondemandenabled",
                "settingInstanceTemplateReference": null,
                "choiceSettingValue": {
                    "settingValueTemplateReference": null,
                    "value": "device_vendor_msft_policy_config_onedrivengscv2~policy~onedrivengsc_filesondemandenabled_1",
                    "children": []
                }
            }
        }
    ]
}
"@

Invoke-MgGraphRequest -Method POST -uri $uri -Body $json -ContentType "application/json"
write-output "OneDrive Policy Created"

##Browser Config
write-output "Creating Browser Config Policy"
$uri = "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies"
if ($whitelabel) {
    $displayname = $whitelabel + "Browser Homepage"
}
else {
    $displayname = "Browser Homepage"
}
$json = @"
{
    "description": "Browser settings",
    "name": "$displayname",
    "platforms": "windows10",
    "priorityMetaData": null,
    "roleScopeTagIds": [
        "0"
    ],
    "settingCount": 11,
    "technologies": "mdm",
    "templateReference": {
        "templateId": "",
        "templateFamily": "none",
        "templateDisplayName": null,
        "templateDisplayVersion": null
    },
    "settings": [
        {
            "id": "0",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_browser_configurehomebutton",
                "settingInstanceTemplateReference": null,
                "choiceSettingValue": {
                    "settingValueTemplateReference": null,
                    "value": "device_vendor_msft_policy_config_browser_configurehomebutton_0",
                    "children": []
                }
            }
        },
        {
            "id": "1",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_browser_homepages",
                "settingInstanceTemplateReference": null,
                "simpleSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationStringSettingValue",
                    "settingValueTemplateReference": null,
                    "value": "$importhomepage"
                }
            }
        },
        {
            "id": "2",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_browser_sethomebuttonurl",
                "settingInstanceTemplateReference": null,
                "simpleSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationStringSettingValue",
                    "settingValueTemplateReference": null,
                    "value": "$importhomepage"
                }
            }
        },
        {
            "id": "3",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_browser_setnewtabpageurl",
                "settingInstanceTemplateReference": null,
                "simpleSettingValue": {
                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationStringSettingValue",
                    "settingValueTemplateReference": null,
                    "value": "$importhomepage"
                }
            }
        },
        {
            "id": "4",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_microsoft_edge~policy~microsoft_edge~startup_restoreonstartup",
                "settingInstanceTemplateReference": null,
                "choiceSettingValue": {
                    "settingValueTemplateReference": null,
                    "value": "device_vendor_msft_policy_config_microsoft_edge~policy~microsoft_edge~startup_restoreonstartup_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_microsoft_edge~policy~microsoft_edge~startup_restoreonstartup_restoreonstartup",
                            "settingInstanceTemplateReference": null,
                            "choiceSettingValue": {
                                "settingValueTemplateReference": null,
                                "value": "device_vendor_msft_policy_config_microsoft_edge~policy~microsoft_edge~startup_restoreonstartup_restoreonstartup_5",
                                "children": []
                            }
                        }
                    ]
                }
            }
        },
        {
            "id": "5",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_microsoft_edge~policy~microsoft_edge~startup_homepagelocation",
                "settingInstanceTemplateReference": null,
                "choiceSettingValue": {
                    "settingValueTemplateReference": null,
                    "value": "device_vendor_msft_policy_config_microsoft_edge~policy~microsoft_edge~startup_homepagelocation_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_microsoft_edge~policy~microsoft_edge~startup_homepagelocation_homepagelocation",
                            "settingInstanceTemplateReference": null,
                            "simpleSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationStringSettingValue",
                                "settingValueTemplateReference": null,
                                "value": "$importhomepage"
                            }
                        }
                    ]
                }
            }
        },
        {
            "id": "6",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_microsoft_edgev79diff~policy~microsoft_edge~startup_newtabpagesetfeedtype",
                "settingInstanceTemplateReference": null,
                "choiceSettingValue": {
                    "settingValueTemplateReference": null,
                    "value": "device_vendor_msft_policy_config_microsoft_edgev79diff~policy~microsoft_edge~startup_newtabpagesetfeedtype_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_microsoft_edgev79diff~policy~microsoft_edge~startup_newtabpagesetfeedtype_newtabpagesetfeedtype",
                            "settingInstanceTemplateReference": null,
                            "choiceSettingValue": {
                                "settingValueTemplateReference": null,
                                "value": "device_vendor_msft_policy_config_microsoft_edgev79diff~policy~microsoft_edge~startup_newtabpagesetfeedtype_newtabpagesetfeedtype_0",
                                "children": []
                            }
                        }
                    ]
                }
            }
        },
        {
            "id": "7",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_microsoft_edge~policy~microsoft_edge~startup_newtabpagelocation",
                "settingInstanceTemplateReference": null,
                "choiceSettingValue": {
                    "settingValueTemplateReference": null,
                    "value": "device_vendor_msft_policy_config_microsoft_edge~policy~microsoft_edge~startup_newtabpagelocation_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_microsoft_edge~policy~microsoft_edge~startup_newtabpagelocation_newtabpagelocation",
                            "settingInstanceTemplateReference": null,
                            "simpleSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationStringSettingValue",
                                "settingValueTemplateReference": null,
                                "value": "$importhomepage"
                            }
                        }
                    ]
                }
            }
        },
        {
            "id": "8",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_microsoft_edge~policy~microsoft_edge~startup_homepageisnewtabpage",
                "settingInstanceTemplateReference": null,
                "choiceSettingValue": {
                    "settingValueTemplateReference": null,
                    "value": "device_vendor_msft_policy_config_microsoft_edge~policy~microsoft_edge~startup_homepageisnewtabpage_1",
                    "children": []
                }
            }
        },
        {
            "id": "9",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_microsoft_edge~policy~microsoft_edge~startup_showhomebutton",
                "settingInstanceTemplateReference": null,
                "choiceSettingValue": {
                    "settingValueTemplateReference": null,
                    "value": "device_vendor_msft_policy_config_microsoft_edge~policy~microsoft_edge~startup_showhomebutton_1",
                    "children": []
                }
            }
        },
        {
            "id": "10",
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                "settingDefinitionId": "device_vendor_msft_policy_config_microsoft_edge~policy~microsoft_edge~startup_restoreonstartupurls",
                "settingInstanceTemplateReference": null,
                "choiceSettingValue": {
                    "settingValueTemplateReference": null,
                    "value": "device_vendor_msft_policy_config_microsoft_edge~policy~microsoft_edge~startup_restoreonstartupurls_1",
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSimpleSettingCollectionInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_config_microsoft_edge~policy~microsoft_edge~startup_restoreonstartupurls_restoreonstartupurlsdesc",
                            "settingInstanceTemplateReference": null,
                            "simpleSettingCollectionValue": [
                                {
                                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationStringSettingValue",
                                    "settingValueTemplateReference": null,
                                    "value": "$importhomepage"
                                }
                            ]
                        }
                    ]
                }
            }
        }
    ]
}
"@

Invoke-MgGraphRequest -Method POST -uri $uri -Body $json -ContentType "application/json"
write-output "Browser Policy Created"

if (!$noupload) {
##MDE Enrollment
write-output "Creating MDE Auto Enrollment Policy"
$uri = "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies"
if ($whitelabel) {
    $displayname = $whitelabel + "Defender for Endpoint Onboarding"
}
else {
    $displayname = "Defender for Endpoint Onboarding"
}
$json = @"

{
    "name":"$displayname",
    "description":"Onboards devices via Auto-enrollment into MDE",
    "platforms":"windows10",
    "technologies":"mdm,microsoftSense",
    "roleScopeTagIds":["0"],
    "settings":
    [
        {
        "@odata.type":"#microsoft.graph.deviceManagementConfigurationSetting",
        "settingInstance":{
            "@odata.type":"#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
            "settingDefinitionId":"device_vendor_msft_windowsadvancedthreatprotection_configurationtype",
            "choiceSettingValue":{
                "@odata.type":"#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                "value":"device_vendor_msft_windowsadvancedthreatprotection_configurationtype_autofromconnector",
                "children":[{
                    "@odata.type":"#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance",
                    "settingDefinitionId":"device_vendor_msft_windowsadvancedthreatprotection_onboarding_fromconnector",
                    "simpleSettingValue":{
                        "@odata.type":"#microsoft.graph.deviceManagementConfigurationSecretSettingValue",
                        "value":"Microsoft ATP connector enabled","valueState":"NotEncrypted"
                    }
                }
                ],
                "settingValueTemplateReference":{
                    "settingValueTemplateId":"e5c7c98c-c854-4140-836e-bd22db59d651"
                }
            },
            "settingInstanceTemplateReference":{
                "settingInstanceTemplateId":"23ab0ea3-1b12-429a-8ed0-7390cf699160"
            }
        }
    },
    {
        "@odata.type":"#microsoft.graph.deviceManagementConfigurationSetting",
        "settingInstance":{
            "@odata.type":"#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
            "settingDefinitionId":"device_vendor_msft_windowsadvancedthreatprotection_configuration_samplesharing",
            "choiceSettingValue":{
                "@odata.type":"#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                "value":"device_vendor_msft_windowsadvancedthreatprotection_configuration_samplesharing_1",
                "children":[],"settingValueTemplateReference":{"settingValueTemplateId":"f72c326c-7c5b-4224-b890-0b9b54522bd9"
            }
        },
        "settingInstanceTemplateReference":{
            "settingInstanceTemplateId":"6998c81e-2814-4f5e-b492-a6159128a97b"
        }
    }
},
{
    "@odata.type":"#microsoft.graph.deviceManagementConfigurationSetting",
    "settingInstance":{
        "@odata.type":"#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
        "settingDefinitionId":"device_vendor_msft_windowsadvancedthreatprotection_configuration_telemetryreportingfrequency",
        "choiceSettingValue":{
            "@odata.type":"#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
            "value":"device_vendor_msft_windowsadvancedthreatprotection_configuration_telemetryreportingfrequency_1",
            "children":[],
            "settingValueTemplateReference":{
                "settingValueTemplateId":"350b0bea-b67b-43d4-9a04-c796edb961fd"
            }
        },
        "settingInstanceTemplateReference":{
            "settingInstanceTemplateId":"03de6095-07c4-4f35-be38-c1cd3bae4484"
        }
    }
}
],
"templateReference":{
    "templateId":"0385b795-0f2f-44ac-8602-9f65bf6adede_1"
}
}
"@

Invoke-MgGraphRequest -Method POST -uri $uri -Body $json -ContentType "application/json"
write-output "MDE Auto Enrollment Policy Created"
}

##ESP Config
write-output "Creating ESP Policy"
$uri = "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations"
if ($whitelabel) {
    $displayname = $whitelabel + "Windows-ESP"
}
else {
    $displayname = "Windows-ESP"
}
$json = @"
{
	"@odata.type": "#microsoft.graph.windows10CustomConfiguration",
	"description": "Custom ESP Settings",
	"displayName": "$displayname",
	"id": "00000000-0000-0000-0000-000000000000",
	"omaSettings": [
		{
			"@odata.type": "#microsoft.graph.omaSettingBoolean",
			"displayName": "UserESP",
			"omaUri": "./Device/Vendor/MSFT/DMClient/Provider/MS DM Server/FirstSyncStatus/SkipUserStatusPage",
			"value": "true"
		}
	],
	"roleScopeTagIds": [
		"0"
	]
}
"@
$policyesp = Invoke-MgGraphRequest -Method POST -uri $uri -Body $json -ContentType "application/json"
write-output "ESP Policy Created"

##Assign it
write-output "Assigning ESP Policy"
$policyidesp = $policyesp.id
$uri = "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations/$policyidesp/assign"
$espgroup = $intunegrp.id
$json = @"
{
	"assignments": [
		{
			"target": {
				"@odata.type": "#microsoft.graph.groupAssignmentTarget",
				"groupId": "$espgroup"
			}
		}
	]
}
"@
Invoke-MgGraphRequest -Method POST -uri $uri -Body $json -ContentType "application/json"

##WDAC Config
write-output "Creating WDAC Policy"
$uri = "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations"
if ($whitelabel) {
    $displayname = $whitelabel + "WDAC"
}
else {
    $displayname = "WDAC"
}
$json = @"
{
	"@odata.type": "#microsoft.graph.windows10CustomConfiguration",
	"description": "WDAC Microsoft Rules\nSets PS to restricted mode",
	"displayName": "$displayname",
	"id": "00000000-0000-0000-0000-000000000000",
	"omaSettings": [
		{
			"@odata.type": "#microsoft.graph.omaSettingBase64",
			"displayName": "WDAC",
			"fileName": "{E39A37BC-41DA-4461-8D80-031640DC938F}.bin",
			"omaUri": "./Vendor/MSFT/ApplicationControl/Policies/E39A37BC-41DA-4461-8D80-031640DC938F/Policy",
			"value": "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"
		}
	],
	"roleScopeTagIds": [
		"0"
	]
}
"@
$policywdac = Invoke-MgGraphRequest -Method POST -uri $uri -Body $json -ContentType "application/json"
write-output "WDAC Policy Created"

##Assign it
write-output "Assigning WDAC Policy"
$policyidwdac = $policywdac.id
$uri = "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations/$policyidwdac/assign"
$espgroup = $intunegrp.id
$json = @"
{
	"assignments": [
		{
			"target": {
				"@odata.type": "#microsoft.graph.groupAssignmentTarget",
				"groupId": "$espgroup"
			}
		}
	]
}
"@
#Invoke-MgGraphRequest -Method POST -uri $uri -Body $json -ContentType "application/json"

##Feature Update
write-output "Creating Feature Update Policy"
if ($whitelabel) {
    $displayname = $whitelabel + "FeatureUpdateWin11"
}
else {
    $displayname = "FeatureUpdateWin11"
}
$url = "https://graph.microsoft.com/beta/deviceManagement/windowsFeatureUpdateProfiles"
$json = @"
{
	"description": "",
	"displayName": "$displayname",
	"featureUpdateVersion": "Windows 11, version 23H2",
	"installLatestWindows10OnWindows11IneligibleDevice": true,
	"roleScopeTagIds": [],
	"rolloutSettings": {
		"offerEndDateTimeInUTC": null,
		"offerIntervalInDays": null,
		"offerStartDateTimeInUTC": null
	}
}
"@
$featurepolicy = Invoke-MgGraphRequest -Method POST -uri $url -Body $json -ContentType "application/json"
write-output "Feature Update Policy Created"

##Assign it
write-output "Assigning Feature Update Policy"
$featurepolicyid = $featurepolicy.id
$uri = "https://graph.microsoft.com/beta/deviceManagement/windowsFeatureUpdateProfiles/$featurepolicyid/assign"
$espgroup = $intunegrp.id
$json = @"
{
	"assignments": [
		{
			"target": {
				"@odata.type": "#microsoft.graph.groupAssignmentTarget",
				"groupId": "$espgroup"
			}
		}
	]
}
"@
Invoke-MgGraphRequest -Method POST -uri $uri -Body $json -ContentType "application/json"



###############################################################################################################
######                                          Create PowerShell Scripts                               ######
###############################################################################################################


##Backup Scheduled Task
$backupscriptcode =@'
$DirectoryToCreate = $env:ProgramFiles+"\backup-restore"
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

##Download Backup Script
$backupurl="https://raw.githubusercontent.com/andrew-s-taylor/public/main/Batch%20Scripts/backup.bat"
$backupscript = $DirectoryToCreate+"\backup.bat"
Invoke-WebRequest -Uri $backupurl -OutFile $backupscript -UseBasicParsing

##Download Restore Script
$restoreurl="https://raw.githubusercontent.com/andrew-s-taylor/public/main/Batch%20Scripts/NEWrestore.bat"
$restorescript = $DirectoryToCreate+"\restore.bat"
Invoke-WebRequest -Uri $restoreurl -OutFile $restorescript -UseBasicParsing

##Download Silent Launch Script
$content = @"
Set WshShell = CreateObject("WScript.Shell")
WshShell.RUN "cmd /c c:\PROGRA~1\backup-restore\backup.bat", 0
"@

$launchscript = $DirectoryToCreate+"\run-invisible.vbs"
$content | Out-File $launchscript -UseBasicParsing



##Create scheduled task
# Create a new task action
$taskAction = New-ScheduledTaskAction -Execute 'C:\Program Files\backup-restore\run-invisible.vbs' 

##Create Trigger (login)
$taskTrigger = New-ScheduledTaskTrigger -AtLogOn

# Register the new PowerShell scheduled task

#Name it
$taskName = "UserBackup"

#Describe it
$description = "Backs up User profile to OneDrive"

# Register it
Register-ScheduledTask `
    -TaskName $taskName `
    -Action $taskAction `
    -Trigger $taskTrigger `
    -Description $description
'@

#Device Config

##Check if $noupload is set
if ($noupload) {
    $devicescriptcode = @'
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
    $clientname = "<CLIENTREPLACENAME>"
        
    
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
    $bytes = [System.Convert]::FromBase64String("<BASE64CODEHERE>")
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
    
'@
    
    #Update Client Name
    
    $devicescriptcode = $devicescriptcode -replace '<CLIENTREPLACENAME>', $clientnameout
    
    
    $backgroundurl = $importbackground
    $bgname = $backgroundurl.Substring($backgroundurl.LastIndexOf("/") + 1)
    ##Background Script
    #Update Base64
    $devicescriptcode = $devicescriptcode -replace '<BASE64CODEHERE>', $imgbase64

    
    #User Config
    $userscriptcode = @'
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
'@
    

}
else {
$devicescriptcode = @'
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
$clientname = "<CLIENTREPLACENAME>"

$backgroundname = "<BACKGROUNDFILENAME>"
#Azure Blob SAS for background image
$backgroundpath = "<BACKGROUNDBLOBURL>"



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

#Download the image from Azure to user profile WALLPAPER
########################################################################################
$url = $backgroundpath
$output = $newpath + "\" + $backgroundname
Invoke-WebRequest -uri $url -outfile $output -usebasicparsing

########################################################################################


write-host "Set Lockscreen"

$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization"
$img =  "C:\Windows\Web\Wallpaper\"+$backgroundname
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

'@

#Update Client Name

$devicescriptcode = $devicescriptcode -replace '<CLIENTREPLACENAME>', $clientnameout


$backgroundurl = $importbackground
$bgname = $backgroundurl.Substring($backgroundurl.LastIndexOf("/") + 1)
##Background Script
#Update URL
$devicescriptcode = $devicescriptcode -replace '<BACKGROUNDBLOBURL>', $backgroundurl

#Update Name
$devicescriptcode = $devicescriptcode -replace '<BACKGROUNDFILENAME>', $bgname

#User Config
$userscriptcode = @'
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
################################################## SET THESE FOR EACH CLIENT ###############################################
##Include File Extension:
$backgroundname = "<BACKGROUNDFILENAME>"
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
Set-ItemProperty -path 'HKCU:\Control Panel\Desktop\' -name wallpaper -value "c:\Windows\Web\Wallpaper\$backgroundname"

rundll32.exe user32.dll, UpdatePerUserSystemParameters

#----------------------------------------------------------------------------------------------------------------------------------

Stop-Transcript
'@

#Update Name
$userscriptcode = $userscriptcode -replace '<BACKGROUNDFILENAME>', $bgname

}

##Base64 Encrypt both

$devicescriptencoded = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($devicescriptcode))
$userscriptencoded = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($userscriptcode))
$backupscriptencoded = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($backupscriptcode))


##Create Powershell Scripts in Graph
$psuriUri = "https://graph.microsoft.com/Beta/deviceManagement/deviceManagementScripts"

##Device Script
if ($whitelabel) {
    $displayname = $whitelabel + "Device Configuration Script"
}
else {
    $displayname = "Device Configuration Script"
}
$postBody = [PSCustomObject]@{
    displayName           = "$displayname"
    description           = "Configures Baseline Device Settings"
    enforceSignatureCheck = $false
    fileName              = "device-config.ps1"
    runAs32Bit            = $false
    runAsAccount          = "System"
    scriptContent         = $devicescriptencoded
} | ConvertTo-Json -Depth 10

Invoke-MgGraphRequest -Uri $psuriUri -Method POST -Body $postBody -ContentType "application/json"

##Backup Script
if ($whitelabel) {
    $displayname = $whitelabel + "Backup Script"
}
else {
    $displayname = "Backup Script"
}
$postBody = [PSCustomObject]@{
    displayName           = "$displayname"
    description           = "Configures Backup Script scheduled task"
    enforceSignatureCheck = $false
    fileName              = "userbackup.ps1"
    runAs32Bit            = $false
    runAsAccount          = "System"
    scriptContent         = $backupscriptencoded
} | ConvertTo-Json -Depth 10

Invoke-MgGraphRequest -Uri $psuriUri -Method POST -Body $postBody -ContentType "application/json"

##User Script
if ($whitelabel) {
    $displayname = $whitelabel + "User Configuration Script"
}
else {
    $displayname = "User Configuration Script"
}
$postBody = [PSCustomObject]@{
    displayName           = "$displayname"
    description           = "Configures Baseline User Settings"
    enforceSignatureCheck = $false
    fileName              = "user-config.ps1"
    runAs32Bit            = $false
    runAsAccount          = "User"
    scriptContent         = $userscriptencoded
} | ConvertTo-Json -Depth 10

Invoke-MgGraphRequest -Uri $psuriUri -Method POST -Body $postBody -ContentType "application/json"




if (!$noupload) {

###############################################################################################################
######                                   Background and Lockscreen                                       ######
###############################################################################################################

## This is only supported for Enterprise licensing so we need to check that first
$enterpriselicense = $licensing.ServicePlanId -contains "e7c91390-7625-45be-94e0-e16907e03118" -or $licensing.ServicePlanId -contains "21b439ba-a0ca-424f-a6cc-52f954a5b111"

if ($enterpriselicense -eq $True) {
    ## All good, lets build
    write-host "Windows Enterprise licensing in place, setting background and lockscreen"
    if ($whitelabel) {
        $displayname = $whitelabel + "Background and Lockscreen"
    }
    else {
        $displayname = "Background and Lockscreen"
    }
    $json = @"
{
	"description": "Sets background and lockscreen\nE3 and E5 only",
	"name": "$displayname",
	"platforms": "windows10",
	"roleScopeTagIds": [
		"0"
	],
	"settings": [
		{
			"@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
			"settingInstance": {
				"@odata.type": "#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance",
				"settingDefinitionId": "vendor_msft_personalization_desktopimageurl",
				"simpleSettingValue": {
					"@odata.type": "#microsoft.graph.deviceManagementConfigurationStringSettingValue",
					"value": "$backgroundurl"
				}
			}
		},
		{
			"@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
			"settingInstance": {
				"@odata.type": "#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance",
				"settingDefinitionId": "vendor_msft_personalization_lockscreenimageurl",
				"simpleSettingValue": {
					"@odata.type": "#microsoft.graph.deviceManagementConfigurationStringSettingValue",
					"value": "$backgroundurl"
				}
			}
		}
	],
	"technologies": "mdm"
}
"@

    $uri = "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies"

    Invoke-MgGraphRequest -Method POST -Uri $uri -Body $json -ContentType "application/json"

}
else {
    ## Not E3 or E5, lets skip
    write-host "Not Windows Enterprise licensing in place, skipping background and lockscreen"

}
}
###############################################################################################################
######                                     Windows Hello for Business                                    ######
###############################################################################################################


$minpin = 6
$maxpin = 127
$lower = "allowed"
$upper = "allowed"
$special = "allowed"
$pinexpiry = 0
$pinhistory = 8


$graphApiVersion = "beta"
$uri2 = "https://graph.microsoft.com/beta/devicemanagement/deviceEnrollmentConfigurations?`$filter=deviceEnrollmentConfigurationType eq 'windowsHelloforBusiness'"

$currentidfull = Invoke-MgGraphRequest -Uri $uri2 -Method Get -OutputType PSObject
$currentvalue = $currentidfull.value
$currentid = $currentvalue.id
$json = @"
{
    "@odata.type": "#microsoft.graph.deviceEnrollmentWindowsHelloForBusinessConfiguration",
    "pinMinimumLength": $minpin,
    "pinMaximumLength": $maxpin,
    "pinUppercaseCharactersUsage": "$upper",
    "pinLowercaseCharactersUsage": "$lower",
    "pinSpecialCharactersUsage": "$special",
    "state": "enabled",
    "securityDeviceRequired": true,
    "unlockWithBiometricsEnabled": true,
    "remotePassportEnabled": true,
    "pinPreviousBlockCount": $pinhistory,
    "pinExpirationInDays": $pinexpiry,
    "enhancedBiometricsState": "enabled",
    "securityKeyForSignIn": "notConfigured"
}
"@
$Resource = "deviceManagement/deviceEnrollmentConfigurations/$currentid"
$uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"
   

Write-Verbose "POST $uri`n$json"

try {
    Invoke-MgGraphRequest -Uri $uri -Method PATCH -Body $JSON -ContentType "application/json" -OutputType PSObject
 
}
catch {
    Write-Error $_.Exception 
        
}

write-output "Windows Hello for Business Profile Configured"


###############################################################################################################
######                                          Create Autopilot Profile                                  ######
###############################################################################################################

$graphApiVersion = "beta"
$Resource = "deviceManagement/windowsAutopilotDeploymentProfiles"
$uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"

    if ($whitelabel) {
        ##Remove any special characters from $whitelabel
        $whitelabel2 = $whitelabel -replace '[^a-zA-Z0-9]', ''
        $profilename = $whitelabel2 + "Autopilot Profile"
    }
    else {
        $profilename = "Autopilot Profile"
    }
    $json = @"
    {
        "@odata.type": "#microsoft.graph.azureADWindowsAutopilotDeploymentProfile",
        "displayName": "$profilename",
        "description": "OOBE Autopilot Profile",
        "language": "os-default",
        "extractHardwareHash": true,
        "deviceNameTemplate": "%SERIAL%",
        "deviceType": "windowsPc",
        "enableWhiteGlove": true,
    	"outOfBoxExperienceSettings": {
    		"deviceUsageType": "singleUser",
    		"hideEscapeLink": true,
    		"hideEULA": true,
    		"hidePrivacySettings": true,
    		"skipKeyboardSelectionPage": true,
    		"userType": "standard"
    	}
    }
"@
    

Write-Verbose "POST $uri`n$json"

try {
    $ap1 = Invoke-MgGraphRequest -Uri $uri -Method POST -Body $JSON -ContentType "application/json" -OutputType PSObject
}
catch {
    Write-Error $_.Exception 
        
}

write-output "Autopilot Profile Configured"


##########################################endregion##############################################################


##Get Autopilot ZTID
$approfile = Get-AutopilotProfile | where-object "DisplayName" -eq $profilename | ConvertTo-AutopilotConfigurationJSON
$ztd = ($approfile | ConvertFrom-Json).ZtdCorrelationId
$aprule = "(device.devicePhysicalIDs -any (_ -startsWith ""[ZTDid]"")) -or (device.enrollmentProfileName -eq ""OfflineAutopilotprofile-$ztd"")"
Get-AutopilotProfile | where-object "DisplayName" -eq $profilename | ConvertTo-AutopilotConfigurationJSON | Set-Content -Encoding Ascii "$path\AutopilotConfigurationFile.json"



if ($fresh -eq "Yes") {
#AutoPilot Group using MG.Graph
if ($whitelabel) {
    $displayname = $whitelabel + "Autopilot-Devices"
}
else {
    $displayname = "Autopilot-Devices"
}
$autopilotgrp = New-MgGroup -DisplayName "$displayname" -Description "Dynamic group for Autopilot Devices" -MailEnabled:$False -MailNickName "autopilotdevices" -SecurityEnabled -GroupTypes "DynamicMembership" -MembershipRule "$aprule" -MembershipRuleProcessingState "On"
}
else
{
#AutoPilot Group using MG.Graph
if ($whitelabel) {
    $displayname = $whitelabel + "Autopilot-Devices-Dynamic"
}
else {
    $displayname = "Autopilot-Devices-Dynamic"
}
$autopilotmaingrp = New-MgGroup -DisplayName "$displayname" -Description "Dynamic group for Autopilot Devices" -MailEnabled:$False -MailNickName "autopilotdevices" -SecurityEnabled -GroupTypes "DynamicMembership" -MembershipRule "$aprule" -MembershipRuleProcessingState "On"
if ($whitelabel) {
    $displayname = $whitelabel + "Intune Pilot Devices"
}
else {
    $displayname = "Intune Pilot Devices"
}
$autopilotgrp = New-MGGroup -DisplayName "$displayname" -Description "Assigned group for Intune Pilot Devices" -MailEnabled:$False -MailNickName "intunepilotdevices" -SecurityEnabled

}

###############################################################################################################
######                                          Assign Autopilot Profile                                 ######
###############################################################################################################


# Defining Variables
$id = $ap1.id
$graphApiVersion = "beta"
$Resource = "deviceManagement/windowsAutopilotDeploymentProfiles"        
$uri = "https://graph.microsoft.com/$graphApiVersion/$Resource/$id/assignments"        

$groupid = $autopilotgrp.id

$full_assignment_id = $id + "_" + $groupid + "_0" 

$json = @"
{
    "id": "$full_assignment_id",
    "target": {
        "@odata.type": "#microsoft.graph.groupAssignmentTarget",
        "groupId": "$groupid"
    }
}
"@

Write-Verbose "POST $uri`n$json"

try {
    Invoke-MgGraphRequest -Uri $uri -Method POST -Body $JSON -ContentType "application/json" -OutputType PSObject

}
catch {
    Write-Error $_.Exception 
            
}



#########################################################################
write-output "Autopilot Profile Assigned"

###############################################################################################################
######                             Enable Android Enrollment                                             ######
###############################################################################################################

##Check if Google Play is Configured

$playcheckurl = "https://graph.microsoft.com/beta/deviceManagement/androidManagedStoreAccountEnterpriseSettings"
$playcheck = (Invoke-MgGraphRequest -Uri $playcheckurl -Method Get -OutputType PSObject).lastAppSyncStatus
if ($playcheck -eq "success") {
    write-output "Google Play Configured, continuing"
    $JSON = @"
    {
        "enabled":true
    }
"@
    
    $uri = "https://graph.microsoft.com/beta/deviceManagement/androidManagedStoreAccountEnterpriseSettings/setAndroidDeviceOwnerFullyManagedEnrollmentState"
    Invoke-MgGraphRequest -Uri $uri -Method Post -Body $JSON -ContentType "application/json" -OutputType PSObject

    ##Download QR code
    $qrcodeurl = (Invoke-MgGraphRequest -Uri $playcheckurl -Method Get -OutputType PSObject).companyCodes
    $qrbase64 = ($qrcodeurl.qrcodeimage).value

    $Image = "$path\AndroidQR.png"
    [byte[]]$Bytes = [convert]::FromBase64String($qrbase64)
    [System.IO.File]::WriteAllBytes($Image, $Bytes)

    ##Get Token
    $androidtoken2 = ($qrcodeurl.enrollmenttoken)
($qrcodeurl.enrollmenttoken) | out-file "$path\token.txt"

}
else {
    write-output "No Google Play Configured, Aborting Android Config"
}

#########################################################################
$msgBody = "Android Enrollment Configured and QR extracted"
write-host $msgBody
###############################################################################################################
######                             Check for AutoPatch                                                   ######
###############################################################################################################

if ($noupload) {
    $autopatchcheck -eq "False"
}
else {
$uri = "https://graph.microsoft.com/beta/organization"
$tenantdetails = (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).value
$tenantid = $tenantdetails.id
$licensing = $tenantdetails.AssignedPlans
$autopatchcheck = $licensing.ServicePlanId -contains "9a6eeb79-0b4b-4bf0-9808-39d99a2cd5a3"
}

if ($autopatchcheck -eq "True") {
    write-host "AutoPatch Licensed"
    ##Autopatch Licensed
    write-host "Nest AutoPilot Devices into the AutoPatch Registration Group"

    ##Remove Update Rings

    ##Finally Remove Policies
    #Get Update Rings
    ##Filter to only Update Policies
    $updateringsurl = "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations?`$filter=(isof('microsoft.graph.windowsUpdateForBusinessConfiguration'))"

    write-host "Getting Update Rings"
    ##Grab the Value
    $currentpolicies = (Invoke-MgGraphRequest -Uri $updateringsurl -Method Get -OutputType PSObject).Value
    foreach ($currentpolicy in $currentpolicies) {
        $policyname = $currentpolicy.DisplayName

        if (($policyname -ne "Modern Workplace Update Policy [Fast]-[Windows Autopatch]") -and ($policyname -ne "Modern Workplace Update Policy [First]-[Windows Autopatch]") -and ($policyname -ne "Modern Workplace Update Policy [Test]-[Windows Autopatch]") -and ($policyname -ne "Modern Workplace Update Policy [Broad]-[Windows Autopatch]")) {
            $policyid = $currentpolicy.Id
            $uri = "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations/$policyid"
            Invoke-MgGraphRequest -Uri $uri -Method Delete
            write-host "$policyname Deleted"
        }
    }
    $newbroadgroupid = (Get-MgGroup -Filter "DisplayName eq 'Windows Autopatch Device Registration'").Id
    $apgrpid = $autopilotgrp.id
    New-MgGroupMember -GroupID "$newbroadgroupid" -DirectoryObjectID "$apgrpid"                #########################################################################
            ##Remove Office Update Rings
            if ($whitelabel) {
                $broadname  = $whitelabel+"Office BroadRing"
                $pilotname = $whitelabel+"Office PilotRing"
                $previewname = $whitelabel+"Office PreviewRing"
                $VIPname = $whitelabel+"Office VIPRing"
            }
            else {
                $broadname  = "Office BroadRing"
                $pilotname = "Office PilotRing"
                $previewname = "Office PreviewRing"
                $VIPname = "Office VIPRing"
            }


            $broadpolicy = Get-DeviceConfigurationPolicySCbyName -name "$broadname"
            $pilotpolicy = Get-DeviceConfigurationPolicySCbyName -name "$pilotname"
            $previewpolicy = Get-DeviceConfigurationPolicySCbyName -name "$previewname"
            $VIPpolicy = Get-DeviceConfigurationPolicySCbyName -name "$VIPname"
            $broadpid = $broadpolicy.id
            $pilotpid = $pilotpolicy.id
            $previewpid = $previewpolicy.id
            $vippid = $VIPpolicy.id


            $buri = "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies/$broadpid"
            Invoke-MgGraphRequest -Uri $buri -Method Delete
            $puri = "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies/$pilotpid"
            Invoke-MgGraphRequest -Uri $puri -Method Delete
            $puriv = "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies/$previewpid"
            Invoke-MgGraphRequest -Uri $puriv -Method Delete
            $vuri = "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies/$vippid"
            Invoke-MgGraphRequest -Uri $vuri -Method Delete

}
else {
    write-host "AutoPatch not licensed"
    ##Autopatch Not Licensed, go old school

    ###############################################################################################################
    ######                             Assign Windows Update Rings                                           ######
    ###############################################################################################################

    #Assign Windows Update Rings
    #Pilot Ring
    if ($whitelabel) {
        $PolicyName = $whitelabel + "Pilot Ring"
    }
    else {
        $PolicyName = "Pilot Ring"
    }

    $DCP = Get-DeviceConfigurationPolicybyName -name $PolicyName

    if ($DCP) {

        Add-DeviceConfigurationPolicyAssignment -ConfigurationPolicyId $DCP.id -TargetGroupId $pilotgrp.id -AssignmentType Included
        write-output "Assigned '$pilotgrp.Name' to $($DCP.displayName)/$($DCP.id)"
        Write-Host

    }

    else {

        write-output "Can't find Device Configuration Policy with name '$PolicyName'..."
        Write-Host 

    }



    #Preview Ring
    if ($whitelabel) {
        $PolicyName = $whitelabel + "Preview Ring"
    }
    else {
        $PolicyName = "Preview Ring"
    }

    $DCP = Get-DeviceConfigurationPolicybyName -name $PolicyName

    if ($DCP) {

        Add-DeviceConfigurationPolicyAssignment -ConfigurationPolicyId $DCP.id -TargetGroupId $previewgrp.id -AssignmentType Included
        write-output "Assigned '$previewgrp' to $($DCP.displayName)/$($DCP.id)"
        Write-Host

    }

    else {

        write-output "Can't find Device Configuration Policy with name '$PolicyName'..."
        Write-Host 

    }



    #VIP Ring
    if ($whitelabel) {
        $PolicyName = $whitelabel + "VIP Channel"
    }
    else {
        $PolicyName = "VIP Channel"
    }

    $DCP = Get-DeviceConfigurationPolicybyName -name $PolicyName

    if ($DCP) {

        Add-DeviceConfigurationPolicyAssignment -ConfigurationPolicyId $DCP.id -TargetGroupId $vipgrp.id -AssignmentType Included
        write-output "Assigned '$vipgrp' to $($DCP.displayName)/$($DCP.id)"
        Write-Host

    }

    else {

        write-output "Can't find Device Configuration Policy with name '$PolicyName'..."
        Write-Host 

    }


    #Broad Ring
    if ($whitelabel) {
        $PolicyName = $whitelabel + "Broad Ring"
    }
    else {
        $PolicyName = "Broad Ring"
    }

    $DCP = Get-DeviceConfigurationPolicybyName -name $PolicyName

    if ($DCP) {
        $vipuser = $vipgrp.Id
        $pilotuser = $pilotgrp.Id
        $previewuser = $previewgrp.Id
        $intuneuser = $intunegrp.Id
        $graphApiVersion = "Beta"
        $configid = $dcp.id
        $Resource = "deviceManagement/deviceConfigurations/$configid/assign"

        $JSON = @"
{
    "assignments":  [
                        {
                            "target":  {
                                           "@odata.type":  "#microsoft.graph.groupAssignmentTarget",
                                           "deviceAndAppManagementAssignmentFilterId":  null,
                                           "deviceAndAppManagementAssignmentFilterType":  "none",
                                           "groupId":  "$intuneuser"
                                       }
                        },
                        {
                            "target":  {
                                           "@odata.type":  "#microsoft.graph.exclusionGroupAssignmentTarget",
                                           "deviceAndAppManagementAssignmentFilterId":  null,
                                           "deviceAndAppManagementAssignmentFilterType":  "none",
                                           "groupId":  "$previewuser"
                                       }
                        },
                        {
                            "target":  {
                                           "@odata.type":  "#microsoft.graph.exclusionGroupAssignmentTarget",
                                           "deviceAndAppManagementAssignmentFilterId":  null,
                                           "deviceAndAppManagementAssignmentFilterType":  "none",
                                           "groupId":  "$pilotuser"
                                       }
                        },
                        {
                            "target":  {
                                           "@odata.type":  "#microsoft.graph.exclusionGroupAssignmentTarget",
                                           "deviceAndAppManagementAssignmentFilterId":  null,
                                           "deviceAndAppManagementAssignmentFilterType":  "none",
                                           "groupId":  "$vipuser"
                                       }
                        }
                    ]
}
"@
        
        # POST to Graph Service
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Invoke-MgGraphRequest -Uri $uri -Method Post -Body $JSON -ContentType "application/json" -OutputType PSObject


        
        write-output "Assigned all groups to $($DCP.displayName)/$($DCP.id)"
        Write-Host

    }

    else {

        write-output "Can't find Device Configuration Policy with name '$PolicyName'..."
        Write-Host 

    }

    write-output "Windows Update Rings Assigned"

###############################################################################################################
######                                          Assign Office Update Rings                               ######
###############################################################################################################


#Assign Office Update Rings

#Pilot Ring
if ($whitelabel) {
    $PolicyName = $whitelabel + "Office PilotRing"
}
else {
    $PolicyName = "Office PilotRing"
}

$DCP = Get-DeviceConfigurationPolicySCbyName -name $PolicyName

if ($DCP) {

    Add-DeviceConfigurationPolicyAssignmentSC -ConfigurationPolicyId $DCP.id -TargetGroupId $pilotgrp.id -AssignmentType Included
    write-output "Assigned '$pilotgrp' to $($DCP.displayName)/$($DCP.id)"
    Write-Host

}

else {

    write-output "Can't find Device Configuration Policy with name '$PolicyName'..."
    Write-Host 

}



#Preview Ring
if ($whitelabel) {
    $PolicyName = $whitelabel + "Office PreviewRing"
}
else {
    $PolicyName = "Office PreviewRing"
}

$DCP = Get-DeviceConfigurationPolicySCbyName -name $PolicyName

if ($DCP) {

    Add-DeviceConfigurationPolicyAssignmentSC -ConfigurationPolicyId $DCP.id -TargetGroupId $previewgrp.id -AssignmentType Included
    write-output "Assigned '$previewgrp' to $($DCP.displayName)/$($DCP.id)"
    Write-Host

}

else {

    write-output "Can't find Device Configuration Policy with name '$PolicyName'..."
    Write-Host 

}



#VIP Ring
if ($whitelabel) {
    $PolicyName = $whitelabel + "Office VIPRing"
}
else {
    $PolicyName = "Office VIPRing"
}

$DCP = Get-DeviceConfigurationPolicySCbyName -name $PolicyName

if ($DCP) {

    Add-DeviceConfigurationPolicyAssignmentSC -ConfigurationPolicyId $DCP.id -TargetGroupId $vipgrp.id -AssignmentType Included
    write-output "Assigned '$vipgrp' to $($DCP.displayName)/$($DCP.id)"
    Write-Host

}

else {

    write-output "Can't find Device Configuration Policy with name '$PolicyName'..."
    Write-Host 

}


#Broad Ring
if ($whitelabel) {
    $PolicyName = $whitelabel + "Office BroadRing"
}
else {
    $PolicyName = "Office BroadRing"
}

$DCP = Get-DeviceConfigurationPolicySCbyName -name $PolicyName

if ($DCP) {
    $vipuser = $vipgrp.Id
    $pilotuser = $pilotgrp.Id
    $previewuser = $previewgrp.Id
    $intuneuser = $intunegrp.Id
    $graphApiVersion = "Beta"
    $configid = $dcp.id
    $Resource = "deviceManagement/configurationPolicies/$configid/assign"

    $JSON = @"
{
    "assignments":  [
                        {
                            "target":  {
                                           "@odata.type":  "#microsoft.graph.groupAssignmentTarget",
                                           "deviceAndAppManagementAssignmentFilterId":  null,
                                           "deviceAndAppManagementAssignmentFilterType":  "none",
                                           "groupId":  "$intuneuser"
                                       }
                        },
                        {
                            "target":  {
                                           "@odata.type":  "#microsoft.graph.exclusionGroupAssignmentTarget",
                                           "deviceAndAppManagementAssignmentFilterId":  null,
                                           "deviceAndAppManagementAssignmentFilterType":  "none",
                                           "groupId":  "$previewuser"
                                       }
                        },
                        {
                            "target":  {
                                           "@odata.type":  "#microsoft.graph.exclusionGroupAssignmentTarget",
                                           "deviceAndAppManagementAssignmentFilterId":  null,
                                           "deviceAndAppManagementAssignmentFilterType":  "none",
                                           "groupId":  "$pilotuser"
                                       }
                        },
                        {
                            "target":  {
                                           "@odata.type":  "#microsoft.graph.exclusionGroupAssignmentTarget",
                                           "deviceAndAppManagementAssignmentFilterId":  null,
                                           "deviceAndAppManagementAssignmentFilterType":  "none",
                                           "groupId":  "$vipuser"
                                       }
                        }
                    ]
}
"@
        
    # POST to Graph Service
    $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
    Invoke-MgGraphRequest -Uri $uri -Method Post -Body $JSON -ContentType "application/json" -OutputType PSObject
    write-output "Assigned all groups to $($DCP.displayName)/$($DCP.id)"
    Write-Host

}

else {

    write-output "Can't find Device Configuration Policy with name '$PolicyName'..."
    Write-Host 

}

$msgBody = "Office Update Rings Assigned"
write-output $msgBody
}


###############################################################################################################
######                                               Add Store Apps                                      ######
###############################################################################################################

##List of apps to install
$storeapps = @("Company Portal", "Microsoft To Do: Lists, Tasks & Reminders", "Windows Terminal Preview")

##Add each
foreach ($app in $storeapps) {
    Add-MSStoreApp -Name $app
}


###############################################################################################################
######                                          Assign what's left                                       ######
###############################################################################################################
$intunegroupname = $intunegrp.DisplayName
##These have already been assigned
if ($whitelabel) {
    $dontuse = $whitelabel + "Pilot Ring", $whitelabel + "Preview Ring", $whitelabel + "VIP Channel", $whitelabel + "Broad Ring", $whitelabel + "Office PilotRing", $whitelabel + "Office PreviewRing", $whitelabel + "Office VIPRing", $whitelabel + "Office BroadRing", $whitelabel + "Remove Bloat", $whitelabel + "Drive-Mapping", $whitelabel + "Windows-ESP"
}
else {
    $dontuse = "Pilot Ring", "Preview Ring", "VIP Channel", "Broad Ring", "Office PilotRing", "Office PreviewRing", "Office VIPRing", "Office BroadRing", "Remove Bloat", "Drive-Mapping", "Windows-ESP"
}

##Security Policies are better device assigned, but are moving to Settings Catalog so build an array especially for them
if ($whitelabel) {
    $secpolicies = $whitelabel + "MDE-AV-Active", $whitelabel + "MDE-AV-Global Exclusions", $whitelabel + "MDE-Targeted-TamperPro", $whitelabel + "Bitlocker Policy", $whitelabel + "MDE-FW-Active", $whitelabel + "MDE-Web Protection-Active", $whitelabel + "MDE-AppGuard-Active", $whitelabel + "MDE-ASR Rules", $whitelabel + "MDE-DeviceControl", $whitelabel + "MDE-EP-Active", $whitelabel + "Defender for Endpoint Onboarding"
}
else {
    $secpolicies = "MDE-AV-Active", "MDE-AV-Global Exclusions", "MDE-Targeted-TamperPro", "Bitlocker Policy", "MDE-FW-Active", "MDE-Web Protection-Active", "MDE-AppGuard-Active", "MDE-ASR Rules", "MDE-DeviceControl", "MDE-EP-Active", "Defender for Endpoint Onboarding"
}


##Create an array of all profiles we have imported except those in the list above
$profilestoassign = @()
foreach ($tempprofile in $temp) {
    if ($dontuse.contains($tempprofile)) {
        write-host "Removing $tempprofile from array to assign"
    }
    else {
        $profilestoassign = $profilestoassign += $tempprofile

    }
}
                ##Add manually created policies
                if ($whitelabel) {
                $profilestoassign = $profilestoassign += $whitelabel +"Background and Lockscreen"
                $profilestoassign = $profilestoassign += $whitelabel +"Defender for Endpoint Onboarding"
                $profilestoassign = $profilestoassign += $whitelabel +"OneDrive Config"
                $profilestoassign = $profilestoassign += $whitelabel +"Browser Homepage"
                }
                else {
                    $profilestoassign = $profilestoassign += "Background and Lockscreen"
                    $profilestoassign = $profilestoassign += "Defender for Endpoint Onboarding"
                    $profilestoassign = $profilestoassign += "OneDrive Config"
                    $profilestoassign = $profilestoassign += "Browser Homepage"  
                }


##Assign Config Policies
$configuration = Get-DeviceConfigurationPolicy

foreach ($policy in $configuration) {
    if ($profilestoassign.contains($policy.displayName )) {

        if ($secpolicies.contains($policy.name) -or $securityonly -eq "Yes") {
            ##Assign to devices
            $autopilotname = $autopilotgrp.DisplayName
            $autopilotid = $autopilotgrp.Id
            write-output "Assigned $autopilotname to $($policy.name)/$($policy.id)"
                
            Add-DeviceConfigurationPolicyAssignment -ConfigurationPolicyId $policy.id -TargetGroupId $autopilotid -AssignmentType Included
        }
        else {
            ##Assign to users
            write-output "Assigned $intunegroupname to $($policy.displayName)/$($policy.id)"

            Add-DeviceConfigurationPolicyAssignment -ConfigurationPolicyId $policy.id -TargetGroupId $intunegrp.id -AssignmentType Included
    
        }
    }
    else {
        write-output "NOT Assigning" + $policy.displayName
    }

}



##Assign Settings Catalog Policies
$configurationsc = Get-DeviceConfigurationPolicySC

foreach ($policy in $configurationsc) {

    if ($profilestoassign.contains($policy.name )) {
        ##Check if security policy
        if ($secpolicies.contains($policy.name) -or $securityonly -eq "Yes") {
            ##Assign to devices
            $autopilotname = $autopilotgrp.DisplayName
            $autopilotid = $autopilotgrp.Id
            write-output "Assigned $autopilotname to $($policy.name)/$($policy.id)"
                
            Add-DeviceConfigurationPolicyAssignmentSC -ConfigurationPolicyId $policy.id -TargetGroupId $autopilotid -AssignmentType Included
        }
        else {
            ##Assign to users
            write-output "Assigned $intunegroupname to $($policy.displayName)/$($policy.id)"

            Add-DeviceConfigurationPolicyAssignmentSC -ConfigurationPolicyId $policy.id -TargetGroupId $intunegrp.id -AssignmentType Included
    
        }
    }
    else {
        write-output "NOT Assigning" + $policy.name
    }

}


##Assign Compliance Policies
$compliance = Get-DeviceCompliancePolicy
write-output "Assigning Compliance Policies"
foreach ($policy in $compliance) {
    if ($profilestoassign.contains($policy.displayName )) {
        write-output "Assigned $intunegroupname to $($policy.displayName)/$($policy.id)"
        $policyid = $policy.ID
        $intunegroupid = $intunegrp.Id
        #Add-DeviceCompliancePolicyAssignment -CompliancePolicyId $policyid -TargetGroupId $intunegrpid
            $JSON = @"
        {
            "assignments": [
            {
                "target": {
                "@odata.type": "#microsoft.graph.groupAssignmentTarget",
                "groupId": "$intunegroupid"
                }
            }
            ]
        }
"@
    
            $uri = "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies/$policyid/assign"
            Invoke-MgGraphRequest -Uri $uri -Method Post -Body $JSON -ContentType "application/json"
    }
    else {
        write-output "NOT Assigning" + $policy.displayName

    }

}

##Assign Security Policies
$security = Get-DeviceSecurityPolicy

foreach ($policy in $security) {
    if ($profilestoassign.contains($policy.displayName )) {
        write-output "Assigned $intunegroupname to $($policy.displayName)/$($policy.id)"
        Add-DeviceSecurityPolicyAssignment -ConfigurationPolicyId $policy.id -TargetGroupId $autopilotgrp.id -AssignmentType Included
    }
    else {
        write-output "NOT Assigning" + $policy.displayName

    }

}


##Assign Scripts
$scripts = Get-DeviceManagementScripts

foreach ($script in $scripts) {
    if ($profilestoassign.contains($script.displayName )) {
        write-output "Assigned $intunegroupname to $($script.displayName)/$($script.id)"
        Add-DeviceManagementScriptAssignment -ScriptId $script.id -TargetGroupId $intunegrp.id
    }
    else {
        write-output "NOT Assigning" + $script.displayName

    }

}




##Assign Bloat Script
if ($whitelabel) {
    $PolicyName = $whitelabel + "Remove Bloat"
}
else {
    $PolicyName = "Remove Bloat"
}
$bloat = Get-DeviceManagementScripts -Name "$PolicyName"
Add-DeviceManagementScriptAssignment -ScriptId $bloat.id -TargetGroupId $autopilotgrp.id

##Assign Device Config Script
if ($whitelabel) {
    $PolicyName = $whitelabel + "Device Configuration Script"
}
else {
    $PolicyName = "Device Configuration Script"
}
$dconfig = Get-DeviceManagementScripts -Name "$PolicyName"
Add-DeviceManagementScriptAssignment -ScriptId $dconfig.id -TargetGroupId $autopilotgrp.id


##Assign User Config Script
#$uconfig = Get-DeviceManagementScripts -Name "User Configuration Script"
#Add-DeviceManagementScriptAssignment -ScriptId $uconfig.id -TargetGroupId $intunegrp.id

##Assign Backup Script
if ($whitelabel) {
    $PolicyName = $whitelabel + "Backup Script"
}
else {
    $PolicyName = "Backup Script"
}
$backupscript = Get-DeviceManagementScripts -Name "$PolicyName"
Add-DeviceManagementScriptAssignment -ScriptId $backupscript.id -TargetGroupId $intunegrp.id

##Assign Windows-ESP custom policy
if ($whitelabel) {
    $PolicyName = $whitelabel + "Windows-ESP"
}
else {
    $PolicyName = "Windows-ESP"
}
$esp = Get-DeviceConfigurationPolicybyName -name "$PolicyName"
Add-DeviceConfigurationPolicyAssignment -ConfigurationPolicyId $esp.id -TargetGroupId $autopilotgrp.id -AssignmentType Included

##Assign Android App Protection

##Get Policy ID
write-output "Getting Android App Protection Policy"
if ($whitelabel) {
    $PolicyName = $whitelabel + "Android-App-Protection"
    $uri = "https://graph.microsoft.com/beta/deviceAppManagement/androidManagedAppProtections?`$filter=displayName eq '$PolicyName'"

}
else {
    $uri = "https://graph.microsoft.com/beta/deviceAppManagement/androidManagedAppProtections?`$filter=displayName eq 'Android-App-Protection'"
}
$androidapp = (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value
$androidappid = $androidapp.Id
write-output "Policy $androidappid found, assigning to Intune Users"
##Assign It
Set-ManagedAppPolicy -Id $androidappid -TargetGroupId $intunegrp.id -OS Android
write-output "Policy Assigned to Intune-Users"


##Assign iOS App Protection

##Get Policy ID
write-output "Getting iOS App Protection Policy"
if ($whitelabel) {
    $PolicyName = $whitelabel + "iOS-App-Protection"
    $uri = "https://graph.microsoft.com/beta/deviceAppManagement/iOSManagedAppProtections?`$filter=displayName eq '$PolicyName'"

}
else {
    $uri = "https://graph.microsoft.com/beta/deviceAppManagement/iOSManagedAppProtections?`$filter=displayName eq 'iOS-App-Protection'"
}

$iosapp = (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value
$iosappid = $iosapp.Id
write-output "Policy $iosappid found, assigning to Intune Users"
##Assign It
Set-ManagedAppPolicy -Id $iosappid -TargetGroupId $intunegrp.id -OS iOS
write-output "Policy Assigned to Intune-Users"


write-output "Remaining Policies Assigned"


##############################################################################################################
#                                 Create Proac to Unpin Store                                                 #
###############################################################################################################   

###############################################################################################################
#                                              Set Variables                                                  #
###############################################################################################################
##Variables
if ($whitelabel) {
    $DisplayName = $whitelabel + "Remediate Store Icon"
    $Publisher = $whitelabel
}
else {
    $DisplayName = "Remediate Store Icon"
    $Publisher = "Andrew Taylor"
}
$Description = "Remove Windows Store from Taskbar"
##RunAs can be "system" or "user"
$RunAs = "user"
##True for 32-bit, false for 64-bit
$RunAs32 = $false
##How Often
$ScheduleFrequency = "1"
##Start Time (if daily)
$StartTime = "01:00"


###############################################################################################################
#                                                 Detection Script                                            #
###############################################################################################################
$detect = @'
##We're looping through the verbs so it's going to be easier to count
$pinned = 0
##Loop through verbs for the store app
$apps = ((New-Object -Com Shell.Application).NameSpace('shell:::{4234d49b-0245-4df3-b780-3893943456e1}').Items() | Where-Object { $_.Name -eq "Microsoft Store" }).verbs()
foreach ($app in $apps) {
    ##Is Unpin an option?
if ($app.Name -eq "Unpin from tas&kbar") {
    ##Yep, increment the counter
$pinned++
}
}

#Has it been found?
if ($pinned -gt 0) {
Write-Warning "Store has been pinned"
exit 1
}
else {
write-host "Not pinned"
exit 0
}
'@

###############################################################################################################
#                                             Remediation Script                                              #
###############################################################################################################
$remediate = @'

$apps = ((New-Object -Com Shell.Application).NameSpace('shell:::{4234d49b-0245-4df3-b780-3893943456e1}').Items())
foreach ($app in $apps) {
$appname = $app.Name
if ($appname -like "*store*") {
$finalname = $app.Name
}
}

((New-Object -Com Shell.Application).NameSpace('shell:::{4234d49b-0245-4df3-b780-3893943456e1}').Items() | ?{$_.Name -eq $finalname}).Verbs() | ?{$_.Name.replace('&','') -match 'Unpin from taskbar'} | %{$_.DoIt(); $exec = $true}

'@


###############################################################################################################
#                                              CREATE IT                                                      #
###############################################################################################################

$params = @{
    displayName              = $DisplayName
    description              = $Description
    publisher                = $Publisher
    runAs32Bit               = $RunAs32
    runAsAccount             = $RunAs
    enforceSignatureCheck    = $false
    detectionScriptContent   = [System.Text.Encoding]::ASCII.GetBytes($detect)
    remediationScriptContent = [System.Text.Encoding]::ASCII.GetBytes($remediate)
    roleScopeTagIds          = @(
        "0"
    )
}

##Create It
write-output "Creating Proactive Remediation"
$graphApiVersion = "beta"
$Resource = "deviceManagement/deviceHealthScripts"
$uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"

try {
    $proactive = Invoke-MgGraphRequest -Uri $uri -Method POST -Body $params -ContentType "application/json" -OutputType PSObject

}
catch {
    Write-Error $_.Exception 
    
}

write-output "Proactive Remediation Created"

##Assign It
$params = @{
    DeviceHealthScriptAssignments = @(
        @{
            target               = @{
                "@odata.type" = "#microsoft.graph.groupAssignmentTarget"
                groupId       = $intunegrp.id
            }
            runRemediationScript = $true
            runSchedule          = @{
                "@odata.type" = "#microsoft.graph.deviceHealthScriptHourlySchedule"
                interval      = $scheduleFrequency
            }
        }
    )
}

$remediationID = $proactive.ID


$graphApiVersion = "beta"
$Resource = "deviceManagement/deviceHealthScripts"
$uri = "https://graph.microsoft.com/$graphApiVersion/$Resource/$remediationID/assign"

try {
    $proactive = Invoke-MgGraphRequest -Uri $uri -Method POST -Body $params -ContentType "application/json" -OutputType PSObject

}
catch {
    Write-Error $_.Exception 
    
}
write-output "Remediation Assigned"


##############################################################################################################
#                                 Create Proac to Backup Data                                                #
###############################################################################################################   

###############################################################################################################
#                                              Set Variables                                                  #
###############################################################################################################
##Variables
if ($whitelabel) {
    $DisplayName = $whitelabel + "User Profile Backup"
    $Publisher = $whitelabel
}
else {
    $DisplayName = "User Profile Backup"
    $Publisher = "Andrew Taylor"
}
$Description = "Profile backup to OneDrive"
##RunAs can be "system" or "user"
$RunAs = "user"
##True for 32-bit, false for 64-bit
$RunAs32 = $false
##How Often
$ScheduleFrequency = "1"
##Start Time (if daily)
$StartTime = "01:00"


###############################################################################################################
#                                                 Detection Script                                            #
###############################################################################################################
$detect = @'
$todaysdate = Get-Date -Format "dd-MM-yyyy-HH"
$dir = $env:APPDATA + "\backup-restore"

##Open File to check contents
$backupfile = $dir + "\backup.txt"
$backupdate = Get-Content -Path $backupfile
$checkdate = (get-date $backupdate -Format "dd-MM-yyyy-HH")
##Check if date is more than 1 hour ago
if ($checkdate -lt $todaysdate) {
    write-host "Run again"
    exit 1
}
else {
    "Already run this hour"
    exit 0
}
'@

###############################################################################################################
#                                             Remediation Script                                              #
###############################################################################################################
$remediate = @'
$DirectoryToCreate = $env:APPDATA + "\backup-restore"
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

##Download Backup Script
$backupurl="https://raw.githubusercontent.com/andrew-s-taylor/public/main/Batch%20Scripts/backup.bat"
$backupscript = $DirectoryToCreate + "\backup.bat"
if (-not (Test-Path -LiteralPath $backupscript)) {
Invoke-WebRequest -Uri $backupurl -OutFile $backupscript -UseBasicParsing
}
##Download Restore Script
$restoreurl="https://raw.githubusercontent.com/andrew-s-taylor/public/main/Batch%20Scripts/NEWrestore.bat"
$restorescript = $DirectoryToCreate + "\restore.bat"
if (-not (Test-Path -LiteralPath $restorescript)) {
Invoke-WebRequest -Uri $restoreurl -OutFile $restorescript -UseBasicParsing
}

##Download Silent Launch Script
$launchurl="https://raw.githubusercontent.com/andrew-s-taylor/public/main/Batch%20Scripts/run-invisible-userprof.vbs"
$launchscript = $DirectoryToCreate + "\run-invisible.vbs"
if (-not (Test-Path -LiteralPath $launchscript)) {
Invoke-WebRequest -Uri $launchurl -OutFile $launchscript -UseBasicParsing
}

##Run it
$acommand = "C:\Windows\System32\Cscript.exe $DirectoryToCreate\run-invisible.vbs"

Invoke-Expression $acommand

##Create/Update txt for detection
$todaysdate = Get-Date -Format "dd-MM-yyyy-HH"
$detection = $DirectoryToCreate + "\backup.txt"
if (-not (Test-Path -LiteralPath $detection)) {
    New-Item -Path $detection -ItemType File -Force
    Add-Content -Path $detection -Value $todaysdate
}
else {
    set-Content -Path $detection -Value $todaysdate
    }
    

'@


###############################################################################################################
#                                              CREATE IT                                                      #
###############################################################################################################

$params = @{
    displayName              = $DisplayName
    description              = $Description
    publisher                = $Publisher
    runAs32Bit               = $RunAs32
    runAsAccount             = $RunAs
    enforceSignatureCheck    = $false
    detectionScriptContent   = [System.Text.Encoding]::ASCII.GetBytes($detect)
    remediationScriptContent = [System.Text.Encoding]::ASCII.GetBytes($remediate)
    roleScopeTagIds          = @(
        "0"
    )
}

##Create It
write-output "Creating Proactive Remediation"
$graphApiVersion = "beta"
$Resource = "deviceManagement/deviceHealthScripts"
$uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"


try {
    $proactive = Invoke-MgGraphRequest -Uri $uri -Method POST -Body $params -ContentType "application/json" -OutputType PSObject
}
catch {
    Write-Error $_.Exception 
    
}

write-output "Proactive Remediation Created"

##Assign It
$params = @{
    DeviceHealthScriptAssignments = @(
        @{
            target               = @{
                "@odata.type" = "#microsoft.graph.groupAssignmentTarget"
                groupId       = $intunegrp.id
            }
            runRemediationScript = $true
            runSchedule          = @{
                "@odata.type" = "#microsoft.graph.deviceHealthScriptHourlySchedule"
                interval      = $scheduleFrequency
            }
        }
    )
}

$remediationID = $proactive.ID


$graphApiVersion = "beta"
$Resource = "deviceManagement/deviceHealthScripts"
$uri = "https://graph.microsoft.com/$graphApiVersion/$Resource/$remediationID/assign"
##Commented out to stop user based scripts, use the scheduled task instead

#try {
#    $proactive = Invoke-MgGraphRequest -Uri $uri -Method POST -Body $params -ContentType "application/json" -OutputType PSObject
#
#}
#catch {
#    Write-Error $_.Exception 
#    
#}
write-output "Remediation Assigned"

###############################################################################################################
######                                          Add Applications                                         ######
###############################################################################################################


##Office 365 MacOS
$JSON = @"
{
  "@odata.type": "#microsoft.graph.macOSOfficeSuiteApp",
  "description": "MacOS Office 365 - Assigned",
  "developer": "Microsoft",
  "displayName": "Mac Office 365 - Assigned",
  "informationUrl": "",
  "isFeatured": false,
  "largeIcon": {
    "type": "image/png",
    "value": "iVBORw0KGgoAAAANSUhEUgAAAF0AAAAeCAMAAAEOZNKlAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAJhUExURf////7z7/i9qfF1S/KCW/i+qv3q5P/9/PrQwfOMae1RG+s8AOxGDfBtQPWhhPvUx/759/zg1vWgg+9fLu5WIvKFX/rSxP728/nCr/FyR+tBBvOMaO1UH+1RHOs+AvSScP3u6f/+/v3s5vzg1+xFDO9kNPOOa/i7pvzj2/vWyes9Af76+Pzh2PrTxf/6+f7y7vOGYexHDv3t5+1SHfi8qPOIZPvb0O1NFuxDCe9hMPSVdPnFs/3q4/vaz/STcu5VIe5YJPWcfv718v/9/e1MFfF4T/F4TvF2TP3o4exECvF0SexIEPONavzn3/vZze1QGvF3Te5dK+5cKvrPwPrQwvKAWe1OGPexmexKEveulfezm/BxRfamiuxLE/apj/zf1e5YJfSXd/OHYv3r5feznPakiPze1P7x7f739f3w6+xJEfnEsvWdf/Wfge1LFPe1nu9iMvnDsfBqPOs/BPOIY/WZevJ/V/zl3fnIt/vTxuxHD+xEC+9mN+5ZJv749vBpO/KBWvBwRP/8+/SUc/etlPjArP/7+vOLZ/F7UvWae/708e1OF/aihvSWdvi8p+tABfSZefvVyPWihfSVde9lNvami+9jM/zi2fKEXvBuQvOKZvalifF5UPJ/WPSPbe9eLfrKuvvd0uxBB/7w7Pzj2vrRw/rOv+1PGfi/q/eymu5bKf3n4PnJuPBrPf3t6PWfgvWegOxCCO9nOO9oOfaskvSYePi5pPi2oPnGtO5eLPevlvKDXfrNvv739Pzd0/708O9gL+9lNfJ9VfrLu/OPbPnDsPBrPus+A/nArfarkQAAAGr5HKgAAADLdFJOU/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////8AvuakogAAAAlwSFlzAAAOwwAADsMBx2+oZAAAAz5JREFUOE+tVTtu4zAQHQjppmWzwIJbEVCzpTpjbxD3grQHSOXKRXgCAT6EC7UBVAmp3KwBnmvfzNCyZTmxgeTZJsXx43B+HBHRE34ZkXgkerXFTheeiCkRrbB4UXmp4wSWz5raaQEMTM5TZwuiXoaKgV+6FsmkZQcSy0kA71yMTMGHanX+AzMMGLAQCxU1F/ZwjULPugazl82GM0NEKm/U8EqFwEkO3/EAT4grgl0nucwlk9pcpTTJ4VPA4g/Rb3yIRhhp507e9nTQmZ1OS5RO4sS7nIRPEeHXCHdkw9ZEW2yVE5oIS7peD58Avs7CN+PVCmHh21oOqBdjDzIs+FldPJ74TFESUSJEfVzy9U/dhu+AuOT6eBp6gGKyXEx8euO450ZE4CMfstMFT44broWw/itkYErWXRx+fFArt9Ca9os78TFed0LVIUsmIHrwbwaw3BEOnOk94qVpQ6Ka2HjxewJnfyd6jUtGDQLdWlzmYNYLeKbbGOucJsNabCq1Yub0o92rtR+i30V2dapxYVEePXcOjeCKPnYyit7BtKeNlZqHbr+gt7i+AChWA9RsRs03pxTQc67ouWpxyESvjK5Vs3DVSy3IpkxPm5X+wZoBi+MFHWW69/w8FRhc7VBe6HAhMB2b8Q0XqDzTNZtXUMnKMjwKVaCrB/CSUL7WSx/HsdJC86lFGXwnioTeOMPjV+szlFvrZLA5VMVK4y+41l4e1xfx7Z88o4hkilRUH/qKqwNVlgDgpvYCpH3XwAy5eMCRnezIUxffVXoDql2rTHFDO+pjWnTWzAfrYXn6BFECblUpWGrvPZvBipETjS5ydM7tdXpH41ZCEbBNy/+wFZu71QO2t9pgT+iZEf657Q1vpN94PQNDxUHeKR103LV9nPVOtDikcNKO+2naCw7yKBhOe9Hm79pe8C4/CfC2wDjXnqC94kEeBU3WwN7dt/2UScXas7zDl5GpkY+M8WKv2J7fd4Ib2rGTk+jsC2cleEM7jI9veF7B0MBJrsZqfKd/81q9pR2NZfwJK2JzsmIT1Ns8jUH0UusQBpU8d2JzsHiXg1zXGLqxfitUNTDT/nUUeqDBp2HZVr+Ocqi/Ty3Rf4Jn82xxfSNtAAAAAElFTkSuQmCC"
  },
  "notes": "",
  "owner": "Microsoft",
  "privacyInformationUrl": "",
  "publisher": "Microsoft"
}
"@

##################################################

write-host "Publishing" ($JSON | ConvertFrom-Json).displayName
$graphApiVersion = "Beta"
$App_resource = "deviceAppManagement/mobileApps"

$uri = "https://graph.microsoft.com/$graphApiVersion/$($App_resource)"
$Create_Application = Invoke-MgGraphRequest -Uri $uri -Method Post -ContentType "application/json" -Body $JSON -OutputType PSObject


Write-Host "Application created as $($Create_Application.displayName)/$($create_Application.id)"

$ApplicationId = $Create_Application.id
$intunegroupid = $intunegrp.Id
$Assign_Application = Add-ApplicationAssignment -ApplicationId $ApplicationId -TargetGroupId $intunegroupid -InstallIntent "required"
write-output "Assigned '$intunegroupname' to $($Create_Application.displayName)/$($Create_Application.id) with" $Assign_Application.InstallIntent "install Intent"




##Edge MacOS
$JSON = @"
{
  "@odata.type": "#microsoft.graph.macOSMicrosoftEdgeApp",
  "description": "MacOS Edge - Assigned",
  "developer": "Microsoft",
  "displayName": "Mac Edge - Assigned",
  "informationUrl": "",
  "isFeatured": false,
  "largeIcon": {
    "type": "image/png",
    "value": "iVBORw0KGgoAAAANSUhEUgAAALAAAACwCAYAAACvt+ReAAAmAklEQVR42u2de5Bcd3Xnv+d3u3sk25IGWwmEl8bZkCxg0HgxmPCIxv4nWxU21q5hU9lHMSxUAUWItTyyJizFOKyNq3aTiP3DXiCYUUJtSGDtkY1NKDtxKxBeNvEIhB/YsmZkWbI1kuYhaTTTfe/v7B+/9723HzOaGT36d6pafbv7dqvn9uee+/2dc37nB0SLFi1atGjRokWLFi1atGjRokWLFi1atGjRokWLFi1atGjRokWLFi1atGjRokWLFi1atGjRokWLFi1atGjRokWLFi1atGjRokWLFi1atGjRokWLFi1atGjRzsooHoKl2xv2HBwCeADgAQYPAugHMADILQDAYAAMEHvvkvpeP0e8h9R+EyBMADxB4ImfveON9XiEI8ArZlv3HB4AeIjBQ1CwbrWAgh2sGk72th3A/r0FGGRBV6+Rfg+B9wI8TsTjANf3vu1N4/GXiAB3bYN7XhgEMKyh3ZoHtTPADtJW8CpgfdD1Yw9sIns/S+A6iMeI5Ng/X/vWmfgrRYADu3rP1ADAOxi8HeAtPoyBVwXAnhzwYXZwh2CGALM96s4Dc3Gb3OtEEkQMgr4n3gvwKJEcfeTN75yJAPewval+fDuDd4B4Wwhs8b5MJpQDnPfAJVLCQotygAHPAxcABuy23E3g0R9dMzQWAe4pcKeHAR4BeAtTO3DRAuYy72wehdq2ALH3PLUCWN97MsIC7F6T6gZGItJJIrkT4NF/uvq3ZyLAF6ldU58dBniEtUwAtfO47CFZ1L1KSlAO6OUBnBvElQNM0vPCMoBYkDTvmRUi3Ungnf+49XdmIsAXib25Prcd4J0MbLGwUXtwywdrIaSdNTBKAHbbBRmRG8QVPbAMoQUKEiMRTRDJWSK5UxDv/Ierts9EgC9Qe0v95ACAUQZvy8doO3vebp7zta10ABPa6t8ygM3jUCZ4elc/FpQB5J4TFurM25Z6O5sUJEceev27RyPAFxy8p0YA7AB4U0HPUmdIW0UbWg3u3Ge3iP22gziIOuQ9cF42hNLB98wlAJv7PYLk8Hde+/sTEeDz3K6tnx4AMMbgrWUDLCbfW7YDWXYRkfAhbxU+8+87AFwiIRygClx4ntgfyCloMwihwNWDu7zsuOXbv/GfRiLA5y+8wwB2AtgUQOsNrLgAqQ+5bOttOyYxuvG+VjK018HGEzuv6jyv0b5Cwy1Epvd1AAsNtNrO9D5kvfG3XvO+C94bi4sJ3rfW50cB+qqCFwEwFOhSoDzFy8FZnQ+Zld9MnUM+6iBz/xdK/t+yR8V97f/G5AUyQukAwEYirJa2VwfvB6cUAnIbQY7fsP+L26MHPi/APdMPoA4tGbgsWkCtEhHS21MGsqGzB5ZBaIwDoEM02U8dF04mT/eWDOjCJIaRAqkFtpXuVd6XnQemDCS0zHD73XLPr354JHrgc2S/WV8YBDBu4A3PTm5zmuY9rncpb+md8zdSsFExnBbC284Ls3enY8qcv2KUfaYAg0DeaUPW88PTxKmNahidLSizGT6Q/OyNE/97NHrgcwYv1wFs8sNZgZckdBXHdVGH4gCupQem1hm5vAQoyJkSvay8MHKhNE//+mll62HVAE6ITHllkVlPbF4vu3feODX77gUw9LdbPjYTPfDaed46QJu6PyspV5QTQkkdVGhQ51uoc0AHzRvKCW7z/ey1QHtlZqH1b/n/ZTSwe4m8T3RRCvjpZzsAtM9tFaJZ//1Dt/dHgFfZ3lZfHCSgHg7WyiCiNlAXgeWg+JzLM2hUXhNRHm0oA5XbjddKIfRlg5EZIepm0OYD7by1jVgEMWNWyRBvMAhgK8D1/3jo1v4I8CrCi1J4S8CgvIeUAWzcUuOW+21q4VFb6tpWxezmGS5R7OzDT2AmDScHGtdq8EJZpoGSwUz2RpAacbL72JPEvo8hILcSyfp/PnxLfwR4he3tLeHtJObLLtrcMYBFpUPCTnByVydFK/nhXxfIB9k7jaigmzXeDCU39M9q3i8o07iryIP5PCFSm/BQXtoO7rYCPBYBXlF4G/0Ajfnw0hKGp9T2us25+G1JHJhkSxC5ReyXO5wgOSVbooXDcBuz962093RevKxwPpet07CqW5aLF3vSQkG/bfiFPx6NAK+c1QFsyataQjchslYYc+E9XDboIl5iyKbdoJBbYmvBZf1uJhusIC9KASYblUCggb2YcU6GwMgJXxAxhd6dAYIPPL/3v7x4844I8Nl731E1wDjbyJ9sA2+ZRw5nVZRpZl6SXOCusM9DLVnYSITNxoH1czoeTLkaDPJ1s9bH1iObmww0M1GWK29mEOSfv//oJwYjwMu0d9SbwwR6b7voQVnMgUr3oo6RAPU+aj8psyxZsiT92xptaiU8TCKCOBjAuQGh9ti5Ant08f1MREL99SqebLywVthjHzj6sf4I8NLhHYAqzOmgYdHlAC1EpXMlAnfMynFHUHlJaaTy4B4XEoAmLkxUDOMxqPD/WlnB7IXoTIw4c5EJ+04dilP3W4iy0Qjw0m2sGHGgNhHeTpEG6kJCQHkj4lyRZKusHIKsX/4GIrS9GBSeloG2LQWc4RXx5ENseQ0MO2AzdcWC0uB9TuFzLrZsAJcQlN3wwWMf2R4B7tLeWU9HnO5tfxGmnACALwPaxmfzEQNpC3S45ftae3lq54gpd1uC2bQyeWEzplxM2w3EmJ1uhj8g1JA6qOF52cx6Yh9iBX1m9PDoh499sD8C3BneAQA7Qh1LLX536vLSXU5W2pBYmFvE4txiF0mJvFqm8m/DvKy/m1peLbzEB+tLv5eoKD2Z/LAeQ4fQJKR0g0HWr5lkiZUVJqwG6XlvBsCb1ExuxGKeDgDXAWwrK4bJe8byIh6ASRXjyExifuYUFmZmsXjiOLJGA/PPHVSXdhBIFKOvLCX6XrYZolZD7fJ+1F5yKSoba6isz3trbgk6L+foMgdz3/KzkVVBOmwxjj/Y0hM5ISjT266EUhX4ZEh0sY8q+kn1vYI08YuBbEw4Q0JZUFSkT54r79z85YkIcIn9Vj3bzuB7ysppUIpysanIyeOzmHv+eZx+/hCaJ+cAEoAQIJGYazKISENs73JekAGpJYWUIM7AMsP6V/0K1r36l1G7fD0q69FyEMfLPLIupOUDnAU1wbaaTAOXaJAVlApAB2iGhJoaXAN0ak8AEJCIpveZGQQ1vYo2qWsm2CsKkrvu3PwXwxHgUoDTCTX1PZ9iLQfYDKZOz57G9MQEZg/sh2w2FaxCgCjRupPUYxsiI6/mNrzXMlOBa4p4JAMswTIDOAOyFJXL1mP9lS/HJVf2Q9RKBly0PBmR7w8hKNV/gvTKIVPrZf0SySRp6BLJzBW+iyx4bLwt6f0s0MIUwjetx3VF8a4nhfHCd2y+ayICHHrfYQBfLSZhizW15pnpI1N44bFH0Th1CpRUtLdNtEIQ2tsKB7EFlwoQuzpdAjGDWYPkxKfaZgnmDJAZkDXBWYp1L/8lXPaGV6K6QSzb+7b0wLlJnQ7QLJzzZut8M7tPYuFMc9Ki6UGbA96mn83MDQcw7PfDrjs23zUcAQ4BnoD1vq0gVv+eODKFI+P/jOapkx64xuNSKBOIABLqsR662miFgTg/1UdDDGbrjUFmtoTU8VTpvHLWBNIGqldsxMZrfhWVDWLZAzlCvpg934Uny3lfJwl8jZt4HpaQhUXvCOF1EiPNFcvn6yjcNCaAr7xj866JCHDgfcukg9uaOTaD5x75EdLTpwHSMkEoeC2QQljvq6bRECAIIO2ZYZ5HUU4w6304V/MotSeWemDPIA0wgcEyVZCnKThdQN/LN2PjNVtKpcXSPHB+2nwRsEQ07By3RDQ8/eoN1jT0Su+qz0iEORFCiK3nhdv2m6vAvoZdd2z+y+EIMIBt9axU+5qtLJOY/MlPMXPwWUAkgCAQVbS21R5WQ0xESgN7HlhBrNwvCacZ8hC7sL7JgHmTMZk9cM3rGmLrjSVIpuC0CU4XsOGaf4lLBi5dQhgtP7Xe975ZTj7IQAsbYF00ouHANx7ZemN/kKceA7mJoJAewG6qEpGSV7q11Uvu+KW/munpOPC2uhw2lWZlGbZTM6ew71vfxvRzB4GkBiRVgKrK64oKiKogUVHbSRVIqmBRARL1HJIquFIFRA1IEu+1KljvD1EBiwpIVJUk0Z9FlRo4cftRoj6PKupePVcF2/dUgGofqLYO1HcZTj22HycefgbZmaXEgDtVS5B/ihWK9Y1WtRk7pCDO7AnnJyzADKOUzC242oDB7D6bmcDSbAMAD8dEBtDiIBAO7z+Ipx56EJkEqFK1UCrIqkCSWBgduGo/FlWgUnX7Jz6g6t6Abz6XzWdVamChPs/uF/w/VVCSgPR7yJxYSUVJm0oNqNRAfeuRzjVw/MG9WDza6Ko6mEtqg72LQK5Xdq6GmQFpM3BQA1GzO0tvloarOAMyMLPV9iz1ANZcYeBvZzoBYiDmHT0tIbbV5QCAA2XJgAN7n8Cx/U8rwIQAQWtdExLTAzclJxItI7ScMLoXpJ8jp32JwnhwYRo+u5kPnCvkYa/uwBvIqe1M6WAToTCvyxTcXAQvzmPjW1+H9a9Y59US6QGjNx0+LIf0B3KyJPKQhjJCJzQS/bzTwKnTzyINuva46IT/+TKohTD62+h0X+KA+eo7X/rX473qgXfkS3SyTGJf/QeYenYCnNQUwFQBJ4mVBDCSQV/2rXwQ2vsmzrOy0J5Tv4eN1xUJWIfdIJS0sO8TifLgIvT6lHhe2pMQap+alTCo1KzXh6iCan2gdZdi7kdP4OS+Kc/7ofwEsorBC2EF9buZ1qWmU6V6Xb1FggNpkOsiZOWB+hx1/hmvzJ4X9vPXElKS9sJ+8pABYHvPSggCtvuXgSxlPPHdRzA/O+d0qgYMpD2x1bo+jBUNY0Xvp1/TnpmJ9AmgH+tIBenHKram7pkSHeEgvV+itDO5k8ZKhaQCttpYaDlRddLCSo8aqNoH6rsU808fxsl9x4MUcjBbgvOyQaFNSHNqONPeHx58MpwexeF0JPe81KySfez0sII50MkSVveygZwzfc+9CfBQXQ7CizwQgIOPP4352VnrBRVkapss0EJBbQZfpMFMFMTsRyV0bJhEomQF6cfQkBpw/f2CmLJQJwZUyI6NbNHwEhlv7fS10eGkrxrKc6vvS1XlieefOYyF5xcKqTsDsSmVtCEruDoItS29yZxcUnPEhcd2P+YAeKt/g0GbhDQnFstQgOskj6ent37ohd/r70UPHAzeJp88gKmJgzrK4HlIkXiXfu2JKVE/tgVXgUdCKDiF8apaJlgPS2BympjJ1TiyjREbT6x0dgC0SMDm80mdSETK07JQJwXp74uKljdGguiTTlRqoNo6zD7yCzSmZa40VMsDDRX5HtST5EaHkwl9IQU4s/A5b5uq10yZqAXPj1ygKDcs4KnePx+tCEeUzDzYiwAPmY3pqVkc+cWzClINnvJsid0GJQ5iz+MSFLhsILUAkv4TyRVt60FbAWLKQ6wKx8PXyv4vJzMocXJGfUcTlfC0sA7jiWoNVF2P2e8/CdmgoIjdn+VsHlmP7D1XzFCafg+ZvVc1SeR5S7dfGJUgJzO4XfuAXGKfi79lTwB8nYo+bCUAiwtN7H90XOvXRAFhwDUeVGfdIBI1iKLEwUSkLvHkgWX8FLED0OpLcoXe3uxct22m7uQAZ7YnBdnvlKh9bPYvcSeYEBrexIX8qKIhVp6YWeDkY4eCafmU23ZT4M0ALgWh6eK2JsHiyQBwFs6wYAN2luvSZp5T3ltJaqd1pWQNOmzvCXv8XCgNYB7oNQ88ZIYq+8efQDODvSwraJPQ0xovp8G1+2pgfc+pjjF5uhJFOO3gyXWH9FsssO294L3P997WS+usH0h95yQ5CJF8DSL5HySqtyIRt0FUb0NS+TZE9VAAcVIDVddh8cU5nHl+oaQsUwbg+qE8MCCQeuE36Q36OBi0FaqopT9oc4CSN7iDHaD5ksGcHF6UQ7I5XgM9FQe+ri5HAbz3xNQsnvzxT8PaBa1VDaRk6h1sZZnwCtJNgQ65eRsldb4Q3gwKFwb2pu3kXvP+8du0BhVrDotZIuwC8+jRj77msXZ/9y/f/oM3A/L9SBv/AVm6gbMMaC6A+Aw2/+tfh0hSPWgzssGUN6ZesbtfTumlhpHZEkkiv0tlU8V64T+fBfXDflzZlEyKXPxZXYikLbxHkOrG7Jde8Y3+XvLAgwDw7M+etuExf/AEf0DkRQuYVB8Eqz/NJZ5z/cXIa9ph9GzQi9efooPAE8NvUWZm+foyxFxCswwvnTv0HEQycPQPfu2mTvACwNGbf/ORoze//UOoXTKASvV/UpIA1RpYJjj1xIlAJgBNCDQ00MYTNwtd4NUALl894qSGybQZr+wkA+l4r3SVdb4ssTcEAzkrG4KIBG/qNQmx9ejhE1hcaCh5YMNZiRfW0oMwIhdJMDKBOScTyIFL4ZXYT6YVIEaXELOXbiACvXiQa4/+3e/u+/TQq6c+cuWSi1mO/tG1J45+euiPkFSuJUpOcmUdTj91BLLhRw+k63lmB08m4iBzcd+mC69x5l4PxmGZlzmUAKe5Foemi0/+fd6pIcPXbKp6mfMAL0iAr6/LIQJw5MAhFYLyIgc2bAUd6yUE3tcArSAOp1I4Tww7YfGsIOYixLxwBtVHH5w5/f3vvPTw1/7wvrM9Fkf/+3U/5kr1SqrWnqTqOpw+MA8yXpdTt40UxE2XgTP6V2tVm8rmzE37Z9Z6l239gh2MmdChAdboXr3ojQvHmVumPgtqYKc+y4Xm0EsAAxhIzyzyqbkFb0CkvC6bEJqN2Tq9C9OTwwM39MQecLwCEOc+M5t8Cs0Hv35s7vnDr5l/+PaplToYU5+5/jgqtXeg2nfk9DPHco0Cldc1gzn1XSSAVN9gU8yASUpkXvIjswMwH2w1FssstCqGHMZ4WTI4F4N2WbiyKrYeAbjG6eDBg1NkpvmwHUBpT+tpTui1IOyoy/Y5gOeJS4BDFxBze4jt29IUzb3/hMZPHkLGdMP8Q7ccW+ljMvWZ649Tbd2/k03G4nTiTXF33leVOWY2MaG8cMOLDmRuGrxftqalgkuSZPo5A71fium8OGuIXQKFvePLwcHmXkolJ8y/d+KFaTc4MyEoH0p4ciHozeslGLhQVNISYv91zr2P8z+EH2bLUjS+txvpgX0Qtcv+bP6hP/n+ah2XqZHf/iGtu3Tn4lQDAotqAGb0qva+ZLwue7rceNHCgM4ve8xyhT25lrDWs3ppOTipoOLBXleisuPVKwDLRlOcWWh4UkG4ZAC87JmOs9oaF6MfrCdGEeIWcd085JxLNJVCvHgGze/eB549AVFdfwqV2m1r8JPcmk6daRhQCE0QqWiC87xNr7IsJxMYYE71gM2fNZI/WOGN/bVAPIkQxJ5zD62cQI9p4LnTjQ22loFcSAzsyQm/PoHDBVB80oIiKwtfB4i5C4gXF9D4+6+DT54AVfqASt//Of3tTx9f7WNz7NZ3HZufzu4kfwClPSxxU39/E4lgKzMEFjXoqa2lYO+90LUSJkJhV2QyWldKCy5y3YCCkmibyHBZu+Bq0AsAn5xvVp1UIJc1KEAcNrSzmbBArJZA2glidIA4TZH++DvK2Sc1lQam5Itrll2q9N25OFcF8WLhcu8PzownVr3QclVjnDqdG8R5pRvEGfBMM0MLsEslO4DZ6WJfmkm7756eAfjwi3OVgt4lkYPYHCUvfVsYjK0CxGmK9If3g09O+9OEnjj9wH97Zq2Oz7Fb3/XUuhQZId/61EsJ6wGbSWyQN5CDjQfnHge6N7XPcy6coMJlrvDdaWBvt0BWMJgx0UNhNA0s+/UL4bQfV2zTYoAF70AibKHbEmLuDLF86ifguRN6dkfF1Gb8dK2P0GXgKSAFccN5UUgQFm20wITUjCem3HWcPHCJHdQspct/wKuJsDOvoSWF89ZBDYQXmXAvc29MKap85vF+41FDvZtviOcN1AgtIXYx3XLQuWTwxi0gli8+Bzn5uJYNXpcfkRxY8x9GyIaftAAaGmYGsZ6bZrSxfp2t3s30PuyK1qHivsxuRrJJdLDN6rHbLs22IYgB+9EQVmuY9IYHPnXyTG6KuFe6yMVZuZzTAeUQt9+nVXLCQrywAPmzf9SyoeLVIAu41VXWzrJ5/hv3fRveF9eSgJtWBrA3mHMgZrlpRPCkiHQDulzkwZ30/hXO08Z+Tzqrh3nyL39td2944PRzr5tJU3Z1uUTBNO1AquYzbKsIsdz3PZBkW5NspzOpmuQ1B/jMy44/4Gp1JQQvek2pMy/BkXp9H6QKodkkhTcFnqWtdQjBzs+skPYxWekSTvS0HthtnxPve848sJvlwGEVWdgqpyRCUIzXcjuIuUuIXzwEPv58MA/Pwquq5NYcYMLioIocNLwiHR0P5szzkhwkJ8KOQpmnfVOro20iIkhY+HUVWSEKIfPTiHxpzGodk94ZxHFuFTdb/ljM6nDJzJZ84LwAcVmEohXEaQr58+/pQZsBNvHgTRB0wV67dM+A0rbsDeD8WRYGbG8EYTWwm5zJppOmV5RDOpXsBmkczJUzxe1BpVlBF9tZzJNf+41zIx/ObTmlH9oKqshKSvhKIUYR4k5htjKID+8HSaknkuqpSsKbW6dubzwHAG9HsBC30a5NwKSYTdLCeFh9byd+sktsqOPjVaZ5XteCXDjmrQZ1wW0E6LnWUpybFRz25V8yxG3CbG0hTpuQB/Z64TIRzviw97RlLY/OW+o7B4mzLaaAx9VD6GGvnbSpPKoa5JlBmdHNKUKVIN3cNtPYhBzIxuPauhGTfrZhRvNe6aYoMSb/72t3j/YewER7S5MQKPHEbaRCdwM3tE49T78IyjJvLh6Fnteu7k5r6oEJ6Q6XcHALrkCH1UJZ0USQdjbll+x14PFre9mklL2QmJUJqssm2Z4QfgTCQeym5fGOnlyliBkzoSulMHTGwV1riHEWEAPgZ37iog6B93U30yR7w3u+ct3aeN8/7VfyoZkrYpdBQbtpeOJavuYHY2UZOA7axBa7+Ug7YCvGewu/4p6vv+7esR5dZosmmEs6LwJrB/HJadDCfBB18CRD0Nldf8+hNTkynI0gP7/Mq92Fv+KmrUiTYT/70io0dlONdA0DbMMTf7aGzB1rP0tnIx+zzK06ivbGIG4iDJPxmkFsG1i/cMBFGILZzoF08JMsN6z2Qbn24c8PAtlNsP17TZrY3YdyINcG1QMUQW2E10ETftIjr8fyU1rCOmGvFnjH31x170QvAzxeBLEzxLwCENsqqqMHQu+L0PO6ZbjsVWLrhn9/18DqwXtbP8BjfnedQsFuIeSiptaTB3yohdmue2fxy+neIHzmAHX7eClkzfQX/vYN944CvbxSZ65yqVuIW4XPeIkZOZo/DcpS22u44H09LxxAvErNnK/9h1v7AVkHsi1hHXBassC4iTT4FWO5GRZcVieSFZuj2J18GZHvjeZDjV3feOO9O4AeX2pW3vb68dYJi5LqsZZF622SGe0gPnEkHLjlva/XHCW31vHwhvfctQrNO3g7mLdSrg+ZK+H3s2t+LYPvnb3HdvAmvYXAywdkXsPKILHkB4DUTBjs+ubW3cNAXOzb2J6OEIdh3pY9G9pBXDpVaOaI7WkWwBusxF2QEABoE1almbMcQAFe6UEpw34QhSVuM692gYte1f5FvrxQcWEf8LCoJ4B+1/8bPP/gPacAs9HBbSHuYnDXVcIjhJhOTbuaZD/SkFuCtkUDrp0r74WV9i1MtAwa+3H5AuY6weF3XfchZr97jn+89Poapd12wgN+y91Xj52X8J5rD1znFr2YuQWtZw8xA1kGNBt6wjOVNEoLyztLKN4EvSzCStmPrv/sOIG/4Oa45eO2smQmsQwK1hHIDZTsj7DqLFisXBZmrzBjkhnX3fOvxkZwHts5BTgMkaH1ZMIVgxig+ZOu+XU7+dC+/eFnN7znKysakfjh9SM7AHkLuGQpokKfh/wVKi8XZEnEgr24bpj1LDl8XwB4cOxNY3Wc53buJMRtr58BsLcdxEsNs3WTekZjPkxY5HUwdd2wc8VDST+8/k9GAL4awB6ng50eDh6XauFwwOdS0AhKKYthOXsAdzFw5b3X3LNj9zVjM7gA7Nx2aGeMFdg9W4g7xYoX5lFIUhCFzrYAcSnU2za85ysjKw/x58Z/cP3nhgjyaoB3AXI2/ANlSR/hvMd2XljN6GbXBy3nbpkxy8AuAFfe95a7h+97890TuICMzul//ql9gwA9VujL2+KbUf5Fyu1W+AwqvFcceRbiuZ+rRRP1zAuzQLi6N+WdQldr+Z/IZWfadSe/8f5VvdS+/eFPDgEYIvAQKBskyE3+guCuT6/0HrO3vrFbb1mv7zZLxGMA14nk2ANv/eYMLlA75wsd0qf2TQC6XHENIBYvPAvx3OOugF0vDuOKedzU/i4BniXmoblvfmDNirrfWb9pgCAHAB4g4gFCBhAPEmS/7T1p15bjGQKP6zU2xol4/Dtv++sJXCR2PgC8A8Cf58mjNt+yW4hdk3X3RPLisxDPPaEXZFGrCbnlt5YFMIh5EsDg3Dc/MINoPbdS5xg6dTvk5WlidFM/4Z8VpQO4rs7xLQDqG9/9F/0RqR4DmD9/1QSA3SV54HCosiKp57wbpxaDtmXZVgXxlwciVj22Wj0XQlJc9KLdQNwx9cyrLaq2Ahjf+O4vD0a0eghgfP6qMQYmzx7iLsJstfWrPTTYpD3xcMSrVwBWdI1w26nL3UDcRay4b/1a/DWbAHx1441fHt1445eiLu4JgG+/ahSMybOBuJvBHVfXtW8pvrItx98LYHzjjV8aiqhd7AArG0HZwutdQtxNhIIrfUBSyy8St5p/0xYAD2+88UujG2/8YvTGuMjiwAW7ed8EgC2F2G5JwJeWmfCoPvMIxOkTdmFu0qvek+nAE8SBCS0X33Bx4HYxPP+1Wag2TDvn7v7geR8zfsnv/K9hMAYArk8/8Ml6BLg7gIcAPFyaoCjJdCwH4uToBCpHnrJT6s8yE7cUgM3DWYA1yB+aOf/A/dNhgEcAbPH+hiunH/jkRAS4O4jHANywWhAn87Oo/uL7SkrYDpRrCrBdYxkqkbNz7u4PjZ/LQ97/rj8bIOZhqFrnTSW1qu+bfuCToxHg7gAe0DOXNy0Z4i5Tz+t+9vdK+4pWHljoFlirCnA+HT0GYHT2ng+PrxW0UFOkhgFspdb9u6IHXgbEukYCrUE9C4irzz+O5MQhQFRDDex74HDZ+tUG2N9vEkAdjDrA47NjH1kRoPv/zc4BgAfBGAIwBPDWNt/B/xtumX7gkyNRAy8d4jqAbe0h7n5w50MsTh5H7dlHgaRiJYSCODc7I/iwNQO47P17AEwAPKHbEkx0+A4DAAbA6Ad4EMCglQZL+w57px/4xGCMQqyElFhhiPue/C4obWjPm3i90ETJf3bOAV7rq4DS6IzB6Qc+MYEYB16G3X7VhNZnrWdfnEXqObviVa7lUmHiZMkP33u243yG9/wHWEE8BuALBYj57CHOrnglWFTC9c56mtfAdk3f/4lRxETGKunhcuWw5IRH9dgkqi88nVvYxZuxHHyeW3jxIpcQe6fv//hgTCWvrG03s5jbON0lp57Ty18JpgTF6ew4ZwtYn2ObXKtWsr0F8O1XzWg9PLuSELNI0PyVX0fYJze/7BejR7TFLIDt0/d/fCYCvDoQj2vvsDSIuT3E6eWvgFy3MRjMcZkXvrgd8iyAoen7Pz6OWI12nkGMzhA3XnWV68nrL8NTsgjjRUjyBQnvhQnwSkNsVursuwTNl73GrQjEMli18iKWErMAhma+9bFxxHrg8wti7gZi70Fz8xZkl14exITZ98ilEHOENwJ81hDv7eB00Wrqft6hNl79Rsi+y4oyAtxGD/MFG224kOG98AEOId7THcTtIxQsEjRe9XowCU9KhA2jyzMpFxTEewEMXujwAhdSIqMbu3nfTgA3dai87CrhIRbn0bf/ERDLcM04283S7Uyt4D0/Exm7Zu77r8OIc+LOS2+8A8C/LejiZaSeZd8lWPwX14BFUj6oy2vi818XzwJ438UE78XngcMqtlGsQOpZLJ5G3+RPQemiTi0L3UvNraOhvJ9x89xGVZwzD7wHwPDMfTsmECd1XlAg7wAwAr8ccxkQk8zQd+AxiMWTtrO7UhPCiojSIxsASOcC4FkwRmbuu2kn4qzkC9ob74SZY3cWRUC1o8+gMnVQLxBDVhNTsKoRhwuXU5kGprUAWHnde2+aQJxWf1GAPKRlxZaOELeZMJrMz6J26HFQc8EuVSA41yCQqFxCUDsPjJUCeBLg4Zl7b6oj9oW4KEEe1rJiy3IhJpmhcvwQqkf3q+gEw+spgdxiMS0kBHXywLRUgCcBjMzc+4ejiI1NegzkZc56puYialMTqEw/72RF4IE1tORPCi3WE4M6SYi2zVUmAYzM7v7oKGJnnp4EWU0rJ9ywHIgNyH1TByDmjoGypvPG1gNT0SHnwLQAUzsJEXjxPQDvnN390THE1lLRcPO+ARCGAQyTr5OXMMNDcIZk7hgqc1MQJ6dAtrcE5dQBFcAseOBcFIOTCijLJgEeBWN0dvcfTMQfLQJcbp/aN0hqBsh2qKbVS571TDKDOD2L5NQ0xMJJJKenNZTkPCnlPTC5IqLaOsj1G3DFFZuObdx42ePNTO568nO/dVf8cSLAS12Epl+DPAjQEMgA3d3Uff9Ii+YCqLGgohmnZ4LX1l92mRTrLuFNlex4pVY9xowHJ5rrdzZGXhs9bQR4hQ/aH/98CLpxCKmGIf0gDPghOmqx9hcBuCThufUJzyQk589I8XenUrEXhInmLa+rx6MbLVq0aNGiRYsWLVq0aNGiRYsWLVq0aNGiRYsWLVq0aNGiRYsWLVq0aNGiRYsWLVq0aNGiRYsWLVq0aNGiRYsWLVq0aNGiRYsWLVq0aNGiRYsWLVq0aNGiRVtT+/+JPxHn+NhcyAAAAABJRU5ErkJggg=="
     },
  "notes": "",
  "owner": "Microsoft",
  "privacyInformationUrl": "",
  "publisher": "Microsoft"
}
"@

##################################################

write-host "Publishing" ($JSON | ConvertFrom-Json).displayName
$graphApiVersion = "Beta"
$App_resource = "deviceAppManagement/mobileApps"

$uri = "https://graph.microsoft.com/$graphApiVersion/$($App_resource)"
$Create_Application = Invoke-MgGraphRequest -Uri $uri -Method Post -ContentType "application/json" -Body $JSON -OutputType PSObject

write-output "Application created as $($Create_Application.displayName)/$($create_Application.id)"

$ApplicationId = $Create_Application.id

$Assign_Application = Add-ApplicationAssignment -ApplicationId $ApplicationId -TargetGroupId $intunegrp.id -InstallIntent "required"
write-output "Assigned '$intunegroupname' to $($Create_Application.displayName)/$($Create_Application.id) with" $Assign_Application.InstallIntent "install Intent"




##Edge Windows
$JSON = @"
{
  "@odata.type": "#microsoft.graph.windowsMicrosoftEdgeApp",
  "autoAcceptEula": true,
  "description": "Edge - Assigned",
  "developer": "Microsoft",
  "displayName": "Edge - Assigned",
  "informationUrl": "",
  "isFeatured": false,
  "largeIcon": {
    "type": "image/png",
    "value": "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"
    },
  "localesToInstall": [
    "en-gb"
  ],
  "notes": "",
  "owner": "Microsoft",
  "privacyInformationUrl": "",
  "publisher": "Microsoft",
  "channel": "stable"
}
"@

##################################################

write-host "Publishing" ($JSON | ConvertFrom-Json).displayName

$graphApiVersion = "Beta"
$App_resource = "deviceAppManagement/mobileApps"

$uri = "https://graph.microsoft.com/$graphApiVersion/$($App_resource)"
$Create_Application = Invoke-MgGraphRequest -Uri $uri -Method Post -ContentType "application/json" -Body $JSON -OutputType PSObject

write-output "Application created as $($Create_Application.displayName)/$($create_Application.id)"

$ApplicationId = $Create_Application.id
##Sleep to let app publish
start-sleep -Seconds 10
$Assign_Application = Add-ApplicationAssignment -ApplicationId $ApplicationId -TargetGroupId $intunegrp.id -InstallIntent "required"
write-output "Assigned '$intunegroupname' to $($Create_Application.displayName)/$($Create_Application.id) with" $Assign_Application.InstallIntent "install Intent"



$newpath = "c:\temp\" + $path2 + "\Applications"
#Create folder for apps
New-Item -ItemType Directory -Path $newpath




#####Add Project as Required to licensed users

New-Item -ItemType Directory -Path $newpath"\Project"
# Find the app
$appurl = "https://github.com/andrew-s-taylor/public/raw/main/Install-Scripts/Project/Deploy-Application.intunewin"

#Set the download location
$output = "c:\temp\" + $path2 + "\Applications\Project\Deploy-Application.intunewin"

#Download it
Invoke-WebRequest -Uri $appurl -OutFile $output -Method Get -UseBasicParsing


$SourceFile = $output

# Defining Intunewin32 detectionRules
#$DetectionXML = Get-IntuneWinXML "$SourceFile" -fileName "detection.xml"

# Defining Intunewin32 detectionRules
$FileRule = New-DetectionRule -File -Path "C:\Program Files\Microsoft Office\root\Office16" `
    -FileOrFolderName "winproj.exe" -FileDetectionType exists -check32BitOn64System False

# Creating Array for detection Rule
$DetectionRule = @($FileRule)

$ReturnCodes = Get-DefaultReturnCodes

# Win32 Application Upload
Invoke-UploadWin32Lob -SourceFile "$SourceFile" -DisplayName "Microsoft-Project" -publisher "Microsoft" `
    -description "Microsoft Project x64 Current Branch" -detectionRules $DetectionRule -returnCodes $ReturnCodes `
    -installCmdLine "ServiceUI.exe -Process:explorer.exe Deploy-Application.exe" `
    -uninstallCmdLine "ServiceUI.exe -Process:explorer.exe Deploy-Application.exe -DeploymentType Uninstall"

# Assign it
$ApplicationName = "Microsoft-Project"

$Application = Get-IntuneApplication | Where-Object { $_.displayName -eq "$ApplicationName" }

#Install
$projectinstallid = $projectinstall.Id
$graphApiVersion = "Beta"
$ApplicationId = $Application.id
$TargetGroupId1 = $projectinstallid
$InstallIntent1 = "required"


#Uninstall
$projectuninstallid = $projectuninstall.Id
$ApplicationId = $Application.id
$TargetGroupId = $projectuninstallid
$InstallIntent = "uninstall"
$Resource = "deviceAppManagement/mobileApps/$ApplicationId/assign"
$JSON = @"

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
    ]
}

"@

$uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
Invoke-MgGraphRequest -Uri $uri -Method Post -Body $JSON -ContentType "application/json" -OutputType psobject

####################################################
# MS VISIO
####################################################
New-Item -ItemType Directory -Path $newpath"\Visio"
# Find the app
$appurl = "https://github.com/andrew-s-taylor/public/raw/main/Install-Scripts/Visio/Deploy-Application.intunewin"

#Set the download location
$output = "c:\temp\" + $path2 + "\Applications\Visio\Deploy-Application.intunewin"

#Download it
Invoke-WebRequest -Uri $appurl -OutFile $output -Method Get -UseBasicParsing


$SourceFile = $output

# Defining Intunewin32 detectionRules
#$DetectionXML = Get-IntuneWinXML "$SourceFile" -fileName "detection.xml"

# Defining Intunewin32 detectionRules
$FileRule = New-DetectionRule -File -Path "C:\Program Files\Microsoft Office\root\Office16" `
    -FileOrFolderName "visio.exe" -FileDetectionType exists -check32BitOn64System False

# Creating Array for detection Rule
$DetectionRule = @($FileRule)

$ReturnCodes = Get-DefaultReturnCodes

# Win32 Application Upload
Invoke-UploadWin32Lob -SourceFile "$SourceFile" -DisplayName "Microsoft-Visio" -publisher "Microsoft" `
    -description "Microsoft Visio x64 Current Branch" -detectionRules $DetectionRule -returnCodes $ReturnCodes `
    -installCmdLine "ServiceUI.exe -Process:explorer.exe Deploy-Application.exe" `
    -uninstallCmdLine "ServiceUI.exe -Process:explorer.exe Deploy-Application.exe -DeploymentType Uninstall"

# Assign it
$ApplicationName1 = "Microsoft-Visio"

$Application1 = Get-IntuneApplication | Where-Object { $_.displayName -eq "$ApplicationName1" }

#Install
$visioinstallid = $visioinstall.Id
$graphApiVersion = "Beta"
$ApplicationId1 = $Application1.id
$TargetGroupId2 = $visioinstallid
$InstallIntent2 = "required"


#Uninstall
$visiouninstallid = $visiouninstall.Id
$TargetGroupId3 = $visiouninstallid
$InstallIntent3 = "uninstall"
$Resource1 = "deviceAppManagement/mobileApps/$ApplicationId1/assign"
$JSON1 = @"

{
    "mobileAppAssignments": [
      {
        "@odata.type": "#microsoft.graph.mobileAppAssignment",
        "target": {
        "@odata.type": "#microsoft.graph.groupAssignmentTarget",
        "groupId": "$TargetGroupId2"
        },
        "intent": "$InstallIntent2"
    },
    {
        "@odata.type": "#microsoft.graph.mobileAppAssignment",
        "target": {
        "@odata.type": "#microsoft.graph.groupAssignmentTarget",
        "groupId": "$TargetGroupId3"
        },
        "intent": "$InstallIntent3"
    }
    ]
}

"@

$uri1 = "https://graph.microsoft.com/$graphApiVersion/$($Resource1)"
Invoke-MgGraphRequest -Uri $uri1 -Method Post -Body $JSON1 -ContentType "application/json" -OutputType PSObject


#####M365 Apps (Win32)

New-Item -ItemType Directory -Path $newpath"\Office"
# Find the app
$appurl = "https://github.com/andrew-s-taylor/public/raw/main/Install-Scripts/O365/Output/setup.intunewin"

#Set the download location
$output = "c:\temp\" + $path2 + "\Applications\Office\office.intunewin"

#Download it
Invoke-WebRequest -Uri $appurl -OutFile $output -Method Get -UseBasicParsing


$SourceFile = $output
# Defining Intunewin32 detectionRules
#$DetectionXML = Get-IntuneWinXML "$SourceFile" -fileName "detection.xml"

# Defining Intunewin32 detectionRules
$RegistryRule = New-DetectionRule -Registry -RegistryKeyPath "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Office\ClickToRun" -RegistryDetectionType exists -check32BitRegOn64System False

# Creating Array for detection Rule
$DetectionRule = @($RegistryRule)


$ReturnCodes = Get-DefaultReturnCodes

# Win32 Application Upload
Invoke-UploadWin32Lob -SourceFile $SourceFile -DisplayName "Microsoft 365 Apps" -publisher "Microsoft" `
    -description "Microsoft 365 Apps" -detectionRules $DetectionRule -returnCodes $ReturnCodes `
    -installCmdLine 'setup.exe /configure Configuration.xml' `
    -uninstallCmdLine 'setup.exe /configure uninstall.xml'

# Assign it
$ApplicationName = "Microsoft 365 Apps"

$Application = Get-IntuneApplication | Where-Object { $_.displayName -eq "$ApplicationName" }

#Install
$graphApiVersion = "Beta"
$O365Id = $Application.id
$TargetGroupId1 = $intunegrp.id
$InstallIntent1 = "required"


$Resource = "deviceAppManagement/mobileApps/$O365Id/assign"
$JSON = @"
{
    "mobileAppAssignments": [
      {
        "@odata.type": "#microsoft.graph.mobileAppAssignment",
        "target": {
        "@odata.type": "#microsoft.graph.allDevicesAssignmentTarget"
        },
        "intent": "$InstallIntent1"
    }
    ]
}
"@

$uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
Invoke-MgGraphRequest -Uri $uri -Method Post -Body $JSON -ContentType "application/json" -OutputType PSObject



##Assign Store Apps
$sapps = Get-MSStoreApps

foreach ($sapp in $sapps) {
    $sappdisplay = $sapp.displayName
    $sappid = $sapp.id
    $sappgroup = $intunegrp.Id
    if ($storeapps.contains($sappdisplay )) {
        write-output "Assigned $intunegroupname to $($sappdisplay)/$($sappid)"
        Add-StoreAppAssignment -StoreAppID $sappid -TargetGroupId $sappgroup
    }
    else {
        write-output "NOT Assigning" + $sappdisplay

    }

}

write-output "Apps Configured and Assigned"



###############################################################################################################
######                                     Create Enrollment Status Page                                 ######
###############################################################################################################


$graphApiVersion = "beta"
$Resource = "deviceManagement/deviceEnrollmentConfigurations"
$uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"
if ($whitelabel) {
    $DisplayName = $whitelabel + "AutoPilot Enrollment"
}
else {
    $DisplayName = "AutoPilot Enrollment"
}
$json = @"
    {
        "@odata.type": "#microsoft.graph.windows10EnrollmentCompletionPageConfiguration",
        "displayName": "$DisplayName",
        "description": "Custom Enrollment Status",
        "showInstallationProgress": true,
        "blockDeviceSetupRetryByUser": false,
        "allowDeviceResetOnInstallFailure": true,
        "allowLogCollectionOnInstallFailure": true,
        "customErrorMessage": "Enter your custom error here",
        "installProgressTimeoutInMinutes": 120,
        "allowDeviceUseOnInstallFailure": true,
        "trackInstallProgressForAutopilotOnly": true,
	 "disableUserStatusTrackingAfterFirstUser": true,
        "selectedMobileAppIds": [
            "$O365Id"
                    ]
}
"@

Write-Verbose "POST $uri`n$json"

try {
    $enrollment = Invoke-MgGraphRequest -Uri $uri -Method POST -Body $JSON -ContentType "application/json" -OutputType PSObject

}
catch {
    Write-Error $_.Exception 
    
}

##Assign it
# Defining Variables

$id = $enrollment.id
#Remove extra text from the ID
#$id2 = $id3.split('_')
#$id = $id2[0]

$groupid = $autopilotgrp.id       
$graphApiVersion = "beta"
$Resource = "deviceManagement/deviceEnrollmentConfigurations"        
$uri = "https://graph.microsoft.com/$graphApiVersion/$Resource/$id/assign"        





$json = @"
    {
        "enrollmentConfigurationAssignments": [
            {
                "target": {
                    "@odata.type": "#microsoft.graph.groupAssignmentTarget",
                    "groupId": "$groupid"
                }
            }
        ]
    }
"@

Write-Verbose "POST $uri`n$json"

try {
    Invoke-MgGraphRequest -Uri $uri -Method POST -Body $JSON -ContentType "application/json" -OutputType PSObject

}
catch {
    Write-Error $_.Exception 
            
}


#######################################################

write-output "Enrollment Status Page Configured and Assigned"

#############################################################################################
###########  This script will create an Autopilot Device Prep Policy in Intune ##############
#############################################################################################


##Set Name
write-output "Setting Name for Autopilot Device Prep Policy"
if ($whitelabel) {
    $DisplayName = $whitelabel + "AutopilotDevicePrep"
}
else {
    $DisplayName = "AutopilotDevicePrep"
}
write-output "Name set to $DisplayName"

##Find Bloat ID
write-output "Finding Bloat ID"
if ($whitelabel) {
    $PolicyName = $whitelabel + "Remove Bloat"
}
else {
    $PolicyName = "Remove Bloat"
}
$bloat = Get-DeviceManagementScripts -Name "$PolicyName"
$bloatid = $bloat.id
write-output "Bloat ID is $bloatid"


$intuneusersid = $intunegrp.id


##Create Autopilot Device Prep Policy
write-output "Creating Autopilot Device Prep Policy"
$apv2uri = "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies"

$json = @"
{
	"description": "",
	"name": "$DisplayName",
	"platforms": "windows10",
	"roleScopeTagIds": [
		"0"
	],
	"settings": [
		{
			"@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
			"settingInstance": {
				"@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
				"choiceSettingValue": {
					"@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
					"children": [],
					"settingValueTemplateReference": {
						"settingValueTemplateId": "5874c2f6-bcf1-463b-a9eb-bee64e2f2d82"
					},
					"value": "enrollment_autopilot_dpp_deploymentmode_0"
				},
				"settingDefinitionId": "enrollment_autopilot_dpp_deploymentmode",
				"settingInstanceTemplateReference": {
					"settingInstanceTemplateId": "5180aeab-886e-4589-97d4-40855c646315"
				}
			}
		},
		{
			"@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
			"settingInstance": {
				"@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
				"choiceSettingValue": {
					"@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
					"children": [],
					"settingValueTemplateReference": {
						"settingValueTemplateId": "e0af022f-37f3-4a40-916d-1ab7281c88d9"
					},
					"value": "enrollment_autopilot_dpp_deploymenttype_0"
				},
				"settingDefinitionId": "enrollment_autopilot_dpp_deploymenttype",
				"settingInstanceTemplateReference": {
					"settingInstanceTemplateId": "f4184296-fa9f-4b67-8b12-1723b3f8456b"
				}
			}
		},
		{
			"@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
			"settingInstance": {
				"@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
				"choiceSettingValue": {
					"@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
					"children": [],
					"settingValueTemplateReference": {
						"settingValueTemplateId": "1fa84eb3-fcfa-4ed6-9687-0f3d486402c4"
					},
					"value": "enrollment_autopilot_dpp_jointype_0"
				},
				"settingDefinitionId": "enrollment_autopilot_dpp_jointype",
				"settingInstanceTemplateReference": {
					"settingInstanceTemplateId": "6310e95d-6cfa-4d2f-aae0-1e7af12e2182"
				}
			}
		},
		{
			"@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
			"settingInstance": {
				"@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
				"choiceSettingValue": {
					"@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
					"children": [],
					"settingValueTemplateReference": {
						"settingValueTemplateId": "bf13bb47-69ef-4e06-97c1-50c2859a49c2"
					},
					"value": "enrollment_autopilot_dpp_accountype_1"
				},
				"settingDefinitionId": "enrollment_autopilot_dpp_accountype",
				"settingInstanceTemplateReference": {
					"settingInstanceTemplateId": "d4f2a840-86d5-4162-9a08-fa8cc608b94e"
				}
			}
		},
		{
			"@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
			"settingInstance": {
				"@odata.type": "#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance",
				"settingDefinitionId": "enrollment_autopilot_dpp_timeout",
				"settingInstanceTemplateReference": {
					"settingInstanceTemplateId": "6dec0657-dfb8-4906-a7ee-3ac6ee1edecb"
				},
				"simpleSettingValue": {
					"@odata.type": "#microsoft.graph.deviceManagementConfigurationIntegerSettingValue",
					"settingValueTemplateReference": {
						"settingValueTemplateId": "0bbcce5b-a55a-4e05-821a-94bf576d6cc8"
					},
					"value": 120
				}
			}
		},
		{
			"@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
			"settingInstance": {
				"@odata.type": "#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance",
				"settingDefinitionId": "enrollment_autopilot_dpp_customerrormessage",
				"settingInstanceTemplateReference": {
					"settingInstanceTemplateId": "2ddf0619-2b7a-46de-b29b-c6191e9dda6e"
				},
				"simpleSettingValue": {
					"@odata.type": "#microsoft.graph.deviceManagementConfigurationStringSettingValue",
					"settingValueTemplateReference": {
						"settingValueTemplateId": "fe5002d5-fbe9-4920-9e2d-26bfc4b4cc97"
					},
					"value": "Contact your oganization's support person for help."
				}
			}
		},
		{
			"@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
			"settingInstance": {
				"@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
				"choiceSettingValue": {
					"@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
					"children": [],
					"settingValueTemplateReference": {
						"settingValueTemplateId": "a2323e5e-ac56-4517-8847-b0a6fdb467e7"
					},
					"value": "enrollment_autopilot_dpp_allowskip_1"
				},
				"settingDefinitionId": "enrollment_autopilot_dpp_allowskip",
				"settingInstanceTemplateReference": {
					"settingInstanceTemplateId": "2a71dc89-0f17-4ba9-bb27-af2521d34710"
				}
			}
		},
		{
			"@odata.type": "#microsoft.graph.deviceManagementConfigurationSetting",
			"settingInstance": {
				"@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
				"choiceSettingValue": {
					"@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
					"children": [],
					"settingValueTemplateReference": {
						"settingValueTemplateId": "c59d26fd-3460-4b26-b47a-f7e202e7d5a3"
					},
					"value": "enrollment_autopilot_dpp_allowdiagnostics_1"
				},
				"settingDefinitionId": "enrollment_autopilot_dpp_allowdiagnostics",
				"settingInstanceTemplateReference": {
					"settingInstanceTemplateId": "e2b7a81b-f243-4abd-bce3-c1856345f405"
				}
			}
		},
		{
			"settingInstance": {
				"@odata.type": "#microsoft.graph.deviceManagementConfigurationSimpleSettingCollectionInstance",
				"settingDefinitionId": "enrollment_autopilot_dpp_allowedappids",
				"settingInstanceTemplateReference": {
					"settingInstanceTemplateId": "70d22a8a-a03c-4f62-b8df-dded3e327639"
				},
				"simpleSettingCollectionValue": [
					{
						"@odata.type": "#microsoft.graph.deviceManagementConfigurationStringSettingValue",
						"value": "{\"id\":\"$o365id\",\"type\":\"#microsoft.graph.win32LobApp\"}"
					}
				]
			}
		},
		{
			"settingInstance": {
				"@odata.type": "#microsoft.graph.deviceManagementConfigurationSimpleSettingCollectionInstance",
				"settingDefinitionId": "enrollment_autopilot_dpp_allowedscriptids",
				"settingInstanceTemplateReference": {
					"settingInstanceTemplateId": "1bc67702-800c-4271-8fd9-609351cc19cf"
				},
				"simpleSettingCollectionValue": [
					{
						"@odata.type": "#microsoft.graph.deviceManagementConfigurationStringSettingValue",
						"value": "$bloatid"
					}
				]
			}
		}
	],
	"technologies": "enrollment",
	"templateReference": {
		"templateId": "80d33118-b7b4-40d8-b15f-81be745e053f_1"
	}
}
"@

$apv2policy = Invoke-MgGraphRequest -uri $apv2uri -Method Post -Body $json -ContentType "application/json" -OutputType PSObject
write-output "Autopilot Device Prep Policy Created"
$apv2policyid = $apv2policy.id


##Check if enterprise app exists
$spid = "f1346770-5b25-470b-88bd-d5744ab7952c"
write-output "Checking if Enterprise App exists"
$lookforsp = get-mgserviceprincipal -filter "AppID eq '$spid'"

if (!$lookforsp) {
    write-output "Enterprise App does not exist, creating"
    $ServicePrincipalId = @{
        "AppId" = "$spid"
    }
   $appregid = New-MgServicePrincipal -BodyParameter $ServicePrincipalId
    write-output "Enterprise App created"
}

##Get app ID
Write-Output "Getting App ID"
if ($lookforsp) {
    $ownerid = $lookforsp.id
}
else {
    $ownerid = $appregid.id
}
write-output "App ID is $ownerid"


##Create device group
write-output "Creating Device Group"
$groupuri = "https://graph.microsoft.com/beta/groups"

$groupjson = @"
{
	"description": "Autopilot DevicePrep Group",
	"displayName": "$DisplayName",
	"mailEnabled": false,
	"mailNickname": "$DisplayName",
	"securityEnabled": true
}
"@

$group = Invoke-MgGraphRequest -Uri $groupuri -Method Post -Body $groupjson -ContentType "application/json" -OutputType PSObject
$groupid = $group.id
write-output "Device Group Created"


##Set owner
write-output "Setting Owner"
$owneruri = "https://graph.microsoft.com/beta/groups/$groupid/owners/`$ref"

$ownerjson = @"
{
	"@odata.id": "https://graph.microsoft.com/beta/directoryObjects/$ownerid"
}
"@

Invoke-MgGraphRequest -uri $owneruri -Method Post -Body $ownerjson -ContentType "application/json" -OutputType PSObject
write-output "Owner set"


##Assign policy to device group
write-output "Assigning Policy to Device Group"
$jituri = "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies/$apv2policyid/assignJustInTimeConfiguration"

$jitjson = @"
{
  "justInTimeAssignments": {
    "targetType": "entraSecurityGroup",
    "target": [
      "$groupid"
    ]
  }
}
"@

Invoke-MgGraphRequest -uri $jituri -Method Post -Body $jitjson -ContentType "application/json" -OutputType PSObject
write-output "Policy Assigned to Device Group"


##Assign user group
write-output "Assigning Policy to User Group"
$v2assignuri = "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies('$apv2policyid')/assign"

$v2json = @"
{
	"assignments": [
		{
			"id": "",
			"source": "direct",
			"target": {
				"@odata.type": "#microsoft.graph.groupAssignmentTarget",
				"deviceAndAppManagementAssignmentFilterType": "none",
				"groupId": "$intuneusersid"
			}
}
	]
}
"@

Invoke-MgGraphRequest -uri $v2assignuri -Method Post -Body $v2json -ContentType "application/json" -OutputType PSObject
write-output "Policy Assigned to User Group"

#############################################################################################


#Check if noupload is set
if ($noupload) {
    $breakglassdetails = "Breakglass Details

    Username: $bglassname
    Password: $bgpassword"
    
    $breakglassdetails | Set-Content "$path\BreakGlassDetails.txt"
## Send an email via Graph to the email address set earlier and attach the Android QR code and Breakglass details

$attachmentpath = "$path\BreakGlassDetails.txt"
$attachmentmessage = [Convert]::ToBase64String([IO.File]::ReadAllBytes($AttachmentPath))
$attachmentname = (Get-Item -Path $attachmentpath).Name

##Get forename from email address
$emailsplit = $emailsend.split('@')
$namesplit = $emailsplit[0].split('.')
if ($namesplit.Count -gt 1) {
    $forename = $namesplit[0]
} else {
    $forename = $emailsplit[0]
}


$Header = @{
    "authorization" = "Bearer $sendgridtoken"
}

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
                                   <h1>Deployment Complete</h1>
                                   <p>Dear $forename, your Intune Deployment has completed, please find your Breakglass details attached.  You can learn more about Breaklass accounts in the links below</p>
                                   
                                   <p>It is important you store these details somewhere secure, ideally in physical format such as in a fireproof safe</p>
                                   <p>You can access some important links, guides and details of your deployed policies <a href="https://deploy.euctoolbox.com/infoandlinks.php">here</a></p>
                                   
                                   <p>Should you require additional custom policies, application packaging or would like us to maintain your environment, please contact us <a href="https://contact.euctoolbox.com">here</a></p>
                              </td>
                         </tr>
                         </table>
</body>
</html>
"@ 

##Email it
write-output "Sending Email"
$Body = @{
    "personalizations" = @(
        @{
            "to"      = @(
                @{
                    "email" = $emailsend
                }
            )
            "subject" = " Intune Deployment Complete "
        }
    )
    "content"          = @(
        @{
            "type"  = "text/html"
            "value" = $bodycontent
        }
    )
    "from"             = @{
        "email" = "deployment@euctoolbox.com"
        "name"  = "DeployIntune"
    }
    "attachments" = @(
        @{
            "content"=$attachmentmessage
            "filename"=$attachmentname
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

##Send email to me with transcript
$Body = @{
    "personalizations" = @(
        @{
            "to"      = @(
                @{
                    "email" = "andrew.taylor@andrewshomelab.co.uk"
                }
            )
            "subject" = " Intune Deployment Complete "
        }
    )
    "content"          = @(
        @{
            "type"  = "text/html"
            "value" = "Deployment completed attached from $emailsend."
        }
    )
    "from"             = @{
        "email" = "deployment@euctoolbox.com"
        "name"  = "DeployIntune"
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


}

###############################################################################################################
######                                          DONE                                                     ######
###############################################################################################################
if (($aadlogin -ne "yes")) {
Stop-Transcript
}
