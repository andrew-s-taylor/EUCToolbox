<#
.SYNOPSIS
Compares live tenant environment to last backup to monitor for drift
.DESCRIPTION
Compares live tenant environment to last backup to monitor for drift
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
.GUID 8d694a5a-bebb-4fb1-91ca-f84e207958d2
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
    [string]$reponame #Reponame is the github/Azure Devops repo
    , 
    [string]$ownername #Ownername is the github account/ Azure Devops Org
    , 
    [string]$token #Token is the github/devops token
    , 
    [string]$project #Project is the project when using Azure Devops or Project ID when using GitLab
    , 
    [string]$repotype #Repotype is the type of repo, github, gitlab or azuredevops, defaults to github
    , 
    [string]$tenant #Tenant ID (optional) for when automating and you want to use across tenants instead of hard-coded
    ,
    [string]$clientid #ClientID is the type of Azure AD App Reg ID
    ,
    [string]$clientsecret #ClientSecret is the type of Azure AD App Reg Secret
    ,
    [string]$goldentenant #To be used when comparing live customer to golden tenant
    ,
    [string]$EmailAddress #Email Alerts
    ,
    [string]$secondtenant #For Live Migration
    ,
    [string]$livemigration #For Live Migration
    ,
    [string]$sendgridtoken #Sendgrid API
    ,
    [object] $WebHookData #Webhook data for Azure Automation

    )

##WebHook Data

if ($WebHookData){
$rawdata = $WebHookData.RequestBody
    $bodyData = ConvertFrom-Json -InputObject ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($rawdata)))

$reponame = ((($bodyData.reponame) | out-string).trim())
$ownername = ((($bodyData.ownername) | out-string).trim())
$token = ((($bodyData.token) | out-string).trim())
$project = ((($bodyData.project) | out-string).trim())
$repotype = ((($bodyData.repotype) | out-string).trim())
$tenant = ((($bodyData.tenant) | out-string).trim())
$clientid = ((($bodyData.clientid) | out-string).trim())
$clientsecret = ((($bodyData.clientsecret) | out-string).trim())
$goldentenant = ((($bodyData.goldentenant) | out-string).trim())
$EmailAddress = ((($bodyData.EmailAddress) | out-string).trim())
$secondtenant = ((($bodyData.secondtenant) | out-string).trim())
$livemigration = ((($bodyData.livemigration) | out-string).trim())
$sendgridtoken = ((($bodyData.sendgridtoken) | out-string).trim())

$keycheck = ((($bodyData.webhooksecret) | out-string).trim())

##Lets add some security, check if a password has been sent in the header

##Set my password
$webhooksecret = ""

##Check if the password is correct
if ($keycheck -ne $webhooksecret) {
    #write-output "Webhook password incorrect, exiting"
    #exit
}


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

##Check if parameters have been set
$clientidcheck = $PSBoundParameters.ContainsKey('clientid')
$clientsecretcheck = $PSBoundParameters.ContainsKey('clientsecret')




if (($clientidcheck -eq $true) -and ($clientsecretcheck -eq $true)) {
##AAD Secret passed, use to login
$aadlogin = "yes"

}


}
############################################################
############################################################
#############         POLICY NAME CHANGES      #############
############################################################
############################################################

## Change the below to "yes" if you want to change the name of the policies when restoring to Name - restore - date
$changename = "no"

####### First check if running automated and bypass parameters to set variables below

############################################################
############################################################
############# CHANGE THIS TO USE IN AUTOMATION #############
############################################################
############################################################
$automated = "no"
############################################################

############################################################
#############           AUTOMATION NOTES       #############
############################################################

## You need to add these modules to your Automation Account if using Azure Automation
## Don't use the V2 preview versions
## https://www.powershellgallery.com/packages/PackageManagement/1.4.8.1
## https://www.powershellgallery.com/packages/Microsoft.Graph.Authentication/1.19.0
## https://www.powershellgallery.com/packages/Microsoft.Graph.Devices.CorporateManagement/1.19.0
## https://www.powershellgallery.com/packages/Microsoft.Graph.Groups/1.19.0
## https://www.powershellgallery.com/packages/Microsoft.Graph.DeviceManagement/1.19.0
## https://www.powershellgallery.com/packages/Microsoft.Graph.Identity.SignIns/1.19.0

##################################################################################################################################
#################                                                  INITIALIZATION                                #################
##################################################################################################################################
$ErrorActionPreference = "Continue"
##Start Logging to %TEMP%\intune.log
$date = get-date -format yyyyMMddTHHmmssffff
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

#Install MS Graph if not available


write-output "Installing Microsoft Graph modules if required (current user scope)"
writelog "Installing Microsoft Graph modules if required (current user scope)"


#Install MS Graph if not available
#Install MS Graph if not available
if (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication) {
    write-output "Microsoft Graph Authentication Already Installed"
    writelog "Microsoft Graph Authentication Already Installed"
} 
else {
        Install-Module -Name Microsoft.Graph.Authentication -Scope CurrentUser -Repository PSGallery -Force
        write-output "Microsoft Graph Authentication Installed"
        writelog "Microsoft Graph Authentication Installed"
}

#Install MS Graph if not available
if (Get-Module -ListAvailable -Name microsoft.graph.devices.corporatemanagement ) {
    write-output "Microsoft Graph Corporate Management Already Installed"
    writelog "Microsoft Graph Corporate Management Already Installed"

} 
else {
        Install-Module -Name microsoft.graph.devices.corporatemanagement  -Scope CurrentUser -Repository PSGallery -Force  
        write-output "Microsoft Graph Corporate Management Installed"
        writelog "Microsoft Graph Corporate Management Installed"

    }

    if (Get-Module -ListAvailable -Name Microsoft.Graph.Groups) {
        write-output "Microsoft Graph Groups Already Installed "
        writelog "Microsoft Graph Groups Already Installed "

    } 
    else {
            Install-Module -Name Microsoft.Graph.Groups -Scope CurrentUser -Repository PSGallery -Force
            write-output "Microsoft Graph Groups Installed"
            writelog "Microsoft Graph Groups Installed"

    }
    
    #Install MS Graph if not available
    if (Get-Module -ListAvailable -Name Microsoft.Graph.DeviceManagement) {
        write-output "Microsoft Graph DeviceManagement Already Installed"
        writelog "Microsoft Graph DeviceManagement Already Installed"

    } 
    else {
            Install-Module -Name Microsoft.Graph.DeviceManagement -Scope CurrentUser -Repository PSGallery -Force  
            write-output "Microsoft Graph DeviceManagement Installed"
            writelog "Microsoft Graph DeviceManagement Installed"

        }

    #Install MS Graph if not available
    if (Get-Module -ListAvailable -Name Microsoft.Graph.identity.signins) {
        write-output "Microsoft Graph Identity SignIns Already Installed"
        writelog "Microsoft Graph Identity SignIns Already Installed"

    } 
    else {
            Install-Module -Name Microsoft.Graph.Identity.SignIns -Scope CurrentUser -Repository PSGallery -Force
            write-output "Microsoft Graph Identity SignIns Installed"
            writelog "Microsoft Graph Identity SignIns Installed"

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
         
                $response = Invoke-RestMethod -Method Post -Uri https://login.microsoftonline.com/$Tenant/oauth2/v2.0/token -Body $body -UseBasicParsing
                $accessToken = $response.access_token
         
                $accessToken
                if ($version -eq 2) {
                    write-output "Version 2 module detected"
                    $accesstokenfinal = ConvertTo-SecureString -String $accessToken -AsPlainText -Force
                }
                else {
                    write-output "Version 1 Module Detected"
                    Select-MgProfile -Name Beta
                    $accesstokenfinal = $accessToken
                }
                $graph = Connect-MgGraph  -AccessToken $accesstokenfinal 
                write-output "Connected to Intune tenant $TenantId using app-based authentication (Azure AD authentication not supported)"
            }
            else {
                if ($version -eq 2) {
                    write-output "Version 2 module detected"
                }
                else {
                    write-output "Version 1 Module Detected"
                    Select-MgProfile -Name Beta
                }
                $graph = Connect-MgGraph -scopes $scopes
                write-output "Connected to Intune tenant $($graph.TenantId)"
            }
        }
    }    

# Load the Graph module
Import-Module microsoft.graph.authentication
import-module Microsoft.Graph.Identity.SignIns
import-module Microsoft.Graph.DeviceManagement
import-module microsoft.Graph.Groups
import-module microsoft.graph.devices.corporatemanagement

if (($automated -eq "yes") -or ($aadlogin -eq "yes")) {
 
Connect-ToGraph -Tenant $tenant -AppId $clientId -AppSecret $clientSecret
write-output "Graph Connection Established"
writelog "Graph Connection Established"

}
else {
##Connect to Graph
Select-MgProfile -Name Beta
Connect-ToGraph -Scopes "Policy.ReadWrite.ConditionalAccess, CloudPC.ReadWrite.All, DeviceManagementServiceConfig.ReadWrite.All, RoleAssignmentSchedule.ReadWrite.Directory, Domain.Read.All, Domain.ReadWrite.All, Directory.Read.All, Policy.ReadWrite.ConditionalAccess, DeviceManagementApps.ReadWrite.All, DeviceManagementConfiguration.ReadWrite.All, DeviceManagementManagedDevices.ReadWrite.All, openid, profile, email, offline_access, DeviceManagementRBAC.Read.All, DeviceManagementRBAC.ReadWrite.All"
}

###############################################################################################################
######                                          Add Functions                                            ######
###############################################################################################################
function convert-sideindicator {
    param (
        [Parameter(Mandatory=$true)]
        [string]$sideindicator
    )
    switch ($sideindicator) {
        "=>" { return "Added to Tenant" }
        "<=" { return "Missing from Tenant" }
        default { return "Unknown" }
    }
}

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
        $token,
        $comment
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
    $commit = ((Invoke-RestMethod -Uri $commituri -Headers @{Authorization=("Basic {0}" -f $base64AuthInfo)} -Method Get).commits).commitId

    if ($commit) {
        $oldid = $commit
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
        "comment": "$comment",
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



Function Get-IntuneApplication(){
    
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
    
    [cmdletbinding()]
    
    param
    (
        $id
    )
    
    $graphApiVersion = "Beta"
    $Resource = "deviceAppManagement/mobileApps"
    
        try {
    
            if($id){
    
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$id"
            (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject)
    
            }
    
            else {
    
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
            (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value | Where-Object { ($_.'@odata.type').Contains("#microsoft.graph.winGetApp") }
    
            }
    
        }
    
        catch {
    
        }
    
    }



Function Get-DeviceConfigurationPolicyGP(){
    
    <#
    .SYNOPSIS
    This function is used to get device configuration policies from the Graph API REST interface - Group Policies
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any device configuration policies
    .EXAMPLE
    Get-DeviceConfigurationPolicy
    Returns any device configuration policies configured in Intune
    .NOTES
    NAME: Get-DeviceConfigurationPolicyGP
    #>
    
    [cmdletbinding()]
    
    param
    (
        $id
    )
    
    $graphApiVersion = "beta"
    $DCP_resource = "deviceManagement/groupPolicyConfigurations"
    
    try {
            if($id){
    
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)?`$filter=id eq '$id'"
            (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).value
    
            }
    
            else {
    
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)"
            (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value
    
            }
        }
        catch {}
     
}


#############################################################################################################    

Function Get-ConditionalAccessPolicy(){
    
    <#
    .SYNOPSIS
    This function is used to get conditional access policies from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any conditional access policies
    .EXAMPLE
    Get-ConditionalAccessPolicy
    Returns any conditional access policies in Azure
    .NOTES
    NAME: Get-ConditionalAccessPolicy
    #>
    
    [cmdletbinding()]
    
    param
    (
        $id
    )
    

    $graphApiVersion = "beta"
    $DCP_resource = "identity/conditionalAccess/policies"
    
    try {
            if($id){
    
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)/$id"
            (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject)
    
            }
    
            else {
    
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)"
            (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).value
    
            }
        }
        catch {}
    
     
}

####################################################

Function Get-DeviceConfigurationPolicy(){
    
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
        $id
    )
    
    $graphApiVersion = "beta"
    $DCP_resource = "deviceManagement/deviceConfigurations"
    
    try {
            if($id){
    
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)?`$filter=id eq '$id'"
            (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).value
    
            }
    
            else {
    
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)"
            (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value
    
            }
        }
        catch {}
    
        
}
    
##########################################################################################
Function Get-GroupPolicyConfigurationsDefinitionValues()
{
	
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
		$GroupPolicyConfigurationID
		
	)
	
	$graphApiVersion = "Beta"
	#$DCP_resource = "deviceManagement/groupPolicyConfigurations/$GroupPolicyConfigurationID/definitionValues?`$filter=enabled eq true"
	$DCP_resource = "deviceManagement/groupPolicyConfigurations/$GroupPolicyConfigurationID/definitionValues"
	
	try {	
		$uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)"
		(Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value
		
    }
    catch{}
	

	
}

####################################################
Function Get-GroupPolicyConfigurationsDefinitionValuesPresentationValues()
{
	
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
		$GroupPolicyConfigurationID,
		$GroupPolicyConfigurationsDefinitionValueID
		
	)
	$graphApiVersion = "Beta"
	
	$DCP_resource = "deviceManagement/groupPolicyConfigurations/$GroupPolicyConfigurationID/definitionValues/$GroupPolicyConfigurationsDefinitionValueID/presentationValues"
	try {
		$uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)"
		(Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value
    }
    catch {}
		
	
}

Function Get-GroupPolicyConfigurationsDefinitionValuesdefinition ()
{
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
		$GroupPolicyConfigurationID,
		[Parameter(Mandatory = $true)]
		$GroupPolicyConfigurationsDefinitionValueID
		
	)
	$graphApiVersion = "Beta"
	$DCP_resource = "deviceManagement/groupPolicyConfigurations/$GroupPolicyConfigurationID/definitionValues/$GroupPolicyConfigurationsDefinitionValueID/definition"
	try {
		
		$uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)"
		
		$responseBody = Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject
    }
    catch{}
		
		
	$responseBody
}


Function Get-GroupPolicyDefinitionsPresentations ()
{
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
		$groupPolicyDefinitionsID,
		[Parameter(Mandatory = $true)]
		$GroupPolicyConfigurationsDefinitionValueID
		
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
            
                    $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)/$id"
                    (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject)
            
                    }
            
                    else {

                        $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)"
                $response = (Invoke-MgGraphRequest -uri $uri -Method Get -OutputType PSObject)
                $allscsettings = $response.value
                
                $allscsettingsNextLink = $response."@odata.nextLink"
                
                while ($null -ne $allscsettingsNextLink) {
                    $allscsettingsResponse = (Invoke-MGGraphRequest -Uri $allscsettingsNextLink -Method Get -outputType PSObject)
                    $allscsettingsNextLink = $allscsettingsResponse."@odata.nextLink"
                    $allscsettings += $allscsettingsResponse.value
                }
                        $allscsettings  
                
                        }
                }
                catch {}
            
            
}
            
################################################################################################


####################################################
    
Function Get-DeviceProactiveRemediations(){
    
    <#
    .SYNOPSIS
    This function is used to get device proactive remediations from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any device proactive remediations
    .EXAMPLE
    Get-DeviceproactiveRemediations
    Returns any device proactive remediations configured in Intune
    .NOTES
    NAME: Get-Deviceproactiveremediations
    #>
    
    [cmdletbinding()]
    
    param
    (
        $id
    )
    
    $graphApiVersion = "beta"
    $DCP_resource = "deviceManagement/devicehealthscripts"
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
    
################################################################################################
Function Get-MobileAppConfigurations(){
    
    <#
    .SYNOPSIS
    This function is used to get Mobile App Configurations from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any Mobile App Configurations
    .EXAMPLE
    Get-mobileAppConfigurations
    Returns any Mobile App Configurations configured in Intune
    .NOTES
    NAME: Get-mobileAppConfigurations
    #>
    
    [cmdletbinding()]
    
    param
    (
        $id
    )
    
    $graphApiVersion = "beta"
    $DCP_resource = "deviceAppManagement/mobileAppConfigurations"
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
Function Get-DeviceCompliancePolicy(){
    
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
                $id
            )
            
            $graphApiVersion = "beta"
            $DCP_resource = "deviceManagement/deviceCompliancePolicies"
            try {
                    if($id){
            
                    $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)?`$filter=id eq '$id'"
                    (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).value
            
                    }
            
                    else {
            
                    $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)"
                    (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value
            
                    }
                }
                catch {}
            
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
            
#################################################################################################
Function Get-DeviceSecurityPolicy(){
    
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

#################################################################################################  

Function Get-ManagedAppProtectionAndroid(){

    <#
    .SYNOPSIS
    This function is used to get managed app protection configuration from the Graph API REST interface Android
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any managed app protection policy Android
    .EXAMPLE
    Get-ManagedAppProtectionAndroid
    .NOTES
    NAME: Get-ManagedAppProtectionAndroid
    #>
    
    param
    (
        $id
    )
    $graphApiVersion = "Beta"
    
            $Resource = "deviceAppManagement/androidManagedAppProtections"
        try {
            if($id){
            
                $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource('$id')"
                (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject)
        
                }
        
                else {
        
                    $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"
                    Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject  
        
                }
            }
            catch {}        
        
        
    
}

#################################################################################################  

Function Get-ManagedAppProtectionIOS(){

    <#
    .SYNOPSIS
    This function is used to get managed app protection configuration from the Graph API REST interface IOS
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any managed app protection policy IOS
    .EXAMPLE
    Get-ManagedAppProtectionIOS
    .NOTES
    NAME: Get-ManagedAppProtectionIOS
    #>
    param
    (
        $id
    )

    $graphApiVersion = "Beta"
    
                $Resource = "deviceAppManagement/iOSManagedAppProtections"
        try {
                if($id){
            
                    $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource('$id')"
                    (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject)
            
                    }
            
                    else {
            
                        $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"
                        Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject
            
                    }
                }
                catch {}
        
}
    
####################################################
Function Get-GraphAADGroups(){
    
    <#
    .SYNOPSIS
    This function is used to get AAD Groups from the Graph API REST interface 
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any AAD Groups
    .EXAMPLE
    Get-GraphAADGroups
    Returns any AAD Groups
    .NOTES
    NAME: Get-GraphAADGroups
    #>
    
    [cmdletbinding()]
    
    param
    (
        $id
    )
    
    $graphApiVersion = "beta"
    $DCP_resource = "Groups"
    try {
            if($id){
    
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)/$id"
            Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject
    
            }
    
            else {
    
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)?`$Filter=onPremisesSyncEnabled ne true&`$count=true"
            #(Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value
            Get-MgGroup | Where-Object OnPremisesSyncEnabled -NE true
    
            }
        }
        catch {}
    
}

#################################################################################################  

Function Get-AutoPilotProfile(){
    
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
                    $id
                )
                
                $graphApiVersion = "beta"
                $DCP_resource = "deviceManagement/windowsAutopilotDeploymentProfiles"
                try {
                        if($id){
                
                        $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)?`$filter=id eq '$id'"
                        (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).value
                
                        }
                
                        else {
                
                        $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)"
                        (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value
                
                        }
                    }
                    catch {}
                
}

#################################################################################################

Function Get-AutoPilotESP(){
    
                    <#
                    .SYNOPSIS
                    This function is used to get autopilot ESP from the Graph API REST interface 
                    .DESCRIPTION
                    The function connects to the Graph API Interface and gets any autopilot ESP
                    .EXAMPLE
                    Get-AutoPilotESP
                    Returns any autopilot ESPs configured in Intune
                    .NOTES
                    NAME: Get-AutoPilotESP
                    #>
                    
                    [cmdletbinding()]
                    
                    param
                    (
                        $id
                    )
                    
                    $graphApiVersion = "beta"
                    $DCP_resource = "deviceManagement/deviceEnrollmentConfigurations"
                    try {
                            if($id){
                    
                            $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)?`$filter=id eq '$id'"
                            (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).value
                    
                            }
                    
                            else {
                    
                            $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)"
                            (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value
                    
                            }
                        }
                        catch{}
}
                
#################################################################################################    

Function Get-DecryptedDeviceConfigurationPolicy(){

    <#
    .SYNOPSIS
    This function is used to decrypt device configuration policies from an json array with the use of the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and decrypt Windows custom device configuration policies that is encrypted
    .EXAMPLE
    Decrypt-DeviceConfigurationPolicy -dcps $DCPs
    Returns any device configuration policies configured in Intune in clear text without encryption
    .NOTES
    NAME: Decrypt-DeviceConfigurationPolicy
    #>
    
    [cmdletbinding()]
    
    param
    (
        $dcpid
    )
    
    $graphApiVersion = "Beta"
    $DCP_resource = "deviceManagement/deviceConfigurations"
    $dcp = Get-DeviceConfigurationPolicy -id $dcpid
        if ($dcp.'@odata.type' -eq "#microsoft.graph.windows10CustomConfiguration") {
            # Convert policy of type windows10CustomConfiguration
            foreach ($omaSetting in $dcp.omaSettings) {
                    if ($omaSetting.isEncrypted -eq $true) {
                        $DCP_resource_function = "$($DCP_resource)/$($dcp.id)/getOmaSettingPlainTextValue(secretReferenceValueId='$($omaSetting.secretReferenceValueId)')"
                        $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource_function)"
                        $value = ((Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value)

                        #Remove any unnecessary properties
                        $omaSetting.PsObject.Properties.Remove("isEncrypted")
                        $omaSetting.PsObject.Properties.Remove("secretReferenceValueId")
                        $omaSetting.value = $value
                    }

            }
        }
    
    $dcp

}


Function Get-DeviceManagementScripts(){
    
    <#
    .SYNOPSIS
    This function is used to get device PowerShell scripts from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any device scripts
    .EXAMPLE
    Get-DeviceManagementScripts
    Returns any device management scripts configured in Intune
    .NOTES
    NAME: Get-DeviceManagementScripts
    #>
    
    [cmdletbinding()]
    
    param
    (
        $id
    )
    
    $graphApiVersion = "beta"
    $DCP_resource = "deviceManagement/devicemanagementscripts"
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

Function Get-Win365UserSettings(){
    
    <#
    .SYNOPSIS
    This function is used to get Windows 365 User Settings Policies from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any device scriptsWindows 365 User Settings Policies
    .EXAMPLE
    Get-Win365UserSettings
    Returns any Windows 365 User Settings Policies configured in Intune
    .NOTES
    NAME: Get-Win365UserSettings
    #>
    
    [cmdletbinding()]
    
    param
    (
        $id
    )
    
    $graphApiVersion = "beta"
    $DCP_resource = "deviceManagement/virtualEndpoint/userSettings"
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


Function Get-FeatureUpdatePolicies(){
    
    <#
    .SYNOPSIS
    This function is used to get Feature Update Policies from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any Feature Update Policies
    .EXAMPLE
    Get-FeatureUpdatePolicies
    Returns any Feature Update Policies configured in Intune
    .NOTES
    NAME: Get-FeatureUpdatePolicies
    #>
    
    [cmdletbinding()]
    
    param
    (
        $id
    )
    
    $graphApiVersion = "beta"
    $DCP_resource = "deviceManagement/windowsFeatureUpdateProfiles"
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

Function Get-DriverUpdatePolicies(){
    
    <#
    .SYNOPSIS
    This function is used to get Driver Update Policies from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any Driver Update Policies
    .EXAMPLE
    Get-DriverUpdatePolicies
    Returns any Driver Update Policies configured in Intune
    .NOTES
    NAME: Get-DriverUpdatePolicies
    #>
    
    [cmdletbinding()]
    
    param
    (
        $id
    )
    
    $graphApiVersion = "beta"
    $DCP_resource = "deviceManagement/windowsDriverUpdateProfiles"
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

Function Get-QualityUpdatePolicies(){
    
    <#
    .SYNOPSIS
    This function is used to get Quality Update Policies from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any Quality Update Policies
    .EXAMPLE
    Get-QualityUpdatePolicies
    Returns any Quality Update Policies configured in Intune
    .NOTES
    NAME: Get-QualityUpdatePolicies
    #>
    
    [cmdletbinding()]
    
    param
    (
        $id
    )
    
    $graphApiVersion = "beta"
    $DCP_resource = "deviceManagement/windowsQualityUpdateProfiles"
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
Function Get-Win365ProvisioningPolicies(){
    
    <#
    .SYNOPSIS
    This function is used to get Windows 365 Provisioning Policies from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any Windows 365 Provisioning Policies
    .EXAMPLE
    Get-Win365ProvisioningPolicies
    Returns any Windows 365 Provisioning Policies configured in Intune
    .NOTES
    NAME: Get-Win365ProvisioningPolicies
    #>
    
    [cmdletbinding()]
    
    param
    (
        $id
    )
    
    $graphApiVersion = "beta"
    $DCP_resource = "deviceManagement/virtualEndpoint/provisioningPolicies"
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

Function Get-IntunePolicySets(){
    
    <#
    .SYNOPSIS
    This function is used to get Intune policy sets from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any Intune policy sets
    .EXAMPLE
    Get-IntunePolicySets
    Returns any policy sets configured in Intune
    .NOTES
    NAME: Get-IntunePolicySets
    #>
    
    [cmdletbinding()]
    
    param
    (
        $id
    )
    
    $graphApiVersion = "beta"
    $DCP_resource = "deviceAppManagement/policySets"
    try {
            if($id){
    
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)/$($id)?`$expand=items"
            (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject)
    
            }
    
            else {
    
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)"
            (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value
    
            }
        }
        catch {}
    
   
}

Function Get-EnrollmentConfigurations(){
    
    <#
    .SYNOPSIS
    This function is used to get Intune enrollment configurations from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any Intune enrollment configurations
    .EXAMPLE
    Get-EnrollmentConfigurations
    Returns any enrollment configurations configured in Intune
    .NOTES
    NAME: Get-EnrollmentConfigurations
    #>
    
    [cmdletbinding()]
    
    param
    (
        $id
    )
    
    $graphApiVersion = "beta"
    $DCP_resource = "deviceManagement/deviceEnrollmentConfigurations"
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
    

Function Get-DeviceCategories(){
    
    <#
    .SYNOPSIS
    This function is used to get Intune device categories from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any Intune device categories
    .EXAMPLE
    Get-DeviceCategories
    Returns any device categories configured in Intune
    .NOTES
    NAME: Get-DeviceCategories
    #>
    
    [cmdletbinding()]
    
    param
    (
        $id
    )
    
    $graphApiVersion = "beta"
    $DCP_resource = "deviceManagement/deviceCategories"
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


Function Get-DeviceFilters(){
    
    <#
    .SYNOPSIS
    This function is used to get Intune device filters from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any Intune device filters
    .EXAMPLE
    Get-DeviceFilters
    Returns any device filters configured in Intune
    .NOTES
    NAME: Get-DeviceFilters
    #>
    
    [cmdletbinding()]
    
    param
    (
        $id
    )
    
    $graphApiVersion = "beta"
    $DCP_resource = "deviceManagement/assignmentFilters"
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


Function Get-BrandingProfiles(){
    
    <#
    .SYNOPSIS
    This function is used to get Intune Branding Profiles from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any Intune Branding Profiles
    .EXAMPLE
    Get-BrandingProfiles
    Returns any Branding Profiles configured in Intune
    .NOTES
    NAME: Get-BrandingProfiles
    #>
    
    [cmdletbinding()]
    
    param
    (
        $id
    )
    
    $graphApiVersion = "beta"
    $DCP_resource = "deviceManagement/intuneBrandingProfiles"
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


Function Get-AdminApprovals(){
    
    <#
    .SYNOPSIS
    This function is used to get Intune admin approvals from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any Intune admin approvals
    .EXAMPLE
    Get-AdminApprovals
    Returns any admin approvals configured in Intune
    .NOTES
    NAME: Get-AdminApprovals
    #>
    
    [cmdletbinding()]
    
    param
    (
        $id
    )
    
    $graphApiVersion = "beta"
    $DCP_resource = "deviceManagement/operationApprovalPolicies"
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

Function Get-OrgMessages(){
    
    <#
    .SYNOPSIS
    This function is used to get Intune organizational messages from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any Intune organizational messages
    .EXAMPLE
    Get-OrgMessages
    Returns any organizational messages configured in Intune
    .NOTES
    NAME: Get-OrgMessages
    #>
    
    [cmdletbinding()]
    
    param
    (
        $id
    )
    
    $graphApiVersion = "beta"
    $DCP_resource = "deviceManagement/organizationalMessageDetails"
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


Function Get-IntuneTerms(){
    
    <#
    .SYNOPSIS
    This function is used to get Intune terms and conditions from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any Intune terms and conditions
    .EXAMPLE
    Get-IntuneTerms
    Returns any terms and conditions configured in Intune
    .NOTES
    NAME: Get-IntuneTerms
    #>
    
    [cmdletbinding()]
    
    param
    (
        $id
    )
    
    $graphApiVersion = "beta"
    $DCP_resource = "deviceManagement/termsAndConditions"
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

Function Get-IntuneRoles(){
    
    <#
    .SYNOPSIS
    This function is used to get Intune custom roles from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any Intune custom roles
    .EXAMPLE
    Get-IntuneRoles
    Returns any custom roles configured in Intune
    .NOTES
    NAME: Get-IntuneRoles
    #>
    
    [cmdletbinding()]
    
    param
    (
        $id
    )
    
    $graphApiVersion = "beta"
    $DCP_resource = "deviceManagement/roleDefinitions"
    try {
            if($id){
    
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)/$id"
            (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject)
    
            }
    
            else {
    
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)"
            (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value | where-object isBuiltIn -eq $False
    
            }
        }
        catch {}
    
   
}
################################################################################################


Function Get-WHfBPolicies(){
    
    <#
    .SYNOPSIS
    This function is used to get Intune Windows Hello for Business policies from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any Intune WHfB Policies
    .EXAMPLE
    Get-WHfBPolicies
    Returns any WHfB Policies configured in Intune
    .NOTES
    NAME: Get-WHfBPolicies
    #>
    
    [cmdletbinding()]
    
    param
    (
        $id
    )
    
    $graphApiVersion = "beta"
    $DCP_resource = "deviceManagement/deviceEnrollmentConfigurations"
    try {
            if($id){
    
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)/$id"
            (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject)
    
            }
    
            else {
    
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)"
            (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value | where-object deviceEnrollmentConfigurationType -eq "WindowsHelloForBusiness"
    
            }
        }
        catch {}
    
   
}

Function Get-WHfBPoliciesbyName(){
    
    <#
    .SYNOPSIS
    This function is used to get Intune Windows Hello for Business policies from the Graph API REST interface by name
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any Intune WHfB Policies
    .EXAMPLE
    Get-WHfBPoliciesbyName
    Returns any WHfB Policies configured in Intune
    .NOTES
    NAME: Get-WHfBPoliciesbyName
    #>
    
    [cmdletbinding()]
    
    param
    (
        $name
    )
    
    $graphApiVersion = "beta"
    $Resource = "deviceManagement/deviceEnrollmentConfigurations"
    try {
    
        $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource/$($DCP_resource)"
        $allpolicies = (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value | where-object deviceEnrollmentConfigurationType -eq "WindowsHelloForBusiness"
        $app = $allpolicies | Where-Object DisplayName -eq $name


    }

    catch {

    }
    $myid = $app.id
    if ($null -ne $myid) {
    $fulluri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$myid"
    $type = "Winget Application"
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


Function Get-IntuneApplicationbyName(){
    
    <#
    .SYNOPSIS
    This function is used to get applications from the Graph API REST interface by name
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any applications added
    .EXAMPLE
    Get-IntuneApplicationbyName
    Returns any applications configured in Intune
    .NOTES
    NAME: Get-IntuneApplicationbyName
    #>
    
    [cmdletbinding()]
    
    param
    (
        $name
    )
    
    $graphApiVersion = "Beta"
    $Resource = "deviceAppManagement/mobileApps"
    
        try {
    
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)?`$filter=displayname eq '$name'"
            $app = (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value | Where-Object { ($_.'@odata.type').Contains("#microsoft.graph.winGetApp") }
    
    
        }
    
        catch {
    
        }
        $myid = $app.id
        if ($null -ne $myid) {
        $fulluri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$myid"
        $type = "Winget Application"
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



Function Get-DeviceConfigurationPolicyGPbyName(){
    
    <#
    .SYNOPSIS
    This function is used to get device configuration policies from the Graph API REST interface - Group Policies
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any device configuration policies
    .EXAMPLE
    Get-DeviceConfigurationPolicyGPbyName
    Returns any device configuration policies configured in Intune
    .NOTES
    NAME: Get-DeviceConfigurationPolicyGPbyName
    #>
    
    [cmdletbinding()]
    
    param
    (
        $name
    )
    
    $graphApiVersion = "beta"
    $Resource = "deviceManagement/groupPolicyConfigurations"
    
    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)?`$filter=displayname eq '$name'"
        $GP = (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value

        }
        catch {}
        $myid = $GP.id
        if ($null -ne $myid) {
            $fulluri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$myid"
            $type = "Group Policy Configuration"
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


#############################################################################################################    

Function Get-ConditionalAccessPolicybyName(){
    
    <#
    .SYNOPSIS
    This function is used to get conditional access policies from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any conditional access policies
    .EXAMPLE
    Get-ConditionalAccessPolicybyName
    Returns any conditional access policies in Azure
    .NOTES
    NAME: Get-ConditionalAccessPolicybyName
    #>
    
    [cmdletbinding()]
    
    param
    (
        $name
    )
    

    $graphApiVersion = "beta"
    $Resource = "identity/conditionalAccess/policies"
    
    try {

    
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)?`$filter=displayname eq '$name'"
        $CA = (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value
    
        }
        catch {}
        $myid = $CA.id
        if ($null -ne $myid) {
            $fulluri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$myid"
            $type = "Conditional Access"
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

    
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)?`$filter=displayname eq '$name'"
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
            
################################################################################################


####################################################
    
Function Get-DeviceProactiveRemediationsbyName(){
    
    <#
    .SYNOPSIS
    This function is used to get device proactive remediations from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any device proactive remediations
    .EXAMPLE
    Get-DeviceProactiveRemediationsbyName
    Returns any device proactive remediations configured in Intune
    .NOTES
    NAME: Get-DeviceProactiveRemediationsbyName
    #>
    
    [cmdletbinding()]
    
    param
    (
        $name
    )
    
    $graphApiVersion = "beta"
    $Resource = "deviceManagement/devicehealthscripts"
    try {

    
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)?`$filter=displayName eq '$name'"
        $PR = (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value
    
        }
        catch {}
        $myid = $PR.id
        if ($null -ne $myid) {
            $fulluri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$myid"
            $type = "Proactive Remediation"
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
    
################################################################################################

Function Get-MobileAppConfigurationsbyName(){
    
    <#
    .SYNOPSIS
    This function is used to get Mobile App Configurations from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any Mobile App Configurations
    .EXAMPLE
    Get-MobileAppConfigurationsbyName
    Returns any Mobile App Configurations configured in Intune
    .NOTES
    NAME: Get-MobileAppConfigurationsbyName
    #>
    
    [cmdletbinding()]
    
    param
    (
        $name
    )
    
    $graphApiVersion = "beta"
    $Resource = "deviceAppManagement/mobileAppConfigurations"
    try {

    
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)?`$filter=displayName eq '$name'"
        $PR = (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value
    
        }
        catch {}
        $myid = $PR.id
        if ($null -ne $myid) {
            $fulluri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$myid"
            $type = "App Config"
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
    
################################################################################################
    
Function Get-DeviceCompliancePolicybyName(){
    
            <#
            .SYNOPSIS
            This function is used to get device compliance policies from the Graph API REST interface
            .DESCRIPTION
            The function connects to the Graph API Interface and gets any device compliance policies
            .EXAMPLE
            Get-DeviceCompliancePolicybyName
            Returns any device compliance policies configured in Intune
            .NOTES
            NAME: Get-DeviceCompliancePolicybyName
            #>
            
            [cmdletbinding()]
            
            param
            (
                $name
            )
            
            $graphApiVersion = "beta"
            $Resource = "deviceManagement/deviceCompliancePolicies"
            try {

    
                $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)?`$filter=displayName eq '$name'"
                $CP = (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value
            
                }
                catch {}
                $myid = $CP.id
                if ($null -ne $myid) {
                    $fulluri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$myid"
                    $type = "Compliance Policy"
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

Function Get-DeviceCompliancePolicyScriptsbyName(){
    
    <#
    .SYNOPSIS
    This function is used to get device compliance policy scripts from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any device compliance policies
    .EXAMPLE
    Get-DeviceCompliancePolicyScriptsbyName
    Returns any device compliance policy scripts configured in Intune
    .NOTES
    NAME: Get-DeviceCompliancePolicyScriptsbyName
    #>
    
    [cmdletbinding()]
    
    param
    (
        $name
    )
    
    $graphApiVersion = "beta"
    $Resource = "deviceManagement/deviceComplianceScripts"
    try {


        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)?`$filter=displayName eq '$name'"
        $CP = (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value
    
        }
        catch {}
        $myid = $CP.id
        if ($null -ne $myid) {
            $fulluri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$myid"
            $type = "Compliance Policy Script"
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
            
#################################################################################################
Function Get-DeviceSecurityPolicybyName(){
    
    <#
    .SYNOPSIS
    This function is used to get device security policies from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any device security policies
    .EXAMPLE
    Get-DeviceSecurityPolicybyName
    Returns any device compliance policies configured in Intune
    .NOTES
    NAME: Get-DeviceSecurityPolicybyName
    #>
    
    [cmdletbinding()]
    
    param
    (
        $name
    )
    
    $graphApiVersion = "beta"
    $Resource = "deviceManagement/intents"
    try {

    
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)?`$filter=displayName eq '$name'"
        $SP = (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value
    
        }
        catch {}
        $myid = $SP.id
        if ($null -ne $myid) {
            $fulluri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$myid"
            $type = "Security Policy"
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

#################################################################################################  

Function Get-ManagedAppProtectionAndroidbyName(){

    <#
    .SYNOPSIS
    This function is used to get managed app protection configuration from the Graph API REST interface Android
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any managed app protection policy Android
    .EXAMPLE
    Get-ManagedAppProtectionAndroidbyName
    .NOTES
    NAME: Get-ManagedAppProtectionAndroidbyName
    #>
    
    param
    (
        $name
    )
    $graphApiVersion = "Beta"
     $Resource = "deviceAppManagement/androidManagedAppProtections"
            try {

    
                $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)?`$filter=displayName eq '$name'"
                $AAP = (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value
            
                }
                catch {}
                $myid = $AAP.id
                if ($null -ne $myid) {
                    $fulluri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$myid"
                    $type = "Android App Protection Policy"
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

#################################################################################################  

Function Get-ManagedAppProtectionIOSbyName(){

    <#
    .SYNOPSIS
    This function is used to get managed app protection configuration from the Graph API REST interface IOS
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any managed app protection policy IOS
    .EXAMPLE
    Get-ManagedAppProtectionIOSbyName
    .NOTES
    NAME: Get-ManagedAppProtectionIOSbyName
    #>
    param
    (
        $name
    )

    $graphApiVersion = "Beta"
    
                $Resource = "deviceAppManagement/iOSManagedAppProtections"
                try {

    
                    $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)?`$filter=displayName eq '$name'"
                    $IAP = (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value
                
                    }
                    catch {}
                    $myid = $IAP.id
                    if ($null -ne $myid) {
                        $fulluri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$myid"
                        $type = "iOS App Protection Policy"
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
    
Function Get-AutoPilotProfilebyName(){
    
                <#
                .SYNOPSIS
                This function is used to get autopilot profiles from the Graph API REST interface 
                .DESCRIPTION
                The function connects to the Graph API Interface and gets any autopilot profiles
                .EXAMPLE
                Get-AutoPilotProfilebyName
                Returns any autopilot profiles configured in Intune
                .NOTES
                NAME: Get-AutoPilotProfilebyName
                #>
                
                [cmdletbinding()]
                
                param
                (
                    $name
                )
                
                $graphApiVersion = "beta"
                $Resource = "deviceManagement/windowsAutopilotDeploymentProfiles"
                try {

    
                    $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)?`$filter=displayName eq '$name'"
                    $AP = (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value
                
                    }
                    catch {}
                    $myid = $AP.id
                    if ($null -ne $myid) {
                        $fulluri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$myid"
                        $type = "Autopilot Profile"
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

#################################################################################################

Function Get-AutoPilotESPbyName(){
    
                    <#
                    .SYNOPSIS
                    This function is used to get autopilot ESP from the Graph API REST interface 
                    .DESCRIPTION
                    The function connects to the Graph API Interface and gets any autopilot ESP
                    .EXAMPLE
                    Get-AutoPilotESPbyName
                    Returns any autopilot ESPs configured in Intune
                    .NOTES
                    NAME: Get-AutoPilotESPbyName
                    #>
                    
                    [cmdletbinding()]
                    
                    param
                    (
                        $name
                    )
                    
                    $graphApiVersion = "beta"
                    $Resource = "deviceManagement/deviceEnrollmentConfigurations"
                    try {

    
                        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)?`$filter=displayName eq '$name'"
                        $ESP = (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value
                    
                        }
                        catch {}
                        $myid = $ESP.id
                        if ($null -ne $myid) {
                            $fulluri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$myid"
                            $type = "Autopilot ESP"
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
                
#################################################################################################    


Function Get-DeviceManagementScriptsbyName(){
    
    <#
    .SYNOPSIS
    This function is used to get device PowerShell scripts from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any device scripts
    .EXAMPLE
    Get-DeviceManagementScriptsbyName
    Returns any device management scripts configured in Intune
    .NOTES
    NAME: Get-DeviceManagementScriptsbyName
    #>
    
    [cmdletbinding()]
    
    param
    (
        $name
    )
    
    $graphApiVersion = "beta"
    $Resource = "deviceManagement/devicemanagementscripts"
    try {

    
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)?`$filter=displayName eq '$name'"
        $Script = (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value
    
        }
        catch {}
        $myid = $Script.id
        if ($null -ne $myid) {
            $fulluri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$myid"
            $type = "PowerShell Script"
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

Function Get-Win365UserSettingsbyName(){
    
    <#
    .SYNOPSIS
    This function is used to get Windows 365 User Settings Policies from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any device scriptsWindows 365 User Settings Policies
    .EXAMPLE
    Get-Win365UserSettingsbyName
    Returns any Windows 365 User Settings Policies configured in Intune
    .NOTES
    NAME: Get-Win365UserSettingsbyName
    #>
    
    [cmdletbinding()]
    
    param
    (
        $name
    )
    
    $graphApiVersion = "beta"
    $Resource = "deviceManagement/virtualEndpoint/userSettings"
    try {

    
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)?`$filter=displayName eq '$name'"
        $W365User = (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value
    
        }
        catch {}
        $myid = $W365User.id
        if ($null -ne $myid) {
            $fulluri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$myid"
            $type = "Win365 User Settings"
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

Function Get-QualityUpdatePoliciesbyName(){
    
    <#
    .SYNOPSIS
    This function is used to get Quality Update Policies from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any Quality Update Policies
    .EXAMPLE
    Get-QualityUpdatePoliciesbyName
    Returns any Quality Update Policies configured in Intune
    .NOTES
    NAME: Get-QualityUpdatePoliciesbyName
    #>
    
    [cmdletbinding()]
    
    param
    (
        $name
    )
    
    $graphApiVersion = "beta"
    $Resource = "deviceManagement/windowsQualityUpdateProfiles"
    try {

    
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)?`$filter=displayName eq '$name'"
        $W365User = (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value
    
        }
        catch {}
        $myid = $W365User.id
        if ($null -ne $myid) {
            $fulluri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$myid"
            $type = "Quality Update"
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

Function GetFeatureUpdatePoliciesbyName(){
    
    <#
    .SYNOPSIS
    This function is used to get Feature Update Policies from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any Feature Update Policies
    .EXAMPLE
    Get-FeatureUpdatePolicies
    Returns any Feature Update Policies configured in Intune
    .NOTES
    NAME: Get-FeatureUpdatePolicies
    #>
    
    [cmdletbinding()]
    
    param
    (
        $name
    )
    
    $graphApiVersion = "beta"
    $Resource = "deviceManagement/windowsFeatureUpdateProfiles"
    try {

    
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)?`$filter=displayName eq '$name'"
        $W365User = (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value
    
        }
        catch {}
        $myid = $W365User.id
        if ($null -ne $myid) {
            $fulluri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$myid"
            $type = "Feature Update"
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


Function GetDriverUpdatePoliciesbyName(){
    
    <#
    .SYNOPSIS
    This function is used to get Driver Update Policies from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any Driver Update Policies
    .EXAMPLE
    Get-DriverUpdatePoliciesbyName
    Returns any Driver Update Policies configured in Intune
    .NOTES
    NAME: Get-DriverUpdatePoliciesbyName
    #>
    
    [cmdletbinding()]
    
    param
    (
        $name
    )
    
    $graphApiVersion = "beta"
    $Resource = "deviceManagement/windowsDriverUpdateProfiles"
    try {

    
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)?`$filter=displayName eq '$name'"
        $W365User = (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value
    
        }
        catch {}
        $myid = $W365User.id
        if ($null -ne $myid) {
            $fulluri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$myid"
            $type = "Driver Update"
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

Function Get-Win365ProvisioningPoliciesbyName(){
    
    <#
    .SYNOPSIS
    This function is used to get Windows 365 Provisioning Policies from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any Windows 365 Provisioning Policies
    .EXAMPLE
    Get-Win365ProvisioningPoliciesbyName
    Returns any Windows 365 Provisioning Policies configured in Intune
    .NOTES
    NAME: Get-Win365ProvisioningPoliciesbyName
    #>
    
    [cmdletbinding()]
    
    param
    (
        $name
    )
    
    $graphApiVersion = "beta"
    $Resource = "deviceManagement/virtualEndpoint/provisioningPolicies"
    try {

    
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)?`$filter=displayName eq '$name'"
        $W365Prov = (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value
    
        }
        catch {}
        $myid = $W365Prov.id
        if ($null -ne $myid) {
            $fulluri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$myid"
            $type = "W365 Provisioning Policy"
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

Function Get-IntunePolicySetsbyName(){
    
    <#
    .SYNOPSIS
    This function is used to get Intune policy sets from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any Intune policy sets
    .EXAMPLE
    Get-IntunePolicySetsbyName
    Returns any policy sets configured in Intune
    .NOTES
    NAME: Get-IntunePolicySetsbyName
    #>
    
    [cmdletbinding()]
    
    param
    (
        $name
    )
    
    $graphApiVersion = "beta"
    $Resource = "deviceAppManagement/policySets"
    try {

    
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)?`$filter=displayName eq '$name'"
        $Policyset = (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value
    
        }
        catch {}
        $myid = $Policyset.id
        if ($null -ne $myid) {
            $fulluri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$myid"
            $type = "Policy Set"
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

Function Get-EnrollmentConfigurationsbyName(){
    
    <#
    .SYNOPSIS
    This function is used to get Intune enrollment configurations from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any Intune enrollment configurations
    .EXAMPLE
    Get-EnrollmentConfigurationsbyName
    Returns any enrollment configurations configured in Intune
    .NOTES
    NAME: Get-EnrollmentConfigurationsbyName
    #>
    
    [cmdletbinding()]
    
    param
    (
        $name
    )
    
    $graphApiVersion = "beta"
    $Resource = "deviceManagement/deviceEnrollmentConfigurations"
    try {

    
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)?`$filter=displayName eq '$name'"
        $EC = (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value
    
        }
        catch {}
        $myid = $EC.id
        if ($null -ne $myid) {
            $fulluri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$myid"
            $type = "Enrollment Configuration"
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
    

Function Get-DeviceCategoriesbyName(){
    
    <#
    .SYNOPSIS
    This function is used to get Intune device categories from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any Intune device categories
    .EXAMPLE
    Get-DeviceCategoriesbyName
    Returns any device categories configured in Intune
    .NOTES
    NAME: Get-DeviceCategoriesbyName
    #>
    
    [cmdletbinding()]
    
    param
    (
        $name
    )
    
    $graphApiVersion = "beta"
    $Resource = "deviceManagement/deviceCategories"
    try {

    
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)?`$filter=displayName eq '$name'"
        $DC = (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value
    
        }
        catch {}
        $myid = $DC.id
        if ($null -ne $myid) {
            $fulluri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$myid"
            $type = "Device Category"
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


Function Get-DeviceFiltersbyName(){
    
    <#
    .SYNOPSIS
    This function is used to get Intune device filters from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any Intune device filters
    .EXAMPLE
    Get-DeviceFiltersbyName
    Returns any device filters configured in Intune
    .NOTES
    NAME: Get-DeviceFiltersbyName
    #>
    
    [cmdletbinding()]
    
    param
    (
        $name
    )
    
    $graphApiVersion = "beta"
    $Resource = "deviceManagement/assignmentFilters"
    try {

    
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)?`$filter=displayName eq '$name'"
        $DF = (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value
    
        }
        catch {}
        $myid = $DF.id
        if ($null -ne $myid) {
            $fulluri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$myid"
            $type = "Device Filter"
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


Function Get-BrandingProfilesbyName(){
    
    <#
    .SYNOPSIS
    This function is used to get Intune Branding Profiles from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any Intune Branding Profiles
    .EXAMPLE
    Get-BrandingProfilesbyName
    Returns any Branding Profiles configured in Intune
    .NOTES
    NAME: Get-BrandingProfilesbyName
    #>
    
    [cmdletbinding()]
    
    param
    (
        $name
    )
    
    $graphApiVersion = "beta"
    $Resource = "deviceManagement/intuneBrandingProfiles"
    try {

    
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)?`$filter=displayName eq '$name'"
        $BP = (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value
    
        }
        catch {}
        $myid = $BP.id
        if ($null -ne $myid) {
            $fulluri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$myid"
            $type = "Branding Profile"
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


Function Get-AdminApprovalsbyName(){
    
    <#
    .SYNOPSIS
    This function is used to get Intune admin approvals from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any Intune admin approvals
    .EXAMPLE
    Get-AdminApprovalsbyName
    Returns any admin approvals configured in Intune
    .NOTES
    NAME: Get-AdminApprovalsbyName
    #>
    
    [cmdletbinding()]
    
    param
    (
        $name
    )
    
    $graphApiVersion = "beta"
    $Resource = "deviceManagement/operationApprovalPolicies"
    try {

    
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)?`$filter=displayName eq '$name'"
        $AdminAp = (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value
    
        }
        catch {}
        $myid = $AdminAp.id
        if ($null -ne $myid) {
            $fulluri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$myid"
            $type = "Admin Approval"
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

Function Get-OrgMessagesbyName(){
    
    <#
    .SYNOPSIS
    This function is used to get Intune organizational messages from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any Intune organizational messages
    .EXAMPLE
    Get-OrgMessagesbyName
    Returns any organizational messages configured in Intune
    .NOTES
    NAME: Get-OrgMessagesbyName
    #>
    
    [cmdletbinding()]
    
    param
    (
        $name
    )
    
    $graphApiVersion = "beta"
    $Resource = "deviceManagement/organizationalMessageDetails"
    try {

    
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)?`$filter=displayName eq '$name'"
        $OM = (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value
    
        }
        catch {}
        $myid = $OM.id
        if ($null -ne $myid) {
            $fulluri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$myid"
            $type = "Organization Message"
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


Function Get-IntuneTermsbyName(){
    
    <#
    .SYNOPSIS
    This function is used to get Intune terms and conditions from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any Intune terms and conditions
    .EXAMPLE
    Get-IntuneTermsbyName
    Returns any terms and conditions configured in Intune
    .NOTES
    NAME: Get-IntuneTermsbyName
    #>
    
    [cmdletbinding()]
    
    param
    (
        $name
    )
    
    $graphApiVersion = "beta"
    $Resource = "deviceManagement/termsAndConditions"
    try {

    
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)?`$filter=displayName eq '$name'"
        $Terms = (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value
    
        }
        catch {}
        $myid = $Terms.id
        if ($null -ne $myid) {
            $fulluri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$myid"
            $type = "Terms and Conditions"
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

Function Get-IntuneRolesbyName(){
    
    <#
    .SYNOPSIS
    This function is used to get Intune custom roles from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any Intune custom roles
    .EXAMPLE
    Get-IntuneRolesbyName
    Returns any custom roles configured in Intune
    .NOTES
    NAME: Get-IntuneRolesbyName
    #>
    
    [cmdletbinding()]
    
    param
    (
        $name
    )
    
    $graphApiVersion = "beta"
    $Resource = "deviceManagement/roleDefinitions"
    try {

    
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)?`$filter=displayName eq '$name'"
        $Roles = (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value
    
        }
        catch {}
        $myid = $Roles.id
        if ($null -ne $myid) {
            $fulluri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$myid"
            $type = "Custom Role"
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
################################################################################################
####################################################
Function Get-GraphAADGroupsbyName(){
    
    <#
    .SYNOPSIS
    This function is used to get AAD Groups from the Graph API REST interface 
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any AAD Groups
    .EXAMPLE
    Get-GraphAADGroupsbyName
    Returns any AAD Groups
    .NOTES
    NAME: Get-GraphAADGroupsbyName
    #>
    
    [cmdletbinding()]
    
    param
    (
        $name
    )
    
    $graphApiVersion = "beta"
    $Resource = "Groups"
    try {

    
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)?`$filter=displayName eq '$name'"
        $AAD = (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value
    
        }
        catch {}
        $myid = $AAD.id
        if ($null -ne $myid) {
            $fulluri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$myid"
            $type = "AAD Group"
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

#################################################################################################  
function Get-DetailsbyName () {
    <#
    .SYNOPSIS
    This function is used to get  ID and URI from only the name
    .DESCRIPTION
    This function is used to get  ID and URI from only the name
    .EXAMPLE
    Get-DetailsbyName
    Returns ID and full URI
    .NOTES
    NAME: Get-DetailsbyName
    #>
    
    [cmdletbinding()]
    
    param
    (
        $name
    )

    $id = ""
    while ($id -eq "") {
$check = Get-DeviceConfigurationPolicybyName -name $name
if ($null -ne $check.id) {
    $id = $check.id
    $uri = $check.fulluri
    $type = $check.type
    break
}
$check = Get-DeviceConfigurationPolicySCbyName -name $name
if ($null -ne $check.id) {
    $id = $check.id
    $uri = $check.fulluri
    $type = $check.type
    break
}
$check = Get-DeviceCompliancePolicybyName -name $name
if ($null -ne $check.id) {
    $id = $check.id
    $uri = $check.fulluri
    $type = $check.type
    break
}
$check = Get-DeviceCompliancePolicyscriptsbyName -name $name
if ($null -ne $check.id) {
    $id = $check.id
    $uri = $check.fulluri
    $type = $check.type
    break
}
$check = Get-DeviceSecurityPolicybyName -name $name
if ($null -ne $check.id) {
    $id = $check.id
    $uri = $check.fulluri
    $type = $check.type
    break
}
$check = Get-AutoPilotProfilebyName -name $name
if ($null -ne $check.id) {
    $id = $check.id
    $uri = $check.fulluri
    $type = $check.type
    break
}
$check = Get-AutoPilotESPbyName -name $name
if ($null -ne $check.id) {
    $id = $check.id
    $uri = $check.fulluri
    $type = $check.type
    break
}
$check = Get-ManagedAppProtectionAndroidbyName -name $name
if ($null -ne $check.id) {
    $id = $check.id
    $uri = $check.fulluri
    $type = $check.type
    break
}
$check = Get-ManagedAppProtectioniosbyName -name $name
if ($null -ne $check.id) {
    $id = $check.id
    $uri = $check.fulluri
    $type = $check.type
    break
}
$check = Get-DeviceConfigurationPolicyGPbyName -name $name
if ($null -ne $check.id) {
    $id = $check.id
    $uri = $check.fulluri
    $type = $check.type
    break
}
$check = Get-ConditionalAccessPolicybyName -name $name
if ($null -ne $check.id) {
    $id = $check.id
    $uri = $check.fulluri
    $type = $check.type
    break
}
$check = Get-DeviceProactiveRemediationsbyName -name $name
if ($null -ne $check.id) {
    $id = $check.id
    $uri = $check.fulluri
    $type = $check.type
    break
}
$check = Get-MobileAppConfigurationsbyName -name $name
if ($null -ne $check.id) {
    $id = $check.id
    $uri = $check.fulluri
    $type = $check.type
    break
}
$check = Get-GraphAADGroupsbyName -name $name
if ($null -ne $check.id) {
    $id = $check.id
    $uri = $check.fulluri
    $type = $check.type
    break
}
$check = Get-IntuneApplicationbyName -name $name
if ($null -ne $check.id) {
    $id = $check.id
    $uri = $check.fulluri
    $type = $check.type
    break
}
$check = Get-DeviceManagementScriptsbyName -name $name
if ($null -ne $check.id) {
    $id = $check.id
    $uri = $check.fulluri
    $type = $check.type
    break
}
$check = Get-Win365UserSettingsbyName -name $name
if ($null -ne $check.id) {
    $id = $check.id
    $uri = $check.fulluri
    $type = $check.type
    break
}
$check = Get-FeatureUpdatePoliciesbyName -name $name
if ($null -ne $check.id) {
    $id = $check.id
    $uri = $check.fulluri
    $type = $check.type
    break
}
$check = Get-QualityUpdatePoliciesbyName -name $name
if ($null -ne $check.id) {
    $id = $check.id
    $uri = $check.fulluri
    $type = $check.type
    break
}
$check = Get-DriverUpdatePoliciesbyName -name $name
if ($null -ne $check.id) {
    $id = $check.id
    $uri = $check.fulluri
    $type = $check.type
    break
}
$check = Get-Win365ProvisioningPoliciesbyName -name $name
if ($null -ne $check.id) {
    $id = $check.id
    $uri = $check.fulluri
    $type = $check.type
    break
}
$check = Get-IntunePolicySetsbyName -name $name
if ($null -ne $check.id) {
    $id = $check.id
    $uri = $check.fulluri
    $type = $check.type
    break
}
$check = Get-EnrollmentConfigurationsbyName -name $name
if ($null -ne $check.id) {
    $id = $check.id
    $uri = $check.fulluri
    $type = $check.type
    break
}
$check = Get-DeviceCategoriesbyName -name $name
if ($null -ne $check.id) {
    $id = $check.id
    $uri = $check.fulluri
    $type = $check.type
    break
}
$check = Get-DeviceFiltersbyName -name $name
if ($null -ne $check.id) {
    $id = $check.id
    $uri = $check.fulluri
    $type = $check.type
    break
}
$check = Get-BrandingProfilesbyName -name $name
if ($null -ne $check.id) {
    $id = $check.id
    $uri = $check.fulluri
    $type = $check.type
    break
}
$check = Get-AdminApprovalsbyName -name $name
if ($null -ne $check.id) {
    $id = $check.id
    $uri = $check.fulluri
    $type = $check.type
    break
}
#$orgmessages = Get-OrgMessages -id $id
$check = Get-IntuneTermsbyName -name $name
if ($null -ne $check.id) {
    $id = $check.id
    $uri = $check.fulluri
    $type = $check.type
    break
}
$check = Get-WHfBPoliciesbyName -name $name
if ($null -ne $check.id) {
    $id = $check.id
    $uri = $check.fulluri
    $type = $check.type
    break
}
$check = Get-IntuneRolesbyName -name $name
if ($null -ne $check.id) {
    $id = $check.id
    $uri = $check.fulluri
    $type = $check.type
    break
}
    }
    $output = "" | Select-Object -Property id,uri, type    
        $output.id = $id
        $output.uri = $uri
        $output.type = $type
        return $output
}
#################################################################################################
### ASSIGNMENT FUNCTIONS
#################################################################################################
Function Get-IntuneApplicationAssignments() {
    
    <#
    .SYNOPSIS
    This function is used to get application assignments from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any application assignments
    .EXAMPLE
    Get-IntuneApplicationAssignments
    Returns any application assignments configured in Intune
    .NOTES
    NAME: Get-IntuneApplicationAssignments
    #>
    
    [cmdletbinding()]
    
    param
    (
        [Parameter(Position = 0, mandatory = $true)]
        $id
    )
    
    $graphApiVersion = "Beta"
    $Resource = "deviceAppManagement/mobileApps"
    
    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$id/assignments"
            (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject)
    }
    
    catch {
    
    }
    
}

Function Get-DeviceConfigurationPolicyGPAssignments() {
    
    <#
        .SYNOPSIS
        This function is used to get Group Policy assignments from the Graph API REST interface
        .DESCRIPTION
        The function connects to the Graph API Interface and gets any group policy assignments
        .EXAMPLE
        Get-DeviceConfigurationPolicyGPAssignments
        Returns any group policy assignments configured in Intune
        .NOTES
        NAME: Get-DeviceConfigurationPolicyGPAssignments
        #>
        
    [cmdletbinding()]
        
    param
    (
        [Parameter(Position = 0, mandatory = $true)]
        $id
    )
        
    $graphApiVersion = "Beta"
    $Resource = "deviceManagement/groupPolicyConfigurations"
        
    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$id/assignments"
                (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject)
    }
        
    catch {
        
    }
        
}


Function Get-DeviceConfigurationPolicyAssignments() {
    
    <#
            .SYNOPSIS
            This function is used to get configuration Policy assignments from the Graph API REST interface
            .DESCRIPTION
            The function connects to the Graph API Interface and gets any configuration policy assignments
            .EXAMPLE
            Get-DeviceConfigurationPolicyAssignments
            Returns any configuration policy assignments configured in Intune
            .NOTES
            NAME: Get-DeviceConfigurationPolicyAssignments
            #>
            
    [cmdletbinding()]
            
    param
    (
        [Parameter(Position = 0, mandatory = $true)]
        $id
    )
            
    $graphApiVersion = "Beta"
    $Resource = "deviceManagement/deviceConfigurations"
            
    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$id/assignments"
                    (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject)
    }
            
    catch {
            
    }
            
}

Function Get-DeviceConfigurationPolicySCAssignments() {
    
    <#
                .SYNOPSIS
                This function is used to get settings catalog Policy assignments from the Graph API REST interface
                .DESCRIPTION
                The function connects to the Graph API Interface and gets any settings catalog policy assignments
                .EXAMPLE
                Get-DeviceConfigurationPolicySCAssignments
                Returns any settings catalog policy assignments configured in Intune
                .NOTES
                NAME: Get-DeviceConfigurationPolicySCAssignments
                #>
                
    [cmdletbinding()]
                
    param
    (
        [Parameter(Position = 0, mandatory = $true)]
        $id
    )
                
    $graphApiVersion = "Beta"
    $Resource = "deviceManagement/configurationPolicies"
                
    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$id/assignments"
                        (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject)
    }
                
    catch {
                
    }
                
}
Function Get-DeviceProactiveRemediationsAssignments() {
    
    <#
                    .SYNOPSIS
                    This function is used to get proactive remediation assignments from the Graph API REST interface
                    .DESCRIPTION
                    The function connects to the Graph API Interface and gets any proactive remediation assignments
                    .EXAMPLE
                    Get-DeviceProactiveRemediationsAssignments
                    Returns any proactive remediation assignments configured in Intune
                    .NOTES
                    NAME: Get-DeviceProactiveRemediationsAssignments
                    #>
                    
    [cmdletbinding()]
                    
    param
    (
        [Parameter(Position = 0, mandatory = $true)]
        $id
    )
                    
    $graphApiVersion = "Beta"
    $Resource = "deviceManagement/devicehealthscripts"
                    
    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$id/assignments"
                            (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject)
    }
                    
    catch {
                    
    }
                    
}


Function Get-MobileAppConfigurationsAssignments() {
    
    <#
                    .SYNOPSIS
                    This function is used to get Mobile App Configuration assignments from the Graph API REST interface
                    .DESCRIPTION
                    The function connects to the Graph API Interface and gets any Mobile App Configuration assignments
                    .EXAMPLE
                    Get-MobileAppConfigurationsAssignments
                    Returns any Mobile App Configuration assignments configured in Intune
                    .NOTES
                    NAME: Get-MobileAppConfigurationsAssignments
                    #>
                    
    [cmdletbinding()]
                    
    param
    (
        [Parameter(Position = 0, mandatory = $true)]
        $id
    )
                    
    $graphApiVersion = "Beta"
    $Resource = "deviceAppManagement/mobileAppConfigurations"
                    
    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$id/assignments"
                            (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject)
    }
                    
    catch {
                    
    }
                    
}
Function Get-DeviceCompliancePolicyAssignments() {
    
    <#
                        .SYNOPSIS
                        This function is used to get compliance policy assignments from the Graph API REST interface
                        .DESCRIPTION
                        The function connects to the Graph API Interface and gets any compliance policy assignments
                        .EXAMPLE
                        Get-DeviceCompliancePolicyAssignments
                        Returns any compliance policy assignments configured in Intune
                        .NOTES
                        NAME: Get-DeviceCompliancePolicyAssignments
                        #>
                        
    [cmdletbinding()]
                        
    param
    (
        [Parameter(Position = 0, mandatory = $true)]
        $id
    )
                        
    $graphApiVersion = "Beta"
    $Resource = "deviceManagement/deviceCompliancePolicies"
                        
    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$id/assignments"
                                (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject)
    }
                        
    catch {
                        
    }
                        
}
Function Get-DeviceSecurityPolicyAssignments() {
    
    <#
                            .SYNOPSIS
                            This function is used to get security policy assignments from the Graph API REST interface
                            .DESCRIPTION
                            The function connects to the Graph API Interface and gets any security policy assignments
                            .EXAMPLE
                            Get-DeviceSecurityPolicyAssignments
                            Returns any security policy assignments configured in Intune
                            .NOTES
                            NAME: Get-DeviceSecurityPolicyAssignments
                            #>
                            
    [cmdletbinding()]
                            
    param
    (
        [Parameter(Position = 0, mandatory = $true)]
        $id
    )
                            
    $graphApiVersion = "Beta"
    $Resource = "deviceManagement/intents"
                            
    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$id/assignments"
                                    (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject)
    }
                            
    catch {
                            
    }
                            
}
                                  

Function Get-AutoPilotProfileAssignments() {
    
    <#
                                        .SYNOPSIS
                                        This function is used to get autopilot profile assignments from the Graph API REST interface
                                        .DESCRIPTION
                                        The function connects to the Graph API Interface and gets any autopilot profile assignments
                                        .EXAMPLE
                                        Get-AutoPilotProfileAssignments
                                        Returns any autopilot profile assignments configured in Intune
                                        .NOTES
                                        NAME: Get-AutoPilotProfileAssignments
                                        #>
                                        
    [cmdletbinding()]
                                        
    param
    (
        [Parameter(Position = 0, mandatory = $true)]
        $id
    )
                                        
    $graphApiVersion = "Beta"
    $Resource = "deviceManagement/windowsAutopilotDeploymentProfiles"
                                        
    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$id/assignments"
                                                (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject)
    }
                                        
    catch {
                                        
    }
                                        
}
                                        
Function Get-AutoPilotESPAssignments() {
    
    <#
                                            .SYNOPSIS
                                            This function is used to get autopilot ESP assignments from the Graph API REST interface
                                            .DESCRIPTION
                                            The function connects to the Graph API Interface and gets any autopilot ESP assignments
                                            .EXAMPLE
                                            Get-AutoPilotESPAssignments
                                            Returns any autopilot ESP assignments configured in Intune
                                            .NOTES
                                            NAME: Get-AutoPilotESPAssignments
                                            #>
                                            
    [cmdletbinding()]
                                            
    param
    (
        [Parameter(Position = 0, mandatory = $true)]
        $id
    )
                                            
    $graphApiVersion = "Beta"
    $Resource = "deviceManagement/deviceEnrollmentConfigurations"
                                            
    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$id/assignments"
                                                    (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject)
    }
                                            
    catch {
                                            
    }
                                            
}
                                            
Function Get-DeviceManagementScriptsAssignments() {
    
    <#
                                                .SYNOPSIS
                                                This function is used to get PowerShell script assignments from the Graph API REST interface
                                                .DESCRIPTION
                                                The function connects to the Graph API Interface and gets any PowerShell script assignments
                                                .EXAMPLE
                                                Get-DeviceManagementScriptsAssignments
                                                Returns any PowerShell script assignments configured in Intune
                                                .NOTES
                                                NAME: Get-DeviceManagementScriptsAssignments
                                                #>
                                                
    [cmdletbinding()]
                                                
    param
    (
        [Parameter(Position = 0, mandatory = $true)]
        $id
    )
                                                
    $graphApiVersion = "Beta"
    $Resource = "deviceManagement/devicemanagementscripts"
                                                
    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$id/assignments"
                                                        (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject)
    }
                                                
    catch {
                                                
    }
                                                
}

Function Get-Win365UserSettingsAssignments() {
    
    <#
                                                    .SYNOPSIS
                                                    This function is used to get Windows 365 User Settings Policies assignments from the Graph API REST interface
                                                    .DESCRIPTION
                                                    The function connects to the Graph API Interface and gets any Windows 365 User Settings Policies assignments
                                                    .EXAMPLE
                                                    Get-Win365UserSettingsAssignments
                                                    Returns any Windows 365 User Settings Policies assignments configured in Intune
                                                    .NOTES
                                                    NAME: Get-Win365UserSettingsAssignments
                                                    #>
                                                    
    [cmdletbinding()]
                                                    
    param
    (
        [Parameter(Position = 0, mandatory = $true)]
        $id
    )
                                                    
    $graphApiVersion = "Beta"
    $Resource = "deviceManagement/virtualEndpoint/userSettings"
                                                    
    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$id/assignments"
                                                            (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject)
    }
                                                    
    catch {
                                                    
    }
                                                    
}

Function Get-FeatureUpdatePoliciesAssignments() {
    
    <#
    .SYNOPSIS
    This function is used to get Feature Update Policies assignments from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any Feature Update Policies assignments
    .EXAMPLE
    Get-FeatureUpdatePoliciesAssignments
    Returns any Feature Update Policies assignments configured in Intune
    .NOTES
    NAME: Get-FeatureUpdatePoliciesAssignments
    #>
    [cmdletbinding()]
    param
    (
        [Parameter(Position = 0, mandatory = $true)]
        $id
    )
    $graphApiVersion = "Beta"
    $Resource = "deviceManagement/windowsFeatureUpdateProfiles"
    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$id/assignments"
        (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject)
    }

    catch {
    }
}


Function Get-QualityUpdatePoliciesAssignments() {
    
    <#
    .SYNOPSIS
    This function is used to get Quality Update Policies assignments from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any Quality Update Policies assignments
    .EXAMPLE
    Get-QualityUpdatePoliciesAssignments
    Returns any Quality Update Policies assignments configured in Intune
    .NOTES
    NAME: Get-QualityUpdatePoliciesAssignments
    #>
    [cmdletbinding()]
    param
    (
        [Parameter(Position = 0, mandatory = $true)]
        $id
    )
    $graphApiVersion = "Beta"
    $Resource = "deviceManagement/windowsQualityUpdateProfiles"
    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$id/assignments"
        (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject)
    }

    catch {
    }
}


Function Get-DriverUpdatePoliciesAssignments() {
    
    <#
    .SYNOPSIS
    This function is used to get Driver Update Policies assignments from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any Driver Update Policies assignments
    .EXAMPLE
    Get-DriverUpdatePoliciesAssignments
    Returns any Driver Update Policies assignments configured in Intune
    .NOTES
    NAME: Get-DriverUpdatePoliciesAssignments
    #>
    [cmdletbinding()]
    param
    (
        [Parameter(Position = 0, mandatory = $true)]
        $id
    )
    $graphApiVersion = "Beta"
    $Resource = "deviceManagement/windowsDriverUpdateProfiles"
    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$id/assignments"
        (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject)
    }

    catch {
    }
}

Function Get-Win365ProvisioningPoliciesAssignments() {
    
    <#
        .SYNOPSIS
        This function is used to get Windows 365 Provisioning Policies assignments from the Graph API REST interface
        .DESCRIPTION
                                                        The function connects to the Graph API Interface and gets any Windows 365 Provisioning Policies assignments
                                                        .EXAMPLE
                                                        Get-Win365ProvisioningPoliciesAssignments
                                                        Returns any Windows 365 Provisioning Policies assignments configured in Intune
                                                        .NOTES
                                                        NAME: Get-Win365ProvisioningPoliciesAssignments
                                                        #>
                                                        
    [cmdletbinding()]
                                                        
    param
    (
        [Parameter(Position = 0, mandatory = $true)]
        $id
    )
                                                        
    $graphApiVersion = "Beta"
    $Resource = "deviceManagement/virtualEndpoint/provisioningPolicies"
                                                        
    try {
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)/$id/assignments"
                                                                (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject)
    }
                                                        
    catch {
                                                        
    }
                                                        
}                         

Function Get-EnrollmentConfigurationsAssignments(){
    
    <#
    .SYNOPSIS
    This function is used to get Intune enrollment configurations from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any Intune enrollment configurations
    .EXAMPLE
    Get-EnrollmentConfigurationsAssignments -id xx
    Returns any enrollment configurations configured in Intune
    .NOTES
    NAME: Get-EnrollmentConfigurationsAssignments
    #>
    
    [cmdletbinding()]
    
    param
    (
        $id
    )
    
    $graphApiVersion = "beta"
    $DCP_resource = "deviceManagement/deviceEnrollmentConfigurations"
    try {
 
    
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)/$id/assignments"
            (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject)

        }
        catch {}
    
   
}


Function Get-BrandingProfilesAssignments(){
    
    <#
    .SYNOPSIS
    This function is used to get Intune Branding Profiles assignments from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any Intune Branding Profiles assignments
    .EXAMPLE
    Get-BrandingProfilesAssignments
    Returns any Branding Profiles assignments configured in Intune
    .NOTES
    NAME: Get-BrandingProfilesAssignments
    #>
    
    [cmdletbinding()]
    
    param
    (
        $id
    )
    
    $graphApiVersion = "beta"
    $DCP_resource = "deviceManagement/intuneBrandingProfiles"
    try {
    
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)/$id/assignments"
            (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject)

        }
        catch {}
    
   
}


Function Get-AdminApprovalsAssignments(){
    
    <#
    .SYNOPSIS
    This function is used to get Intune admin approvals assignments from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any Intune admin approvals assignments
    .EXAMPLE
    Get-AdminApprovalsAssignments
    Returns any admin approvals assignments configured in Intune
    .NOTES
    NAME: Get-AdminApprovalsAssignments
    #>
    
    [cmdletbinding()]
    
    param
    (
        $id
    )
    
    $graphApiVersion = "beta"
    $DCP_resource = "deviceManagement/operationApprovalPolicies"
    try {
   
    
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)/$id/assignments"
            (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject)
  
    }
        catch {}
    
   
}

Function Get-DeviceCompliancePolicyScriptsAssignments(){
    
    <#
    .SYNOPSIS
    This function is used to get device custom compliance policy scripts Assignments from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any device compliance policies assignments
    .EXAMPLE
    Get-DeviceCompliancePolicyScriptsAssignments
    Returns any device compliance policy scripts assignments configured in Intune
    .NOTES
    NAME: Get-DeviceCompliancePolicyScriptsAssignments
    #>
    
    [cmdletbinding()]
    
    param
    (
        $id
    )
    
    $graphApiVersion = "beta"
    $DCP_resource = "deviceManagement/deviceComplianceScripts"
    try {
      
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)/$id/assignments"
            (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject)
    
        }
        catch {}
    
}

Function Get-IntuneTermsAssignments(){
    
    <#
    .SYNOPSIS
    This function is used to get Intune terms and conditions assignments from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any Intune terms and conditions assignments
    .EXAMPLE
    Get-IntuneTermsAssignments
    Returns any terms and conditions assignments configured in Intune
    .NOTES
    NAME: Get-IntuneTermsAssignments
    #>
    
    [cmdletbinding()]
    
    param
    (
        $id
    )
    
    $graphApiVersion = "beta"
    $DCP_resource = "deviceManagement/termsAndConditions"
    try {
    
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)/$id/assignments"
            (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject)

        }
        catch {}
    
   
}
function getallgroups () {
<#
.SYNOPSIS
This function is used to grab all groups in Azure AD
.DESCRIPTION
The function connects to the Graph API Interface and gets all groups
.EXAMPLE
getallgroups
 Returns all groups
.NOTES
 NAME: getallgroups
#>
    $response = (Invoke-MgGraphRequest -uri "https://graph.microsoft.com/beta/groups" -Method Get -OutputType PSObject)
    $allgroups = $response.value
    
    $allgroupsNextLink = $response."@odata.nextLink"
    
    while ($null -ne $allgroupsNextLink) {
        $allgroupsResponse = (Invoke-MGGraphRequest -Uri $allgroupsNextLink -Method Get -outputType PSObject)
        $allgroupsNextLink = $allgroupsResponse."@odata.nextLink"
        $allgroups += $allgroupsResponse.value
    }
    
    return $allgroups
}
function getallfilters () {
    $response = (Invoke-MgGraphRequest -uri "https://graph.microsoft.com/beta/deviceManagement/assignmentFilters" -Method Get -OutputType PSObject)
    $allfilters = $response.value
    
    $allfiltersNextLink = $response."@odata.nextLink"
    
    while ($null -ne $allfiltersNextLink) {
        $allfiltersResponse = (Invoke-MGGraphRequest -Uri $allfiltersNextLink -Method Get -outputType PSObject)
        $allfiltersNextLink = $allfiltersResponse."@odata.nextLink"
        $allfilters += $allfiltersResponse.value
    }
    
    return $allfilters
    }
function convertidtoname() {
    [cmdletbinding()]
    
    param
    (
        [Parameter(Position = 0, mandatory = $true)]
        $json,
        $allgroups,
        $allfilters
    )
    
foreach ($assignment in $json) {
    $groupid = $assignment.target.groupid
    if ($groupid) {
    $groupname = $allgroups | where-object {$_.id -eq $groupid} | select-object -expandproperty displayname
    $assignment.target.groupId = $groupname
    }
    $filterid = $assignment.target.deviceAndAppManagementAssignmentFilterId
    if ($filterid) {
    $filtername = $allfilters | where-object {$_.id -eq $filterid} | select-object -expandproperty displayname
    $assignment.target.deviceAndAppManagementAssignmentFilterId = $filtername
    }
}
return $json
}

function convertnametoid() {
    [cmdletbinding()]
    
    param
    (
        [Parameter(Position = 0, mandatory = $true)]
        $json,
        $allgroups,
        $allfilters,
        $create
    )
foreach ($assignment in $json) {
    $groupid = $assignment.target.groupid
    if ($groupid) {
    $groupname = $allgroups | where-object {$_.displayName -eq $groupid} | select-object -expandproperty ID
    ##If group can't be found and create is yes, create it
    if (!$groupname -and $create -eq "yes") {
                ##Remove all spaces and special characters for the nickname
                $groupidnick = $groupid -replace " ",""
                $groupidnick = $groupid -replace "[^a-zA-Z0-9]",""
    $groupjson = @"
        {
            "description": "$groupid Automatically Created",
            "displayName": "$groupid",
            "groupTypes": [
            ],
            "mailEnabled": false,
            "mailNickname": "$groupidnick",
            "securityEnabled": true,
          }
"@
        $group = Invoke-MgGraphRequest -Uri "https://graph.microsoft.com/beta/groups" -Method Post -Body $groupjson -OutputType PSObject
        $groupname = $group.id
    }
    $assignment.target.groupId = $groupname
    }
    $filterid = $assignment.target.deviceAndAppManagementAssignmentFilterId
    if ($filterid) {
    $filtername = $allfilters | where-object {$_.displayName -eq $filterid} | select-object -expandproperty ID
    $assignment.target.deviceAndAppManagementAssignmentFilterId = $filtername
    }
}
return $json
}

#################################################################################################
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

#################################################################################################
function getpolicyjson() {
    <#
.SYNOPSIS
This function is used to add a new device policy by copying an existing policy, manipulating the JSON and then adding via Graph
.DESCRIPTION
The function grabs an existing policy, decrypts if requires, renames, removes any GUIDs and then returns the JSON
.EXAMPLE
getpolicyjson -policy $policy -name $name
.NOTES
NAME: getpolicyjson
#>

param
(
    $resource,
    $policyid
)
write-host $resource
$id = $policyid
$graphApiVersion = "beta"
switch ($resource) {
"deviceManagement/deviceConfigurations" {
 $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"
 $policy = Get-DecryptedDeviceConfigurationPolicy -dcpid $id
 $oldname = $policy.displayName
 $restoredate = get-date -format dd-MM-yyyy-HH-mm-ss
 if ($changename -eq "yes") {
    $newname = $oldname + "-restore-" + $restoredate
}
else {
    $newname = $oldname
}
 $policy.displayName = $newname

 ##Custom settings only for OMA-URI
         ##Remove settings which break Custom OMA-URI
    
         
         if ($null -ne $policy.omaSettings) {
            $policyconvert = $policy.omaSettings
         $policyconvert = $policyconvert | Select-Object -Property * -ExcludeProperty secretReferenceValueId
         foreach ($pvalue in $policyconvert) {
         $unencoded = $pvalue.value
         ##Check if $unencoded is boolean
         if ($unencoded -is [bool] -or $unencoded -is [int] -or $unencoded -is [int32] -or $unencoded -is [int64]) {
            $unencoded = $unencoded.ToString().ToLower()
        }
        $EncodedText =[Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($unencoded))
        
$pvalue.value = $unencoded
         }
         $policy.omaSettings = @($policyconvert)
        }
     # Set SupportsScopeTags to $false, because $true currently returns an HTTP Status 400 Bad Request error.
if ($policy.supportsScopeTags) {
    $policy.supportsScopeTags = $false
}



    $policy.PSObject.Properties | Foreach-Object {
        if ($null -ne $_.Value) {
            if ($_.Value.GetType().Name -eq "DateTime") {
                $_.Value = (Get-Date -Date $_.Value -Format s) + "Z"
            }
            if ($_.Value.GetType().Name -eq "isEncrypted") {
                $_.Value = "false"
            }
        }
    }

    $assignments = Get-DeviceConfigurationPolicyAssignments -id $id
}

"deviceManagement/groupPolicyConfigurations" {
    $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"
    $policy = Get-DeviceConfigurationPolicyGP -id $id
    $oldname = $policy.DisplayName
    $restoredate = get-date -format dd-MM-yyyy-HH-mm-ss
    if ($changename -eq "yes") {
        $newname = $oldname + "-restore-" + $restoredate
    }
    else {
        $newname = $oldname
    }        
    $policy.displayName = $newname
        # Set SupportsScopeTags to $false, because $true currently returns an HTTP Status 400 Bad Request error.
   if ($policy.supportsScopeTags) {
       $policy.supportsScopeTags = $false
   }

       $policy.PSObject.Properties | Foreach-Object {
           if ($null -ne $_.Value) {
               if ($_.Value.GetType().Name -eq "DateTime") {
                   $_.Value = (Get-Date -Date $_.Value -Format s) + "Z"
               }
           }
       }
       $gppolicyid = $policy.id
                       ##Now grab the JSON
                       $GroupPolicyConfigurationsDefinitionValues = Get-GroupPolicyConfigurationsDefinitionValues -GroupPolicyConfigurationID $gppolicyid
                       
       foreach ($GroupPolicyConfigurationsDefinitionValue in $GroupPolicyConfigurationsDefinitionValues)
       {
           $DefinitionValuedefinition = Get-GroupPolicyConfigurationsDefinitionValuesdefinition -GroupPolicyConfigurationID $gppolicyid -GroupPolicyConfigurationsDefinitionValueID $GroupPolicyConfigurationsDefinitionValue.id
           $DefinitionValuedefinitionID = $DefinitionValuedefinition.id
           $DefinitionValuedefinitionDisplayName = $DefinitionValuedefinition.displayName
           $DefinitionValuedefinitionDisplayName = $DefinitionValuedefinitionDisplayName
           $GroupPolicyDefinitionsPresentations = Get-GroupPolicyDefinitionsPresentations -groupPolicyDefinitionsID $id -GroupPolicyConfigurationsDefinitionValueID $GroupPolicyConfigurationsDefinitionValue.id
           $DefinitionValuePresentationValues = Get-GroupPolicyConfigurationsDefinitionValuesPresentationValues -GroupPolicyConfigurationID $id -GroupPolicyConfigurationsDefinitionValueID $GroupPolicyConfigurationsDefinitionValue.id
           $policy | Add-Member -MemberType NoteProperty -Name "definition@odata.bind" -Value "https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions('$definitionValuedefinitionID')" -Force
           $policy | Add-Member -MemberType NoteProperty -Name "enabled" -value $($GroupPolicyConfigurationsDefinitionValue.enabled.tostring().tolower()) -Force
               if ($DefinitionValuePresentationValues) {
                   $i = 0
                   $PresValues = @()
                   foreach ($Pres in $DefinitionValuePresentationValues) {
                       $P = $pres | Select-Object -Property * -ExcludeProperty id, createdDateTime, lastModifiedDateTime, version
                       $GPDPID = $groupPolicyDefinitionsPresentations[$i].id
                       $P | Add-Member -MemberType NoteProperty -Name "presentation@odata.bind" -Value "https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions('$definitionValuedefinitionID')/presentations('$GPDPID')" -Force
                       $PresValues += $P
                       $i++
                   }
               $policy | Add-Member -MemberType NoteProperty -Name "presentationValues" -Value $PresValues -Force
               }
            }

            
          $assignments = Get-DeviceConfigurationPolicyGPAssignments -id $id
   }

"deviceManagement/devicehealthscripts" {
    $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"
    $policy = Get-DeviceProactiveRemediations -id $id
    $oldname = $policy.DisplayName
    $restoredate = get-date -format dd-MM-yyyy-HH-mm-ss
    if ($changename -eq "yes") {
        $newname = $oldname + "-restore-" + $restoredate
    }
    else {
        $newname = $oldname
    }        $policy.displayName = $newname
        # Set SupportsScopeTags to $false, because $true currently returns an HTTP Status 400 Bad Request error.
   if ($policy.supportsScopeTags) {
       $policy.supportsScopeTags = $false
   }

       $policy.PSObject.Properties | Foreach-Object {
           if ($null -ne $_.Value) {
               if ($_.Value.GetType().Name -eq "DateTime") {
                   $_.Value = (Get-Date -Date $_.Value -Format s) + "Z"
               }
           }
       }

            $assignments = Get-DeviceProactiveRemediationsAssignments -id $id
   }
   "deviceAppManagement/mobileAppConfigurations" {
    $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"
    $policy = Get-MobileAppConfigurations -id $id
    $oldname = $policy.DisplayName
    $restoredate = get-date -format dd-MM-yyyy-HH-mm-ss
    if ($changename -eq "yes") {
        $newname = $oldname + "-restore-" + $restoredate
    }
    else {
        $newname = $oldname
    }        $policy.displayName = $newname
        # Set SupportsScopeTags to $false, because $true currently returns an HTTP Status 400 Bad Request error.
   if ($policy.supportsScopeTags) {
       $policy.supportsScopeTags = $false
   }

       $policy.PSObject.Properties | Foreach-Object {
           if ($null -ne $_.Value) {
               if ($_.Value.GetType().Name -eq "DateTime") {
                   $_.Value = (Get-Date -Date $_.Value -Format s) + "Z"
               }
           }
       }

            $assignments = Get-MobileAppConfigurationsAssignments -id $id
   }

   "deviceManagement/devicemanagementscripts" {
    $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"
    $policy = Get-DeviceManagementScripts -id $id
    $oldname = $policy.DisplayName
    $restoredate = get-date -format dd-MM-yyyy-HH-mm-ss
    if ($changename -eq "yes") {
        $newname = $oldname + "-restore-" + $restoredate
    }
    else {
        $newname = $oldname
    }        $policy.displayName = $newname
        # Set SupportsScopeTags to $false, because $true currently returns an HTTP Status 400 Bad Request error.
   if ($policy.supportsScopeTags) {
       $policy.supportsScopeTags = $false
   }

       $policy.PSObject.Properties | Foreach-Object {
           if ($null -ne $_.Value) {
               if ($_.Value.GetType().Name -eq "DateTime") {
                   $_.Value = (Get-Date -Date $_.Value -Format s) + "Z"
               }
           }
       }

            $assignments = Get-DeviceManagementScriptsAssignments -id $id
   }

   "deviceManagement/deviceComplianceScripts" {
    $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"
    $policy = Get-DeviceCompliancePolicyScripts -id $id
    $oldname = $policy.DisplayName
    $restoredate = get-date -format dd-MM-yyyy-HH-mm-ss
    if ($changename -eq "yes") {
        $newname = $oldname + "-restore-" + $restoredate
    }
    else {
        $newname = $oldname
    }        $policy.displayName = $newname
        # Set SupportsScopeTags to $false, because $true currently returns an HTTP Status 400 Bad Request error.
   if ($policy.supportsScopeTags) {
       $policy.supportsScopeTags = $false
   }

       $policy.PSObject.Properties | Foreach-Object {
           if ($null -ne $_.Value) {
               if ($_.Value.GetType().Name -eq "DateTime") {
                   $_.Value = (Get-Date -Date $_.Value -Format s) + "Z"
               }
           }
       }
        
                $assignments = Get-DeviceCompliancePolicyScriptsAssignments -id $id
   }


   "deviceManagement/configurationPolicies" {
    $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"
    $policy = Get-DeviceConfigurationPolicysc -id $id
    $policy | Add-Member -MemberType NoteProperty -Name 'settings' -Value @() -Force
    #$settings = Invoke-MSGraphRequest -HttpMethod GET -Url "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies/$id/settings" | Get-MSGraphAllPages
    $uri2 = "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies/$id/settings"
    $response = (Invoke-MgGraphRequest -uri $uri2 -Method Get -OutputType PSObject)
    $allsettings = $response.value
    
    $allsettingsNextLink = $response."@odata.nextLink"
    
    while ($null -ne $allsettingsNextLink) {
        $allsettingsResponse = (Invoke-MGGraphRequest -Uri $allsettingsNextLink -Method Get -outputType PSObject)
        $allsettingsNextLink = $allsettingsResponse."@odata.nextLink"
        $allsettings += $allsettingsResponse.value
    }

    $settings =  $allsettings | select-object * -ExcludeProperty '@odata.count'
    if ($settings -isnot [System.Array]) {
        $policy.Settings = @($settings)
    } else {
        $policy.Settings = $settings
    }
    
    #
    $oldname = $policy.Name
    $restoredate = get-date -format dd-MM-yyyy-HH-mm-ss
    if ($changename -eq "yes") {
        $newname = $oldname + "-restore-" + $restoredate
    }
    else {
        $newname = $oldname
    }        $policy.Name = $newname
        $assignments = Get-DeviceConfigurationPolicySCAssignments -id $id

}

"deviceManagement/deviceCompliancePolicies" {
    $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"
    $policy = Get-DeviceCompliancePolicy -id $id
    $oldname = $policy.DisplayName
    $restoredate = get-date -format dd-MM-yyyy-HH-mm-ss
    if ($changename -eq "yes") {
        $newname = $oldname + "-restore-" + $restoredate
    }
    else {
        $newname = $oldname
    }        $policy.displayName = $newname
    
        $scheduledActionsForRule = @(
            @{
                ruleName = "PasswordRequired"
                scheduledActionConfigurations = @(
                    @{
                        actionType = "block"
                        gracePeriodHours = 0
                        notificationTemplateId = ""
                    }
                )
            }
        )
        $policy | Add-Member -NotePropertyName scheduledActionsForRule -NotePropertyValue $scheduledActionsForRule
        
        $assignments = Get-DeviceCompliancePolicyAssignments -id $id
        
}

"deviceManagement/intents" {
    $policy = Get-DeviceSecurityPolicy -id $id
    $templateid = $policy.templateID
    $uri = "https://graph.microsoft.com/beta/deviceManagement/templates/$templateId/createInstance"
    #$template = Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/deviceManagement/templates/$templateid" -Headers $authToken -Method Get
    $template = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/deviceManagement/templates/$templateid" -OutputType PSObject
    $template = $template
    #$templateCategory = Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/deviceManagement/templates/$templateid/categories" -Headers $authToken -Method Get
    $templateCategories = (Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/deviceManagement/templates/$templateid/categories" -OutputType PSObject).Value
    #$intentSettingsDelta = (Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/deviceManagement/intents/$id/categories/$($templateCategory.id)/settings" -Headers $authToken -Method Get).value
    $intentSettingsDelta = @()
    foreach ($templateCategory in $templateCategories) {
        # Get all configured values for the template categories
        Write-Verbose "Requesting Intent Setting Values"
        $intentSettingsDelta += (Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/deviceManagement/intents/$($policy.id)/categories/$($templateCategory.id)/settings").value
    }
    $oldname = $policy.displayName
    $restoredate = get-date -format dd-MM-yyyy-HH-mm-ss
    if ($changename -eq "yes") {
        $newname = $oldname + "-restore-" + $restoredate
    }
    else {
        $newname = $oldname
    }           $policy = @{
        "displayName" = $newname
        "description" = $policy.description
        "settingsDelta" = $intentSettingsDelta
        "roleScopeTagIds" = $policy.roleScopeTagIds
    }
    $policy | Add-Member -NotePropertyName displayName -NotePropertyValue $newname

    $assignments = Get-DeviceSecurityPolicyAssignments -id $id

}
"deviceManagement/windowsAutopilotDeploymentProfiles" {
    $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"
    $policy = Get-AutoPilotProfile -id $id
    $oldname = $policy.displayName
    $restoredate = get-date -format dd-MM-yyyy-HH-mm-ss
    if ($changename -eq "yes") {
        $newname = $oldname + "-restore-" + $restoredate
    }
    else {
        $newname = $oldname
    }           $policy.displayName = $newname

    $assignments = Get-AutoPilotProfileAssignments -id $id
}
"groups" {
    $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"
    $policy = Get-GraphAADGroups -id $id
    $oldname = $policy.displayName
    $restoredate = get-date -format dd-MM-yyyy-HH-mm-ss
    if ($changename -eq "yes") {
        $newname = $oldname + "-restore-" + $restoredate
    }
    else {
        $newname = $oldname
    }           $policy.displayName = $newname
    $policy = $policy | Select-Object description, DisplayName, groupTypes, mailEnabled, mailNickname, securityEnabled, isAssignabletoRole, membershiprule, MembershipRuleProcessingState

    $assignments = "none"
}
"deviceManagement/deviceEnrollmentConfigurationsESP" {
    $uri = "https://graph.microsoft.com/$graphApiVersion/deviceManagement/deviceEnrollmentConfigurations"
    $policy = Get-AutoPilotESP -id $id
    $oldname = $policy.displayName
    $restoredate = get-date -format dd-MM-yyyy-HH-mm-ss
    if ($changename -eq "yes") {
        $newname = $oldname + "-restore-" + $restoredate
    }
    else {
        $newname = $oldname
    }           $policy.displayName = $newname

    $assignments = Get-AutoPilotESPAssignments -id $id
}
"deviceManagement/virtualEndpoint/userSettings" {
    $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"
    $policy = Get-Win365UserSettings -id $id
    $oldname = $policy.displayName
    $restoredate = get-date -format dd-MM-yyyy-HH-mm-ss
    if ($changename -eq "yes") {
        $newname = $oldname + "-restore-" + $restoredate
    }
    else {
        $newname = $oldname
    }        $policy.displayName = $newname

    $assignments = Get-Win365UserSettingsAssignments -id $id
}
"deviceManagement/windowsFeatureUpdateProfiles" {
    $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"
    $policy = Get-FeatureUpdatePolicies -id $id
    $oldname = $policy.displayName
    $restoredate = get-date -format dd-MM-yyyy-HH-mm-ss
    if ($changename -eq "yes") {
        $newname = $oldname + "-restore-" + $restoredate
    }
    else {
        $newname = $oldname
    }        
    $policy.displayName = $newname
    $policyendtime = $policy.rolloutSettings.offerEndDateTimeinUTC
    $policystarttime = $policy.rolloutSettings.offerStartDateTimeinUTC
    if ($policyendtime -ne $null) {
    $policyendtime = $policyendtime.tostring('yyyy-MM-ddTHH:mm:ss.000Z')
    }
    if ($policystarttime -ne $null) {
    $policystarttime = $policystarttime.tostring('yyyy-MM-ddTHH:mm:ss.000Z')
    }
    $policy.rolloutSettings.offerEndDateTimeinUTC = $policyendtime
    $policy.rolloutSettings.offerStartDateTimeinUTC = $policystarttime


    $policy = $policy | Select-Object * -ExcludeProperty endOfSupportDate


    $assignments = Get-FeatureUpdatePoliciesAssignments -id $id
}

"deviceManagement/windowsQualityUpdateProfiles" {
    $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"
    $policy = Get-QualityUpdatePolicies -id $id
    $oldname = $policy.displayName
    $restoredate = get-date -format dd-MM-yyyy-HH-mm-ss
    if ($changename -eq "yes") {
        $newname = $oldname + "-restore-" + $restoredate
    }
    else {
        $newname = $oldname
    }        
    $policy.displayName = $newname
    $policyupdaterelease = $policy.expeditedUpdateSettings.qualityUpdateRelease
    if ($policyupdaterelease -ne $null) {
    $policyupdaterelease = $policyupdaterelease.tostring('yyyy-MM-ddTHH:mm:ss.000Z')
    }
    $policy.expeditedUpdateSettings.qualityUpdateRelease = $policyupdaterelease


    $policy = $policy


    $assignments = Get-QualityUpdatePoliciesAssignments -id $id
}
"deviceManagement/windowsDriverUpdateProfiles" {
    $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"
    $policy = Get-DriverUpdatePolicies -id $id
    $oldname = $policy.displayName
    $restoredate = get-date -format dd-MM-yyyy-HH-mm-ss
    if ($changename -eq "yes") {
        $newname = $oldname + "-restore-" + $restoredate
    }
    else {
        $newname = $oldname
    }        $policy.displayName = $newname

    $assignments = Get-DriverUpdatePoliciesAssignments -id $id
}

"deviceManagement/virtualEndpoint/provisioningPolicies" {
    $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"
    $policy = Get-Win365ProvisioningPolicies -id $id
    $oldname = $policy.displayName
    $restoredate = get-date -format dd-MM-yyyy-HH-mm-ss
    if ($changename -eq "yes") {
        $newname = $oldname + "-restore-" + $restoredate
    }
    else {
        $newname = $oldname
    }        $policy.displayName = $newname

    $assignments = Get-Win365ProvisioningPoliciesAssignments -id $id
}
"deviceAppManagement/managedAppPoliciesandroid" {
    $uri = "https://graph.microsoft.com/$graphApiVersion/deviceAppManagement/managedAppPolicies"
    #$policy = Invoke-RestMethod -Uri "https://graph.microsoft.com/$graphApiVersion/deviceAppManagement/managedAppPolicies('$id')" -Headers $authToken -Method Get
    $policy = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/$graphApiVersion/deviceAppManagement/managedAppPolicies('$id')" -OutputType PSObject
    $oldname = $policy.displayName
    $restoredate = get-date -format dd-MM-yyyy-HH-mm-ss
    if ($changename -eq "yes") {
        $newname = $oldname + "-restore-" + $restoredate
    }
    else {
        $newname = $oldname
    }           $policy.displayName = $newname
     # Set SupportsScopeTags to $false, because $true currently returns an HTTP Status 400 Bad Request error.
     if ($policy.supportsScopeTags) {
        $policy.supportsScopeTags = $false
    }

        $policy.PSObject.Properties | Foreach-Object {
            if ($null -ne $_.Value) {
                if ($_.Value.GetType().Name -eq "DateTime") {
                    $_.Value = (Get-Date -Date $_.Value -Format s) + "Z"
                }
            }
        }

    $assignments = "none"

}
"deviceAppManagement/managedAppPoliciesios" {
    $uri = "https://graph.microsoft.com/$graphApiVersion/deviceAppManagement/managedAppPolicies"
    #$policy = Invoke-RestMethod -Uri "https://graph.microsoft.com/$graphApiVersion/deviceAppManagement/managedAppPolicies('$id')" -Headers $authToken -Method Get
    $policy = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/$graphApiVersion/deviceAppManagement/managedAppPolicies('$id')" -OutputType PSObject
    $oldname = $policy.displayName
    $restoredate = get-date -format dd-MM-yyyy-HH-mm-ss
    if ($changename -eq "yes") {
        $newname = $oldname + "-restore-" + $restoredate
    }
    else {
        $newname = $oldname
    }           $policy.displayName = $newname
     # Set SupportsScopeTags to $false, because $true currently returns an HTTP Status 400 Bad Request error.
     if ($policy.supportsScopeTags) {
        $policy.supportsScopeTags = $false
    }

        $policy.PSObject.Properties | Foreach-Object {
            if ($null -ne $_.Value) {
                if ($_.Value.GetType().Name -eq "DateTime") {
                    $_.Value = (Get-Date -Date $_.Value -Format s) + "Z"
                }
            }
        }


    $assignments = "none"
}

"conditionalaccess" {
    $uri = "conditionalaccess"
    $policy = Get-ConditionalAccessPolicy -id $id
    $includelocations = $policy.conditions.locations.includeLocations
    $excludelocations = $policy.conditions.locations.excludeLocations
    $newincludelocations = @()
    $newexcludelocations = @()
    foreach ($ilocation in $includelocations) {
        ##Check if it is a GUID
        if ($ilocation -match '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$') {
            # $location is a GUID
            $nameduri = "https://graph.microsoft.com/beta/identity/conditionalAccess/namedLocations/$ilocation"
            $ilocjson = Invoke-MgGraphRequest -Uri $nameduri -Method GET -OutputType PSObject | Select-Object * -ExcludeProperty modifiedDateTime, createdDateTime
            $newincludelocations += $ilocjson
        } else {
            # $location is not a GUID
            $newincludelocations += $ilocation
        }
    }

    foreach ($elocation in $excludelocations) {
        ##Check if it is a GUID
        if ($elocation -match '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$') {
            # $location is a GUID
            $nameduri = "https://graph.microsoft.com/beta/identity/conditionalAccess/namedLocations/$elocation"
            $elocjson = Invoke-MgGraphRequest -Uri $nameduri -Method GET -OutputType PSObject | Select-Object * -ExcludeProperty modifiedDateTime, createdDateTime
            $newexcludelocations += $elocjson
        } else {
            # $location is not a GUID
            $newexcludelocations += $elocation
        }
    }
    $policy.conditions.locations.includeLocations = $newincludelocations
    $policy.conditions.locations.excludeLocations = $newexcludelocations
    $oldname = $policy.displayName
}
"deviceAppManagement/mobileApps" {
    $uri = "https://graph.microsoft.com/$graphApiVersion/deviceAppManagement/mobileApps"
    $policy = Get-IntuneApplication -id $id
    $oldname = $policy.displayName
    $restoredate = get-date -format dd-MM-yyyy-HH-mm-ss
    if ($changename -eq "yes") {
        $newname = $oldname + "-restore-" + $restoredate
    }
    else {
        $newname = $oldname
    }           $policy.displayName = $newname
    $policy = $policy | Select-Object * -ExcludeProperty uploadState, publishingState, isAssigned, dependentAppCount, supersedingAppCount, supersededAppCount

    $assignments = Get-IntuneApplicationAssignments -id $id
}
"deviceAppManagement/policySets" {
    $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"
    $policy = Get-IntunePolicySets -id $id
    $oldname = $policy.displayName
    $restoredate = get-date -format dd-MM-yyyy-HH-mm-ss
    if ($changename -eq "yes") {
        $newname = $oldname + "-restore-" + $restoredate
    }
    else {
        $newname = $oldname
    }        $policy.displayName = $newname
    $policyitems = $policy.items | select-object * -ExcludeProperty createdDateTime, lastModifiedDateTime, id, itemType, displayName, status, errorcode, priority, targetedAppManagementLevels
    $policy.items = $policyitems
    $policy = $policy | Select-Object * -ExcludeProperty '@odata.context', status, errorcode, 'items@odata.context'

    $assignments = "none"
}
"deviceManagement/deviceEnrollmentConfigurations" {
    $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"
    $policy = Get-EnrollmentConfigurations -id $id
    $oldname = $policy.displayName
    $restoredate = get-date -format dd-MM-yyyy-HH-mm-ss
    if ($changename -eq "yes") {
        $newname = $oldname + "-restore-" + $restoredate
    }
    else {
        $newname = $oldname
    }        $policy.displayName = $newname

    $assignments = Get-EnrollmentConfigurationsAssignments -id $id
}
"deviceManagement/deviceEnrollmentConfigurationswhfb" {
    $uri = "https://graph.microsoft.com/$graphApiVersion/deviceManagement/deviceEnrollmentConfigurations"
    $policy = Get-WHfBPolicies -id $id
    $oldname = $policy.displayName
    $restoredate = get-date -format dd-MM-yyyy-HH-mm-ss
    if ($changename -eq "yes") {
        $newname = $oldname + "-restore-" + $restoredate
    }
    else {
        $newname = $oldname
    }        $policy.displayName = $newname

    $assignments = Get-EnrollmentConfigurationsAssignments -id $id

}
"deviceManagement/deviceCategories" {
    $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"
    $policy = Get-DeviceCategories -id $id
    $oldname = $policy.displayName
    $restoredate = get-date -format dd-MM-yyyy-HH-mm-ss
    if ($changename -eq "yes") {
        $newname = $oldname + "-restore-" + $restoredate
    }
    else {
        $newname = $oldname
    }        $policy.displayName = $newname

    $assignments = "none"
}
"deviceManagement/assignmentFilters" {
    $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"
    $policy = Get-DeviceFilters -id $id
    $oldname = $policy.displayName
    $restoredate = get-date -format dd-MM-yyyy-HH-mm-ss
    if ($changename -eq "yes") {
        $newname = $oldname + "-restore-" + $restoredate
    }
    else {
        $newname = $oldname
    }        $policy.displayName = $newname
    $policy = $policy | Select-Object * -ExcludeProperty Payloads

    $assignments = "none"
}
"deviceManagement/intuneBrandingProfiles" {
    $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"
    $policy = Get-BrandingProfiles -id $id
    $oldname = $policy.profileName
    $restoredate = get-date -format dd-MM-yyyy-HH-mm-ss
    if ($changename -eq "yes") {
        $newname = $oldname + "-restore-" + $restoredate
    }
    else {
        $newname = $oldname
    }        $policy.profileName = $newname

    $assignments = Get-BrandingProfilesAssignments -id $id
}
"deviceManagement/operationApprovalPolicies" {
    $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"
    $policy = Get-AdminApprovals -id $id
    $oldname = $policy.displayName
    $restoredate = get-date -format dd-MM-yyyy-HH-mm-ss
    if ($changename -eq "yes") {
        $newname = $oldname + "-restore-" + $restoredate
    }
    else {
        $newname = $oldname
    }        $policy.displayName = $newname

    $assignments = get-adminapprovalassignments -id $id
}
"deviceManagement/organizationalMessageDetails" {
    $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"
    $policy = Get-OrgMessages -id $id
    $oldname = $policy.displayName
    $restoredate = get-date -format dd-MM-yyyy-HH-mm-ss
    if ($changename -eq "yes") {
        $newname = $oldname + "-restore-" + $restoredate
    }
    else {
        $newname = $oldname
    }        $policy.displayName = $newname

    $assignments = "none"
}
"deviceManagement/termsAndConditions" {
    $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"
    $policy = Get-IntuneTerms -id $id
    $oldname = $policy.displayName
    $restoredate = get-date -format dd-MM-yyyy-HH-mm-ss
    if ($changename -eq "yes") {
        $newname = $oldname + "-restore-" + $restoredate
    }
    else {
        $newname = $oldname
    }        $policy.displayName = $newname
    $policy = $policy | Select-Object * -ExcludeProperty modifiedDateTime

    $assignments = Get-IntuneTermsAssignments -id $id
}
"deviceManagement/roleDefinitions" {
    $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource"
    $policy = Get-IntuneRoles -id $id
    $oldname = $policy.displayName
    $restoredate = get-date -format dd-MM-yyyy-HH-mm-ss
    if ($changename -eq "yes") {
        $newname = $oldname + "-restore-" + $restoredate
    }
    else {
        $newname = $oldname
    }        $policy.displayName = $newname

    $assignments = "none"
}
}

##We don't want to convert CA policy to JSON
if (($resource -eq "conditionalaccess")) {
    $policy = $policy
        ##If Authentication strength is included, we need to make some tweaks
if ($policy.grantControls.authenticationStrength) {
    $policy.grantControls = $policy.grantControls | Select-Object * -ExcludeProperty authenticationStrength@odata.context
    $policy.grantControls.authenticationStrength = $policy.grantControls.authenticationStrength | Select-Object id
    write-host "set"
    }
    $assignments = "none"
}
else {
# Remove any GUIDs or dates/times to allow Intune to regenerate
if ($resource -eq "deviceManagement/termsAndConditions") {
    ##We need the version number for T&Cs
    $policy = $policy | Select-Object * -ExcludeProperty id, createdDateTime, LastmodifieddateTime, creationSource, '@odata.count' | ConvertTo-Json -Depth 100

    }
    else {
    $policy = $policy | Select-Object * -ExcludeProperty id, createdDateTime, LastmodifieddateTime, version, creationSource, '@odata.count', installLatestWindows10OnWindows11IneligibleDevice | ConvertTo-Json -Depth 100
    }
    }

return $policy, $uri, $oldname, $assignments

}


###############################################################################################################
#################################            Current Environment        #######################################
###############################################################################################################
    ##Get the domain name
    $uri = "https://graph.microsoft.com/beta/organization"
    $tenantdetails = (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).value
    $domain = ($tenantdetails.VerifiedDomains | Where-Object isDefault -eq $true).name

###############################################################################################################
######                                          Grab the Profiles                                        ######
###############################################################################################################
$profiles = @()
$configuration = @()


##Get Config Policies
$configuration += Get-DeviceConfigurationPolicy | Select-Object ID, DisplayName, Description, @{N='Type';E={"Config Policy"}}

##Get Admin Template Policies
$configuration += Get-DeviceConfigurationPolicyGP | Select-Object ID, DisplayName, Description, @{N='Type';E={"Admin Template"}}


##Get Settings Catalog Policies
$configuration += Get-DeviceConfigurationPolicySC | Select-Object @{N='ID';E={$_.id}}, @{N='DisplayName';E={$_.Name}}, @{N='Description';E={$_.Description}} , @{N='Type';E={"Settings Catalog"}}

##Get Compliance Policies
$configuration += Get-DeviceCompliancePolicy | Select-Object ID, DisplayName, Description, @{N='Type';E={"Compliance Policy"}}

##Get Proactive Remediations
$configuration += Get-DeviceProactiveRemediations | Select-Object ID, DisplayName, Description, @{N='Type';E={"Proactive Remediation"}}

##Get App Config
$configuration += Get-MobileAppConfigurations | Select-Object ID, DisplayName, Description, @{N='Type';E={"App Config"}}


##Get Device Scripts
$configuration += Get-DeviceManagementScripts | Select-Object ID, DisplayName, Description, @{N='Type';E={"PowerShell Script"}}

##Get Compliance Scripts
$configuration += Get-DeviceCompliancePolicyScripts | Select-Object ID, DisplayName, Description, @{N='Type';E={"Compliance Script"}}


##Get Security Policies
$configuration += Get-DeviceSecurityPolicy | Select-Object ID, DisplayName, Description, @{N='Type';E={"Security Policy"}}

##Get Autopilot Profiles
$configuration += Get-AutoPilotProfile | Select-Object ID, DisplayName, Description, @{N='Type';E={"Autopilot Profile"}}

if ($livemigration -ne "yes") {
##Get AAD Groups
$configuration += Get-GraphAADGroups | Select-Object ID, DisplayName, Description, @{N='Type';E={"AAD Group"}}
}

##Get Autopilot ESP
$configuration += Get-AutoPilotESP | Select-Object ID, DisplayName, Description, @{N='Type';E={"Autopilot ESP"}}

##Get App Protection Policies
#Android
$androidapp = Get-ManagedAppProtectionAndroid | Select-Object -expandproperty Value
$configuration += $androidapp | Select-Object ID, DisplayName, Description, @{N='Type';E={"Android App Protection"}}
#IOS
$iosapp = Get-ManagedAppProtectionios | Select-Object -expandproperty Value
$configuration += $iosapp | Select-Object ID, DisplayName, Description, @{N='Type';E={"iOS App Protection"}}

##Get Conditional Access Policies
$configuration += Get-ConditionalAccessPolicy | Select-Object ID, DisplayName, @{N='Type';E={"Conditional Access Policy"}}

##Get Winget Apps
$configuration += Get-IntuneApplication | Select-Object ID, DisplayName, Description,  @{N='Type';E={"Winget Application"}}

##Get Win365 User Settings
$configuration += Get-Win365UserSettings | Select-Object ID, DisplayName, Description,  @{N='Type';E={"Win365 User Settings"}}

##Get Feature Updates
$configuration += Get-FeatureUpdatePolicies | Select-Object ID, DisplayName, Description,  @{N='Type';E={"Feature Update"}}

##Get Quality Updates
$configuration += Get-QualityUpdatePolicies | Select-Object ID, DisplayName, Description,  @{N='Type';E={"Quality Update"}}

##Get Driver Updates
$configuration += Get-DriverUpdatePolicies | Select-Object ID, DisplayName, Description,  @{N='Type';E={"Driver Update"}}

##Get Win365 Provisioning Policies
$configuration += Get-Win365ProvisioningPolicies | Select-Object ID, DisplayName, Description,  @{N='Type';E={"Win365 Provisioning Policy"}}

##Get Intune Policy Sets
$configuration += Get-IntunePolicySets | Select-Object ID, DisplayName, Description,  @{N='Type';E={"Policy Set"}}

##Get Enrollment Configurations
$configuration += Get-EnrollmentConfigurations | Select-Object ID, DisplayName, Description,  @{N='Type';E={"Enrollment Configuration"}}

##Get WHfBPolicies
$configuration += Get-WHfBPolicies | Select-Object ID, DisplayName, Description,  @{N='Type';E={"WHfB Policy"}}

##Get Device Categories
$configuration += Get-DeviceCategories | Select-Object ID, DisplayName, Description,  @{N='Type';E={"Device Categories"}}

##Get Device Filters
$configuration += Get-DeviceFilters | Select-Object ID, DisplayName, Description,  @{N='Type';E={"Device Filter"}}

##Get Branding Profiles
$configuration += Get-BrandingProfiles | Select-Object ID, @{N='DisplayName';E={$_.profileName}}, Description,  @{N='Type';E={"Branding Profile"}}

##Get Admin Approvals
$configuration += Get-AdminApprovals | Select-Object ID, DisplayName, Description,  @{N='Type';E={"Admin Approval"}}

##Get Org Messages
##NOTE: API NOT LIVE YET
#$configuration += Get-OrgMessages | Select-Object ID, DisplayName, Description,  @{N='Type';E={"Organization Message"}}

##Get Intune Terms
$configuration += Get-IntuneTerms | Select-Object ID, DisplayName, Description,  @{N='Type';E={"Intune Terms"}}

##Get Intune Roles
$configuration += Get-IntuneRoles | Select-Object ID, DisplayName, Description,  @{N='Type';E={"Intune Role"}}


    $configuration2 = $configuration



$configuration2 | foreach-object {

##Find out what it is
$id = $_.ID
write-output $id
writelog $id
##Performance improvement, use existing array instead of additional graph calls

$policy = $configuration | where-object {($_.ID -eq $id) -and ($_.Type -eq "Config Policy")}
$catalog = $configuration | where-object {($_.ID -eq $id) -and ($_.Type -eq "Settings Catalog")}
$compliance = $configuration | where-object {($_.ID -eq $id) -and ($_.Type -eq "Compliance Policy")}
$security = $configuration | where-object {($_.ID -eq $id) -and ($_.Type -eq "Security Policy")}
$autopilot = $configuration | where-object {($_.ID -eq $id) -and ($_.Type -eq "Autopilot Profile")}
$esp = $configuration | where-object {($_.ID -eq $id) -and ($_.Type -eq "Autopilot ESP")}
$android = $configuration | where-object {($_.ID -eq $id) -and ($_.Type -eq "Android App Protection")}
$ios = $configuration | where-object {($_.ID -eq $id) -and ($_.Type -eq "iOS App Protection")}
$gp = $configuration | where-object {($_.ID -eq $id) -and ($_.Type -eq "Admin Template")}
$ca = $configuration | where-object {($_.ID -eq $id) -and ($_.Type -eq "Conditional Access Policy")}
$proac = $configuration | where-object {($_.ID -eq $id) -and ($_.Type -eq "Proactive Remediation")}
$appconfig = $configuration | where-object {($_.ID -eq $id) -and ($_.Type -eq "App Config")}
if ($livemigration -ne "yes") {
$aad = $configuration | where-object {($_.ID -eq $id) -and ($_.Type -eq "AAD Group")}
}
$wingetapp = $configuration | where-object {($_.ID -eq $id) -and ($_.Type -eq "Winget Application")}
$scripts = $configuration | where-object {($_.ID -eq $id) -and ($_.Type -eq "PowerShell Script")}
$compliancescripts = $configuration | where-object {($_.ID -eq $id) -and ($_.Type -eq "Compliance Script")}
$win365usersettings = $configuration | where-object {($_.ID -eq $id) -and ($_.Type -eq "Win365 User Settings")}
$featureupdates = $configuration | where-object {($_.ID -eq $id) -and ($_.Type -eq "Feature Update")}
$qualityupdates = $configuration | where-object {($_.ID -eq $id) -and ($_.Type -eq "Quality Update")}
$driverupdates = $configuration | where-object {($_.ID -eq $id) -and ($_.Type -eq "Driver Update")}
$win365provisioning = $configuration | where-object {($_.ID -eq $id) -and ($_.Type -eq "Win365 Provisioning Policy")}
$policysets = $configuration | where-object {($_.ID -eq $id) -and ($_.Type -eq "Policy Set")}
$enrollmentconfigs = $configuration | where-object {($_.ID -eq $id) -and ($_.Type -eq "Enrollment Configuration")}
$devicecategories = $configuration | where-object {($_.ID -eq $id) -and ($_.Type -eq "Device Categories")}
$devicefilters = $configuration | where-object {($_.ID -eq $id) -and ($_.Type -eq "Device Filter")}
$brandingprofiles = $configuration | where-object {($_.ID -eq $id) -and ($_.Type -eq "Branding Profile")}
$adminapprovals = $configuration | where-object {($_.ID -eq $id) -and ($_.Type -eq "Admin Approval")}
$intuneterms = $configuration | where-object {($_.ID -eq $id) -and ($_.Type -eq "Intune Terms")}
$intunerole = $configuration | where-object {($_.ID -eq $id) -and ($_.Type -eq "Intune Role")}
$whfb = $configuration | where-object {($_.ID -eq $id) -and ($_.Type -eq "WHfB Policy")}




##Grab the groups
$allgroups = getallgroups

##Grab the filters
$allfilters = getallfilters



# Copy it
if ($null -ne $policy) {
    # Standard Device Configuratio Policy
write-output "It's a policy"
writelog "It's a policy"

$id = $policy.id
$Resource = "deviceManagement/deviceConfigurations"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$rawassignments = $copypolicy[3]
if ($rawassignments -eq "none") {
$assignmentname = "No Available Assignment" 
} 
else {
$assignmentname = convertidtoname -json $rawassignments.value -allgroups $allgroups -allfilters $allfilters
}
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id, $assignmentname))

}
if ($null -ne $gp) {
    # Standard Device Configuration Policy
write-output "It's an Admin Template"
writelog "It's an Admin Template"

$id = $gp.id
$Resource = "deviceManagement/groupPolicyConfigurations"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$rawassignments = $copypolicy[3]
if ($rawassignments -eq "none") {
$assignmentname = "No Available Assignment" 
} 
else {
$assignmentname = convertidtoname -json $rawassignments.value -allgroups $allgroups -allfilters $allfilters
}
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id, $assignmentname))}
if ($null -ne $catalog) {
    # Settings Catalog Policy
write-output "It's a Settings Catalog"
writelog "It's a Settings Catalog"

$id = $catalog.id
$Resource = "deviceManagement/configurationPolicies"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$rawassignments = $copypolicy[3]
if ($rawassignments -eq "none") {
$assignmentname = "No Available Assignment" 
} 
else {
$assignmentname = convertidtoname -json $rawassignments.value -allgroups $allgroups -allfilters $allfilters
}
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id, $assignmentname))
}
if ($null -ne $compliance) {
    # Compliance Policy
write-output "It's a Compliance Policy"
writelog "It's a Compliance Policy"

$id = $compliance.id
$Resource = "deviceManagement/deviceCompliancePolicies"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$rawassignments = $copypolicy[3]
if ($rawassignments -eq "none") {
$assignmentname = "No Available Assignment" 
} 
else {
$assignmentname = convertidtoname -json $rawassignments.value -allgroups $allgroups -allfilters $allfilters
}
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id, $assignmentname))}
if ($null -ne $proac) {
    # Proactive Remediations
write-output "It's a Proactive Remediation"
writelog "It's a Proactive Remediation"

$id = $proac.id
$Resource = "deviceManagement/devicehealthscripts"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$rawassignments = $copypolicy[3]
if ($rawassignments -eq "none") {
$assignmentname = "No Available Assignment" 
} 
else {
$assignmentname = convertidtoname -json $rawassignments.value -allgroups $allgroups -allfilters $allfilters
}
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id, $assignmentname))}
if ($null -ne $appconfig) {
    # App Config
write-output "It's an App Config"
writelog "It's an App Config"

$id = $appconfig.id
$Resource = "deviceAppManagement/mobileAppConfigurations"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$rawassignments = $copypolicy[3]
if ($rawassignments -eq "none") {
$assignmentname = "No Available Assignment" 
} 
else {
$assignmentname = convertidtoname -json $rawassignments.value -allgroups $allgroups -allfilters $allfilters
}
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id, $assignmentname))
}
if ($null -ne $scripts) {
    # Device Scripts
    write-output "It's a PowerShell Script"
    writelog "It's a PowerShell Script"

$id = $scripts.id
$Resource = "deviceManagement/devicemanagementscripts"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$rawassignments = $copypolicy[3]
if ($rawassignments -eq "none") {
$assignmentname = "No Available Assignment" 
} 
else {
$assignmentname = convertidtoname -json $rawassignments.value -allgroups $allgroups -allfilters $allfilters
}
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id, $assignmentname))}

if ($null -ne $compliancescripts) {
    # Compliance Scripts
    write-output "It's a Compliance Script"
    writelog "It's a Compliance Script"

$id = $compliancescripts.id
$Resource = "deviceManagement/deviceComplianceScripts"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$rawassignments = $copypolicy[3]
if ($rawassignments -eq "none") {
$assignmentname = "No Available Assignment" 
} 
else {
$assignmentname = convertidtoname -json $rawassignments.value -allgroups $allgroups -allfilters $allfilters
}
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id, $assignmentname))}

if ($null -ne $security) {
    # Security Policy
write-output "It's a Security Policy"
writelog "It's a Security Policy"

$id = $security.id
$Resource = "deviceManagement/intents"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$rawassignments = $copypolicy[3]
if ($rawassignments -eq "none") {
$assignmentname = "No Available Assignment" 
} 
else {
$assignmentname = convertidtoname -json $rawassignments.value -allgroups $allgroups -allfilters $allfilters
}
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id, $assignmentname))}
if ($null -ne $autopilot) {
    # Autopilot Profile
write-output "It's an Autopilot Profile"
writelog "It's an Autopilot Profile"

$id = $autopilot.id
$Resource = "deviceManagement/windowsAutopilotDeploymentProfiles"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$rawassignments = $copypolicy[3]
if ($rawassignments -eq "none") {
$assignmentname = "No Available Assignment" 
} 
else {
$assignmentname = convertidtoname -json $rawassignments.value -allgroups $allgroups -allfilters $allfilters
}
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id, $assignmentname))}
if ($null -ne $esp) {
    # Autopilot ESP
write-output "It's an AutoPilot ESP"
writelog "It's an AutoPilot ESP"

$id = $esp.id
$Resource = "deviceManagement/deviceEnrollmentConfigurationsESP"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$rawassignments = $copypolicy[3]
if ($rawassignments -eq "none") {
$assignmentname = "No Available Assignment" 
} 
else {
$assignmentname = convertidtoname -json $rawassignments.value -allgroups $allgroups -allfilters $allfilters
}
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id, $assignmentname))}
if ($null -ne $whfb) {
    # Windows Hello for Business
write-output "It's a WHfB Policy"
writelog "It's a WHfB Policy"

$id = $esp.id
$Resource = "deviceManagement/deviceEnrollmentConfigurationswhfb"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$rawassignments = $copypolicy[3]
if ($rawassignments -eq "none") {
$assignmentname = "No Available Assignment" 
} 
else {
$assignmentname = convertidtoname -json $rawassignments.value -allgroups $allgroups -allfilters $allfilters
}
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id, $assignmentname))}
if ($null -ne $android) {
    # Android App Protection
write-output "It's an Android App Protection Policy"
writelog "It's an Android App Protection Policy"

$id = $android.id
$Resource = "deviceAppManagement/managedAppPoliciesandroid"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$rawassignments = $copypolicy[3]
if ($rawassignments -eq "none") {
$assignmentname = "No Available Assignment" 
} 
else {
$assignmentname = convertidtoname -json $rawassignments.value -allgroups $allgroups -allfilters $allfilters
}
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id, $assignmentname))}
if ($null -ne $ios) {
    # iOS App Protection
write-output "It's an iOS App Protection Policy"
writelog "It's an iOS App Protection Policy"

$id = $ios.id
$Resource = "deviceAppManagement/managedAppPoliciesios"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$rawassignments = $copypolicy[3]
if ($rawassignments -eq "none") {
$assignmentname = "No Available Assignment" 
} 
else {
$assignmentname = convertidtoname -json $rawassignments.value -allgroups $allgroups -allfilters $allfilters
}
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id, $assignmentname))
}
if ($livemigration -ne "yes") {
if ($null -ne $aad) {
    # AAD Groups
write-output "It's an AAD Group"
writelog "It's an AAD Group"

$id = $aad.id
$Resource = "groups"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$rawassignments = $copypolicy[3]
if ($rawassignments -eq "none") {
$assignmentname = "No Available Assignment" 
} 
else {
$assignmentname = convertidtoname -json $rawassignments.value -allgroups $allgroups -allfilters $allfilters
}
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id, $assignmentname))
}
}
if ($null -ne $ca) {
    # Conditional Access
write-output "It's a Conditional Access Policy"
writelog "It's a Conditional Access Policy"

$id = $ca.id
$Resource = "ConditionalAccess"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$rawassignments = $copypolicy[3]
if ($rawassignments -eq "none") {
$assignmentname = "No Available Assignment" 
} 
else {
$assignmentname = convertidtoname -json $rawassignments.value -allgroups $allgroups -allfilters $allfilters
}
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id, $assignmentname))
}
if ($null -ne $wingetapp) {
    # Winget App
write-output "It's a Windows Application"
writelog "It's a Windows Application"

$id = $wingetapp.id
$Resource = "deviceAppManagement/mobileApps"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$rawassignments = $copypolicy[3]
if ($rawassignments -eq "none") {
$assignmentname = "No Available Assignment" 
} 
else {
$assignmentname = convertidtoname -json $rawassignments.value -allgroups $allgroups -allfilters $allfilters
}
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id, $assignmentname))
}
if ($null -ne $win365usersettings) {
    # W365 User Settings
write-output "It's a W365 User Setting"
writelog "It's a W365 User Setting"

$id = $win365usersettings.id
$Resource = "deviceManagement/virtualEndpoint/userSettings"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$rawassignments = $copypolicy[3]
if ($rawassignments -eq "none") {
$assignmentname = "No Available Assignment" 
} 
else {
$assignmentname = convertidtoname -json $rawassignments.value -allgroups $allgroups -allfilters $allfilters
}
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id, $assignmentname))
}

if ($null -ne $featureupdates) {
    # Feature Updates
write-output "It's a Feature Update"
writelog "It's a Feature Update"

$id = $featureupdates.id
$Resource = "deviceManagement/windowsFeatureUpdateProfiles"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$rawassignments = $copypolicy[3]
if ($rawassignments -eq "none") {
$assignmentname = "No Available Assignment" 
} 
else {
$assignmentname = convertidtoname -json $rawassignments.value -allgroups $allgroups -allfilters $allfilters
}
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id, $assignmentname))
}

if ($null -ne $qualityupdates) {
    # Quality Updates
write-output "It's a Quality Update"
writelog "It's a Quality Update"

$id = $qualityupdates.id
$Resource = "deviceManagement/windowsQualityUpdateProfiles"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$rawassignments = $copypolicy[3]
if ($rawassignments -eq "none") {
$assignmentname = "No Available Assignment" 
} 
else {
$assignmentname = convertidtoname -json $rawassignments.value -allgroups $allgroups -allfilters $allfilters
}
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id, $assignmentname))
}

if ($null -ne $driverupdates) {
    # Quality Updates
write-output "It's a Driver Update"
writelog "It's a Driver Update"

$id = $driverupdates.id
$Resource = "deviceManagement/windowsDriverUpdateProfiles"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$rawassignments = $copypolicy[3]
if ($rawassignments -eq "none") {
$assignmentname = "No Available Assignment" 
} 
else {
$assignmentname = convertidtoname -json $rawassignments.value -allgroups $allgroups -allfilters $allfilters
}
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id, $assignmentname))
}

if ($null -ne $win365provisioning) {
    # W365 Provisioning Policy
write-output "It's a W365 Provisioning Policy"
writelog "It's a W365 Provisioning Policy"

$id = $win365provisioning.id
$Resource = "deviceManagement/virtualEndpoint/provisioningPolicies"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$rawassignments = $copypolicy[3]
if ($rawassignments -eq "none") {
$assignmentname = "No Available Assignment" 
} 
else {
$assignmentname = convertidtoname -json $rawassignments.value -allgroups $allgroups -allfilters $allfilters
}
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id, $assignmentname))
}
if ($null -ne $policysets) {
    # Policy Set
write-output "It's a Policy Set"
writelog "It's a Policy Set"

$id = $policysets.id
$Resource = "deviceAppManagement/policySets"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$rawassignments = $copypolicy[3]
if ($rawassignments -eq "none") {
$assignmentname = "No Available Assignment" 
} 
else {
$assignmentname = convertidtoname -json $rawassignments.value -allgroups $allgroups -allfilters $allfilters
}
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id, $assignmentname))
}
if ($null -ne $enrollmentconfigs) {
    # Enrollment Config
write-output "It's an enrollment configuration"
writelog "It's an enrollment configuration"

$id = $enrollmentconfigs.id
$Resource = "deviceManagement/deviceEnrollmentConfigurations"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$rawassignments = $copypolicy[3]
if ($rawassignments -eq "none") {
$assignmentname = "No Available Assignment" 
} 
else {
$assignmentname = convertidtoname -json $rawassignments.value -allgroups $allgroups -allfilters $allfilters
}
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id, $assignmentname))
}
if ($null -ne $devicecategories) {
    # Device Categories
write-output "It's a device category"
writelog "It's a device category"

$id = $devicecategories.id
$Resource = "deviceManagement/deviceCategories"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$rawassignments = $copypolicy[3]
if ($rawassignments -eq "none") {
$assignmentname = "No Available Assignment" 
} 
else {
$assignmentname = convertidtoname -json $rawassignments.value -allgroups $allgroups -allfilters $allfilters
}
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id, $assignmentname))
}
if ($null -ne $devicefilters) {
    # Device Filter
write-output "It's a device filter"
writelog "It's a device filter"

$id = $devicefilters.id
$Resource = "deviceManagement/assignmentFilters"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$rawassignments = $copypolicy[3]
if ($rawassignments -eq "none") {
$assignmentname = "No Available Assignment" 
} 
else {
$assignmentname = convertidtoname -json $rawassignments.value -allgroups $allgroups -allfilters $allfilters
}
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id, $assignmentname))
}
if ($null -ne $brandingprofiles) {
    # Branding Profile
write-output "It's a branding profile"
writelog "It's a branding profile"

$id = $brandingprofiles.id
$Resource = "deviceManagement/intuneBrandingProfiles"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$rawassignments = $copypolicy[3]
if ($rawassignments -eq "none") {
$assignmentname = "No Available Assignment" 
} 
else {
$assignmentname = convertidtoname -json $rawassignments.value -allgroups $allgroups -allfilters $allfilters
}
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id, $assignmentname))
}
if ($null -ne $adminapprovals) {
    # Multi-admin approval
write-output "It's a multi-admin approval"
writelog "It's a multi-admin approval"

$id = $adminapprovals.id
$Resource = "deviceManagement/operationApprovalPolicies"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$rawassignments = $copypolicy[3]
if ($rawassignments -eq "none") {
$assignmentname = "No Available Assignment" 
} 
else {
$assignmentname = convertidtoname -json $rawassignments.value -allgroups $allgroups -allfilters $allfilters
}
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id, $assignmentname))
}
#if ($null -ne $orgmessages) {
    # Organizational Message
#write-output "It's an organizational message"
#$id = $orgmessages.id
#$Resource = "deviceManagement/organizationalMessageDetails"
#$copypolicy = getpolicyjson -resource $Resource -policyid $id
#$profiles+= ,(@($copypolicy[0],$copypolicy[1], $id))
#}
if ($null -ne $intuneterms) {
    # Intune Terms
write-output "It's a T&C"
writelog "It's a T&C"

$id = $intuneterms.id
$Resource = "deviceManagement/termsAndConditions"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$rawassignments = $copypolicy[3]
if ($rawassignments -eq "none") {
$assignmentname = "No Available Assignment" 
} 
else {
$assignmentname = convertidtoname -json $rawassignments.value -allgroups $allgroups -allfilters $allfilters
}
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id, $assignmentname))
}
if ($null -ne $intunerole) {
    # Intune Role
write-output "It's a role"
writelog "It's a role"

$id = $intunerole.id
$Resource = "deviceManagement/roleDefinitions"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$rawassignments = $copypolicy[3]
if ($rawassignments -eq "none") {
$assignmentname = "No Available Assignment" 
} 
else {
$assignmentname = convertidtoname -json $rawassignments.value -allgroups $allgroups -allfilters $allfilters
}
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id, $assignmentname))
}
}

##Convert profiles to JSON
$currentprofilesjson = $profiles | convertto-json -Depth 50 




#######################################################################################################################################
#########                                                   END CURRENT                        ########################################
#######################################################################################################################################




#######################################################################################################################################
#########                                                   GRAB OLD                           ########################################
#######################################################################################################################################
        

if ($livemigration -eq "yes") {

Disconnect-MgGraph
    if (($automated -eq "yes") -or ($aadlogin -eq "yes")) {
 
        Connect-ToGraph -Tenant $secondtenant -AppId $clientId -AppSecret $clientSecret
        write-output "Graph Connection Established"
        writelog "Graph Connection Established"
        
        }
        else {
        ##Connect to Graph
        Select-MgProfile -Name Beta
        Connect-ToGraph -Scopes "Policy.ReadWrite.ConditionalAccess, CloudPC.ReadWrite.All, DeviceManagementServiceConfig.ReadWrite.All, RoleAssignmentSchedule.ReadWrite.Directory, Domain.Read.All, Domain.ReadWrite.All, Directory.Read.All, Policy.ReadWrite.ConditionalAccess, DeviceManagementApps.ReadWrite.All, DeviceManagementConfiguration.ReadWrite.All, DeviceManagementManagedDevices.ReadWrite.All, openid, profile, email, offline_access, DeviceManagementRBAC.Read.All, DeviceManagementRBAC.ReadWrite.All"
        }
        
###############################################################################################################
#################################            Current Environment        #######################################
###############################################################################################################
    ##Get the domain name
    $uri = "https://graph.microsoft.com/beta/organization"
    $tenantdetails = (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).value
    $domain = ($tenantdetails.VerifiedDomains | Where-Object isDefault -eq $true).name

###############################################################################################################
######                                          Grab the Profiles                                        ######
###############################################################################################################
$profiles = @()
$configuration = @()


##Get Config Policies
$configuration += Get-DeviceConfigurationPolicy | Select-Object ID, DisplayName, Description, @{N='Type';E={"Config Policy"}}

##Get Admin Template Policies
$configuration += Get-DeviceConfigurationPolicyGP | Select-Object ID, DisplayName, Description, @{N='Type';E={"Admin Template"}}


##Get Settings Catalog Policies
$configuration += Get-DeviceConfigurationPolicySC | Select-Object @{N='ID';E={$_.id}}, @{N='DisplayName';E={$_.Name}}, @{N='Description';E={$_.Description}} , @{N='Type';E={"Settings Catalog"}}

##Get Compliance Policies
$configuration += Get-DeviceCompliancePolicy | Select-Object ID, DisplayName, Description, @{N='Type';E={"Compliance Policy"}}

##Get Proactive Remediations
$configuration += Get-DeviceProactiveRemediations | Select-Object ID, DisplayName, Description, @{N='Type';E={"Proactive Remediation"}}

##Get App Config
$configuration += Get-MobileAppConfigurations | Select-Object ID, DisplayName, Description, @{N='Type';E={"App Config"}}


##Get Device Scripts
$configuration += Get-DeviceManagementScripts | Select-Object ID, DisplayName, Description, @{N='Type';E={"PowerShell Script"}}

##Get Compliance Scripts
$configuration += Get-DeviceCompliancePolicyScripts | Select-Object ID, DisplayName, Description, @{N='Type';E={"Compliance Script"}}


##Get Security Policies
$configuration += Get-DeviceSecurityPolicy | Select-Object ID, DisplayName, Description, @{N='Type';E={"Security Policy"}}

##Get Autopilot Profiles
$configuration += Get-AutoPilotProfile | Select-Object ID, DisplayName, Description, @{N='Type';E={"Autopilot Profile"}}

if ($livemigration -ne "yes") {
##Get AAD Groups
$configuration += Get-GraphAADGroups | Select-Object ID, DisplayName, Description, @{N='Type';E={"AAD Group"}}
}

##Get Autopilot ESP
$configuration += Get-AutoPilotESP | Select-Object ID, DisplayName, Description, @{N='Type';E={"Autopilot ESP"}}

##Get App Protection Policies
#Android
$androidapp = Get-ManagedAppProtectionAndroid | Select-Object -expandproperty Value
$configuration += $androidapp | Select-Object ID, DisplayName, Description, @{N='Type';E={"Android App Protection"}}
#IOS
$iosapp = Get-ManagedAppProtectionios | Select-Object -expandproperty Value
$configuration += $iosapp | Select-Object ID, DisplayName, Description, @{N='Type';E={"iOS App Protection"}}

##Get Conditional Access Policies
$configuration += Get-ConditionalAccessPolicy | Select-Object ID, DisplayName, @{N='Type';E={"Conditional Access Policy"}}

##Get Winget Apps
$configuration += Get-IntuneApplication | Select-Object ID, DisplayName, Description,  @{N='Type';E={"Winget Application"}}

##Get Win365 User Settings
$configuration += Get-Win365UserSettings | Select-Object ID, DisplayName, Description,  @{N='Type';E={"Win365 User Settings"}}

##Get Feature Updates
$configuration += Get-FeatureUpdatePolicies | Select-Object ID, DisplayName, Description,  @{N='Type';E={"Feature Update"}}

##Get Quality Updates
$configuration += Get-QualityUpdatePolicies | Select-Object ID, DisplayName, Description,  @{N='Type';E={"Quality Update"}}

##Get Driver Updates
$configuration += Get-DriverUpdatePolicies | Select-Object ID, DisplayName, Description,  @{N='Type';E={"Driver Update"}}

##Get Win365 Provisioning Policies
$configuration += Get-Win365ProvisioningPolicies | Select-Object ID, DisplayName, Description,  @{N='Type';E={"Win365 Provisioning Policy"}}

##Get Intune Policy Sets
$configuration += Get-IntunePolicySets | Select-Object ID, DisplayName, Description,  @{N='Type';E={"Policy Set"}}

##Get Enrollment Configurations
$configuration += Get-EnrollmentConfigurations | Select-Object ID, DisplayName, Description,  @{N='Type';E={"Enrollment Configuration"}}

##Get WHfBPolicies
$configuration += Get-WHfBPolicies | Select-Object ID, DisplayName, Description,  @{N='Type';E={"WHfB Policy"}}

##Get Device Categories
$configuration += Get-DeviceCategories | Select-Object ID, DisplayName, Description,  @{N='Type';E={"Device Categories"}}

##Get Device Filters
$configuration += Get-DeviceFilters | Select-Object ID, DisplayName, Description,  @{N='Type';E={"Device Filter"}}

##Get Branding Profiles
$configuration += Get-BrandingProfiles | Select-Object ID, @{N='DisplayName';E={$_.profileName}}, Description,  @{N='Type';E={"Branding Profile"}}

##Get Admin Approvals
$configuration += Get-AdminApprovals | Select-Object ID, DisplayName, Description,  @{N='Type';E={"Admin Approval"}}

##Get Org Messages
##NOTE: API NOT LIVE YET
#$configuration += Get-OrgMessages | Select-Object ID, DisplayName, Description,  @{N='Type';E={"Organization Message"}}

##Get Intune Terms
$configuration += Get-IntuneTerms | Select-Object ID, DisplayName, Description,  @{N='Type';E={"Intune Terms"}}

##Get Intune Roles
$configuration += Get-IntuneRoles | Select-Object ID, DisplayName, Description,  @{N='Type';E={"Intune Role"}}


    $configuration2 = $configuration



$configuration2 | foreach-object {

##Find out what it is
$id = $_.ID
write-output $id
writelog $id
##Performance improvement, use existing array instead of additional graph calls

$policy = $configuration | where-object {($_.ID -eq $id) -and ($_.Type -eq "Config Policy")}
$catalog = $configuration | where-object {($_.ID -eq $id) -and ($_.Type -eq "Settings Catalog")}
$compliance = $configuration | where-object {($_.ID -eq $id) -and ($_.Type -eq "Compliance Policy")}
$security = $configuration | where-object {($_.ID -eq $id) -and ($_.Type -eq "Security Policy")}
$autopilot = $configuration | where-object {($_.ID -eq $id) -and ($_.Type -eq "Autopilot Profile")}
$esp = $configuration | where-object {($_.ID -eq $id) -and ($_.Type -eq "Autopilot ESP")}
$android = $configuration | where-object {($_.ID -eq $id) -and ($_.Type -eq "Android App Protection")}
$ios = $configuration | where-object {($_.ID -eq $id) -and ($_.Type -eq "iOS App Protection")}
$gp = $configuration | where-object {($_.ID -eq $id) -and ($_.Type -eq "Admin Template")}
$ca = $configuration | where-object {($_.ID -eq $id) -and ($_.Type -eq "Conditional Access Policy")}
$proac = $configuration | where-object {($_.ID -eq $id) -and ($_.Type -eq "Proactive Remediation")}
$appconfig = $configuration | where-object {($_.ID -eq $id) -and ($_.Type -eq "App Config")}
if ($livemigration -ne "yes") {
$aad = $configuration | where-object {($_.ID -eq $id) -and ($_.Type -eq "AAD Group")}
}
$wingetapp = $configuration | where-object {($_.ID -eq $id) -and ($_.Type -eq "Winget Application")}
$scripts = $configuration | where-object {($_.ID -eq $id) -and ($_.Type -eq "PowerShell Script")}
$compliancescripts = $configuration | where-object {($_.ID -eq $id) -and ($_.Type -eq "Compliance Script")}
$win365usersettings = $configuration | where-object {($_.ID -eq $id) -and ($_.Type -eq "Win365 User Settings")}
$featureupdates = $configuration | where-object {($_.ID -eq $id) -and ($_.Type -eq "Feature Update")}
$qualityupdates = $configuration | where-object {($_.ID -eq $id) -and ($_.Type -eq "Quality Update")}
$driverupdates = $configuration | where-object {($_.ID -eq $id) -and ($_.Type -eq "Driver Update")}
$win365provisioning = $configuration | where-object {($_.ID -eq $id) -and ($_.Type -eq "Win365 Provisioning Policy")}
$policysets = $configuration | where-object {($_.ID -eq $id) -and ($_.Type -eq "Policy Set")}
$enrollmentconfigs = $configuration | where-object {($_.ID -eq $id) -and ($_.Type -eq "Enrollment Configuration")}
$devicecategories = $configuration | where-object {($_.ID -eq $id) -and ($_.Type -eq "Device Categories")}
$devicefilters = $configuration | where-object {($_.ID -eq $id) -and ($_.Type -eq "Device Filter")}
$brandingprofiles = $configuration | where-object {($_.ID -eq $id) -and ($_.Type -eq "Branding Profile")}
$adminapprovals = $configuration | where-object {($_.ID -eq $id) -and ($_.Type -eq "Admin Approval")}
$intuneterms = $configuration | where-object {($_.ID -eq $id) -and ($_.Type -eq "Intune Terms")}
$intunerole = $configuration | where-object {($_.ID -eq $id) -and ($_.Type -eq "Intune Role")}
$whfb = $configuration | where-object {($_.ID -eq $id) -and ($_.Type -eq "WHfB Policy")}




##Grab the groups
$allgroups = getallgroups

##Grab the filters
$allfilters = getallfilters



# Copy it
if ($null -ne $policy) {
    # Standard Device Configuratio Policy
write-output "It's a policy"
writelog "It's a policy"

$id = $policy.id
$Resource = "deviceManagement/deviceConfigurations"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$rawassignments = $copypolicy[3]
if ($rawassignments -eq "none") {
$assignmentname = "No Available Assignment" 
} 
else {
$assignmentname = convertidtoname -json $rawassignments.value -allgroups $allgroups -allfilters $allfilters
}
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id, $assignmentname))

}
if ($null -ne $gp) {
    # Standard Device Configuration Policy
write-output "It's an Admin Template"
writelog "It's an Admin Template"

$id = $gp.id
$Resource = "deviceManagement/groupPolicyConfigurations"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$rawassignments = $copypolicy[3]
if ($rawassignments -eq "none") {
$assignmentname = "No Available Assignment" 
} 
else {
$assignmentname = convertidtoname -json $rawassignments.value -allgroups $allgroups -allfilters $allfilters
}
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id, $assignmentname))}
if ($null -ne $catalog) {
    # Settings Catalog Policy
write-output "It's a Settings Catalog"
writelog "It's a Settings Catalog"

$id = $catalog.id
$Resource = "deviceManagement/configurationPolicies"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$rawassignments = $copypolicy[3]
if ($rawassignments -eq "none") {
$assignmentname = "No Available Assignment" 
} 
else {
$assignmentname = convertidtoname -json $rawassignments.value -allgroups $allgroups -allfilters $allfilters
}
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id, $assignmentname))
}
if ($null -ne $compliance) {
    # Compliance Policy
write-output "It's a Compliance Policy"
writelog "It's a Compliance Policy"

$id = $compliance.id
$Resource = "deviceManagement/deviceCompliancePolicies"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$rawassignments = $copypolicy[3]
if ($rawassignments -eq "none") {
$assignmentname = "No Available Assignment" 
} 
else {
$assignmentname = convertidtoname -json $rawassignments.value -allgroups $allgroups -allfilters $allfilters
}
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id, $assignmentname))}
if ($null -ne $proac) {
    # Proactive Remediations
write-output "It's a Proactive Remediation"
writelog "It's a Proactive Remediation"

$id = $proac.id
$Resource = "deviceManagement/devicehealthscripts"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$rawassignments = $copypolicy[3]
if ($rawassignments -eq "none") {
$assignmentname = "No Available Assignment" 
} 
else {
$assignmentname = convertidtoname -json $rawassignments.value -allgroups $allgroups -allfilters $allfilters
}
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id, $assignmentname))}
if ($null -ne $appconfig) {
    # App Config
write-output "It's an App Config"
writelog "It's an App Config"

$id = $appconfig.id
$Resource = "deviceAppManagement/mobileAppConfigurations"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$rawassignments = $copypolicy[3]
if ($rawassignments -eq "none") {
$assignmentname = "No Available Assignment" 
} 
else {
$assignmentname = convertidtoname -json $rawassignments.value -allgroups $allgroups -allfilters $allfilters
}
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id, $assignmentname))
}
if ($null -ne $scripts) {
    # Device Scripts
    write-output "It's a PowerShell Script"
    writelog "It's a PowerShell Script"

$id = $scripts.id
$Resource = "deviceManagement/devicemanagementscripts"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$rawassignments = $copypolicy[3]
if ($rawassignments -eq "none") {
$assignmentname = "No Available Assignment" 
} 
else {
$assignmentname = convertidtoname -json $rawassignments.value -allgroups $allgroups -allfilters $allfilters
}
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id, $assignmentname))}

if ($null -ne $compliancescripts) {
    # Compliance Scripts
    write-output "It's a Compliance Script"
    writelog "It's a Compliance Script"

$id = $compliancescripts.id
$Resource = "deviceManagement/deviceComplianceScripts"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$rawassignments = $copypolicy[3]
if ($rawassignments -eq "none") {
$assignmentname = "No Available Assignment" 
} 
else {
$assignmentname = convertidtoname -json $rawassignments.value -allgroups $allgroups -allfilters $allfilters
}
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id, $assignmentname))}

if ($null -ne $security) {
    # Security Policy
write-output "It's a Security Policy"
writelog "It's a Security Policy"

$id = $security.id
$Resource = "deviceManagement/intents"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$rawassignments = $copypolicy[3]
if ($rawassignments -eq "none") {
$assignmentname = "No Available Assignment" 
} 
else {
$assignmentname = convertidtoname -json $rawassignments.value -allgroups $allgroups -allfilters $allfilters
}
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id, $assignmentname))}
if ($null -ne $autopilot) {
    # Autopilot Profile
write-output "It's an Autopilot Profile"
writelog "It's an Autopilot Profile"

$id = $autopilot.id
$Resource = "deviceManagement/windowsAutopilotDeploymentProfiles"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$rawassignments = $copypolicy[3]
if ($rawassignments -eq "none") {
$assignmentname = "No Available Assignment" 
} 
else {
$assignmentname = convertidtoname -json $rawassignments.value -allgroups $allgroups -allfilters $allfilters
}
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id, $assignmentname))}
if ($null -ne $esp) {
    # Autopilot ESP
write-output "It's an AutoPilot ESP"
writelog "It's an AutoPilot ESP"

$id = $esp.id
$Resource = "deviceManagement/deviceEnrollmentConfigurationsESP"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$rawassignments = $copypolicy[3]
if ($rawassignments -eq "none") {
$assignmentname = "No Available Assignment" 
} 
else {
$assignmentname = convertidtoname -json $rawassignments.value -allgroups $allgroups -allfilters $allfilters
}
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id, $assignmentname))}
if ($null -ne $whfb) {
    # Windows Hello for Business
write-output "It's a WHfB Policy"
writelog "It's a WHfB Policy"

$id = $esp.id
$Resource = "deviceManagement/deviceEnrollmentConfigurationswhfb"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$rawassignments = $copypolicy[3]
if ($rawassignments -eq "none") {
$assignmentname = "No Available Assignment" 
} 
else {
$assignmentname = convertidtoname -json $rawassignments.value -allgroups $allgroups -allfilters $allfilters
}
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id, $assignmentname))}
if ($null -ne $android) {
    # Android App Protection
write-output "It's an Android App Protection Policy"
writelog "It's an Android App Protection Policy"

$id = $android.id
$Resource = "deviceAppManagement/managedAppPoliciesandroid"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$rawassignments = $copypolicy[3]
if ($rawassignments -eq "none") {
$assignmentname = "No Available Assignment" 
} 
else {
$assignmentname = convertidtoname -json $rawassignments.value -allgroups $allgroups -allfilters $allfilters
}
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id, $assignmentname))}
if ($null -ne $ios) {
    # iOS App Protection
write-output "It's an iOS App Protection Policy"
writelog "It's an iOS App Protection Policy"

$id = $ios.id
$Resource = "deviceAppManagement/managedAppPoliciesios"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$rawassignments = $copypolicy[3]
if ($rawassignments -eq "none") {
$assignmentname = "No Available Assignment" 
} 
else {
$assignmentname = convertidtoname -json $rawassignments.value -allgroups $allgroups -allfilters $allfilters
}
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id, $assignmentname))
}
if ($livemigration -ne "yes") {
if ($null -ne $aad) {
    # AAD Groups
write-output "It's an AAD Group"
writelog "It's an AAD Group"

$id = $aad.id
$Resource = "groups"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$rawassignments = $copypolicy[3]
if ($rawassignments -eq "none") {
$assignmentname = "No Available Assignment" 
} 
else {
$assignmentname = convertidtoname -json $rawassignments.value -allgroups $allgroups -allfilters $allfilters
}
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id, $assignmentname))
}
}
if ($null -ne $ca) {
    # Conditional Access
write-output "It's a Conditional Access Policy"
writelog "It's a Conditional Access Policy"

$id = $ca.id
$Resource = "ConditionalAccess"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$rawassignments = $copypolicy[3]
if ($rawassignments -eq "none") {
$assignmentname = "No Available Assignment" 
} 
else {
$assignmentname = convertidtoname -json $rawassignments.value -allgroups $allgroups -allfilters $allfilters
}
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id, $assignmentname))
}
if ($null -ne $wingetapp) {
    # Winget App
write-output "It's a Windows Application"
writelog "It's a Windows Application"

$id = $wingetapp.id
$Resource = "deviceAppManagement/mobileApps"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$rawassignments = $copypolicy[3]
if ($rawassignments -eq "none") {
$assignmentname = "No Available Assignment" 
} 
else {
$assignmentname = convertidtoname -json $rawassignments.value -allgroups $allgroups -allfilters $allfilters
}
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id, $assignmentname))
}
if ($null -ne $win365usersettings) {
    # W365 User Settings
write-output "It's a W365 User Setting"
writelog "It's a W365 User Setting"

$id = $win365usersettings.id
$Resource = "deviceManagement/virtualEndpoint/userSettings"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$rawassignments = $copypolicy[3]
if ($rawassignments -eq "none") {
$assignmentname = "No Available Assignment" 
} 
else {
$assignmentname = convertidtoname -json $rawassignments.value -allgroups $allgroups -allfilters $allfilters
}
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id, $assignmentname))
}

if ($null -ne $featureupdates) {
    # Feature Updates
write-output "It's a Feature Update"
writelog "It's a Feature Update"

$id = $featureupdates.id
$Resource = "deviceManagement/windowsFeatureUpdateProfiles"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$rawassignments = $copypolicy[3]
if ($rawassignments -eq "none") {
$assignmentname = "No Available Assignment" 
} 
else {
$assignmentname = convertidtoname -json $rawassignments.value -allgroups $allgroups -allfilters $allfilters
}
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id, $assignmentname))
}

if ($null -ne $qualityupdates) {
    # Quality Updates
write-output "It's a Quality Update"
writelog "It's a Quality Update"

$id = $qualityupdates.id
$Resource = "deviceManagement/windowsQualityUpdateProfiles"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$rawassignments = $copypolicy[3]
if ($rawassignments -eq "none") {
$assignmentname = "No Available Assignment" 
} 
else {
$assignmentname = convertidtoname -json $rawassignments.value -allgroups $allgroups -allfilters $allfilters
}
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id, $assignmentname))
}

if ($null -ne $driverupdates) {
    # Quality Updates
write-output "It's a Driver Update"
writelog "It's a Driver Update"

$id = $driverupdates.id
$Resource = "deviceManagement/windowsDriverUpdateProfiles"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$rawassignments = $copypolicy[3]
if ($rawassignments -eq "none") {
$assignmentname = "No Available Assignment" 
} 
else {
$assignmentname = convertidtoname -json $rawassignments.value -allgroups $allgroups -allfilters $allfilters
}
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id, $assignmentname))
}

if ($null -ne $win365provisioning) {
    # W365 Provisioning Policy
write-output "It's a W365 Provisioning Policy"
writelog "It's a W365 Provisioning Policy"

$id = $win365provisioning.id
$Resource = "deviceManagement/virtualEndpoint/provisioningPolicies"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$rawassignments = $copypolicy[3]
if ($rawassignments -eq "none") {
$assignmentname = "No Available Assignment" 
} 
else {
$assignmentname = convertidtoname -json $rawassignments.value -allgroups $allgroups -allfilters $allfilters
}
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id, $assignmentname))
}
if ($null -ne $policysets) {
    # Policy Set
write-output "It's a Policy Set"
writelog "It's a Policy Set"

$id = $policysets.id
$Resource = "deviceAppManagement/policySets"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$rawassignments = $copypolicy[3]
if ($rawassignments -eq "none") {
$assignmentname = "No Available Assignment" 
} 
else {
$assignmentname = convertidtoname -json $rawassignments.value -allgroups $allgroups -allfilters $allfilters
}
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id, $assignmentname))
}
if ($null -ne $enrollmentconfigs) {
    # Enrollment Config
write-output "It's an enrollment configuration"
writelog "It's an enrollment configuration"

$id = $enrollmentconfigs.id
$Resource = "deviceManagement/deviceEnrollmentConfigurations"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$rawassignments = $copypolicy[3]
if ($rawassignments -eq "none") {
$assignmentname = "No Available Assignment" 
} 
else {
$assignmentname = convertidtoname -json $rawassignments.value -allgroups $allgroups -allfilters $allfilters
}
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id, $assignmentname))
}
if ($null -ne $devicecategories) {
    # Device Categories
write-output "It's a device category"
writelog "It's a device category"

$id = $devicecategories.id
$Resource = "deviceManagement/deviceCategories"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$rawassignments = $copypolicy[3]
if ($rawassignments -eq "none") {
$assignmentname = "No Available Assignment" 
} 
else {
$assignmentname = convertidtoname -json $rawassignments.value -allgroups $allgroups -allfilters $allfilters
}
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id, $assignmentname))
}
if ($null -ne $devicefilters) {
    # Device Filter
write-output "It's a device filter"
writelog "It's a device filter"

$id = $devicefilters.id
$Resource = "deviceManagement/assignmentFilters"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$rawassignments = $copypolicy[3]
if ($rawassignments -eq "none") {
$assignmentname = "No Available Assignment" 
} 
else {
$assignmentname = convertidtoname -json $rawassignments.value -allgroups $allgroups -allfilters $allfilters
}
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id, $assignmentname))
}
if ($null -ne $brandingprofiles) {
    # Branding Profile
write-output "It's a branding profile"
writelog "It's a branding profile"

$id = $brandingprofiles.id
$Resource = "deviceManagement/intuneBrandingProfiles"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$rawassignments = $copypolicy[3]
if ($rawassignments -eq "none") {
$assignmentname = "No Available Assignment" 
} 
else {
$assignmentname = convertidtoname -json $rawassignments.value -allgroups $allgroups -allfilters $allfilters
}
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id, $assignmentname))
}
if ($null -ne $adminapprovals) {
    # Multi-admin approval
write-output "It's a multi-admin approval"
writelog "It's a multi-admin approval"

$id = $adminapprovals.id
$Resource = "deviceManagement/operationApprovalPolicies"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$rawassignments = $copypolicy[3]
if ($rawassignments -eq "none") {
$assignmentname = "No Available Assignment" 
} 
else {
$assignmentname = convertidtoname -json $rawassignments.value -allgroups $allgroups -allfilters $allfilters
}
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id, $assignmentname))
}
#if ($null -ne $orgmessages) {
    # Organizational Message
#write-output "It's an organizational message"
#$id = $orgmessages.id
#$Resource = "deviceManagement/organizationalMessageDetails"
#$copypolicy = getpolicyjson -resource $Resource -policyid $id
#$profiles+= ,(@($copypolicy[0],$copypolicy[1], $id))
#}
if ($null -ne $intuneterms) {
    # Intune Terms
write-output "It's a T&C"
writelog "It's a T&C"

$id = $intuneterms.id
$Resource = "deviceManagement/termsAndConditions"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$rawassignments = $copypolicy[3]
if ($rawassignments -eq "none") {
$assignmentname = "No Available Assignment" 
} 
else {
$assignmentname = convertidtoname -json $rawassignments.value -allgroups $allgroups -allfilters $allfilters
}
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id, $assignmentname))
}
if ($null -ne $intunerole) {
    # Intune Role
write-output "It's a role"
writelog "It's a role"

$id = $intunerole.id
$Resource = "deviceManagement/roleDefinitions"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$rawassignments = $copypolicy[3]
if ($rawassignments -eq "none") {
$assignmentname = "No Available Assignment" 
} 
else {
$assignmentname = convertidtoname -json $rawassignments.value -allgroups $allgroups -allfilters $allfilters
}
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id, $assignmentname))
}
}

##Convert profiles to JSON
$oldjson = $profiles | convertto-json -Depth 50 


}
else {
###############################################################################################################
######                                          Get Commits                                              ######
###############################################################################################################

if ($goldentenant) {
    $gittenant = $goldentenant
}
else {
    $gittenant = $tenant
}
if ($repotype -eq "github") {

 $validfiles = @()
    write-output "Finding Latest Backup Commit from Repo $reponame in $ownername GitHub"
    writelog "Finding Latest Backup Commit from Repo $reponame in $ownername GitHub"

    $uri = "https://api.github.com/repos/$ownername/$reponame/commits?per_page=100"
    $events = @()
    $page = 1

Do
{
    $response = Invoke-RestMethod -Headers @{'Authorization'='bearer '+$token;} -Uri "$uri&page=$page"
    
    foreach ($obj in $response)
    {
        $events += $obj.commit
    }
    
    $page = $page + 1
}
While ($response.Count -gt 0)

    ##$events = (Invoke-RestMethod -Uri $uri -Method Get -Headers @{'Authorization'='bearer '+$token;}).commit
    $events2 = $events | Select-Object message, url | Where-Object {($_.message -notmatch "\blog\b") -and ($_.message -notmatch "\bdelete\b") -and ($_.message -notmatch "\bdaily\b") -and ($_.message -notmatch "\bdrift\b") -and ($_.message -notmatch "\btemplate\b")}        
    ForEach ($event in $events2) 
        {
    $eventsuri = $event.url
    $commitid = Split-Path $eventsuri -Leaf
    $commituri = "https://api.github.com/repos/$ownername/$reponame/commits/$commitid"
    $commitfilename2 = ((Invoke-RestMethod -Uri $commituri -Method Get -Headers @{'Authorization' = 'token ' + $token; 'Accept' = 'application/json' }).Files).raw_url
    ##Grab the filename from the URL
$raw_url = $commitfilename2
    $commitfullname = [System.IO.Path]::GetFileName($raw_url)
    if (![string]::IsNullOrEmpty($commitfullname)) {
        $committenant = $commitfullname.Substring(0,36)
    }
    $commitfullname2 = $commitfullname -replace ".json", ""
    if (![string]::IsNullOrEmpty($commitfullname2)) {
    $last12digits = $commitfullname2.Substring($commitfullname2.Length-12)
}
    $DateTimeFormat = "yyMMddHHmmss"
    try {
        $DateTimeObject = [datetime]::ParseExact($last12digits, $DateTimeFormat, $null)
    } catch {
        # Do nothing if it fails
    }
    
    if ($committenant -eq $gittenant -and $commitfullname -notmatch "\b(log|drift|golddrift|daily|intunereport|template)\b") {
        ##If $commitfullname is empty, don't add it
        if ($commitfullname -like "*$gittenant*") {
        $commitObject = New-Object PSObject -Property @{
            CommitFullName = $commitfullname
            DateTime = $DateTimeObject
        }
        $validfiles += $commitObject
    }

    }
}
# Sort the $validfiles array on DateTime in descending order and select the most recent
$mostRecentFile = $validfiles | Sort-Object DateTime -Descending | Select-Object -First 1

# Retrieve the CommitFullName
$commitfilename = $mostRecentFile.CommitFullName
    

    
    $filename = $commitfilename.Substring($commitfilename.LastIndexOf("/") + 1)
    $commitfilename2 = " https://api.github.com/repos/$ownername/$reponame/contents/$filename"
    $decodedbackupdownload = (Invoke-RestMethod -Uri $commitfilename2 -Method Get -Headers @{'Authorization'='bearer '+$token; 'Accept'='Accept: application/json';'Cache-Control'='no-cache'}).download_url
    $decodedbackup = (Invoke-RestMethod -Uri $decodedbackupdownload -Method Get)
    }

    if ($repotype -eq "gitlab") {
        $validfiles = @()

        $GitLabUrl = "https://gitlab.com/api/v4"
        $Headers = @{
            "PRIVATE-TOKEN" = $token
        }
       
        write-output "Finding Latest Backup Commit from Project $project in GitLab"
        writelog "Finding Latest Backup Commit from Project $project in GitLab"

        $uri = "$GitLabUrl/projects/$project/repository/commits?per_page=100"
        $events = @()
        $page = 1
    
    Do
    {
        $response = Invoke-RestMethod -Headers @{'Authorization'='bearer '+$token;} -Uri "$uri&page=$page"
        
        foreach ($obj in $response)
        {
            $events += $obj.commit
        }
        
        $page = $page + 1
    }
    While ($response.Count -gt 0)
    
        ##$events = (Invoke-RestMethod -Uri $uri -Method Get -Headers @{'Authorization'='bearer '+$token;}).commit
        $events2 = $events | Select-Object message, url | Where-Object {($_.message -notmatch "\blog\b") -and ($_.message -notmatch "\bdelete\b") -and ($_.message -notmatch "\bdaily\b") -and ($_.message -notmatch "\bdrift\b") -and ($_.message -notmatch "\btemplate\b")}        
        ForEach ($event in $events2) 
            {
                $eventsuri = $event.web_url
                $commitid = Split-Path $eventsuri -Leaf
                $commituri = "$GitLabUrl/projects/$project/repository/commits/$commitid/diff"
                $commit = Invoke-RestMethod -Uri $commitUri -Method Get -Headers $Headers
                $commitFilename = $commit.new_path

                $raw_url = $commitFilename
                $commitfullname = [System.IO.Path]::GetFileName($raw_url)
                if (![string]::IsNullOrEmpty($commitfullname)) {
                    $committenant = $commitfullname.Substring(0,36)
                }
                $commitfullname2 = $commitfullname -replace ".json", ""
                if (![string]::IsNullOrEmpty($commitfullname2)) {
                $last12digits = $commitfullname2.Substring($commitfullname2.Length-12)
            }
                $DateTimeFormat = "yyMMddHHmmss"
                try {
                    $DateTimeObject = [datetime]::ParseExact($last12digits, $DateTimeFormat, $null)
                } catch {
                    # Do nothing if it fails
                }
                
                if ($committenant -eq $gittenant -and $commitfullname -notmatch "\b(log|drift|golddrift|daily|intunereport|template)\b") {
                    ##If $commitfullname is empty, don't add it
                    if ($commitfullname -like "*$gittenant*") {
                    $commitObject = New-Object PSObject -Property @{
                        CommitFullName = $commitfullname
                        DateTime = $DateTimeObject
                    }
                    $validfiles += $commitObject
                }
            
                }
            }
            # Sort the $validfiles array on DateTime in descending order and select the most recent
            $mostRecentFile = $validfiles | Sort-Object DateTime -Descending | Select-Object -First 1
            
            # Retrieve the CommitFullName
            $commitfilename = $mostRecentFile.CommitFullName
        
        
        $filename = $commitfilename.Substring($commitfilename.LastIndexOf("/") + 1)
    
        $commitfilename2 = "$GitLabUrl/projects/$project/repository/files/$filename"+"/raw?ref=main"
        
        $decodedbackupdownload = (Invoke-RestMethod -Uri $commitfilename2 -Method Get -Headers $Headers)
        ##Decode

        $decodedbackup = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($decodedbackupdownload))

        
        }
    
    if ($repotype -eq "azuredevops") {
        $validfiles = @()

        $base64AuthInfo= [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes(":$($token)"))
        write-output "Finding Latest Backup Commit from Repo $reponame in $ownername DevOps"
        writelog "Finding Latest Backup Commit from Repo $reponame in $ownername DevOps"

        $events = Get-DevOpsCommits -repo $reponame -project $project -organization $ownername -token $token
        $events2 = $events | Select-Object message, url | Where-Object {($_.message -notmatch "\blog\b") -and ($_.message -notmatch "\bdelete\b") -and ($_.message -notmatch "\bdaily\b") -and ($_.message -notmatch "\bdrift\b") -and ($_.message -notmatch "\btemplate\b")}        
        ForEach ($event in $events2) 
        {
            $eventsuri = $event.url
            $commitid = Split-Path $eventsuri -Leaf
            $commituri = "https://dev.azure.com/$ownername/$project/_apis/git/repositories/$reponame/commits/$commitid/changes"
            $commitfilename2 = (((Invoke-RestMethod -Uri $commituri -Method Get -Headers @{Authorization=("Basic {0}" -f $base64AuthInfo)}).changes))[0].item.path

            $raw_url = $commitfilename2
            $commitfullname = [System.IO.Path]::GetFileName($raw_url)
            if (![string]::IsNullOrEmpty($commitfullname)) {
                $committenant = $commitfullname.Substring(0,36)
            }
            $commitfullname2 = $commitfullname -replace ".json", ""
            if (![string]::IsNullOrEmpty($commitfullname2)) {
            $last12digits = $commitfullname2.Substring($commitfullname2.Length-12)
        }
            $DateTimeFormat = "yyMMddHHmmss"
            try {
                $DateTimeObject = [datetime]::ParseExact($last12digits, $DateTimeFormat, $null)
            } catch {
                # Do nothing if it fails
            }
            
            if ($committenant -eq $gittenant -and $commitfullname -notmatch "\b(log|drift|golddrift|daily|intunereport|template)\b") {
                ##If $commitfullname is empty, don't add it
                if ($commitfullname -like "*$gittenant*") {
                $commitObject = New-Object PSObject -Property @{
                    CommitFullName = $commitfullname
                    DateTime = $DateTimeObject
                }
                $validfiles += $commitObject
            }
        
            }
        }
        # Sort the $validfiles array on DateTime in descending order and select the most recent
        $mostRecentFile = $validfiles | Sort-Object DateTime -Descending | Select-Object -First 1
        
        # Retrieve the CommitFullName
        $commitfilename = $mostRecentFile.CommitFullName
            $repoUrl = "https://dev.azure.com/$ownername/$project/_apis/git/repositories/$reponame"
            $repo = Invoke-RestMethod -Uri $repoUrl -Headers @{Authorization=("Basic {0}" -f $base64AuthInfo)} -Method Get
            $repoId = $repo.id
            $jsonuri = " https://dev.azure.com/$ownername/$project/_apis/git/repositories/$reponame/items?scopepath=$commitfilename&api-version=7.0&version=master"
            $decodedbackup2 = (Invoke-RestMethod -Uri $jsonuri -Method Get -UseDefaultCredential -Headers @{Authorization=("Basic {0}" -f $base64AuthInfo)})
            $decodedbackup = $decodedbackup2.Substring(1)
            
    }
    

###############################################################################################################
######                                              Grab Backup                                          ######
###############################################################################################################

if ($repotype -eq "azuredevops") {
$profilelist2 = $decodedbackup | ConvertFrom-Json
}
if ($repotype -eq "gitlab") {
    $profilelist2 = $decodedbackup | ConvertFrom-Json
    }
if ($repotype -eq "github") {
$profilelist2 = $decodedbackup
}

$oldjson = $profilelist2 | ConvertTo-Json -Depth 50
}

#######################################################################################################################################
#########                                               Compare them                           ########################################
#######################################################################################################################################

##Source
$psdoc1 = ($oldjson -split '\r?\n')

##Destination
$psdoc2 = ($currentprofilesjson -split '\r?\n')

$sourcepolicies = @()
$destinationpolicies = @()

$doc1asps = $psdoc1 | ConvertFrom-Json
foreach ($policy1 in $doc1asps) {
$var = ($policy1.value[0] | convertfrom-json)
try {
if (Get-Member -inputobject $var -name "Name" -Membertype Properties -ErrorAction SilentlyContinue) {
    $policy1name = $var.Name
}
}
catch {
    ##Do nothing, silence errors
}
try {
if (Get-Member -inputobject $var1 -name "DisplayName" -Membertype Properties -ErrorAction SilentlyContinue) {
    $policy1name = $var.DisplayName
}
}
catch {
    ##Do nothing, silence errors
}

    $policy1code = (($policy1.value[0]))
    $policy1url = $policy1.value[1]
    $policyid = $policy1.value[3]
    $object1 = [pscustomobject]@{
        Name = $policy1name
        Settings = $policy1code
        URL = $policy1url
        ID = $policyid
    }
    ##Add object to array
    $sourcepolicies += $object1
}


$doc2asps = $psdoc2 | ConvertFrom-Json
foreach ($policy2 in $doc2asps) {
$var1 = ($policy2.value[0] | convertfrom-json)
if (Get-Member -inputobject $var1 -name "Name" -Membertype Properties) {
    $policy2name = $var1.Name
}
if (Get-Member -inputobject $var1 -name "DisplayName" -Membertype Properties) {
    $policy2name = $var1.DisplayName
}
    $policy2code = (($policy2.value[0]))
       $policy2url = $policy2.value[1]
       $policyid = $policy2.value[3]
    $object2 = [pscustomobject]@{
        Name = $policy2name
        Settings = $policy2code
        URL = $policy2url
        ID = $policyid
    }
    ##Add object to array
    $destinationpolicies += $object2
}

$changearray = @()
$differences = Compare-Object -ReferenceObject ($sourcepolicies.settings) -DifferenceObject ($destinationpolicies.settings) -PassThru


$sourcepolicynames = $sourcepolicies.Name


##First grab policies which don't exist in the source
foreach ($difference in $differences) {        
try {
    $policybits = $difference | convertfrom-json   
    }
    catch {
    
    }
    $response = convert-sideindicator($difference.SideIndicator)

if (Get-Member -inputobject $policybits -name "Name" -Membertype Properties) {
    $sourcename = $policybits.Name
}
if (Get-Member -inputobject $policybits -name "DisplayName" -Membertype Properties) {
    $sourcename = $policybits.DisplayName
}

    $sourcesetting2 = $policybits.Settings
    
    if ([string]::IsNullOrWhitespace($sourcesetting2.Values)) {
            $sourcesetting = $difference
    }
    else {
            $sourcesetting = ($sourcesetting2.Values) | convertto-json -Depth 50
        write-host $sourcename
    }    
    if ($sourcepolicynames -notcontains $sourcename) {
        $sourceURL = $destinationpolicies | Where-Object Name -eq $sourcename | Select-Object -ExpandProperty URL
        $sourceID = $destinationpolicies | Where-Object Name -eq $sourcename | Select-Object -ExpandProperty ID
        $object4 = [pscustomobject]@{
            Name = $sourcename
            Source = $sourcesetting
            Destination = "Missing from Source"
            Location = $response
            URL = $sourceURL
            Type = "Add"
            PolicyID = $sourceID
        }
        ##Add object to array
        $changearray += $object4
    }
}

$destinationpolicynames = $destinationpolicies.Name


##Now grab policies which don't exist in the destination
foreach ($difference in $differences) {  
try {
    $policybits = $difference | convertfrom-json   
   }
   catch {
   write-host $difference
   }
    $response = convert-sideindicator($difference.SideIndicator)  
    if (Get-Member -inputobject $policybits -name "Name" -Membertype Properties) {
    $diffname = $policybits.Name
}
if (Get-Member -inputobject $policybits -name "DisplayName" -Membertype Properties) {
    $diffname = $policybits.DisplayName
}    
    $destsetting2 = $policybits.Settings
    if ([string]::IsNullOrWhitespace($destsetting2.Values)) {
            $destsetting = $difference

    }
    else {
            $sourcesetting = ($destsetting2.Values) | convertto-json -Depth 50

    }      
    if ($destinationpolicynames -notcontains $diffname) {
        $destURL = $sourcepolicies | Where-Object Name -eq $diffname | Select-Object -ExpandProperty URL
        $destID = $sourcepolicies | Where-Object Name -eq $diffname | Select-Object -ExpandProperty ID

        $object5 = [pscustomobject]@{
            Name = $diffname
            Source = "Missing from Destination"
            Destination = $destsetting
            Location = $response
            URL = $destURL
            Type = "Add"
            ID = $destID
        }
        ##Add object to array
        $changearray += $object5
    }

}


##Now look for policies which exist in both but with different settings
foreach ($difference in $differences) {  
try {
    $policybits = $difference | convertfrom-json   
    }
    catch {}
    if (Get-Member -inputobject $policybits -name "Name" -Membertype Properties) {
    $name = $policybits.Name
}
if (Get-Member -inputobject $policybits -name "DisplayName" -Membertype Properties) {
    $name = $policybits.DisplayName
}    

    $response = convert-sideindicator($difference.SideIndicator)      
    if ($changearray.Name -notcontains $name) {
    foreach ($sourcepolicy in $sourcepolicies) {
        if ($sourcepolicy.Name -eq $name) {
            $sourcesetting2 = $sourcepolicy.Settings
        }
    if ($null -ne $sourcesetting2.Values) {
        $sourcesetting = $sourcesetting2.Values
    }
    else {
        $sourcesetting = $sourcesetting2
    }
    if ($sourcesetting -eq "") {
        $sourcesetting = "No settings"
    }
}
    foreach ($destinationpolicy in $destinationpolicies) {
        if ($destinationpolicy.Name -eq $name) {
            $destinationsetting2 = $destinationpolicy.Settings
        }
    }
    if ($null -ne $destinationsetting2.Values) {
        $destinationsetting = $destinationsetting2.Values
    }
    else {
        $destinationsetting = $destinationsetting2
    }
    if ($destinationsetting -eq "") {
        $destinationsetting = "No settings"
    }
    $destURL = $sourcepolicies | Where-Object Name -eq $name | Select-Object -ExpandProperty URL
    $sourceURL = $destinationpolicies | Where-Object Name -eq $name | Select-Object -ExpandProperty URL
    $destID = $sourcepolicies | Where-Object Name -eq $name | Select-Object -ExpandProperty ID
    $sourceID = $destinationpolicies | Where-Object Name -eq $name | Select-Object -ExpandProperty ID

    ##Grab ID depending on $reponse
    if ($response -eq "Added to Tenant") {
$policyid = $sourceID
    }
    if ($response -eq "Missing from Tenant") {
        $policyid = $destID
    }

    if ($destURL) {
    $URL = $destURL
    }
    else {
    $URL = $sourceURL
    }

    $object3 = [pscustomobject]@{
        Name = $name
        Source = $sourcesetting
        Destination = $destinationsetting
        Location = $response
        URL = $URL
        Type = "Update"
        ID = $policyID
    }
    ##Add object to array
    $changearray += $object3
}
}


#######################################################################################################################################
#########                                            Send Email                                ########################################
#######################################################################################################################################

if (($EmailAddress) -and (!$goldentenant) -and ($changearray)) {



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
</style>
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
                                   <h1>Drift Alert</h1>
                                   <p>Drift detected on tenant $domain</p>
                                   <p>Please login to the portal to review</p>
                              </td>
                         </tr>
                         </table>

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
                    "email" = $EmailAddress
                }
            )
            "subject" = " Drift Alert for $domain "
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
        "name"  = "Drift Alert"
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
## Invoke-RestMethod @Parameters
write-output "Email Sent"


}

if  ($livemigration -ne "yes") {
#######################################################################################################################################
#########                                            Save Config                               ########################################
#######################################################################################################################################

        ##Clear Tenant Connections
        Disconnect-MgGraph
        if (!$WebHookData) {
            Stop-Transcript  
        }
                  

        if ($goldentenant) {
            $filename = $tenant+"-golddrift.json"
        }
        else {
            $filename = $tenant+"-drift.json"
        }

                $backupreason = "Drift Check"

                $logcontent = $changearray | ConvertTo-Json -Depth 50
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
                $uri = "https://api.github.com/repos/$ownername/$reponame/contents/$filename"
                try {
                    # Get the SHA of the file
                    $getShaResponse = Invoke-RestMethod -Uri $uri -Method get -Headers @{'Authorization'='bearer '+$token;}
                    $sha = $getShaResponse.sha
                } catch {
                    # If the file does not exist, the SHA is null
                    $sha = $null
                }

                $message = "$backupreason - $readabledate"
                if ($null -eq $sha) {
                    # If the file does not exist, create a new file
                    $body = '{{"message": "{0}", "content": "{1}" }}' -f $message, $logencoded
                } else {
                    # If the file exists, overwrite it
                    $body = '{{"message": "{0}", "content": "{1}", "sha": "{2}" }}' -f $message, $logencoded, $sha
                }
                (Invoke-RestMethod -Uri $uri -Method put -Headers @{'Authorization'='bearer '+$token;} -Body $body -ContentType "application/json")
                }
                if ($repotype -eq "gitlab") {
                    writelog "Uploading to GitLab"
                ##Upload to GitLab
                $date = Get-Date -Format yyMMddHHmmss
                $date = $date.ToString()
                $readabledate = Get-Date -Format dd-MM-yyyy-HH-mm-ss
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
try {
    $fileUrl = "$GitLabUrl/projects/$project/repository/files/$filename"
    $fileExistsResponse = Invoke-RestMethod -Uri $fileUrl -Method get -Headers $Headers
} catch {
    $fileExists = $false
}
if ($null -eq $fileExistsResponse) {
    # If the file does not exist, create a new file
    # Your existing code to create a new file goes here
    Invoke-RestMethod -Uri $CreateFileUrl -Method Post -Headers $Headers -Body $FileContentJson -ContentType "application/json"
} else {
    # If the file exists, overwrite it
    # Your existing code to overwrite the file goes here
    Invoke-RestMethod -Uri $CreateFileUrl -Method PUT -Headers $Headers -Body $FileContentJson -ContentType "application/json"
}

                }
                if ($repotype -eq "azuredevops") {
                    $date =get-date -format yyMMddHHmmss
                $date = $date.ToString()
                                    writelog "Uploading to Azure DevOps"
                    Add-DevopsFile -repo $reponame -project $project -organization $ownername -filename $filename -filecontent $logcontent -token $token -comment $backupreason
                
                }
            

            }


            else {

#######################################################################################################################################
#########                                            Sync Policies                             ########################################
#######################################################################################################################################


##Loop through $changearray and only return items where Location is "Missing from Tenant"
foreach ($change in $changearray) {
    if ($change.Location -eq "Added to Tenant") {
$type = $change.Type
$policyuri = $change.URL
##If $policyuri is an array, select the first object
if ($policyuri -is [array]) {
    $policyuri = $policyuri[0]
}
else {
    $policyuri = $policyuri

}



    ##if $policyuri starts with https://graph.microsoft.com/beta/devicemanagement/templates change to https://graph.microsoft.com/beta/deviceManagement/intents
    if ($policyuri -like "https://graph.microsoft.com/beta/devicemanagement/templates*") {
        $policyuri = "https://graph.microsoft.com/beta/deviceManagement/intents"
    }
$policyname = $change.Name
$policyjson = $change.Source
$policyjson = $policyjson -replace $tenant, $secondtenant 
write-output "Updating $policyname"
if ($type -eq "Update") {

if ($policyuri -like "https://graph.microsoft.com/beta/deviceAppManagement/managedAppPolicies*") {
    $geturi = "https://graph.microsoft.com/beta/deviceAppManagement/managedAppPolicies?$filter=displayName eq '$policyname'"
}
else {
$var = ($policyjson | convertfrom-json)
if (Get-Member -inputobject $var -name "DisplayName" -Membertype Properties) {
    $geturi = $policyuri+"?`$filter=(startswith(displayName,'$policyname'))";
}
if (Get-Member -inputobject $var -name "Name" -Membertype Properties) {
     $geturi = $policyuri+"?`$filter=(startswith(Name,'$policyname'))";
}
}


    $getpolicy = Invoke-MgGraphRequest -Method GET -Uri $geturi -OutputType PSObject
    $policyid = $getpolicy.value.id
    ##If policyid is a single object, make it an array
    if ($policyid -isnot [array]) {
        $policyid = @($policyid)
    }
    foreach ($todelete in $policyid) {
    ##Check if $policyuri contains default
if ($policyid -like "*Default*") {
    write-output "Default policy, skipping"
}
else {
    $url = $policyuri+"/"+$todelete
    ##Delete existing
   Invoke-MgGraphRequest -Method DELETE -Uri $url
    
    ##Create new
   Invoke-MgGraphRequest -Method POST -Uri $policyuri -Body $policyjson -ContentType "application/json"
   }
   }
}
else {
    Invoke-MgGraphRequest -Method POST -Uri $policyuri -Body $policyjson -ContentType "application/json"
}
    }
    }
            }

        