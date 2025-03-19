<#PSScriptInfo
.VERSION 1.0.0
.GUID ca8677b9-a7de-456f-831c-52dc36af3808
.AUTHOR AndrewTaylor
.DESCRIPTION Creates an app reg and outputs client ID and secret
.COMPANYNAME 
.COPYRIGHT GPL
.TAGS entra, app reg
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
  Creates an Entra app reg and outputs the details
.DESCRIPTION
.Creates an Entra app reg and outputs the details

.INPUTS
None
.OUTPUTS
Client ID and secret

.NOTES
  Version:        1.0.0
  Author:         Andrew Taylor
  Twitter:        @AndrewTaylor_2
  WWW:            andrewstaylor.com
  Creation Date:  22/08/2024
.EXAMPLE
N/A
#>

<#
  __ _  _ __    __| | _ __   ___ __      __ ___ | |_   __ _  _   _ | |  ___   _ __      ___   ___   _ __ ___
 / _` || '_ \  / _` || '__| / _ \\ \ /\ / // __|| __| / _` || | | || | / _ \ | '__|    / __| / _ \ | '_ ` _ \
| (_| || | | || (_| || |   |  __/ \ V  V / \__ \| |_ | (_| || |_| || || (_) || |    _ | (__ | (_) || | | | | |
 \__,_||_| |_| \__,_||_|    \___|  \_/\_/  |___/ \__| \__,_| \__, ||_| \___/ |_|   (_) \___| \___/ |_| |_| |_|

#>

##Creates a multi-tenant App Reg
##Secret is randomly generated
##App ID and Secret passed to the output

#Install MS Graph if not available
if (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication) {
    write-output "Microsoft Graph Authentication Already Installed"
} 
else {
        Install-Module -Name Microsoft.Graph.Authentication -Scope CurrentUser -Repository PSGallery -Force
        write-output "Microsoft Graph Authentication Installed"
}

#Install MS Graph if not available
if (Get-Module -ListAvailable -Name Microsoft.Graph.Applications) {
    write-output "Microsoft Graph Applications Already Installed"
} 
else {
        Install-Module -Name Microsoft.Graph.Applications -Scope CurrentUser -Repository PSGallery -Force
        write-output "Microsoft Graph Applications Installed"
}

#Import Module
Import-Module Microsoft.Graph.Authentication
Import-Module Microsoft.Graph.Applications
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

Connect-ToGraph -Scopes "Application.Read.All,Application.ReadWrite.All,User.Read.All"


function Get-RandomPassword {
    param (
        [Parameter(Mandatory)]
        [int] $length,
        [int] $amountOfNonAlphanumeric = 1
    )
    Add-Type -AssemblyName 'System.Web'
    return [System.Web.Security.Membership]::GeneratePassword($length, $amountOfNonAlphanumeric)
}

###############################################################################
#Create AAD Application
###############################################################################
$AppName =  "IntuneBackupEUCToolbox"
$App = New-MgApplication -DisplayName $AppName -SignInAudience AzureADMultipleOrgs
$APPObjectID = $App.Id

###############################################################################
#Add a ClientSecret
###############################################################################
$passwordCred = @{
    "displayName" = "IntuneBackupSecret"
    "endDateTime" = (Get-Date).AddMonths(+24)
}
$ClientSecret2 = Add-MgApplicationPassword -ApplicationId $APPObjectID -PasswordCredential $passwordCred

$appsecret = $ClientSecret2.SecretText

###############################################################################
#Add Permissions
###############################################################################
#Add Delegated Permission
$params = @{
	RequiredResourceAccess = @(
		@{
			ResourceAppId = "00000003-0000-0000-c000-000000000000"
			ResourceAccess = @(
				@{
					Id = "40b534c3-9552-4550-901b-23879c90bcf9"
					Type = "Scope"
				},
				@{
					Id = "a8ead177-1889-4546-9387-f25e658e2a79"
					Type = "Scope"
				},
				@{
					Id = "e1fe6dd8-ba31-4d61-89e7-88639da4683d"
					Type = "Scope"
				},
				@{
					Id = "dc149144-f292-421e-b185-5953f2e98d7f"
					Type = "Role"
				},
				@{
					Id = "9a5d68dd-52b0-4cc2-bd40-abcf44ac3a30"
					Type = "Role"
				},
				@{
					Id = "b0afded3-3588-46d8-8b3d-9842eff778da"
					Type = "Role"
				},
				@{
					Id = "3b4349e1-8cf5-45a3-95b7-69d1751d3e6a"
					Type = "Role"
				},
				@{
					Id = "1138cb37-bd11-4084-a2b7-9f71582aeddb"
					Type = "Role"
				},
				@{
					Id = "78145de6-330d-4800-a6ce-494ff2d33d07"
					Type = "Role"
				},
				@{
					Id = "9241abd9-d0e6-425a-bd4f-47ba86e767a4"
					Type = "Role"
				},
				@{
					Id = "243333ab-4d21-40cb-a475-36241daa0842"
					Type = "Role"
				},
				@{
					Id = "e330c4f0-4170-414e-a55a-2f022ec2b57b"
					Type = "Role"
				},
				@{
					Id = "5ac13192-7ace-4fcf-b828-1a26f28068ee"
					Type = "Role"
				},
				@{
					Id = "19dbc75e-c2e2-444c-a770-ec69d8559fc7"
					Type = "Role"
				},
				@{
					Id = "7e05723c-0bb0-42da-be95-ae9f08a6e53c"
					Type = "Role"
				},
				@{
					Id = "62a82d76-70ea-41e2-9197-370581804d09"
					Type = "Role"
				},
				@{
					Id = "dbaae8cf-10b5-4b86-a4a1-f871c94c6695"
					Type = "Role"
				},
				@{
					Id = "498476ce-e0fe-48b0-b801-37ba7e2685c6"
					Type = "Role"
				},
				@{
					Id = "246dd0d5-5bd0-4def-940b-0421030a5b68"
					Type = "Role"
				},
				@{
					Id = "01c0a623-fc9b-48e9-b794-0756f8e8f067"
					Type = "Role"
				},
				@{
					Id = "a402ca1c-2696-4531-972d-6e5ee4aa11ea"
					Type = "Role"
				},
				@{
					Id = "1c6e93a6-28e2-4cbb-9f64-1a46a821124d"
					Type = "Role"
				},
				@{
					Id = "230c1aed-a721-4c5d-9cb4-a90514e508ef"
					Type = "Role"
				},
				@{
					Id = "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8"
					Type = "Role"
				},
				@{
					Id = "bf394140-e372-4bf9-a898-299cfc7564e5"
					Type = "Role"
				},
				@{
					Id = "332a536c-c7ef-4017-ab91-336970924f0d"
					Type = "Role"
				},
				@{
					Id = "1b620472-6534-4fe6-9df2-4680e8aa28ec"
					Type = "Role"
				},
				@{
					Id = "79c261e0-fe76-4144-aad5-bdc68fbe4037"
					Type = "Role"
				}
			)
		}
	)
}
Update-MgApplication -ApplicationId $APPObjectID -BodyParameter $params

###############################################################################
#Redirect URI
#If you need to add Redirect URI's.
###############################################################################
#Redirect URI
$App = Get-MgApplication -ApplicationId $APPObjectID -Property *
$AppId = $App.AppId
$RedirectURI = @()
$RedirectURI += "https://login.microsoftonline.com/common/oauth2/nativeclient"
$RedirectURI += "msal" + $AppId + "://auth"

$params = @{
    RedirectUris = @($RedirectURI)
}
Update-MgApplication -ApplicationId $APPObjectID -IsFallbackPublicClient -PublicClient $params

###############################################################################
#Grant Admin Consent - Opens URL in Browser
###############################################################################
#https://login.microsoftonline.com/{tenant-id}/adminconsent?client_id={client-id}
$App = Get-MgApplication | Where-Object {$_.DisplayName -eq $AppName}
$TenantID = $App.PublisherDomain
$AppID = $App.AppID
$URL = "https://login.microsoftonline.com/$TenantID/adminconsent?client_id=$AppID"
Start-Process $URL

write-host "Your App ID is $AppID"

write-host "Your App Secret is $appsecret"

