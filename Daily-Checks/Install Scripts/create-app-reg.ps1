<#PSScriptInfo
.VERSION 1.0.0
.GUID ab9f4e18-acf9-4aa5-815a-ea63fba45bc0
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
$AppName =  "DailyChecksEUCToolbox"
$App = New-MgApplication -DisplayName $AppName -SignInAudience AzureADMultipleOrgs
$APPObjectID = $App.Id

###############################################################################
#Add a ClientSecret
###############################################################################
$passwordCred = @{
    "displayName" = "DailyChecksSecret"
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
                    Id = "e1fe6dd8-ba31-4d61-89e7-88639da4683d"
                    Type = "Scope"
                },
                @{
                    "id"   = "e12dae10-5a57-4817-b79d-dfbec5348930"
                    "type" = "Role"
                },
                @{
                    "id"   = "9a5d68dd-52b0-4cc2-bd40-abcf44ac3a30"
                    "type" = "Role"
                },
                @{
                    "id"   = "b0afded3-3588-46d8-8b3d-9842eff778da"
                    "type" = "Role"
                },
                @{
                    "id"   = "a9e09520-8ed4-4cde-838e-4fdea192c227"
                    "type" = "Role"
                },
                @{
                    "id"   = "7438b122-aefc-4978-80ed-43db9fcc7715"
                    "type" = "Role"
                },
                @{
                    "id"   = "7a6ee1e7-141e-4cec-ae74-d9db155731ff"
                    "type" = "Role"
                },
                @{
                    "id"   = "dc377aa6-52d8-4e23-b271-2a7ae04cedf3"
                    "type" = "Role"
                },
                @{
                    "id"   = "2f51be20-0bb4-4fed-bf7b-db946066c75e"
                    "type" = "Role"
                },
                @{
                    "id"   = "58ca0d9a-1575-47e1-a3cb-007ef2e4583b"
                    "type" = "Role"
                },
                @{
                    "id"   = "06a5fe6d-c49d-46a7-b082-56b1b14103c7"
                    "type" = "Role"
                },
                @{
                    "id"   = "7ab1d382-f21e-4acd-a863-ba3e13f7da61"
                    "type" = "Role"
                },
                @{
                    "id"   = "dbb9058a-0e50-45d7-ae91-66909b5d4664"
                    "type" = "Role"
                },
                @{
                    "id"   = "5b567255-7703-4780-807c-7be8301ae99b"
                    "type" = "Role"
                },
                @{
                    "id"   = "98830695-27a2-44f7-8c18-0c3ebc9698f6"
                    "type" = "Role"
                },
                @{
                    "id"   = "498476ce-e0fe-48b0-b801-37ba7e2685c6"
                    "type" = "Role"
                },
                @{
                    "id"   = "246dd0d5-5bd0-4def-940b-0421030a5b68"
                    "type" = "Role"
                },
                @{
                    "id"   = "37730810-e9ba-4e46-b07e-8ca78d182097"
                    "type" = "Role"
                },
                @{
                    "id"   = "9e640839-a198-48fb-8b9a-013fd6f6cbcd"
                    "type" = "Role"
                },
                @{
                    "id"   = "1c6e93a6-28e2-4cbb-9f64-1a46a821124d"
                    "type" = "Role"
                },
                @{
                    "id"   = "230c1aed-a721-4c5d-9cb4-a90514e508ef"
                    "type" = "Role"
                },
                @{
                    "id"   = "483bed4a-2ad3-4361-a73b-c83ccdbdc53c"
                    "type" = "Role"
                },
                @{
                    "id"   = "bf394140-e372-4bf9-a898-299cfc7564e5"
                    "type" = "Role"
                },
                @{
                    "id"   = "bf394140-e372-4bf9-a898-299cfc7564e5"
                    "type" = "Role"
                },
                @{
                    "id"   = "79c261e0-fe76-4144-aad5-bdc68fbe4037"
                    "type" = "Role"
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

