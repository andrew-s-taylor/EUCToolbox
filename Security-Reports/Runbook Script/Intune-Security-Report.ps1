<#
.SYNOPSIS
Reviews and Intune environment against NCSC and CIS baselines and produces an html report
.DESCRIPTION
Reviews and Intune environment against NCSC and CIS baselines and produces an html report
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
.GUID 3485a7e6-b4b2-4b6b-b829-509c44a6efd8
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
    [string]$recipient #Email recipient
    , 
    [string]$sendgridtoken #Sendgrid API token
    , 
    [object]$WebHookData #Webhook data for Azure Automation

    )

##WebHook Data

if ($WebHookData){

$rawdata = $WebHookData.RequestBody
    $bodyData = ConvertFrom-Json -InputObject ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($rawdata)))


$tenant = ((($bodyData.tenant) | out-string).trim())
$clientid = ((($bodyData.clientid) | out-string).trim())
$clientsecret = ((($bodyData.clientsecret) | out-string).trim())
$recipient = ((($bodyData.recipient) | out-string).trim())
$sendgridtoken = ((($bodyData.sendgridtoken) | out-string).trim())




##Check if parameters have been set

$clientidcheck = $PSBoundParameters.ContainsKey('clientid')

if (($clientidcheck -eq $true)) {
##AAD Secret passed, use to login
$aadlogin = "yes"

}

##if tenant isn't set, exit
if (!$tenant) {
    Write-Host "Tenant ID not set, exiting"
    exit
}


}
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
######                                          Add Functions                                            ######
###############################################################################################################
function Test-RegistryKey {
    <#
        .SYNOPSIS
            Test if registry key exists
    #>
    param (
        [parameter (Mandatory = $true)]
        [ValidateNotNullOrEmpty()]$Path,
        [parameter (Mandatory = $true)]
        [ValidateNotNullOrEmpty()]$Key
    )

    try {
        Get-ItemProperty -Path $Path -Name $Key -ErrorAction Stop | Out-Null
        return $true
    }
    catch {
        return $false
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
		[string]$GroupPolicyConfigurationID
		
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
               
   $pvalue.value = $EncodedText
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
}

}

##We don't want to convert CA policy to JSON
# Remove any GUIDs or dates/times to allow Intune to regenerate

    $policy = $policy | Select-Object * -ExcludeProperty id, createdDateTime, LastmodifieddateTime, version, creationSource, '@odata.count' | ConvertTo-Json -Depth 100

return $policy, $uri, $oldname

}



function get-arrayvalue {
        <#
    .SYNOPSIS
    This function is used to look for a specific value in a multidimensional Intune output array
    .DESCRIPTION
    The function ingests a json file and looks for a specific array key-value
    .EXAMPLE
    get-arrayvalue -requiredvalue "true" -inputfile $inputfile -lookfor "RequireDeviceEncryption"
    .NOTES
    NAME: get-arrayvalue
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$requiredvalue,
        [Parameter(Mandatory=$true)]
        $inputfile,
        [Parameter(Mandatory=$true)]
        [string]$lookfor
    )
    $returnvalue = 0
    ##Convert requiredvalue to lowercase
    $requiredvalue = $requiredvalue.ToLower()
    $inps = ($inputfile | ConvertFrom-Json).value
    $line3 = (($inps -match $lookfor) | convertfrom-json)
    foreach ($item in $line3) {
        if ($item.values) {
            $item = $item.values
        }
        else {
            $item = $item
        }
        $hasdefinition = $item.definitionId
        if ($hasdefinition) {
            if ($item.definitionId -like "*$lookfor*") {
                foreach ($object in $item) {
                    if ($object.definitionId -like "*$lookfor*") {
                        $objectvalue2 = ($object.valuejson | convertfrom-json)
                        if ($objectvalue2) {
                            if ($requiredvalue.contains(":")) 
                            {
                                $objname  = $requiredvalue.Split(":")[0]
                                $objvalue = $requiredvalue.split(":")[1]
                                $objectvalue = $objectvalue2.$objname
                                $requiredvalue = $objvalue
                            }
                            else {
                            $objectvalue = $objectvalue2
                            }                        }
                        else {
                            $objectvalue2 = $object.value
                        }
                        if ($objectvalue -like "*$requiredvalue*") {
                            $returnvalue++
                        }
                    }
                }
            }
        }
        else {
            if ($item -like "*$lookfor*") {
                foreach ($object in $item) {
                    $result = (($object.$lookfor).ToString().tolower())
                    if ($requiredvalue -eq "null-notset") {
                        if (!$result) {
                            $returnvalue++
                        }
                    }
                    else {
                    if ($result -eq $requiredvalue) {
                        $returnvalue++
                    }
                }
                }
            }
        }
        }
    if ($returnvalue -gt 0) {
        return $true
    } else {
        return $false
        }
}

function get-valueexists {
        <#
    .SYNOPSIS
    This function is used to check if a specific value exists in a multidimensional Intune output array
    .DESCRIPTION
    The function ingests a json file and looks for a specific value
    .EXAMPLE
    get-valueexists -inputfile $inputfile -lookfor "RequireDeviceEncryption"
    .NOTES
    NAME: get-valueexists
    #>
    param(
        [Parameter(Mandatory=$true)]
        $inputfile,
        [Parameter(Mandatory=$true)]
        [string]$lookfor
    )
    $inps = ($inputfile | ConvertFrom-Json).value
    $line = ($inps -match "$lookfor")
    if ($line) {
        return $true
    } else {
        return $false
        }
}

function set-reportoutput {
        <#
    .SYNOPSIS
    This function is used to download a CSV file, loop through and output an html table
    .DESCRIPTION
    The function downloads a CSV, loops through the values, calling the functions above and outputs HTML
    .EXAMPLE
    set-reportoutput -csvuri "https://yourcsvurl/file.csv" -type "Windows CIS" -outputpath "C:\temp\"
    .NOTES
    NAME: set-reportoutput
    #>
    param(
        [Parameter(Mandatory=$true)]
        $csvuri,
        [Parameter(Mandatory=$true)]
        $inputfile,
        [Parameter(Mandatory=$true)]
        $type
    )
    ##Remove spaces etc. from tye
    $typepath = $type -replace " ", ""
    ##Download the CSV file
    $csvpath = "$env:temp\$typepath.csv"
    invoke-webrequest -uri $csvuri -outfile $csvpath
    $output = @()
    $csv = Import-Csv $csvpath
    $counter = 0
    #$log = @()
    foreach ($item in $csv) {
        $counter++
        $setting = $item."Setting Name"
        $urgency = $item.urgency
        $description = $item.Reason
        Write-Progress -Activity 'Processing Entries' -CurrentOperation $setting -PercentComplete (($counter / $csv.count) * 100)
        if ($item.Setting1 -eq "ISPRESENT") {
            $itemtocheck = $item.Field1
            ##$log += "Checking if $itemtocheck is present"
            $check = get-valueexists -inputfile $inputfile -lookfor $itemtocheck
        }
        else {
            $itemtocheck = $item.Field1
            $itemtocheckvalue = $item.Setting1
            #$log += "Checking if $itemtocheck is $itemtocheckvalue"
           $check = get-arrayvalue -requiredvalue $itemtocheckvalue -lookfor $itemtocheck -inputfile $inputfile
        }
        if ($item.Field2) {
            if ($item.Setting2 -eq "ISPRESENT") {
                $itemtocheck2 = $item.Field2
                #$log += "SECOND Checking if $itemtocheck2 is present"
                $check2 = get-valueexists -inputfile $inputfile -lookfor $itemtocheck2
            }
            else {
                $itemtocheck2 = $item.Field2
                $itemtocheckvalue2 = $item.Setting2
                #$log += "SECOND Checking if $itemtocheck2 is $itemtocheckvalue2"
                $check2 = get-arrayvalue -requiredvalue $itemtocheckvalue2 -lookfor $itemtocheck2 -inputfile $inputfile
            }
            }
        if ($check -eq $true -or $check2 -eq $true) {
           $settingvalue = "Pass"
        }
        else {
           $settingvalue = "Fail"
        }
        $itemobject = [pscustomobject]@{
            Setting = $setting
            Value = $settingvalue
            Urgency = $urgency
            Description = $description
        }
        $output += $itemobject
    }
    $htmloutput = ($output | sort-object value) | ConvertTo-Html -Fragment
    $fullcount = $csv.count
    $truecount = ($output | Where-Object {$_.value -eq "Pass"}).count
    $finalcounts = "Total Settings: $fullcount | Settings Passed: $truecount"
    
    return $htmloutput, $finalcounts, $output, $fullcount, $truecount
}

function set-reportoutputapi {
    <#
.SYNOPSIS
This function is used to connect to the EUCToolbox API, loop through and output an html table
.DESCRIPTION
The function grabs output from API, loops through the values, calling the functions above and outputs HTML
.EXAMPLE
set-reportoutput -type "Windows CIS" -outputpath "C:\temp\"
.NOTES
NAME: set-reportoutput
#>
param(
    [Parameter(Mandatory=$true)]
    $inputfile,
    [Parameter(Mandatory=$true)]
    $type
)
##Remove spaces etc. from tye
$typepath = $type -replace " ", ""

    $apiurl = "https://intunereport.euctoolbox.com/api?action=$typepath"
        $csv  = Invoke-RestMethod -Method GET -Uri $apiurl
$output = @()

$counter = 0
#$log = @()
foreach ($item in $csv) {
    $counter++
    $setting = $item.SettingName
    $urgency = $item.Urgency
    $description = $item.Reason
    Write-Progress -Activity 'Processing Entries' -CurrentOperation $setting -PercentComplete (($counter / $csv.count) * 100)
    if ($item.Setting1 -eq "ISPRESENT") {
        $itemtocheck = $item.Field1
        ##$log += "Checking if $itemtocheck is present"
        $check = get-valueexists -inputfile $inputfile -lookfor $itemtocheck
    }
    else {
        $itemtocheck = $item.Field1
        $itemtocheckvalue = $item.Setting1
        #$log += "Checking if $itemtocheck is $itemtocheckvalue"
       $check = get-arrayvalue -requiredvalue $itemtocheckvalue -lookfor $itemtocheck -inputfile $inputfile
    }
    if ($item.Field2) {
        if ($item.Setting2 -eq "ISPRESENT") {
            $itemtocheck2 = $item.Field2
            #$log += "SECOND Checking if $itemtocheck2 is present"
            $check2 = get-valueexists -inputfile $inputfile -lookfor $itemtocheck2
        }
        else {
            $itemtocheck2 = $item.Field2
            $itemtocheckvalue2 = $item.Setting2
            #$log += "SECOND Checking if $itemtocheck2 is $itemtocheckvalue2"
            $check2 = get-arrayvalue -requiredvalue $itemtocheckvalue2 -lookfor $itemtocheck2 -inputfile $inputfile
        }
        }
    if ($check -eq $true -or $check2 -eq $true) {
       $settingvalue = "Pass"
    }
    else {
       $settingvalue = "Fail"
    }
    $itemobject = [pscustomobject]@{
        Setting = $setting
        Value = $settingvalue
        Urgency = $urgency
        Description = $description
    }
    $output += $itemobject
}
$htmloutput = ($output | sort-object value) | ConvertTo-Html -Fragment
$fullcount = $csv.count
$truecount = ($output | Where-Object {$_.value -eq "Pass"}).count
$finalcounts = "Total Settings: $fullcount | Settings Passed: $truecount"

return $htmloutput, $finalcounts, $output, $fullcount, $truecount
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
###############################################################################################################
######                                              END FUNCTIONS                                        ######
###############################################################################################################




##################################################################################################################################
#################                                                  INITIALIZATION                                #################
##################################################################################################################################
$ErrorActionPreference = "Continue"


###############################################################################################################
######                                         Install Modules                                           ######
###############################################################################################################
write-output "Installing Intune modules if required (current user scope)"
        # Get NuGet
        $provider = Get-PackageProvider NuGet -ErrorAction Ignore
        if (-not $provider) {
            Write-Host "Installing provider NuGet"
            Find-PackageProvider -Name NuGet -ForceBootstrap -IncludeDependencies
        }

write-output "Installing Microsoft Graph Authentication modules if required (current user scope)"

#Install Graph Groups module if not available

#Install Graph Authentication module if not available
if (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication) {
    write-output "Microsoft Graph Authentication Module Already Installed"
} 
else {
    try {
        Install-Module -Name Microsoft.Graph.Authentication -Scope CurrentUser -Repository PSGallery -Force -AllowClobber 
    }
    catch [Exception] {
        $_.message 
    }
}


##Import Modules
write-output "Importing Modules"
import-module Microsoft.Graph.Authentication

write-output "Modules Imported"

###############################################################################################################
######                                            Connect                                                ######
###############################################################################################################


###############################################################################################################
######                                     Graph Connection                                              ######
###############################################################################################################
##Connect using Secret
$tenantId = $tenant
write-output "Connecting to Graph"
if (($WebHookData) -or ($aadlogin -eq "yes")) { 
    Connect-ToGraph -Tenant $tenant -AppId $clientId -AppSecret $clientSecret
    write-output "Graph Connection Established"
    }
    else {
    ##Connect to Graph
    Connect-ToGraph -Scopes "Policy.ReadWrite.ConditionalAccess, CloudPC.ReadWrite.All, DeviceManagementServiceConfig.ReadWrite.All, RoleAssignmentSchedule.ReadWrite.Directory, Domain.Read.All, Domain.ReadWrite.All, Directory.Read.All, Policy.ReadWrite.ConditionalAccess, DeviceManagementApps.ReadWrite.All, DeviceManagementConfiguration.ReadWrite.All, DeviceManagementManagedDevices.ReadWrite.All, openid, profile, email, offline_access, DeviceManagementRBAC.Read.All, DeviceManagementRBAC.ReadWrite.All"
    }
write-output "Graph Connection Established"

##################################################################################################################################
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

##Get Security Policies
$configuration += Get-DeviceSecurityPolicy | Select-Object ID, DisplayName, Description, @{N='Type';E={"Security Policy"}}

##Get WHfBPolicies
$configuration += Get-WHfBPolicies | Select-Object ID, DisplayName, Description,  @{N='Type';E={"WHfB Policy"}}

$configuration2 = $configuration

$configuration2 | foreach-object {

    ##Find out what it is
    $id = $_.ID
    write-output $id
    $policy = $configuration | where-object {($_.ID -eq $id) -and ($_.Type -eq "Config Policy")}
    $catalog = $configuration | where-object {($_.ID -eq $id) -and ($_.Type -eq "Settings Catalog")}
    $security = $configuration | where-object {($_.ID -eq $id) -and ($_.Type -eq "Security Policy")}
    $gp = $configuration | where-object {($_.ID -eq $id) -and ($_.Type -eq "Admin Template")}
    $whfb = $configuration | where-object {($_.ID -eq $id) -and ($_.Type -eq "WHfB Policy")}

    # Copy it
if ($null -ne $policy) {
    # Standard Device Configuratio Policy
write-output "It's a policy"
$id = $policy.id
$Resource = "deviceManagement/deviceConfigurations"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id))

}
if ($null -ne $gp) {
    # Standard Device Configuration Policy
write-output "It's an Admin Template"
$id = $gp.id
$Resource = "deviceManagement/groupPolicyConfigurations"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id))
}
if ($null -ne $catalog) {
    # Settings Catalog Policy
write-output "It's a Settings Catalog"
$id = $catalog.id
$Resource = "deviceManagement/configurationPolicies"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id))

}
if ($null -ne $security) {
    # Security Policy
write-output "It's a Security Policy"
$id = $security.id
$Resource = "deviceManagement/intents"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id))
}
if ($null -ne $whfb) {
    # Windows Hello for Business
write-output "It's a WHfB Policy"
$id = $esp.id
$Resource = "deviceManagement/deviceEnrollmentConfigurationswhfb"
$copypolicy = getpolicyjson -resource $Resource -policyid $id
$profiles+= ,(@($copypolicy[0],$copypolicy[1],$copypolicy[2], $id))
}
}

##Convert profiles to JSON
$list = $profiles | convertto-json -Depth 50 
###############################################################################################################
######                                           PROCESS EVERYTHING                                      ######
###############################################################################################################
write-output "Creating Folder for Reports"
##Create a folder to store the output
$folder = "$env:temp\Reports"
if (!(Test-Path $folder)) {
    New-Item -ItemType Directory -Path $folder
}

write-output "Folder Created"

###############################################################################################################
######                                                 INTUNE                                            ######
###############################################################################################################
$dateTime = Get-Date
$formattedDateTime = $dateTime.ToString("dddd MMMM d' 'yyyy hh:mmtt")

##Get the domain name
$uri = "https://graph.microsoft.com/beta/organization"
$tenantdetails = (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).value
$domain = ($tenantdetails.VerifiedDomains | Where-Object isDefault -eq $true).name

if (!$tenant) {
    $tenant = $tenantdetails.id
}



###Summary Report
write-output "Creating Intune Report"
##Create the basic html structure and CSS
$htmlsummary = @"
<html>
<head>
<title>Baseline Report</title>
<style type="text/css">
/* Set default font family and color for entire page */
body {
    font-family: Arial, sans-serif;
    color: #333;
  }
  
  /* Style for main heading */
  .heading-1 {
    font-size: 2.5rem;
    margin: 2rem 0;
    color: #000000; /* blue */
    text-align: center;
  }
  
  /* Style for subheadings */
  h2 {
    font-size: 2rem;
    margin: 1.5rem 0;
    color: #202020; /* orange */
    text-align: center;
  }
  
  /* Style for sub-subheadings */
  h3 {
    font-size: 1.5rem;
    margin: 1rem 0;
    color: #333333; /* blue */
    text-align: center;
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
    background-color: #ff6633;
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
    color: #ff6633;
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
  @property --p{
    syntax: '<number>';
    inherits: true;
    initial-value: 0;
  }
  
  .pie {
    --p:20;
    --b:22px;
    --c:darkred;
    --w:150px;
    
    width:var(--w);
    aspect-ratio:1;
    position:relative;
    display:inline-grid;
    margin:5px;
    place-content:center;
    font-size:12px;
    font-weight:bold;
    font-family:sans-serif;
  }
  .pie:before,
  .pie:after {
    content:"";
    position:absolute;
    border-radius:50%;
  }
  .pie:before {
    inset:0;
    background:
      radial-gradient(farthest-side,var(--c) 98%,#0000) top/var(--b) var(--b) no-repeat,
      conic-gradient(var(--c) calc(var(--p)*1%),#0000 0);
    -webkit-mask:radial-gradient(farthest-side,#0000 calc(99% - var(--b)),#000 calc(100% - var(--b)));
            mask:radial-gradient(farthest-side,#0000 calc(99% - var(--b)),#000 calc(100% - var(--b)));
  }
  .pie:after {
    inset:calc(50% - var(--b)/2);
    background:var(--c);
    transform:rotate(calc(var(--p)*3.6deg)) translateY(calc(50% - var(--w)/2));
  }
  .animate {
    animation:p 1s .5s both;
  }
  .no-round:before {
    background-size:0 0,auto;
  }
  .no-round:after {
    content:none;
  }
  @keyframes p {
    from{--p:0}
  }
</style>
</head>
<body>
<div id="container">
<div id="header">
<img src="https://baselinepolicy.blob.core.windows.net/templates/combined.png?sp=r&st=2024-04-22T16:52:28Z&se=2044-04-23T00:52:28Z&spr=https&sv=2022-11-02&sr=b&sig=auEM7hk0UhzrNgElb91nmfADzYk1BcGMtGnMNkTp7lE%3D" alt="EUCToolbox" width="50% height="50%">
</div>
<h1 class="heading-1">Report generated for $domain at $formattedDateTime</h1>
"@
##Get the CIS Data

$cistest = set-reportoutputapi -type "windowscis" -inputfile $list
$cishtml = $cistest[0]
$ciscount = $cistest[1]
$cistotal = $cistest[3]
$cispassed = $cistest[4]
##Get the NCSC Data
$ncsctest = set-reportoutputapi -type "windowsncsc" -inputfile $list
$ncschtml = $ncsctest[0]
$ncsccount = $ncsctest[1]
$ncsctotal = $ncsctest[3]
$ncscpassed = $ncsctest[4]
##Get the Android Data
$androidtest = set-reportoutputapi -type "android" -inputfile $list
$androidhtml = $androidtest[0]
$androidcount = $androidtest[1]
$androidtotal = $androidtest[3]
$androidpassed = $androidtest[4]
##Get the iOS Data
$iostest = set-reportoutputapi -type "ios" -inputfile $list
$ioshtml = $iostest[0]
$ioscount = $iostest[1]
$iostotal = $iostest[3]
$iospassed = $iostest[4]


##Output table with pass/fail count
$htmlsummary += "<h2>Summary</h2>"
$htmlsummary += "<table>"
$htmlsummary += "<tr><th>Platform</th><th>Count</th></tr>"
$htmlsummary += "<tr><td>Windows CIS</td><td>$ciscount</td></tr>"
$htmlsummary += "<tr><td>Windows NCSC</td><td>$ncsccount</td></tr>"
$htmlsummary += "<tr><td>Android</td><td>$androidcount</td></tr>"
$htmlsummary += "<tr><td>iOS</td><td>$ioscount</td></tr>"
$htmlsummary += "</table>"

##Add pie charts
$cispassrate = [math]::Round(($cispassed / $cistotal)*100)
$ncscpassrate = [math]::Round(($ncscpassed / $ncsctotal)*100)
$androidpassrate = [math]::Round(($androidpassed / $androidtotal)*100)
$iospassrate = [math]::Round(($iospassed / $iostotal)*100)


$htmlsummary += @"
<div class="pie" style="--p:$cispassrate;--c:lightgreen">CIS: $cispassrate%</div>
<div class="pie" style="--p:$ncscpassrate;--c:lightgreen">NCSC: $ncscpassrate%</div>
<div class="pie" style="--p:$androidpassrate;--c:lightgreen">Android: $androidpassrate%</div>
<div class="pie" style="--p:$iospassrate;--c:lightgreen">iOS: $iospassrate%</div>
"@


##Close the HTML
$htmlsummary += @"
</div>
</body>
</html>
"@

write-output "Generating HTML Report"
#The command below will generate the report to an HTML file
$pathhtmlsummary = "$folder\$tenant-intunereportsummary.html"
$htmlsummary | Out-File $pathhtmlsummary

    write-output "Report Generated"


##Full Report
write-output "Creating Intune Report"
##Create the basic html structure and CSS
$html = @"
<html>
<head>
<title>Baseline Report</title>
<style type="text/css">
/* Set default font family and color for entire page */
body {
    font-family: Arial, sans-serif;
    color: #333;
  }
  
  /* Style for main heading */
  .heading-1 {
    font-size: 2.5rem;
    margin: 2rem 0;
    color: #000000; /* blue */
    text-align: center;
  }
  
  /* Style for subheadings */
  h2 {
    font-size: 2rem;
    margin: 1.5rem 0;
    color: #202020; /* orange */
    text-align: center;
  }
  
  /* Style for sub-subheadings */
  h3 {
    font-size: 1.5rem;
    margin: 1rem 0;
    color: #333333; /* blue */
    text-align: center;
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
    background-color: #ff6633;
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
    color: #ff6633;
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
  @property --p{
    syntax: '<number>';
    inherits: true;
    initial-value: 0;
  }
  
  .pie {
    --p:20;
    --b:22px;
    --c:darkred;
    --w:150px;
    
    width:var(--w);
    aspect-ratio:1;
    position:relative;
    display:inline-grid;
    margin:5px;
    place-content:center;
    font-size:12px;
    font-weight:bold;
    font-family:sans-serif;
  }
  .pie:before,
  .pie:after {
    content:"";
    position:absolute;
    border-radius:50%;
  }
  .pie:before {
    inset:0;
    background:
      radial-gradient(farthest-side,var(--c) 98%,#0000) top/var(--b) var(--b) no-repeat,
      conic-gradient(var(--c) calc(var(--p)*1%),#0000 0);
    -webkit-mask:radial-gradient(farthest-side,#0000 calc(99% - var(--b)),#000 calc(100% - var(--b)));
            mask:radial-gradient(farthest-side,#0000 calc(99% - var(--b)),#000 calc(100% - var(--b)));
  }
  .pie:after {
    inset:calc(50% - var(--b)/2);
    background:var(--c);
    transform:rotate(calc(var(--p)*3.6deg)) translateY(calc(50% - var(--w)/2));
  }
  .animate {
    animation:p 1s .5s both;
  }
  .no-round:before {
    background-size:0 0,auto;
  }
  .no-round:after {
    content:none;
  }
  @keyframes p {
    from{--p:0}
  }
</style>
</head>
<body>
<div id="container">
<div id="header">
<img src="https://baselinepolicy.blob.core.windows.net/templates/combined.png?sp=r&st=2024-04-22T16:52:28Z&se=2044-04-23T00:52:28Z&spr=https&sv=2022-11-02&sr=b&sig=auEM7hk0UhzrNgElb91nmfADzYk1BcGMtGnMNkTp7lE%3D" alt="EUCToolbox" width="50% height="50%">
</div>
<h1 class="heading-1">Report generated for $domain at $formattedDateTime</h1>
<div id="contents">
<a id="top"></a>
<a href="#cis">Windows CIS</a> | <a href="#ncsc">Windows NCSC</a> | <a href="#android">Android</a> | <a href="#ios">IOS</a>
</div>
"@
##Add a header
$html += '<h1 class="heading-1">Baseline Report</h1>'

##Get the CIS Data

$cistest = set-reportoutputapi -type "windowscis" -inputfile $list
$cishtml = $cistest[0]
$ciscount = $cistest[1]
$cistotal = $cistest[3]
$cispassed = $cistest[4]
##Get the NCSC Data
$cistest = set-reportoutputapi -type "windowsncsc" -inputfile $list
$ncschtml = $ncsctest[0]
$ncsccount = $ncsctest[1]
$ncsctotal = $ncsctest[3]
$ncscpassed = $ncsctest[4]
##Get the Android Data
$cistest = set-reportoutputapi -type "android" -inputfile $list
$androidhtml = $androidtest[0]
$androidcount = $androidtest[1]
$androidtotal = $androidtest[3]
$androidpassed = $androidtest[4]
##Get the iOS Data
$cistest = set-reportoutputapi -type "ios" -inputfile $list
$ioshtml = $iostest[0]
$ioscount = $iostest[1]
$iostotal = $iostest[3]
$iospassed = $iostest[4]


##Output table with pass/fail count
$html += "<h2>Summary</h2>"
$html += "<table>"
$html += "<tr><th>Platform</th><th>Count</th></tr>"
$html += "<tr><td>Windows CIS</td><td>$ciscount</td></tr>"
$html += "<tr><td>Windows NCSC</td><td>$ncsccount</td></tr>"
$html += "<tr><td>Android</td><td>$androidcount</td></tr>"
$html += "<tr><td>iOS</td><td>$ioscount</td></tr>"
$html += "</table>"


##Add pie charts
$cispassrate = [math]::Round(($cispassed / $cistotal)*100)
$ncscpassrate = [math]::Round(($ncscpassed / $ncsctotal)*100)
$androidpassrate = [math]::Round(($androidpassed / $androidtotal)*100)
$iospassrate = [math]::Round(($iospassed / $iostotal)*100)


$html += @"
<div class="pie" style="--p:$cispassrate;--c:lightgreen">CIS: $cispassrate%</div>
<div class="pie" style="--p:$ncscpassrate;--c:lightgreen">NCSC: $ncscpassrate%</div>
<div class="pie" style="--p:$androidpassrate;--c:lightgreen">Android: $androidpassrate%</div>
<div class="pie" style="--p:$iospassrate;--c:lightgreen">iOS: $iospassrate%</div>
"@


##Output the CIS Data
$html += '<h2 id="cis">Windows CIS</h2> <a href="#top">Back to Top</a>'
##Add the pass/fail count
$html += "<h3>$ciscount</h3>"
##Add the tabulated data
$html += $cishtml
$html += "<hr>"

##Output the NCSC Data
$html += '<h2 id="ncsc">Windows NCSC</h2> <a href="#top">Back to Top</a>'
##Add the pass/fail count
$html += "<h3>$ncsccount</h3>"
##Add the tabulated data
$html += $ncschtml
$html += "<hr>"

##Output the Android Data
$html += '<h2 id="android">Android</h2> <a href="#top">Back to Top</a>'
##Add the pass/fail count
$html += "<h3>$androidcount</h3>"
##Add the tabulated data
$html += $androidhtml
$html += "<hr>"

##Output the iOS Data
$html += '<h2 id="ios">iOS</h2> <a href="#top">Back to Top</a>'
##Add the pass/fail count
$html += "<h3>$ioscount</h3>"
##Add the tabulated data
$html += $ioshtml


##Close the HTML
$html += @"
</div>
</body>
</html>
"@

write-output "Generating HTML Report"
#The command below will generate the report to an HTML file
$path = "$folder\$tenant-intunereport.html"
$html | Out-File $path


    write-output "Report Generated"



###############################################################################################################
######                                            PROCESS REPORTS                                        ######
###############################################################################################################

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

##Calculate total passrate
$totalpassrate = ($cispassrate + $ncscpassrate + $androidpassrate + $iospassrate) /4

if ($totalpassrate -ge 75) {
##Passed
$bodycontent = @"   
<html>
<head>
<style>
table, td, div, h1, p {font-family: Roboto, sans-serif;}
h1 {color: #EB5D2F}
         .responsive-image {
  height: 50px; /* Set the desired height */
  width: auto;   /* Automatically adjust the width to maintain aspect ratio */
  padding:5px;
}
</style>
</head>
<body>
Hello.
<br>
Here is how your Intune tenant compares to CIS and NCSC security baselines:
<br><br>
$htmlsummary
<br><br>
Everything looks good, and no significant changes are needed to your configuration!
<br><br>
Have you considered drift monitoring for your tenant to keep it running well?  You can find our solution <a href="https://manage.euctoolbox.com">here</a>
<br><br>
With thanks
<br><br>
EUC Toolbox from AndrewSTaylor.com
<br>
<p>Sponsored by: $footerhtml</p>

</body>
</html>
"@ 
}
else {
##Failed
$bodycontent = @"   
<html>
<head>
<style>
table, td, div, h1, p {font-family: Roboto, sans-serif;}
h1 {color: #EB5D2F}
         .responsive-image {
  height: 50px; /* Set the desired height */
  width: auto;   /* Automatically adjust the width to maintain aspect ratio */
  padding:5px;
}
</style>
</head>
<body>
Hello.
<br>
Here is how your Intune tenant compares to CIS and NCSC security baselines:
<br><br>
$htmlsummary
<br><br>
Your tenant doesn't meet the baselines!
<br><br><br>

<b>What can you do now?</b>
<br><br><br>
Start afresh by creating a new, fully CIS/NCSC compliant tenant using the <a href="https://deploy.euctoolbox.com">DeployIntune</a> tool. This tool provides a set of pre-curated Intune policies and can have you up and running in as little as 20 minutes, all for a fixed price.
<br><br>
Get the full tenant security report, which looks beyond Intune alone.
<br><br>
Subscribe to <a href="https://manage.euctoolbox.com">IntuneManage<a/>, a comprehensive multi-tenant Intune management portal that ensures your tenants remain secure.  
<br><br>
If you need assistance preparing and migrating your applications to Intune or want to know more about how an Intune-managed service can eliminate the headache of configuring, securing, and managing endpoints, please contact <a href="https://contact.euctoolbox.com">Us</a> today.
<br><br>
With thanks
<br><br>
EUC Toolbox from AndrewSTaylor.com
<br>
<p>Sponsored by: $footerhtml</br>

</body>
</html>
"@ 
}


$FileName=$path.name
$base64string = [Convert]::ToBase64String([IO.File]::ReadAllBytes($path))


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
            "subject" = " Intune Report Complete for $domain at $formattedDateTime"
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
            "filename"="$tenant-intunereport.html"
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



Disconnect-MgGraph
