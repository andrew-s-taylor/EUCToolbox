# EUCToolbox
# Instructions for Use

# Scripted Deployment

First you will need an app-reg with the appropriate permissions which can be created by running "create-app-reg.ps1"
[create-app-reg.ps1](https://raw.githubusercontent.com/andrew-s-taylor/EUCToolbox/refs/heads/main/Intune-Manage/Install%20Scripts/create-app-reg.ps1)
  Make a note of the client ID and secret, you will need these later
  When prompted for a domain, enter the domain name where the app will be hosted, this will populate the redirect URI

Second you want to deploy the resources to Azure by clicking this link:
[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fandrew-s-taylor%2FEUCToolbox%2Fmain%2FIntune-Manage%2FInstall%2520Scripts%2Farm-template.json)

Fill in the required details and it will create runbooks and an app service with the web page content.  
The runbook script content will be automatically populated, but if you want to start with a forked version, update accordingly.  
When it is complete, click on Outputs and make a note of the details.  
![alt text](https://euctoolbox.com/images/outputs-image.jpg)  

Finally, navigate to your new app service website and you will be prompted to enter the details recorded earlier.  


Add these and you are now up and running

  
# Manual Deployment

App Reg:
1) Create a new App Registration (multi-tenant if required) and make a note of the Application (client) ID
2) Add the redirect URIs to Microsoft default values:
- https://{DOMAINNAME}/processor.php
3) Add these API permissions (all Application type):
- AppCatalog.ReadWrite.All
- DeviceManagementApps.ReadWrite.All
- DeviceManagementConfiguration.ReadWrite.All
- DeviceManagementManagedDevices.ReadWrite.All
- DeviceManagementRBAC.ReadWrite.All
- DeviceManagementServiceConfig.ReadWrite.All
- Directory.ReadWrite.All
- Domain.ReadWrite.All
- Group.ReadWrite.All
- GroupMember.ReadWrite.All
- Policy.Read.All
- Policy.ReadWrite.ConditionalAccess
- Policy.ReadWrite.PermissionGrant
- Policy.ReadWrite.SecurityDefaults
- RoleManagement.ReadWrite.Directory
- CloudPC.ReadWrite.All
- AuditLog.Read.All
4) Click on Certificates and secrets and create a new secret.  Make a note of the secret value

Runbooks:
1) Create a new automation account and add these modules to it:
- Microsoft.Graph.Devices.CorporateManagement
- Microsoft.Graph.Groups
- Microsoft.Graph.DeviceManagement
- Microsoft.Graph.Authentication
- Microsoft.Graph.Identity.Signins
2) Create a runbook for the backup/restore script, run on Azure, PowerShell v5.1
3) Paste this script into the content:
[intune-backup-restore-withgui.ps1](https://raw.githubusercontent.com/andrew-s-taylor/EUCToolbox/main/Manage-Intune/Runbook%20Script/intune-backup-restore-withgui.ps1)
4) Publish it
5) Click Webhooks and create a new webhook.  Don't populate any of the fields, they are passed from the application itself.
6) Make a note of the URI, it will not display again after leaving the page.
7) Create a second runbook following the same process for this drift monitoring using this script:
[monitor-drift.ps1](https://raw.githubusercontent.com/andrew-s-taylor/EUCToolbox/main/Manage-Intune/Runbook%20Script/monitor-drift.ps1)


Web Service
1) Create an Azure App Service running PHP (latest version), or you can use any other web hosting facilities
2) Copy the contents of this directory into the root:
[Webpage Content](https://github.com/andrew-s-taylor/EUCToolbox/tree/main/Manage-Intune/Webpage%20Content)
3) Navigate to the new URL and add /install to the URL
4) Complete the steps to setup the environment

Logic App for Drift Cron job
1) Create a new logic app using the designer
2) Set the trigger to be Recurrence at the date/time/frequency required
3) Add an HTTP action sending a POST request to the website URL "/cron.php"


