<?php
/**
 * This file is part of a GPL-licensed project.
 *
 * Copyright (C) 2024 Andrew Taylor (andrew.taylor@andrewstaylor.com)
 * A special thanks to David at Codeshack.io for the basis of the login system!
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://github.com/andrew-s-taylor/public/blob/main/LICENSE>.
 */
?>
<?php
include 'main.php';
// Check logged-in
check_loggedin($con);
// output message (errors, etc)
$msg = '';
?>
<style>
a {
	color: #EB5D2F;
	font-size:14px;
}
</style>
<?php
$sitename = "Intune Manager from EUC Toolbox";
$pagetitle = "Intune Manager";
include "header1.php";

?>

			<h2>Getting Started</h2>
			
			<div class="block">
			<h1 id="top">Congratulations on setting up your account, here are some tips to make the most of the system.</h1>
            <h2>Table of Contents</h2>
            <ol>
                <li><a href="#setup-gold-tenants">Setup Gold Tenant(s)</a></li>
                <li><a href="#profile">Profile</a></li>
                <li><a href="#onboard-tenant">Onboard a Tenant</a></li>
                <li><a href="#run-backup">Run a Backup</a></li>
                <li><a href="#restore-policies">Restore Policies</a></li>
                <li><a href="#manage-backups">Managing Backups</a></li>
                <li><a href="#check-drift">Checking Drift</a></li>
                <li><a href="#manage-tenants">Managing Tenants</a></li>
                <li><a href="#gold-tenant">Gold Tenant</a></li>
                <li><a href="#daily-checks">Daily Checks</a></li>
                <li><a href="#security-checks">Security Checks</a></li>
                <li><a href="#deploy-apps">Deploying Apps</a></li>
                <li><a href="#deploy-templates">Deploying Templates</a></li>
                <li><a href="#tenant-migration">Tenant Migration</a></li>
                <li><a href="#api">API Usage</a></li>
            </ol>
    <h1 id="setup-gold-tenants">Setup Gold Tenant(s) <a href="profile-select.php">(Profile Page)</a> | <a href="#top">Top</a></h1>
    <p>First, we need a gold tenant to use as a baseline to compare your customers against. This isn't a strict requirement, but without it you can only monitor in-tenant drift rather than comparing to your baseline. We can also use this tenant for deploying policies and creating templated deployments. You can have one gold tenant for all customers, or different ones, depending on your own requirements.</p>
    <p><strong>Note:</strong> The gold tenant does not count in your tenant count for licensing.</p>
	
    
    <p>The first step is to register the application in the tenant. Click on Manage Tenants and then click the Onboard button. After completing you will be returned to the tenant screen. If you want to add the gold tenant as a standard tenant as well, you can do so here.</p>
<img src = "images/onboard.jpg" alt = "Onboard">
    <p>Then navigate back to Profile and add the tenant ID for your golden tenant against you and any applicable customer accounts, more on those next.</p>
	<img src = "images/update-golden.jpg" alt = "Gold Tenant">
    <h1 id="profile">Profile <a href="profile-select.php">(Profile Page)</a> | <a href="#top">Top</a></h1>
    <p>Here you can configure your golden tenant and permissions on your account as well as:</p>
    
    <h2>Add a customer</h2>
    <p>Within the profile page, you have the "Add new customer" button where you can add customers within your account who can have their own login details with restricted access, you set what they can and cannot do.</p>
    <p>To add a new customer, click Profile and press the "Add new customer" button. Here you can set their login details as well as where to store the files and the golden tenant (these can be the same as your account). You can also configure what aspects of the portal they can manage.</p>
    <p>You will have access to all of your customers within the portal, but customer accounts are restricted to only tenants assigned to them.</p>
<img src = "images/add-customer.jpg" alt = "Add Customer">
    <h2>Add new admin</h2>
    <p>You will no doubt have other staff in your organization who need to access the portal and obviously you don't want to share logins! Here you can create new admin accounts and as with the customers, you can specify exactly what they can do. If you just want read-only access to reports, that's not an issue at all, simply check the correct boxes.</p>
    <p>As with the main admin account, any admin account has access to all customer tenants.</p>
<img src = "images/add-admin.jpg" alt = "Add Admin">
    <h2>Edit/Delete accounts</h2>
    <p>You have full control to both edit and delete both customer and admin accounts (including yours if required).</p>
<img src = "images/delete-account.jpg" alt = "Delete">
<img src = "images/edit-profile.jpg" alt = "Edit">
    <h1>Onboard a tenant <a href="tenants.php">(Tenants Page)</a> | <a href="#top">Top</a></h1>
    <p>We are now ready to onboard our first customer tenant. First, click the Onboard button and add the app reg into the tenant by logging in with an account with the appropriate elevated rights. You will then be redirected back to the Manage Tenants page with the tenant ID pre-filled. Add a name to remember the tenant and select the customer to assign it to (if you don't want customers to access anything, assign them to your account). Then simply click Add.</p>
	<img src = "images/onboard.jpg" alt = "Onboard">

    <h1 id="run-backup">Run a backup <a href="backup.php">(Backup page)</a> | <a href="#top">Top</a></h1>
    <p>One of the reasons for using this platform, we need to create our first backup. The latest backup will also be used to monitor for in-tenant drift.</p>
    <p>To run a backup, simply click Backup, select the tenant(s) and press the button, yes, you can select multiple tenants at once.</p>
    <p>At present, backups have to be manually triggered so you have better control and it makes changes easier to track. If the backups ran daily and a breaking change happened, you may find yourself having to test multiple backups to find the original setting.</p>
<img src = "images/backup.jpg" alt = "Backup">
    <h1 id="restore-policies">Restore policies <a href="restore.php">(Restore page)</a> | <a href="#top">Top</a></h1>
    <p>In an ideal world, an option you will hopefully not need, but accidents happen. Within here you can restore policies from a previous backup for that tenant.</p>
    <p>Select the tenant you wish to restore to, then select the backup to restore from and click Deploy to Tenant. You will then be presented with all of the items in the backup, select those to restore. If wanted, you can also tick the box to restore policy assignments and optionally create any assignment groups if they cannot be found on the tenant (note: it only creates static groups).</p>
    <p>If you are restoring groups and policies, the system will restore groups first so if you have selected to restore assignments, it will find the newly restored group and assign accordingly (the group ID does not have to match).</p>
    <p>Once selected, click Restore and the policy will re-appear within minutes.</p>
<img src = "images/restore-select.jpg" alt = "Restore">
<img src = "images/restore-1.jpg" alt = "Restore">
<img src = "images/restore-button.jpg" alt = "Restore">
    <h1 id="manage-backups">Managing Backups <a href="manage-backups1.php">(Manage Backups page)</a> | <a href="#top">Top</a></h1>
    <p>Whilst there is no limit to the number of backups stored, or any cost for storage, you can use this menu to remove backups if required. Whilst there is some central backup of files, we cannot guarantee we can restore deleted backups.</p>
<img src = "images/manage-backups.jpg" alt = "Manage Backups">
    <h1 id="check-drift">Checking drift <a href="check-drift.php">(Check Drift page)</a> | <a href="#top">Top</a></h1>
    <p>This is where you can fully monitor your tenant for any changes (by anyone). Each night at 12am - 1am (Zulu), your tenants will be compared against:</p>
    <ol>
        <li>The last backup taken</li>
        <li>The golden tenant's last backup</li>
    </ol>
	<img src = "images/check-drift.jpg" alt = "Drift">
    <p>You also have the ability to run an ad-hoc drift check against any of your tenants.</p>
	<img src = "images/manual-drift-check.jpg" alt = "Drift">
    <p>If a change is detected, you will be alerted via email and then you can access the portal to view. It will display the changed policy as well as the values which have been amended.</p>
    <p>For an in-tenant change, you can acknowledge the change by simply running a fresh backup, or you can revert by clicking the button.</p>
<img src = "images/acknowledge-local.jpg" alt = "Drift">
<img src = "images/drift-revert-local.jpg" alt = "Drift">
    <p>For a change against the golden tenant you can:</p>
    <ol>
        <li>Revert the change - Either update or delete the policy</li>
        <li>Acknowledge the change - This adds to a database of approved changes which will no longer alert. These can be managed and removed afterwards for temporary acknowledgements.</li>
    </ol>

    <p>If the change is at the tenant and you wish to add this to your gold tenant, this is also an option.</p>
	<img src = "images/gold-drift.jpg" alt = "Drift">
    <h1 id="manage-tenants">Managing tenants <a href="tenants.php">(Tenants Page)</a> | <a href="#top">Top</a></h1>
    <p>This menu is where you can add, update or delete tenants from your account. You can also change the display name and customer assigned as required.</p>
<img src = "images/update-tenant.jpg" alt = "Manage Tenants">
    <h1 id="gold-tenant">Gold Tenant <a href="gold-select.php">(Gold Tenant page)</a> | <a href="#top">Top</a></h1>
    <p>Within here you have three options:</p>

    <h2>Backup</h2>
    <p>This creates a backup of your gold tenant, similar to just running from the backup menu, but pre-populates the tenant details.</p>
<img src = "images/backup-gold.jpg" alt = "Gold Backup">
    <h2>Deploy Policies</h2>
    <p>One of the advantages of configuring a gold tenant is a single source for policy deployment. By clicking onto the Gold tenant menu, you can deploy selected policies to any or all of your customer tenants in a few short clicks. It uses the same functionality as the single tenant restore so is simply a case of selecting the policies to restore and assignments if required. Then select the tenant(s) to deploy to and your policies will appear within a matter of minutes. Any hard-coded tenant IDs in the policy details (such as OneDrive) will be automatically converted to the destination tenant ID during restoration.</p>
<img src = "images/deploy-gold.jpg" alt = "Gold Deploy">
    <h2>Creating templates</h2>
    <p>Deploying policies from the gold tenant is an excellent approach for incremental changes, but you may have a bulk set of policies you need to apply to one or more tenants, onboarding new customers for example. It follows a similar process to restoring policies, but when selecting, you can enter a name for the template and rather than deploying the policies, it creates a template file which you can then deploy to other tenants (more on that later).</p>
	<img src = "images/deploy-gold.jpg" alt = "Gold Deploy">
    <h1 id="daily-checks">Daily Checks <a href="daily-select.php">(Daily checks page)</a> | <a href="#top">Top</a></h1>
    <p>Each day at 12:00am (Zulu) your tenant is checked and reported on. This report includes:</p>
    <ul>
        <li>Updated applications</li>
        <li>Admin alerts</li>
        <li>License Count</li>
        <li>Licenses assigned to old users</li>
        <li>Microsoft Secure Score</li>
        <li>Your non-compliant devices</li>
        <li>Any unused Windows 365 devices</li>
        <li>Devices with the firewall disabled</li>
        <li>Any AV or Malware alerts</li>
        <li>Outdated Windows devices</li>
        <li>Outdated feature update policies</li>
        <li>Failed Signins</li>
        <li>Failed app installs</li>
        <li>App Protection Issues</li>
        <li>Outstanding security tasks</li>
        <li>Expiring Apple Certificates</li>
        <li>Expiring App registration secrets</li>
        <li>Stale devices in Entra</li>
    </ul>
    <p>As well as being sent to you by email, you can view the daily check for any of your tenants in the menu with the option to export as a PDF. You can delegate RBAC permissions to view these reports and nothing else if required.</p>
<img src = "images/daily-check.jpg" alt = "Daily Check">
    <h1 id="security-checks">Security Checks <a href="security-select.php">(Security Checks Page)</a> | <a href="#top">Top</a></h1>
    <p>Similar to the daily checks, this nightly task checks all of your tenants against NCSC and CIS baselines to add to the Microsoft Secure Score from the daily checks. It lists all compliant and non-compliant settings and the severity of them. This is a useful tool when reviewing any new customers.</p>

    <h1 id="deploy-apps">Deploying Apps <a href="listapps.php">(Deploy apps page)</a> | <a href="#top">Top</a></h1>
    <p>Using the Winget community repository, from this menu you can deploy applications to your tenant(s). Simply select the application and specify if you want custom install groups (default is Application Name - Install/Uninstall) as well as if you would like the application to be available for self-service. Once selected, pick the tenant(s) and deploy. The application will package into a win32 application and deploy to the tenant. If licensed, it will also deploy a proactive remediation to keep the application updated.</p>
<img src = "images/deploy-app.jpg" alt = "Deploy App">
    <h1 id="deploy-templates">Deploying Templates <a href="deploydemo.php">(Deploy Templates page)</a> | <a href="#top">Top</a></h1>
    <p>As covered in the Gold menu, this option is where you can deploy your pre-configured templates to your tenant(s). Simply select the template to deploy and the tenant to deploy to. We have also included our own "getting started" baseline as well as the OpenIntuneBaseline (<a href="https://github.com/SkipToTheEndpoint/OpenIntuneBaseline">https://github.com/SkipToTheEndpoint/OpenIntuneBaseline</a>). When deploying a custom template, any hard-coded tenant IDs from the source tenant will be automatically converted to the destination tenant.</p>
<img src = "images/deploy-template.jpg" alt = "Deploy Template">
    <h1 id="tenant-migration">Tenant Migration <a href="migrate.php">(Migrate Page)</a> | <a href="#top">Top</a></h1>
    <p>Migrating M365 tenants is a difficult task with many moving pieces. There are numerous tools for users, mailboxes, files etc. but very few (if any) for Intune configuration. Using this menu, you can bulk migrate from one tenant to another. It supports initial migration to move the policies over and then incremental migration to add/update/delete any policies prior to cut-over. All hard-coded tenant IDs will automatically be updated to the destination tenant.</p>
    <p>A migration does not offer the option to create groups as this is designed to be used alongside an identity migration tool so it is assumed the groups have already been migrated.</p>
    <p><strong>Please note:</strong> Your machines will still either need rebuilding, or manually migrating using third party tools, such as the migration script from GetRubix (<a href="https://github.com/stevecapacity">https://github.com/stevecapacity</a>).</p>
<img src = "images/migrate.jpg" alt = "Tenant Migration">

<h1 id="api">API Usage | <a href="#top">Top</a></h1>
    <p>An API is available at https://manage.euctoolbox.com/api with the following options currently available:</p>
    <ul>
        <li>Grab tenant details for all tenants (drift, gold drift and details from daily checks) - https://manage.euctoolbox.com/api?action=getall</li>
        <li>Grab tenant details for single tenant (drift, gold drift and details from daily checks) - https://manage.euctoolbox.com/api?action=singletenant&tenantid=TENANT_ID</li>
        <li>Show audit events - https://manage.euctoolbox.com/api?action=auditlog</li>
        <li>Trigger a backup (single tenant) - https://manage.euctoolbox.com/api?action=backup&tenantid=TENANT_ID</li>

    </ul>
            <p>To connect to the API, you need the API key which is available in the primary administrators profile page.  There is also a button to rotate the key</p>
            <p>The header required is called "X-Api-Key"</p>
			</div>
            
	
			<?php
include "footer.php";
?>