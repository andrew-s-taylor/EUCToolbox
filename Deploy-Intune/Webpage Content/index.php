<?php
/* This file is part of a GPL-licensed project.
 *
 * Copyright (C) 2024 Andrew Taylor (andrew.taylor@andrewstaylor.com)
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
include('config.php');

?>

<?php
$sitename = "DeployIntune from EUC Toolbox";
$pagetitle = "DeployIntune";
include "header.php";
if (webhook == "WEBHOOKHERE") {
  ?>
  <form action="update_config.php" method="post">
      <label for="webhook">Webhook:</label>
      <input type="text" id="webhook" name="webhook" required><br><br>
      
      <label for="appid">App ID:</label>
      <input type="text" id="eappid" name="eappid" required><br><br>
      
      <label for="appsecret">App Secret:</label>
      <input type="text" id="eappsecret" name="eappsecret" required><br><br>

      <label for="sendgridtoken">Sendgrid Token:</label>
      <input type="text" id="sendgridtoken" name="sendgridtoken" required><br><br>
      
      <input type="submit" value="Update Config">
  </form>

  <?php
}
else {
?>

    <form action="setup-process.php" enctype="multipart/form-data" method="post">
        <div class="form">

            <div class="title">Welcome</div>
            <div class="subtitle">Instructions</div>
<p>After clicking next, you will be taken to a form to setup your Intune tenant</p>
<ol>
  <li>The first field is your Company Name, this is just used for identification and adds a registry key on the device with the build information</li>
  <li>After this, please enter an email address.  This is the email address your Breakglass account details will be sent to on completion</li>
  <li>The homepage field is a web URL (typically starting https://) which will be set as the default homepage in Microsoft Edge browser.</li>
  <li>Company Size has no impact on the deployment</li>
  <li>Entering a prefix will add it before all policies and Entra groups.  If left blank, it will default to "ID"</li>
  <li>In the upload field, please add an image to be used as the desktop wallpaper/background on your Windows devices
    <br>
    This can be changed after deployment if required
  </li>
  <li>If this is a fresh environment, enabling the chechbox will create automated Entra groups to automatically add users based on license and Autopilot devices to all profiles
    <br>
    If this is an existing environment, leave unchecked and the policies will be assigned to static groups to avoid clashes.
  </li>
  <li>You can also toggle to deploy Conditional Access policies.  If you do not have these already, they add an extra layer of security to your tenant.
  <p>Conditional access policies are switched off by default to avoid impacting your environment and are available for you to review and enable</p>
<p>For more information about Conditional Access, please visit the Microsoft documentation <a href="https://learn.microsoft.com/en-us/entra/identity/conditional-access/overview">here</a></p>
  </li>
</ol>
  <p>After clicking the Submit button, our systems will deploy your environment in the background.  This will usually take around 15 minutes</p>
  <p>You will receive an email upon completion confirming your account details</p>

            <button type="text" class="profile-btn">Next</button>
          </div>
                    </div>
                    </form>
 <?php
 }
include "footer.php";
?>