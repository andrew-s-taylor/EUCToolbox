<?php
include('config.php');
$sitename = "Daily Checks from EUC Toolbox";
$pagetitle = "Daily Checks";
include "header.php";
?>


<?php

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

        <label for="templatepath">HTML Template URL:</label>
        <input type="text" id="templatepath" name="templatepath" required><br><br>
        
        <input type="submit" value="Update Config">
    </form>

    <?php
}
else {
//Check for any POST messages and if found, display them
if (isset($_GET['message'])) {
    $message = $_GET['message'];
    echo "<div class='alert alert-success' role='alert'>$message</div>";
}
?>   
      <h1>Welcome to Daily Checks from EUC Toolbox</h1>
      <div class="step-container">
   <p>This service will send you an email every day with the following information for FREE!</p>
    <ul>
        <li>Updated applications</li>
        <li>Admin alerts</li>
        <li>License Count</li>
        <li>Licenses assigned to old users (90 days)</li>
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
   <p>Simply enter your email and tenant ID and click submit</p>
</div>
<form action="process.php" method="post">
    <table class="styled-table">
        <tr>
            <td>Email Address:</td>
            <td><input type="email" name="email" id="email" required></td>
</tr>
<tr>
<td>Tenant ID:</td>
<td><input type="text" name="tenant" id="tenant" required></td>
</tr>
<tr>
            <td class="tableButton"><input class="profile-btn" type="submit" value="Submit"></td>
        </tr>
    </table>
</form>
<?php
}
?>
<script>
    // JavaScript logic to check email format
    var emailInput = document.getElementById('email');
    emailInput.addEventListener('input', function() {
        var email = emailInput.value;
        var emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            emailInput.setCustomValidity('Please enter a valid email address');
        } else {
            emailInput.setCustomValidity('');
        }
    });
</script>
                
    </div>
            
    
<?php
include "footer.php";
?>