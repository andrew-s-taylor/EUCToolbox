<?php
/**
 * This file is part of a GPL-licensed project.
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


$sitename = "App Deploy from EUC Toolbox";
$pagetitle = "App Deploy";
include "header.php";
?>

    <script>
      $(window).bind("load", function () {
        $('#work-in-progress').fadeOut(100);
    });
</script>
<?php
if (webhookcommunity == "COMMUNITYWEBHOOKHERE") {
    ?>
    <form action="update_config.php" method="post">
        <label for="webhookcommunity">Community Webhook:</label>
        <input type="text" id="webhookcommunity" name="webhookcommunity" required><br><br>
        
        <label for="webhookmanifest">Manifest Webhook:</label>
        <input type="text" id="webhookmanifest" name="webhookmanifest" required><br><br>
        
        <label for="appid">App ID:</label>
        <input type="text" id="eappid" name="eappid" required><br><br>
        
        <label for="appsecret">App Secret:</label>
        <input type="text" id="eappsecret" name="eappsecret" required><br><br>
        
        <label for="sendgridkey">SendGrid Key:</label>
        <input type="text" id="sendgridkey" name="sendgridkey" required><br><br>
        
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
   <h1>Welcome to App Deploy from EUC Toolbox</h1>
   <div class="step-container">
    <p>This free service will deploy Winget community applications directly into your tenant pre-configured</p>
    <p>Alternatively, you can use the second form to deploy custom Winget manifests, packaged into Win32 apps</p>
   <p>Please select your application from the list below.</p>
   <p>On clicking submit you will be prompted to approve our app registration and then your app will be deployed to your tenant</p>
   <p>If you want to be emailed on completion, add your email into the box</p>
   <p>For a full list of supported apps, click <a href="allapps.php">here</a></p>
   <p>We also have an API available, you can find out more <a href="https://euctoolbox.com/api-faq.php">here</a></p>
</div>
<h2>Winget Community App Deployment</h2>
   <form action="index.php" method="post">
    <input type="hidden" name="sent" value="confirm">
   <table class="styled-table">
    <tr><td colspan="2">
    <label for="appid">Select an app:</label>
<?php
$api_url = 'https://appdeploy.euctoolbox.com/api?distinct';

// Grab them via CURL
$curl = curl_init();
curl_setopt_array($curl, array(
    CURLOPT_URL => "$api_url",
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_ENCODING => '',
    CURLOPT_MAXREDIRS => 10,
    CURLOPT_TIMEOUT => 0,
    CURLOPT_FOLLOWLOCATION => true,
    CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
    CURLOPT_SSL_VERIFYHOST => false,
    CURLOPT_SSL_VERIFYPEER => true,
    CURLOPT_CUSTOMREQUEST => 'GET',
    CURLOPT_HTTPHEADER => array(
      'Content-Type: application/json'
    ),
  ));

// Initialize the cURL session
$result = curl_exec($curl);

// Decode the JSON output
$apps = json_decode($result, true);
//Sort alphabetically by appdisplayname
usort($apps, function($a, $b) {
    return $a['appdisplayname'] <=> $b['appdisplayname'];
});


    // Loop through the array and create the select dropdown
    echo "<select name='appid' id='appid'>";
//If sent is confirmed, add selected app as first option here
$confirmed = $_POST['sent'];
if ($confirmed == "confirm") {
    $appidsent = $_POST['appid'];
    $appdetails = explode("^", $appidsent);
    $appid = $appdetails[0];
    $appname = $appdetails[1];
    $appversion = $appdetails[2];
    echo "<option value='" . $appidsent . "'>" . $appname . " - " . $appversion . "</option>";
}

    foreach ($apps as $app) {
        //If appdisplayname is blank, set to appid
        if ($app['appdisplayname'] == "") {
            $app['appdisplayname'] = $app['appid'];
        }
        // Combine the appid and appname into a single value
        $value = $app['appid'] . "^" . $app['appdisplayname'] . "^" . $app['appversion'];

        echo "<option value='" . $value . "'>" . $app['appdisplayname'] . " - " . $app['appversion'] . "</option>";
    }
    echo "</select>";

?>
</td>
</tr>
    <tr><td class="tableButton" colspan="2" align="center"><input class="profile-btn" type="submit" value="Show Details"></td></tr>
    </form>
    </table>

<?php
$confirmed = $_POST['sent'];
if ($confirmed == "confirm") {
    $appidsent = $_POST['appid'];
    $appdetails = explode("^", $appidsent);
    $appid = $appdetails[0];
    $appname = $appdetails[1];
    $appversion = $appdetails[2];
    ?>


    <h2>App Details</h2>
    <table class="styled-table">
    <tr>
        <td colspan="2">
            <h2>App Details</h2>
            <?php
//Use the api to grab apps
$api_url = "https://appdeploy.euctoolbox.com/api?app=$appID&appversion=$appversion";

// Grab them via CURL
$curl = curl_init();
curl_setopt_array($curl, array(
    CURLOPT_URL => "$api_url",
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_ENCODING => '',
    CURLOPT_MAXREDIRS => 10,
    CURLOPT_TIMEOUT => 0,
    CURLOPT_FOLLOWLOCATION => true,
    CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
    CURLOPT_SSL_VERIFYHOST => false,
    CURLOPT_SSL_VERIFYPEER => true,
    CURLOPT_CUSTOMREQUEST => 'GET',
    CURLOPT_HTTPHEADER => array(
      'Content-Type: application/json'
    ),
  ));

// Initialize the cURL session
$result = curl_exec($curl);

// Decode the JSON output
$apps = json_decode($result, true);

foreach ($apps as $app){
                // Display the app details in a table
                echo "<table>";
                echo "<tr><td>App ID:</td><td>" . $app['appid'] . "</td></tr>";
                echo "<tr><td>App Description:</td><td>" . $app['appdescription'] . "</td></tr>";
                echo "<tr><td>App Version:</td><td>" . $app['appversion'] . "</td></tr>";
                echo "<tr><td>App Scope:</td><td>" . $app['appscope'] . "</td></tr>";
                echo "<tr><td>App Display Name:</td><td>" . $app['appdisplayname'] . "</td></tr>";
                echo "<tr><td>App Publisher:</td><td>" . $app['apppublisher'] . "</td></tr>";
                echo "<tr><td>App Silent Command:</td><td>" . $app['appsilent'] . "</td></tr>";
                echo "<tr><td>App URL:</td><td>" . $app['apppackage'] . "</td></tr>";
                echo "<tr><td>App Architecture:</td><td>" . $app['apparchitecture'] . "</td></tr>";
                echo "<tr><td>App Info:</td><td>" . $app['appinfourl'] . "</td></tr>";
                echo "<tr><td>App Developer:</td><td>" . $app['appdeveloper'] . "</td></tr>";
                echo "<tr><td>App Owner:</td><td>" . $app['appowner'] . "</td></tr>";
                echo "</table>";
            }
            ?>
        </td>
    </tr>
</table>
<form action="processapp.php" method="post">
    <input type="hidden" name="appid" value="<?php echo $appidsent; ?>">
   <table class="styled-table">
	   <tr><td colspan="2">	   <label for="checkbox">Custom Group Name?:</label>
    <input type="checkbox" id="checkbox" name="grpcheck" onchange="toggleTextField()">
    <div id="textfield" style="display: none;">
        <label for="text">Install Group Name:</label>
        <input type="text" id="installgroupname" name="installgroupname">
		<br>
		<label for="text">Uninstall Group Name:</label>
        <input type="text" id="uninstallgroupname" name="uninstallgroupname">
    </div>
    <script>
        function toggleTextField() {
            var checkbox = document.getElementById("checkbox");
            var textfield = document.getElementById("textfield");
            if (checkbox.checked) {
                textfield.style.display = "block";
            } else {
                textfield.style.display = "none";
            }
        }
    </script></td></tr>
        	   <tr><td colspan="2">	   <label for="checkbox">Make Available for users?:</label>
    <input type="checkbox" id="checkbox" name="useravailable">
</td></tr>
<tr>
<td colspan="2">	   <label for="checkbox">Make Available for devices?:</label>
    <input type="checkbox" id="checkbox" name="deviceavailable">
</td>
</tr>
<tr>
    <tr></tr>
        <td colspan="2">
            <label for="email">Email Address: (Optional, to be told when app is deployed)</label>
            <input type="email" id="email" name="email">
        </td>
    </tr>
</tr>
    <tr><td class="tableButton" colspan="2" align="center"><input class="profile-btn" type="submit" value="Deploy to Intune"></td></tr>
    </form>
    </table>
    <table class="styled-table">
        <tr><td>
    <form action="process-rimo3.php" method="post">        
        <input type="hidden" name="appid" value="<?php echo $appid; ?>">
        <input class="profile-btn" type="submit" value="Deploy to Rimo3">
    </form>
    </td></tr>
    </table>
                
<?php
}
?>
    <h2>Winget Custom Manifest deployment</h2>
   <form action="redirector.php" method="post">
    <input type="hidden" name="appdeploytype" value="manifest">
   <table class="styled-table">
<tr>
    <td>
    <label for="installgroupname">Manifest URL (YAML File, publicly accessible)</label>
            <input type="installgroupname" id="installgroupname" name="installgroupname">
    </td>
</tr>
    <tr>
        <td>
            <label for="email">Email Address: (Optional, to be told when app is deployed)</label>
            <input type="email" id="email" name="email">
        </td>
    </tr>
</tr>
    <tr><td class="tableButton" align="center"><input class="profile-btn" type="submit" value="Next"></td></tr>
    </form>
    </table>
    <?php
}
?>
    </div>
            
    
               <!-- Script -->
               <script>
        $(document).ready(function(){
            
            // Initialize select2
            $("#appid").select2();

            // Read selected option
            $('#but_read').click(function(){
                var username = $('#selUser option:selected').text();
                var userid = $('#selUser').val();
           
                $('#result').html("id : " + userid + ", name : " + username);
            });
        });
        </script>
<?php
include "footer.php";
?>