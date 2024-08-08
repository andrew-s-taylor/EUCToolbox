<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN"
    "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
<link rel="stylesheet" href="install.css" type="text/css">
</head>
<body>
<div id="container">
<div class="content2">
<div id="installbox">

<div id="installtitle">
<h5>Database Settings</h5>
<?php
if (isset($_GET['error'])) {
$error = $_GET['error'];
if ($error == "link") {
echo "Error - Could not connect to the database, please check your settings and try again";
}
if ($error == "conn") {
echo "Error - Could not connect to the database, please check your settings and try again";
}
}
?>
</div>
<div id="installleft">
<form method="post" action="process.php" enctype="multipart/form-data">
<table>
  <tr>
    <td>Server</td>
    <td>
    <input name="server"></td>
    <td>Usually localhost</td>
  </tr>
  <tr>
    <td>Username</td>
    <td>
    <input name="username"></td>
    <td>Your Database Username</td>
  </tr>
  <tr>
    <td>Password</td>
    <td>
    <input name="password"></td>
    <td>Your Database Password</td>
  </tr>
  <tr>
    <td>Database Name</td>
    <td>
    <input name="database"></td>
    <td>Your Database Name</td>
  </tr>
  <tr>
    <td>From Email</td>
    <td>
    <input name="email"></td>
    <td>Your Reply to Address</td>
  </tr>
  <tr>
    <td>Encryption Key</td>
    <td>
    <input name="encryption"></td>
    <td>Your Encryption Key for storing secrets</td>
  </tr>
  <tr>
    <td>Webhook URL</td>
    <td>
    <input name="webhookurl"></td>
    <td>Webhook URL</td>
  </tr>
  <tr>
    <td>Webhook Secret</td>
    <td>
    <input name="webhooksecret"></td>
    <td>Secret Set in Webhook</td>
  </tr>
  <tr>
    <td>App Webhook URL</td>
    <td>
    <input name="appwebhookurl"></td>
    <td>App Webhook URL</td>
  </tr>
  <tr>
    <td>Drift Webhook URL</td>
    <td>
    <input name="driftwebhookurl"></td>
    <td>Drift Webhook URL</td>
  </tr>
</table>
</div>
<div id="installright">
<input type="submit" value="        Next        "> </form>
<FORM METHOD="LINK" ACTION="index.php">
<input type="submit" value="        Back        "> </FORM>
</div>
</div>

</div>
 </div>
</div>
 </body>