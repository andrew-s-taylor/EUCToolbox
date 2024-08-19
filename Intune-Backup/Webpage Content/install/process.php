<?php

$server = $_POST['server'];
$username = $_POST['username'];
$password = $_POST['password'];
$database = $_POST['database'];
$email = $_POST['email'];
$encryption = $_POST['encryption'];
$webhookurl = $_POST['webhookurl'];
$webhooksecret = $_POST['webhooksecret'];
$appwebhookurl = $_POST['appwebhookurl'];
$driftwebhookurl = $_POST['driftwebhookurl'];




$url  = isset($_SERVER['HTTPS']) ? 'https://' : 'http://';
$url .= $_SERVER['SERVER_NAME'];
$url .= htmlspecialchars($_SERVER['REQUEST_URI']);
$themeurl = dirname(dirname($url)) . "/activate.php";

$your_data =
<<<EOD
<?php
// Your MySQL database hostname.
define('db_host','$server');
// Your MySQL database username.
define('db_user','$username');
// Your MySQL database password.
define('db_pass','$password');
// Your MySQL database name.
define('db_name','$database');
// Your MySQL database charset.
define('db_charset','utf8');
/* Registration */
// If enabled, the user will be redirected to the homepage automatically upon registration.
define('auto_login_after_register',true);
/* Account Activation */
// If enabled, the account will require email activation before the user can login.
define('account_activation',false);
// Change "Your Company Name" and "yourdomain.com" - do not remove the < and > characters.
define('mail_from','$email');
// The link to the activation file.
define('activation_link','$themeurl');
//Encryption key
define('encryption_key','$encryption');
//Webhook URL
define('webhook',"$webhookurl");
//App Webhook URL
define('appwebhook','$appwebhookurl');
//Drift Webhook URL
define('driftwebhook','$driftwebhookurl');
?>
EOD;

// Open the file and erase the contents if any
$fp = fopen("../config.php", "w");

// Write the data to the file
fwrite($fp, $your_data);

// Close the file
fclose($fp);


header("Location: dbcheck.php");
?>