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

$server = $_POST['server'];
$username = $_POST['username'];
$password = $_POST['password'];
$database = $_POST['database'];
$email = $_POST['email'];
$webhookurl = $_POST['webhookurl'];
$webhooksecret = $_POST['webhooksecret'];
$appwebhookurl = $_POST['appwebhookurl'];
$driftwebhookurl = $_POST['driftwebhookurl'];
$dailywebhookurl = $_POST['dailywebhookurl'];
$securitywebhookurl = $_POST['securitywebhookurl'];
$encryption = bin2hex(openssl_random_pseudo_bytes(16));
$domainname = $_POST['domainname'];
$appid = $_POST['appid'];
$appsecret = $_POST['appsecret'];
$fullgittoken = $_POST['gittoken'];
$gittype = "github";
$gitowner = $_POST['gitowner'];
$sendgridtoken = $_POST['sendgridtoken'];
$gitorg = $_POST['gitorg'];





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
    //DailyChecks Webhook URL
define('dailywebhook','$dailywebhookurl');
    //Security Checks Webhook URL
define('securitywebhook','$securitywebhookurl');
define('appID','$appid');
define('appSecret','$appsecret');
define('fullgittoken', '$fullgittoken');
define('gittype','github');
define('gitowner','$gitowner');
define('sendgridtoken', '$sendgridtoken');
define('gitorg', '$gitorg');
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