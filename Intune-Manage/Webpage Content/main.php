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
// The main file contains the database connection, session initializing, and functions, other PHP files will depend on this file.
// Include the configuration file
@include_once dirname( __FILE__ ) . '/config.php';
// We need to use sessions, so you should always start sessions using the below function
session_start();
// Connect to the MySQL database using MySQLi
$con = mysqli_connect(db_host, db_user, db_pass, db_name);
// If there is an error with the MySQL connection, stop the script and output the error
if (mysqli_connect_errno()) {
	exit('Failed to connect to MySQL: ' . mysqli_connect_error());
}
// Update the charset
mysqli_set_charset($con, db_charset);
// The below function will check if the user is logged-in and also check the remember me cookie
function check_loggedin($con, $redirect_file = 'index.php') {
	// If you want to update the "last seen" column on every page load, you can uncomment the below code
	/*
	if (isset($_SESSION['loggedin'])) {
		$date = date('Y-m-d\TH:i:s');
		$stmt = $con->prepare('UPDATE accounts SET last_seen = ? WHERE id = ?');
		$stmt->bind_param('si', $date, $id);
		$stmt->execute();
		$stmt->close();
	}
	*/
	// Check for remember me cookie variable and loggedin session variable
    if (isset($_COOKIE['rememberme']) && !empty($_COOKIE['rememberme']) && !isset($_SESSION['loggedin'])) {
    	// If the remember me cookie matches one in the database then we can update the session variables.
    	$stmt = $con->prepare('SELECT id, email, role FROM accounts WHERE rememberme = ?');
		$stmt->bind_param('s', $_COOKIE['rememberme']);
		$stmt->execute();
		$stmt->store_result();
		// If there are results
		if ($stmt->num_rows > 0) {
			// Found a match, update the session variables and keep the user logged-in
			$stmt->bind_result($id, $username, $role);
			$stmt->fetch();
            $stmt->close();
			// Regenerate session ID
			session_regenerate_id();
			// Declare session variables; authenticate the user
			$_SESSION['loggedin'] = TRUE;
			$_SESSION['name'] = $username;
			$_SESSION['id'] = $id;
			$_SESSION['role'] = $role;
			// Update last seen date
			$date = date('Y-m-d\TH:i:s');
			$stmt = $con->prepare('UPDATE accounts SET last_seen = ? WHERE id = ?');
			$stmt->bind_param('si', $date, $id);
			$stmt->execute();
			$stmt->close();
		} else {
			// If the user is not remembered, redirect to the login page.
			header('Location: ' . $redirect_file);
			exit;
		}
    } else if (!isset($_SESSION['loggedin'])) {
    	// If the user is not logged-in, redirect to the login page.
    	header('Location: ' . $redirect_file);
    	exit;
    }
}
// Send activation email function
function send_activation_email($email, $code) {
	// Email Subject
	$subject = 'Account Activation Required';
	// Email Headers
	$headers = 'From: ' . mail_from . "\r\n" . 'Reply-To: ' . mail_from . "\r\n" . 'Return-Path: ' . mail_from . "\r\n" . 'X-Mailer: PHP/' . phpversion() . "\r\n" . 'MIME-Version: 1.0' . "\r\n" . 'Content-Type: text/html; charset=UTF-8' . "\r\n";
	// Activation link
	$activate_link = activation_link . '?email=' . $email . '&code=' . $code;
	// Read the template contents and replace the "%link" placeholder with the above variable
	$email_template = str_replace('%link%', $activate_link, file_get_contents('activation-email-template.html'));
	// Send email to user
	mail($email, $subject, $email_template, $headers);
}
function login_attempts($con, $update = TRUE) {
	$ip = $_SERVER['REMOTE_ADDR'];
	$now = date('Y-m-d H:i:s');
	if ($update) {
		$stmt = $con->prepare('INSERT INTO login_attempts (ip_address, `date`) VALUES (?,?) ON DUPLICATE KEY UPDATE attempts_left = attempts_left - 1, `date` = VALUES(`date`)');
		$stmt->bind_param('ss', $ip, $now);
		$stmt->execute();
		$stmt->close();
	}
	$stmt = $con->prepare('SELECT * FROM login_attempts WHERE ip_address = ?');
	$stmt->bind_param('s', $ip);
	$stmt->execute();
	$result = $stmt->get_result();
	$login_attempts = $result->fetch_array(MYSQLI_ASSOC);
	$stmt->close();
	if ($login_attempts) {
		// The user can try to login after 1 day... change the "+1 day" if you want to increase/decrease this date.
		$expire = date('Y-m-d H:i:s', strtotime('+1 day', strtotime($login_attempts['date'])));
		if ($now > $expire) {
			$stmt = $con->prepare('DELETE FROM login_attempts WHERE ip_address = ?');
			$stmt->bind_param('s', $ip);
			$stmt->execute();
			$stmt->close();
			$login_attempts = array();
		}
	}
	return $login_attempts;
}

function encryptstring($string) {
	$encryption_key = encryption_key;
	$iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length('aes-256-cbc'));
	$encrypted = openssl_encrypt($string, 'aes-256-cbc', $encryption_key, 0, $iv);
	return base64_encode($encrypted . '::' . $iv);
}

function decryptstring($string) {
	$encryption_key = encryption_key;
	list($encrypted_data, $iv) = explode('::', base64_decode($string), 2);
	return openssl_decrypt($encrypted_data, 'aes-256-cbc', $encryption_key, 0, $iv);
}
if (isset($_SESSION['id'])) {
$userid = $_SESSION['id'];
$stmt = $con->prepare('SELECT id, role, primaryadmin, canbackup, canrestore, canviewlogs, canmanagebackups, cancheckdrift, canmanagedrift, canmanagetenants, cangolddeploy, canviewreports, candeployapps, candeploytemplates, canmigrate, plevel, regtype, canmanageapi FROM accounts WHERE id = ?');
// Get the account info using the logged-in session ID
$stmt->bind_param('i', $_SESSION['id']);
$stmt->execute();
$stmt->bind_result($accountid, $accountrole, $primaryadmin, $canbackup, $canrestore, $canviewlogs, $canmanagebackups, $cancheckdrift, $canmanagedrift, $canmanagetenants, $cangolddeploy, $canviewreports, $candeployapps, $candeploytemplates, $canmigrate, $plevel, $regtype, $canmanageapi);
$stmt->fetch();
$stmt->close();
}
$sitetitle = "EUCToolbox Intune Manager";
$webhookuri = webhook;
$webhooksecret = webhooksecret;
$appwebhookuri = appwebhook;
$driftwebookuri = driftwebhook;
$dailywebhookuri = dailywebhook;
$securitywebhookuri = securitywebhook;
$gittype = gittype;
$repoowner = gitowner;
$gittoken = fullgittoken;
$gitproject = "GitHub";
?>