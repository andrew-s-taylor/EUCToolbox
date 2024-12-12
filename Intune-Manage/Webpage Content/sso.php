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
$code = $_GET['code'];
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);

    //Create a Graph access token using aadclient and secret
    $clientId = appID; 
    $clientSecret = appSecret;

    $token_Body = array(
        'client_id' => $clientId,
        'scope' => 'https://graph.microsoft.com/User.Read',
        'code' => $code,
        'redirect_uri' => 'https://manage.euctoolbox.com/sso.php',
        'grant_type' => 'authorization_code',
        'client_secret' => $clientSecret
    );

    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, "https://login.microsoftonline.com/common/oauth2/v2.0/token");
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($ch, CURLOPT_POST, 1);
    curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($token_Body));

    $headers = array();
    $headers[] = 'Content-Type: application/x-www-form-urlencoded';
    curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);

    $result = curl_exec($ch);
    if (curl_errno($ch)) {
        echo 'Error:' . curl_error($ch);
    }
    curl_close($ch);
    
    $token_Response = json_decode($result, true);
    $authentication = $token_Response['access_token'];
    $headers = array(
        'Content-Type: application/json',
        'Authorization: Bearer ' . $authentication . ''
    );

//Perform a GET request using the headers against https://graph.microsoft.com/v1.0/me
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, "https://graph.microsoft.com/v1.0/me");
curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
curl_setopt($ch, CURLOPT_CUSTOMREQUEST, "GET");
curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
$result = curl_exec($ch);
if (curl_errno($ch)) {
    echo 'Error:' . curl_error($ch);
}
curl_close($ch);

//Grab the email address
$profile = json_decode($result, true);
$email = $profile['mail'];


// Prepare our SQL query and find the account associated with the login details
// Preparing the SQL statement will prevent SQL injection
$stmt = $con->prepare('SELECT id, password, rememberme, activation_code, role, ip,  regtype, registered FROM accounts WHERE email = ?');// Bind parameters (s = string, i = int, b = blob, etc), in our case the username is a string and therefore we specify "s"
$stmt->bind_param('s', $email);
$stmt->execute();
$stmt->store_result();
// Check if the account exists:
if ($stmt->num_rows > 0) {
	// Bind results
	$stmt->bind_result($id, $password, $rememberme, $activation_code, $role, $ip, $regtype, $registered);
		$stmt->fetch();
	$stmt->close();
	// Account exists... Verify the form password
        		$currentDateMinus30Days = date('Y-m-d H:i:s', strtotime('+7 days'));

            if ($regtype == 'trial' && (strtotime($registered) > strtotime($currentDateMinus30Days))) {
        $expired = 0;
        }
        else {
       $expired = 1;
        }
		//Check if regtype is expired, not paid or trial and over 30 days old
		if ($regtype == 'expired' || $expired == "0") {

			// User has not paid, output the message
			echo 'Your account has expired! Please renew your subscription to login!';
		}
        //else if ($_SERVER['REMOTE_ADDR'] != $ip) {
			// Two-factor authentication required
		//	$_SESSION['tfa_code'] = uniqid();
		//	$_SESSION['tfa_email'] = $email;
		//	$_SESSION['tfa_id'] = $id;
		//	header('Location: twofactor.php');
		//} 
        else {
			// Verification success! User has loggedin!
			// Declare the session variables, which will basically act like cookies, but will store the data on the server as opposed to the client
			session_regenerate_id();
			$_SESSION['loggedin'] = TRUE;
			$_SESSION['name'] = $email;
			$_SESSION['id'] = $id;
			$_SESSION['role'] = $role;
			// IF the "remember me" checkbox is checked...
			if (isset($_POST['rememberme'])) {
				// Generate a hash that will be stored as a cookie and in the database. It will be used to identify the user.
				$usernamehash = preg_replace('/[^A-Za-z0-9\-]/', '', $email);

				$cookiehash = !empty($rememberme) ? $rememberme : password_hash($id . $usernamehash . 'yoursecretkey', PASSWORD_DEFAULT);
				// The number of days the user will be remembered
				$days = 30;
				// Create the cookie
				setcookie('rememberme', $cookiehash, (int)(time()+60*60*24*$days));
				// Update the "rememberme" field in the accounts table with the new hash
				$stmt = $con->prepare('UPDATE accounts SET rememberme = ? WHERE id = ?');
				$stmt->bind_param('si', $cookiehash, $id);
				$stmt->execute();
				$stmt->close();
			}
			// Update last seen date
			$date = date('Y-m-d\TH:i:s');
			$stmt = $con->prepare('UPDATE accounts SET last_seen = ? WHERE id = ?');
			$stmt->bind_param('si', $date, $id);
			$stmt->execute();
			$stmt->close();
			// Output msg; do not change this line as the AJAX code depends on it
			$ip = $_SERVER['REMOTE_ADDR'];
			$stmt = $con->prepare('DELETE FROM login_attempts WHERE ip_address = ?');
			$stmt->bind_param('s', $ip);
			$stmt->execute();
			$stmt->close();
			echo 'Success'; 

			$auditlog_userID = $id;
$auditlog_ipAddress = $_SERVER['REMOTE_ADDR'];
$auditlog_timestamp = date('Y-m-d H:i:s');
$auditlog_message = "Account login";
$stmt = $con->prepare('INSERT INTO auditlog (UserID, IPAddress, Timestamp, Task) VALUES (?, ?, ?, ?)');
$stmt->bind_param('isss', $auditlog_userID, $auditlog_ipAddress, $auditlog_timestamp, $auditlog_message);
$stmt->execute();
$stmt->close();
			header('Location: home.php');
		}

} else {
	// Incorrect email
	echo "Email $email not found, please contact your administrator";
}
?>