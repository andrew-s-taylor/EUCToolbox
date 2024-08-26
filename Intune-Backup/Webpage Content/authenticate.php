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

if (!isset($_POST['token']) || $_POST['token'] != $_SESSION['token']) {
	exit('Incorrect token provided!');
}
$login_attempts = login_attempts($con, FALSE);
if ($login_attempts && $login_attempts['attempts_left'] <= 0) {
	exit('You cannot login right now! Please try again later!');
}
// Now we check if the data from the login form was submitted, isset() will check if the data exists
if (!isset($_POST['username'], $_POST['password'])) {
	$login_attempts = login_attempts($con);
	// Could not retrieve the captured data, output error
	exit('Please fill both the username and password fields!');
}
// Prepare our SQL query and find the account associated with the login details
// Preparing the SQL statement will prevent SQL injection
$stmt = $con->prepare('SELECT id, password, rememberme, activation_code, role, username, ip, email FROM accounts WHERE username = ?');// Bind parameters (s = string, i = int, b = blob, etc), in our case the username is a string and therefore we specify "s"
$stmt->bind_param('s', $_POST['username']);
$stmt->execute();
$stmt->store_result();
// Check if the account exists:
if ($stmt->num_rows > 0) {
	// Bind results
	$stmt->bind_result($id, $password, $rememberme, $activation_code, $role, $username, $ip, $email);
		$stmt->fetch();
	$stmt->close();
	// Account exists... Verify the form password
	if (password_verify($_POST['password'], $password)) {
		// Check if the account is activated
		if (account_activation && $activation_code != 'activated') {
			// User has not activated their account, output the message
			echo 'Please activate your account to login! Click <a href="resend-activation.php">here</a> to resend the activation email.';
		} else {
			// Verification success! User has loggedin!
			// Declare the session variables, which will basically act like cookies, but will store the data on the server as opposed to the client
			session_regenerate_id();
			$_SESSION['loggedin'] = TRUE;
			$_SESSION['name'] = $username;
			$_SESSION['id'] = $id;
			$_SESSION['role'] = $role;
			// IF the "remember me" checkbox is checked...
			if (isset($_POST['rememberme'])) {
				// Generate a hash that will be stored as a cookie and in the database. It will be used to identify the user.
				$cookiehash = !empty($rememberme) ? $rememberme : password_hash($id . $username . 'yoursecretkey', PASSWORD_DEFAULT);
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
			$ip = $_SERVER['REMOTE_ADDR'];
			$stmt = $con->prepare('DELETE FROM login_attempts WHERE ip_address = ?');
			$stmt->bind_param('s', $ip);
			$stmt->execute();
			$stmt->close();
			header('Location: home.php');
		}
	} else {
		// Incorrect password
		$login_attempts = login_attempts($con, TRUE);
		echo 'Incorrect username and/or password! You have ' . $login_attempts['attempts_left'] . ' attempts remaining!';
		}
} else {
	// Incorrect email
	$login_attempts = login_attempts($con, TRUE);
	echo 'Incorrect username and/or password! You have ' . $login_attempts['attempts_left'] . ' attempts remaining!';
}
?>