<?php
include 'main.php';
//if (!isset($_POST['token']) || $_POST['token'] != $_SESSION['token']) {
//	exit('Incorrect token provided!');
//}
$login_attempts = login_attempts($con, FALSE);
if ($login_attempts && $login_attempts['attempts_left'] <= 0) {
	exit('You cannot login right now! Please try again later!');
}
// Now we check if the data from the login form was submitted, isset() will check if the data exists
if (!isset($_POST['email'], $_POST['password'])) {
	$login_attempts = login_attempts($con);
	// Could not retrieve the captured data, output error
	exit('Please fill both the email and password fields!');
}
// Prepare our SQL query and find the account associated with the login details
// Preparing the SQL statement will prevent SQL injection
$stmt = $con->prepare('SELECT id, password, rememberme, activation_code, role, ip,  regtype, registered FROM accounts WHERE email = ?');// Bind parameters (s = string, i = int, b = blob, etc), in our case the username is a string and therefore we specify "s"
$stmt->bind_param('s', $_POST['email']);
$stmt->execute();
$stmt->store_result();
// Check if the account exists:
if ($stmt->num_rows > 0) {
	// Bind results
	$stmt->bind_result($id, $password, $rememberme, $activation_code, $role, $ip, $regtype, $registered);
		$stmt->fetch();
	$stmt->close();
	$email = $_POST['email'];
	// Account exists... Verify the form password
        		$currentDateMinus30Days = date('Y-m-d H:i:s', strtotime('+7 days'));
	if (password_verify($_POST['password'], $password)) {
    
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
		// Check if the account is activated
		else if (account_activation && $activation_code != 'activated') {
			// User has not activated their account, output the message
			echo 'Please activate your account to login! Click <a href="resend-activation.php">here</a> to resend the activation email.';
		} else if ($_SERVER['REMOTE_ADDR'] != $ip) {
			// Two-factor authentication required
			$_SESSION['tfa_code'] = uniqid();
			$_SESSION['tfa_email'] = $email;
			$_SESSION['tfa_id'] = $id;
			header('Location: twofactor.php');
		} else {
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