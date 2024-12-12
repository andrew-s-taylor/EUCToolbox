<?php
include 'main.php';
// Check logged-in
check_loggedin($con);
// output message (errors, etc)

$primaryadmin = $_POST['primaryadmin'];
// Retrieve additional account info from the database because we don't have them stored in sessions
$stmt = $con->prepare('SELECT password, email, activation_code, role, registered, reponame, golden, outdated FROM accounts WHERE id = ?');
// In this case, we can use the account ID to retrieve the account info.
$stmt->bind_param('i', $primaryadmin);
$stmt->execute();
$stmt->bind_result($password, $email, $activation_code, $role, $registered_date, $reponame, $golden, $daystocheck);
$stmt->fetch();
$stmt->close();


$stmt = $con->prepare('SELECT role FROM accounts WHERE id = ?');
// Get the account info using the logged-in session ID
$stmt->bind_param('i', $_SESSION['id']);
$stmt->execute();
$stmt->bind_result($role2);
$stmt->fetch();
$stmt->close();

// Handle edit profile post data
if (isset($_POST['password'], $_POST['cpassword'], $_POST['email'])) {
	// Make sure the submitted registration values are not empty.
	if (empty($_POST['email']) || empty($_POST['email'])) {
		$msg = 'The input fields must not be empty!';
	} else if (!filter_var($_POST['email'], FILTER_VALIDATE_EMAIL)) {
		$msg = 'Please provide a valid email address!';
	} else if (!empty($_POST['password']) && (strlen($_POST['password']) > 20 || strlen($_POST['password']) < 5)) {
		$msg = 'Password must be between 5 and 20 characters long!';
	} else if ($_POST['cpassword'] != $_POST['password']) {
		$msg = 'Passwords do not match!';
	}
	// No validation errors... Process update
	if (empty($msg)) {

		if (isset($_POST['ccanbackup'])) {
			$pcanbackup = 1;
		} else {
			$pcanbackup = 0;
		}
		
		if (isset($_POST['ccanrestore'])) {
			$pcanrestore = 1;
		} else {
			$pcanrestore = 0;
		}
		
		if (isset($_POST['ccanviewlogs'])) {
			$pcanviewlogs = 1;
		} else {
			$pcanviewlogs = 0;
		}
		
		if (isset($_POST['ccanmanagebackups'])) {
			$pcanmanagebackups = 1;
		} else {
			$pcanmanagebackups = 0;
		}
		
		if (isset($_POST['ccancheckdrift'])) {
			$pcancheckdrift = 1;
		} else {
			$pcancheckdrift = 0;
		}
		
		if (isset($_POST['ccanmanagedrift'])) {
			$pcanmanagedrift = 1;
		} else {
			$pcanmanagedrift = 0;
		}
		
		if (isset($_POST['ccanmanagetenants'])) {
			$pcanmanagetenants = 1;
		} else {
			$pcanmanagetenants = 0;
		}
		
		if (isset($_POST['ccangolddeploy'])) {
			$pcangolddeploy = 1;
		} else {
			$pcangolddeploy = 0;
		}
		
		if (isset($_POST['ccanviewreports'])) {
			$pcanviewreports = 1;
		} else {
			$pcanviewreports = 0;
		}
		
		if (isset($_POST['ccandeployapps'])) {
			$pcandeployapps = 1;
		} else {
			$pcandeployapps = 0;
		}
		
		if (isset($_POST['ccandeploytemplates'])) {
			$pcandeploytemplates = 1;
		} else {
			$pcandeploytemplates = 0;
		}

		if (isset($_POST['ccanmigrate'])) {
			$pcanmigrate = 1;
		} else {
			$pcanmigrate = 0;
		}

		if (isset($_POST['ccanmanageapi'])) {
			$pcanmanageapi = 1;
		} else {
			$pcanmanageapi = 0;
		}
		// Check if new username or email already exists in the database
		$stmt = $con->prepare('SELECT * FROM accounts WHERE (email = ?) AND (id != ?)');
		$stmt->bind_param('si', $_POST['email'], $_SESSION['id']);
		$stmt->execute();
		$stmt->store_result();
		// Account exists? Output error...
		if ($stmt->num_rows > 0) {
			echo 'Account already exists with that email!';
			exit;
		} else {
			// No errors occured, update the account...
			$stmt->close();
			// If email has changed, generate a new activation code
            $uniqid = "activated";
			$role = 'SubAdmin';
			// Current date
			$date = date('Y-m-d\TH:i:s');
			$ip = $_SERVER['REMOTE_ADDR'];
            $stmt = $con->prepare('INSERT IGNORE INTO accounts (password, email, activation_code, role, registered, last_seen, ip, regtype, canbackup, canrestore, canviewlogs, canmanagebackups, cancheckdrift, canmanagedrift, canmanagetenants, cangolddeploy, canviewreports, candeployapps, candeploytemplates, canmigrate, primaryadmin, reponame, golden, canmanageapi) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)');
			// We do not want to expose passwords in our database, so hash the password and use password_verify when a user logs in.
			$password = !empty($_POST['password']) ? password_hash($_POST['password'], PASSWORD_DEFAULT) : $password;
			$paid = "paid";
			$stmt->bind_param('ssssssssiiiiiiiiiiiiissi', $password, $_POST['email'], $uniqid, $role, $date, $date, $ip, $paid, $pcanbackup, $pcanrestore, $pcanviewlogs, $pcanmanagebackups, $pcancheckdrift, $pcanmanagedrift, $pcanmanagetenants, $pcangolddeploy, $pcanviewreports, $pcandeployapps, $pcandeploytemplates, $pcanmigrate, $primaryadmin, $reponame, $golden, $pcanmanageapi);
			$stmt->execute();
			$stmt->close();

						// Write to auditlog with userID, IP address, timestamp and update message
						$adminemail = $_POST['email'];
						$auditlog_message = "Admin added: " . $adminemail;
						$auditlog_userID = $_SESSION['id'];
						$auditlog_ipAddress = $_SERVER['REMOTE_ADDR'];
						$auditlog_timestamp = date('Y-m-d H:i:s');
						$stmt = $con->prepare('INSERT INTO auditlog (UserID, IPAddress, Timestamp, Task) VALUES (?, ?, ?, ?)');
						$stmt->bind_param('isss', $auditlog_userID, $auditlog_ipAddress, $auditlog_timestamp, $auditlog_message);
						$stmt->execute();
						$stmt->close();
			// Update the session variables
				// Profile updated successfully, redirect the user back to the profile page
				header('Location: profile-select.php?updatemessage=Admin Added');
				exit;
			
		}
	}
	else {
		// Display error message
		echo $msg;
	}
}
?>