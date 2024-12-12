<?php
include 'main.php';
// Check logged-in
check_loggedin($con);
// output message (errors, etc)
$msg = '';
$selectedid = $_POST['profileid'];


// Retrieve additional account info from the database because we don't have them stored in sessions
$stmt = $con->prepare('SELECT password, email, activation_code, role, registered, golden, outdated, canbackup, canrestore, canviewlogs, canmanagebackups, cancheckdrift, canmanagedrift, canmanagetenants, cangolddeploy, canviewreports, candeployapps, candeploytemplates, canmigrate, apikey, alertsemail, canmanageapi FROM accounts WHERE id = ?');
// In this case, we can use the account ID to retrieve the account info.
$stmt->bind_param('i', $selectedid);
$stmt->execute();
$stmt->bind_result($password, $email, $activation_code, $role, $registered_date, $golden, $daystocheck, $ccanbackup, $ccanrestore, $ccanviewlogs, $ccanmanagebackups, $ccancheckdrift, $ccanmanagedrift, $ccanmanagetenants, $ccangolddeploy, $ccanviewreports, $ccandeployapps, $ccandeploytemplates, $ccanmigrate, $capikey, $calertsemail, $ccanmanageapi );
$stmt->fetch();
$stmt->close();
$stmt = $con->prepare('SELECT role FROM accounts WHERE id = ?');
// Get the account info using the logged-in session ID
$stmt->bind_param('i', $_SESSION['id']);
$stmt->execute();
$stmt->bind_result($role2);
$stmt->fetch();
$stmt->close();

if (isset($_POST['apikey'])) {

	function generateApiKey($length = 64) {
		return bin2hex(random_bytes($length / 2));
	}
	
	// Usage example
	$apiKey = generateApiKey();
	
	//Update the key in the databae
	$stmt = $con->prepare('UPDATE accounts SET apikey = ? WHERE id = ?');
	$stmt->bind_param('si', $apiKey, $selectedid);
	$stmt->execute();
	$stmt->close();

	// Write to auditlog with userID, IP address, timestamp and update message
	$auditlog_message = "API Key rotated for user with ID: " . $selectedid;
	$auditlog_userID = $_SESSION['id'];
	$auditlog_ipAddress = $_SERVER['REMOTE_ADDR'];
	$auditlog_timestamp = date('Y-m-d H:i:s');
	$stmt = $con->prepare('INSERT INTO auditlog (UserID, IPAddress, Timestamp, Task) VALUES (?, ?, ?, ?)');
	$stmt->bind_param('isss', $auditlog_userID, $auditlog_ipAddress, $auditlog_timestamp, $auditlog_message);
	$stmt->execute();
	$stmt->close();

	//Refresh page retaining POST data
	echo '<form id="refreshForm" method="post" action="">';
	echo '<input type="hidden" name="profileid" value="' . $selectedid . '">';
	echo '</form>';
	echo '<script>document.getElementById("refreshForm").submit();</script>';

}
	
// Handle edit profile post data
if (isset($_POST['password'], $_POST['cpassword'], $_POST['email'])) {
	// Make sure the submitted registration values are not empty.
	if (empty($_POST['email'])) {
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
		// Check if new username or email already exists in the database
		$stmt = $con->prepare('SELECT * FROM accounts WHERE (email = ?) AND (id != ?)');
		$stmt->bind_param('si', $_POST['email'], $selectedid);
		$stmt->execute();
		$stmt->store_result();
		// Account exists? Output error...
		if ($stmt->num_rows > 0) {
			$msg = 'Account already exists with that email!';
		} else {
			// No errors occured, update the account...
			$stmt->close();
			// If email has changed, generate a new activation code
// Import the password_hash function
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
			// Write to auditlog with userID, IP address, timestamp and update message
			$auditlog_message = "Profile updated for user with ID: " . $selectedid;
			$auditlog_userID = $_SESSION['id'];
			$auditlog_ipAddress = $_SERVER['REMOTE_ADDR'];
			$auditlog_timestamp = date('Y-m-d H:i:s');
			$stmt = $con->prepare('INSERT INTO auditlog (UserID, IPAddress, Timestamp, Task) VALUES (?, ?, ?, ?)');
			$stmt->bind_param('isss', $auditlog_userID, $auditlog_ipAddress, $auditlog_timestamp, $auditlog_message);
			$stmt->execute();
			$stmt->close();
if ($role2 =="Admin" || $role2 == "SuperAdmin") {
	$uniqid = account_activation && $email != $_POST['email'] ? uniqid() : $activation_code;
$alertsemail = $_POST['alertsemail'];
			//Update the profile
			$stmt = $con->prepare('UPDATE accounts SET password = ?, email = ?, activation_code = ?, golden = ?, outdated = ?, canbackup = ?, canrestore = ?, canviewlogs = ?, canmanagebackups = ?, cancheckdrift = ?, canmanagedrift = ?, canmanagetenants = ?, cangolddeploy = ?, canviewreports = ?, candeployapps = ?, candeploytemplates = ?, canmigrate = ?, alertsemail = ?, canmanageapi = ? WHERE id = ?');
			$stmt->bind_param('ssssiiiiiiiiiiiiisii', $password, $_POST['email'], $uniqid, $_POST['golden'], $_POST['daystocheck'], $pcanbackup, $pcanrestore, $pcanviewlogs, $pcanmanagebackups, $pcancheckdrift, $pcanmanagedrift, $pcanmanagetenants, $pcangolddeploy, $pcanviewreports, $pcandeployapps, $pcandeploytemplates, $pcanmigrate, $alertsemail, $pcanmanageapi, $selectedid);
			$stmt->execute();
			$stmt->close();

			// Update the session variables
			$_SESSION['name'] = $_POST['email'];
			if (account_activation && $email != $_POST['email']) {
				// Account activation required, send the user the activation email with the "send_activation_email" function from the "main.php" file
				send_activation_email($_POST['email'], $uniqid);
				// Logout the user
				unset($_SESSION['loggedin']);
				$msg = 'You have changed your email address! You need to re-activate your account!';
			} else {
				// Profile updated successfully, redirect the user back to the profile page
				header('Location: profile-select.php?updatemessage=ProfileUpdated');
				exit;
			}
		}
		else {
			$stmt = $con->prepare('UPDATE accounts SET password = ?, email = ? WHERE id = ?');
			// We do not want to expose passwords in our database, so hash the password and use password_verify when a user logs in.
			$password = !empty($_POST['password']) ? password_hash($_POST['password'], PASSWORD_DEFAULT) : $password;
			$uniqid = account_activation && $email != $_POST['email'] ? uniqid() : $activation_code;

			$stmt->bind_param('ssi', $password, $_POST['email'], $selectedid);
			$stmt->execute();
			$stmt->close();
			// Update the session variables
			$_SESSION['name'] = $_POST['email'];
			if (account_activation && $email != $_POST['email']) {
				// Account activation required, send the user the activation email with the "send_activation_email" function from the "main.php" file
				send_activation_email($_POST['email'], $uniqid);
				// Logout the user
				unset($_SESSION['loggedin']);
				$msg = 'You have changed your email address! You need to re-activate your account!';
			} else {
				// Profile updated successfully, redirect the user back to the profile page
				header('Location: profile-select.php?updatemessage=ProfileUpdated');
				exit;
			}

		}
		}
	}
}
?>
<?php
$sitename = "Intune Manager from EUC Toolbox";
$pagetitle = "Intune Manager";
include "header1.php";
?>

		<?php if (!isset($_GET['action'])): ?>

			<h2>Your Details</h2>

			<div class="block">
<p>
	<?php
if (isset($_GET['updatemessage'])) {
	//Display Process Messages
	echo $_GET['updatemessage'];
}
	?>
</p>
				<p>Your account details are below.</p>


				<div class="profile-detail">
					<strong>Email</strong>
					<?=$email?>
				</div>

<?php
if ($role2 == "Admin" || $role2 =="SuperAdmin") {
	?>
				<div class="profile-detail">
					<strong>Registered</strong>
					<?=date('Y-m-d H:ia', strtotime($registered_date))?>
				</div>
				
				<div class="profile-detail">
					<strong>Golden Tenant ID (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)</strong>
					<?=$golden?>
				</div>

				<div class="profile-detail">
					<strong>Alerts email</strong>
					<?=$calertsemail?>
				</div>

				<div class="profile-detail">
					<strong>Can Backup</strong>
					<?php if ($ccanbackup == 1) {
						echo "Yes";
					}
					else {
						echo "No";
					}
					?>
				</div>
				<div class="profile-detail">
					<strong>Can Restore</strong>
					<?php if ($ccanrestore == 1) {
						echo "Yes";
					}
					else {
						echo "No";
					}
					?>
				</div>
				<div class="profile-detail">
					<strong>Can View Logs</strong>
					<?php if ($ccanviewlogs == 1) {
						echo "Yes";
					}
					else {
						echo "No";
					}
					?>
				</div>
				<div class="profile-detail">
					<strong>Can Manage Backups</strong>
					<?php if ($ccanmanagebackups == 1) {
						echo "Yes";
					}
					else {
						echo "No";
					}
					?>
				</div>
				<div class="profile-detail">
					<strong>Can Check Drift</strong>
					<?php if ($ccancheckdrift == 1) {
						echo "Yes";
					}
					else {
						echo "No";
					}
					?>
				</div>
				<div class="profile-detail">
					<strong>Can Manage Drift</strong>
					<?php if ($ccanmanagedrift == 1) {
						echo "Yes";
					}
					else {
						echo "No";
					}
					?>
				</div>
				<div class="profile-detail">
					<strong>Can Manage API Integrations</strong>
					<?php if ($ccanmanageapi == 1) {
						echo "Yes";
					}
					else {
						echo "No";
					}
					?>
				</div>
				<div class="profile-detail">
					<strong>Can Deploy from Gold</strong>
					<?php if ($ccangolddeploy == 1) {
						echo "Yes";
					}
					else {
						echo "No";
					}
					?>
				</div>
				<div class="profile-detail">
					<strong>Can View Reports</strong>
					<?php if ($ccanviewreports == 1) {
						echo "Yes";
					}
					else {
						echo "No";
					}
					?>
				</div>
				<div class="profile-detail">
					<strong>Can Deploy Apps</strong>
					<?php if ($ccandeployapps == 1) {
						echo "Yes";
					}
					else {
						echo "No";
					}
					?>
				</div>
				<div class="profile-detail">
					<strong>Can Deploy Templates</strong>
					<?php if ($ccandeploytemplates == 1) {
						echo "Yes";
					}
					else {
						echo "No";
					}
					?>
				</div>
				<div class="profile-detail">
					<strong>Can Perform Migrations</strong>
					<?php if ($ccanmigrate == 1) {
						echo "Yes";
					}
					else {
						echo "No";
					}
					?>
				</div>
					<?php
}
?>
				
				

				<table class="styled-table"><tr><td>
				<form action="profile.php?action=edit" method="post">
			<input type="hidden" name="profileid" value="<?=$selectedid; ?>"/>
			<input type="submit" value="Edit Details" class="profile-btn">
		</form></td></tr></table>


			<div class="wrapper">
		<h2>Delete Account</h2>
		<table class="styled-table"><tr><td>
		<form action="deleteaccount.php" method="post">
			<input type="hidden" name="accountid" value="<?=$selectedid?>"/>
			<input type="submit" value="Delete Account" class="profile-btn">
		</form></td></tr></table>
	</div>


	<div class="wrapper">
		<h2>API Key</h2>
		<table class="styled-table"><tr><td>
		<form action="profile.php" method="post">
		<input type="hidden" name="profileid" value="<?=$selectedid; ?>"/>
			<input type="hidden" name="apikey" id="apikey"> 
			<input type="text" name="apikey2" id="apikey2" readonly value="<?php echo $capikey; ?>">
			<button onclick="copyText()">Copy</button>
			<script>
			function copyText() {
				event.preventDefault()
				var textField = document.getElementById("apikey2");
				textField.select();
				document.execCommand("copy");
				alert("Text copied!");
			}
			</script>
			<input type="submit" value="Rotate" class="profile-btn">
		</form></td></tr></table>
	</div>
		</div>
		<?php elseif ($_GET['action'] == 'edit'): ?>
		<div class="content profile">

			<h2>Edit Profile Page</h2>
			
			<div class="block">

				<form action="profile.php?action=edit" method="post">
					<input type="hidden" name="profileid" value="<?=$selectedid?>">

					<label for="password">New Password</label>
					<input type="password" name="password" id="password" placeholder="New Password">

					<label for="cpassword">Confirm Password</label>
					<input type="password" name="cpassword" id="cpassword" placeholder="Confirm Password">

					<label for="email">Email</label>
					<input type="email" value="<?=$email?>" name="email" id="email" placeholder="Email">
<?php if ($role2 == "Admin" || $role2 == "SuperAdmin") {
	?>
					<label for="golden">Golden Tenant</label>
					<input type="text" value="<?=$golden?>" name="golden" id="golden" placeholder="Golden Tenant">

					<label for="daystocheck">Days Before Outdated</label>
					<input type="text" value="<?=$daystocheck?>" name="daystocheck" id="daystocheck" placeholder="7">
					<label for="alertsemail">Email for daily alerts</label>
					<input type="text" value="<?=$calertsemail?>" name="alertsemail" id="alertsemail" placeholder="Alerts Email Address">
					<label for="ccanbackup">Can Backup</label>
					<input type="checkbox" name="ccanbackup" id="ccanbackup" value="1" <?php if ($ccanbackup == 1) { echo "checked"; } ?>>

					<label for="ccanrestore">Can Restore</label>
					<input type="checkbox" name="ccanrestore" id="ccanrestore" value="1" <?php if ($ccanrestore == 1) { echo "checked"; } ?>>

					<label for="ccanviewlogs">Can View Logs</label>
					<input type="checkbox" name="ccanviewlogs" id="ccanviewlogs" value="1" <?php if ($ccanviewlogs == 1) { echo "checked"; } ?>>

					<label for="ccanmanagebackups">Can Manage Backups</label>
					<input type="checkbox" name="ccanmanagebackups" id="ccanmanagebackups" value="1" <?php if ($ccanmanagebackups == 1) { echo "checked"; } ?>>

					<label for="ccancheckdrift">Can Check Drift</label>
					<input type="checkbox" name="ccancheckdrift" id="ccancheckdrift" value="1" <?php if ($ccancheckdrift == 1) { echo "checked"; } ?>>

					<label for="ccanmanagedrift">Can Manage Drift</label>
					<input type="checkbox" name="ccanmanagedrift" id="ccanmanagedrift" value="1" <?php if ($ccanmanagedrift == 1) { echo "checked"; } ?>>

					<label for="ccanmanagetenants">Can Manage Tenants</label>
					<input type="checkbox" name="ccanmanagetenants" id="ccanmanagetenants" value="1" <?php if ($ccanmanagetenants == 1) { echo "checked"; } ?>>

					<label for="ccangolddeploy">Can Deploy from Gold</label>
					<input type="checkbox" name="ccangolddeploy" id="ccangolddeploy" value="1" <?php if ($ccangolddeploy == 1) { echo "checked"; } ?>>

					<label for="ccanviewreports">Can View Reports</label>
					<input type="checkbox" name="ccanviewreports" id="ccanviewreports" value="1" <?php if ($ccanviewreports == 1) { echo "checked"; } ?>>

					<label for="ccandeployapps">Can Deploy Apps</label>
					<input type="checkbox" name="ccandeployapps" id="ccandeployapps" value="1" <?php if ($ccandeployapps == 1) { echo "checked"; } ?>>

					<label for="ccandeploytemplates">Can Deploy Templates</label>
					<input type="checkbox" name="ccandeploytemplates" id="ccandeploytemplates" value="1" <?php if ($ccandeploytemplates == 1) { echo "checked"; } ?>>

					<label for="ccanmigrate">Can Migrate Tenants</label>
					<input type="checkbox" name="ccanmigrate" id="ccanmigrate" value="1" <?php if ($ccanmigrate == 1) { echo "checked"; } ?>>

					<label for="ccanmanageapi">Can Manage API Integrations</label>
					<input type="checkbox" name="ccanmanageapi" id="ccanmanageapi" value="1" <?php if ($ccanmanageapi == 1) { echo "checked"; } ?>>


<?php 
}
?>
					<div>
						<input class="profile-btn" type="submit" value="Save">
					</div>

					<p><?=$msg?></p>

				</form>

			</div>

			<?php endif; ?>

		</div>
		


		<?php
include "footer.php";
?>