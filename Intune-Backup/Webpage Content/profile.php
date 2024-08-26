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
// Check logged-in
check_loggedin($con);
// output message (errors, etc)
$msg = '';
// Retrieve additional account info from the database because we don't have them stored in sessions
$stmt = $con->prepare('SELECT password, email, activation_code, role, registered, repoowner, reponame, gitproject, aadclient, gittype, gittoken, aadsecret, golden, outdated FROM accounts WHERE id = ?');
// In this case, we can use the account ID to retrieve the account info.
$stmt->bind_param('i', $_SESSION['id']);
$stmt->execute();
$stmt->bind_result($password, $email, $activation_code, $role, $registered_date, $repoowner, $reponame, $gitproject, $aadclient, $gittype, $gittoken, $aadsecret, $golden, $daystocheck);
$stmt->fetch();
$stmt->close();
// Handle edit profile post data
if (isset($_POST['username'], $_POST['password'], $_POST['cpassword'], $_POST['email'])) {
	// Make sure the submitted registration values are not empty.
	if (empty($_POST['username']) || empty($_POST['email'])) {
		$msg = 'The input fields must not be empty!';
	} else if (!filter_var($_POST['email'], FILTER_VALIDATE_EMAIL)) {
		$msg = 'Please provide a valid email address!';
	} else if (!preg_match('/^[a-zA-Z0-9]+$/', $_POST['username'])) {
	    $msg = 'Username must contain only letters and numbers!';
	} else if (!empty($_POST['password']) && (strlen($_POST['password']) > 20 || strlen($_POST['password']) < 5)) {
		$msg = 'Password must be between 5 and 20 characters long!';
	} else if ($_POST['cpassword'] != $_POST['password']) {
		$msg = 'Passwords do not match!';
	}
	// No validation errors... Process update
	if (empty($msg)) {
		if ($_POST['gittoken'] == "********") {
			$gittoken = $gittoken;
		}
		else {
			$gittoken2 = $_POST['gittoken'];
			$gittoken = encryptstring($gittoken2);
		}
		if ($_POST['aadsecret'] == "********") {
			$aadsecret = $aadsecret;
		}
		else {
			$aadsecret2 = $_POST['aadsecret'];
			$aadsecret = encryptstring($aadsecret2);
		}
		if ($_POST['gitproject'] == "") {
			$gitproject = "GitHub";
		}
		else {
			$gitproject = $_POST['gitproject'];
		}
		// Check if new username or email already exists in the database
		$stmt = $con->prepare('SELECT * FROM accounts WHERE (username = ? OR email = ?) AND username != ? AND email != ?');
		$stmt->bind_param('ssss', $_POST['username'], $_POST['email'], $_SESSION['name'], $email);
		$stmt->execute();
		$stmt->store_result();
		// Account exists? Output error...
		if ($stmt->num_rows > 0) {
			$msg = 'Account already exists with that username and/or email!';
		} else {
			// No errors occured, update the account...
			$stmt->close();
			// If email has changed, generate a new activation code
			$uniqid = account_activation && $email != $_POST['email'] ? uniqid() : $activation_code;
			$stmt = $con->prepare('UPDATE accounts SET username = ?, password = ?, email = ?, activation_code = ?, repoowner = ?, reponame = ?, gitproject = ?, aadclient = ?, gittype = ?, gittoken = ?, aadsecret = ?, golden = ?, outdated = ? WHERE id = ?');
			// We do not want to expose passwords in our database, so hash the password and use password_verify when a user logs in.
			$password = !empty($_POST['password']) ? password_hash($_POST['password'], PASSWORD_DEFAULT) : $password;
			$stmt->bind_param('ssssssssssssii', $_POST['username'], $password, $_POST['email'], $uniqid, $_POST['repoowner'], $_POST['reponame'], $gitproject, $_POST['aadclient'], $_POST['gittype'], $gittoken, $aadsecret, $_POST['golden'], $_POST['daystocheck'], $_SESSION['id']);
			$stmt->execute();
			$stmt->close();
			// Update the session variables
			$_SESSION['name'] = $_POST['username'];
			if (account_activation && $email != $_POST['email']) {
				// Account activation required, send the user the activation email with the "send_activation_email" function from the "main.php" file
				send_activation_email($_POST['email'], $uniqid);
				// Logout the user
				unset($_SESSION['loggedin']);
				$msg = 'You have changed your email address! You need to re-activate your account!';
			} else {
				// Profile updated successfully, redirect the user back to the profile page
				header('Location: profile.php?updatemessage=ProfileUpdated');
				exit;
			}
		}
	}
}
?>
<?php
$sitename = "Intune Backup from EUC Toolbox";
$pagetitle = "Intune Backup";
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
					<strong>Username</strong>
					<?=$_SESSION['name']?>
				</div>

				<div class="profile-detail">
					<strong>Email</strong>
					<?=$email?>
				</div>


				<div class="profile-detail">
					<strong>Registered</strong>
					<?=date('Y-m-d H:ia', strtotime($registered_date))?>
				</div>

				<div class="profile-detail">
					<strong>Repo Owner</strong>
					<?=$repoowner?>
				</div>

				<div class="profile-detail">
					<strong>Repo Name</strong>
					<?=$reponame?>
				</div>
				<?php
				if (($gittype == "azure") or ($gittype == "gitlab")) {
					?>
					<div class="profile-detail">
					<strong>Git Project Name (Azure) or ID (GitLab)</strong>
					<?=$gitproject?>
				</div>
					<?php
				}
				?>

				<div class="profile-detail">
					<strong>Git Type</strong>
					<?=$gittype?>
				</div>

				<div class="profile-detail">
					<strong>AAD App ID</strong>
					<?=$aadclient?>
				</div>

				<div class="profile-detail">
					<strong>AAD Secret</strong>
					<?php
					if ($aadsecret != "") {
						echo "********";
					}
					?>
				</div>

				<div class="profile-detail">
					<strong>Git Token</strong>
					<?php
					if ($gittoken != "") {
						echo "********";
					}
					?>
				</div>
				
				<div class="profile-detail">
					<strong>Golden Tenant</strong>
					<?=$golden?>
				</div>

				<div class="profile-detail">
					<strong>Number of days before outdated</strong>
					<?=$daystocheck?>
				</div>

				<a href="profile.php?action=edit"><button class="button">Edit Details</button></a>

			</div>
			<div class="wrapper">
		<h2>Delete Account</h2>
		<table class="styled-table"><tr><td>
		<form action="deleteaccount.php" method="post">
			<input type="hidden" name="accountid" value="<?=$_SESSION['id']?>"/>
			<input type="submit" value="Delete Account" class="profile-btn">
		</form>
		</td></tr></table>
	</div>
	<div class="wrapper">
		<h2>Test Git Connection</h2>
		<table class="styled-table"><tr><td>
		<form action="runtest.php" method="post">
			<input type="hidden" name="testtype" value="git"/>
			<input type="submit" value="Test Git" class="profile-btn">
		</form>
		</td></tr></table>
	</div>
		</div>
		<?php elseif ($_GET['action'] == 'edit'): ?>
		<div class="content profile">

			<h2>Edit Profile Page</h2>
			
			<div class="block">

				<form action="profile.php?action=edit" method="post">

					<label for="username">Username</label>
					<input type="text" value="<?=$_SESSION['name']?>" name="username" id="username" placeholder="Username">

					<label for="password">New Password</label>
					<input type="password" name="password" id="password" placeholder="New Password">

					<label for="cpassword">Confirm Password</label>
					<input type="password" name="cpassword" id="cpassword" placeholder="Confirm Password">

					<label for="email">Email</label>
					<input type="email" value="<?=$email?>" name="email" id="email" placeholder="Email">

					<label for="repoowner">Repo Owner</label>
					<input type="text" value="<?=$repoowner?>" name="repoowner" id="repoowner" placeholder="Repo Owner">

					<label for="reponame">Repo Name</label>
					<input type="text" value="<?=$reponame?>" name="reponame" id="reponame" placeholder="Repo Name">

					<label for="gitproject">Git Project (Azure) or Project ID (GitLab)</label>
					<input type="text" value="<?=$gitproject?>" name="gitproject" id="gitproject" placeholder="Git Project">

					<label for="gittype">Git Type</label>
					<select name="gittype" id="gittype">
						<option value="github" <?php if ($gittype == "github") { echo "selected"; } ?>>GitHub</option>
						<option value="azure" <?php if ($gittype == "azure") { echo "selected"; } ?>>Azure DevOps</option>
						<option value="gitlab" <?php if ($gittype == "gitlab") { echo "selected"; } ?>>GitLab</option>
					</select>

					<label for="aadclient">AAD App ID</label>
					<input type="text" value="<?=$aadclient?>" name="aadclient" id="aadclient" placeholder="AAD App ID">

					<label for="aadsecret">AAD Secret</label>
					<input type="text" value="<?php
					if ($aadsecret != "") {
						echo "********";
					}
					?>" name="aadsecret" id="aadsecret" placeholder="AAD Secret">

					<label for="gittoken">Git Token</label>
					<input type="text" value="<?php
					if ($gittoken != "") {
						echo "********";
					}
					?>" name="gittoken" id="gittoken" placeholder="Git Token">

					<label for="golden">Golden Tenant</label>
					<input type="text" value="<?=$golden?>" name="golden" id="golden" placeholder="Golden Tenant">

					<label for="daystocheck">Days Before Outdated</label>
					<input type="text" value="<?=$daystocheck?>" name="daystocheck" id="daystocheck" placeholder="7">

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