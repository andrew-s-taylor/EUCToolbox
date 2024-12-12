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
$pprimaryadmin = $_POST['primaryadmin'];

$stmt = $con->prepare('SELECT role FROM accounts WHERE id = ?');
// Get the account info using the logged-in session ID
$stmt->bind_param('i', $_SESSION['id']);
$stmt->execute();
$stmt->bind_result($role2);
$stmt->fetch();
$stmt->close();
// Check if the user is an admin...
if ($role2 != 'Admin' && $role2 != 'SuperAdmin') {
    exit('You do not have permission to access this page!');
}

?>
<?php
$sitename = "Intune Manager from EUC Toolbox";
$pagetitle = "Intune Manager";
include "header1.php";
?>
		<div class="content profile">

			<h2>Add Admin</h2>

		
			<div class="block">

				<form action="processadmin.php" method="post">
					<input type="hidden" name="primaryadmin" value="<?=$pprimaryadmin?>">
					<label for="email">Email</label>
					<input type="email" name="email" id="email" placeholder="Email">

					<label for="password">New Password</label>
					<input type="password" name="password" id="password" placeholder="New Password">

					<label for="cpassword">Confirm Password</label>
					<input type="password" name="cpassword" id="cpassword" placeholder="Confirm Password">



					<label for="ccanbackup">Can Backup</label>
					<input type="checkbox" name="ccanrestore" id="ccanrestore" value="1">

					<label for="ccanrestore">Can Restore</label>
					<input type="checkbox" name="ccanrestore" id="ccanrestore" value="1">

					<label for="ccanviewlogs">Can View Logs</label>
					<input type="checkbox" name="ccanviewlogs" id="ccanviewlogs" value="1">

					<label for="ccanmanagebackups">Can Manage Backups</label>
					<input type="checkbox" name="ccanmanagebackups" id="ccanmanagebackups" value="1">

					<label for="ccancheckdrift">Can Check Drift</label>
					<input type="checkbox" name="ccancheckdrift" id="ccancheckdrift" value="1">

					<label for="ccanmanagedrift">Can Manage Drift</label>
					<input type="checkbox" name="ccanmanagedrift" id="ccanmanagedrift" value="1" >

					<label for="ccanmanagetenants">Can Manage Tenants</label>
					<input type="checkbox" name="ccanmanagetenants" id="ccanmanagetenants" value="1" >

					<label for="ccangolddeploy">Can Deploy from Gold</label>
					<input type="checkbox" name="ccangolddeploy" id="ccangolddeploy" value="1">

					<label for="ccanviewreports">Can View Reports</label>
					<input type="checkbox" name="ccanviewreports" id="ccanviewreports" value="1">

					<label for="ccandeployapps">Can Deploy Apps</label>
					<input type="checkbox" name="ccandeployapps" id="ccandeployapps" value="1" >

					<label for="ccandeploytemplates">Can Deploy Templates</label>
					<input type="checkbox" name="ccandeploytemplates" id="ccandeploytemplates" value="1" >
					
					<label for="ccanmigrate">Can Perform Migrations</label>
					<input type="checkbox" name="ccanmigrate" id="ccanmigrate" value="1" >

					<label for="ccanmanageapi">Can Manage API Integrations</label>
					<input type="checkbox" name="ccanmanageapi" id="ccanmanageapi" value="1" >

					
					<div>
						<input class="profile-btn" type="submit" value="Save">
					</div>

					<p><?=$msg?></p>

				</form>

			</div>

		</div>
		


		<?php
include "footer.php";
?>