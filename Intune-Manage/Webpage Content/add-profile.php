<?php
include 'main.php';
// Check logged-in
check_loggedin($con);
// output message (errors, etc)
$msg = '';
$primaryid = $_POST['primaryid'];

// Retrieve additional account info from the database because we don't have them stored in sessions
$stmt = $con->prepare('SELECT password, email, activation_code, role, registered, golden, outdated, reponame FROM accounts WHERE id = ?');
// In this case, we can use the account ID to retrieve the account info.
$stmt->bind_param('i', $primaryid);
$stmt->execute();
$stmt->bind_result($password, $email, $activation_code, $role, $registered_date, $golden, $daystocheck, $reponame);
$stmt->fetch();
$stmt->close();


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


			<h2>Add Profile</h2>

			<div class="block">
						<div class="content profile">


				<form action="processprofile.php" method="post">
					<input type="hidden" name="primaryid" value="<?=$primaryid?>">

					<label for="email">Email</label>
					<input type="email" name="email" id="email" placeholder="Email">

					<label for="password">New Password</label>
					<input type="password" name="password" id="password" placeholder="New Password">

					<label for="cpassword">Confirm Password</label>
					<input type="password" name="cpassword" id="cpassword" placeholder="Confirm Password">

					<label for="golden">Golden Tenant</label>
					<input type="text" name="golden" id="golden" placeholder="Golden Tenant">

					<label for="daystocheck">Days Before Outdated</label>
					<input type="text" name="daystocheck" id="daystocheck" placeholder="7">
					<label for="ccanbackup">Can Backup</label>
					<input type="checkbox" name="ccanbackup" id="ccanbackup" value="1">

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