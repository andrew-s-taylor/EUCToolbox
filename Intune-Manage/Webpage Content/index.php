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
// No need for the user to see the login form if they're logged-in, so redirect them to the home page
if (isset($_SESSION['loggedin'])) {
	// If the user is logged in, redirect to the home page.
	header('Location: home.php');
	exit;
}
// Also check if they are "remembered"
if (isset($_COOKIE['rememberme']) && !empty($_COOKIE['rememberme'])) {
	// If the remember me cookie matches one in the database then we can update the session variables.
	$stmt = $con->prepare('SELECT id, email, role FROM accounts WHERE rememberme = ?');
	$stmt->bind_param('s', $_COOKIE['rememberme']);
	$stmt->execute();
	$stmt->store_result();
	if ($stmt->num_rows > 0) {
		// Found a match
		$stmt->bind_result($id, $username, $role);
		$stmt->fetch();
		$stmt->close();
		// Authenticate the user
		session_regenerate_id();
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
		// Redirect to the home page
		header('Location: home.php');
		exit;
	}
}
$_SESSION['token'] = md5(uniqid(rand(), true));
?>
<?php
$sitename = "Intune Manager from EUC Toolbox";
$pagetitle = "Intune Manager";
include "header.php";
?>

<div class="step-container buyContainer">
	<table>
		<tr>
			<td style="text-align: center;">
				<a href="login.php" class="button">Login Here</a>
			</td>
			<td style="text-align: center;">
				<a href="register.php" class="button">Register for a 14 day free trial</a>
			</td>
	</table>
</div>


<div class="step-container lpHeadlineContainer">
        <h1>Manage multiple Intune tenants and customers including full backup/restore, drift monitoring, daily reports and more!</h1>
        
        </div>
		<div class="mainLPsubheadings paddme">

<h1 id="deployment">What you get</h1>
</div>

	<div class="step-container highlightedStepsContainer">
	<ul class="highlightedSteps">
					<li>Tenant backup/Restore</li>
					<li>Tenant drift against last backup</li>
					<li>
					<div class="tooltip">Tenant drift against Gold tenant
  <span class="tooltiptext">Ability to acknowledge to stop alerting, or revert/deploy policy</span>
</div></li>
					<li>Tenant migrations</li>
					<li>Policy deployment from Gold tenant</li>
					<li>Template creation and deployment</li>
					<li>Full access to our Intune Deploy tool</li>
					<li>Backup management</li>
					<li>
					<div class="tooltip">Customer RBAC
  <span class="tooltiptext">Customers have their own accounts with specified permissions</span>
</div></li>
					<li>
					<div class="tooltip">Admin RBAC
  <span class="tooltiptext">Configure multiple admin accounts with individual permissions</span>
</div></li>
					<li>Ability to use different gold tenant per customer</li>
					<li>Easier tenant onboarding</li>
					<li>
					<div class="tooltip">Daily checks
  <span class="tooltiptext">Compares tenant against CIS and NCSC (Intune policies only)</span>
</div></li>
<li>
					<div class="tooltip">Security check
  <span class="tooltiptext">Audit logs, updated apps, license usage, old users with licenses, secure score, non-compliant devices, AV and firewall alerts, outdated machines, failed sign-ins, failed app installs, app protection issues, apple cert expiry - Plus PDF export</span>
</div></li>
<li>
					<div class="tooltip">App deployment
  <span class="tooltiptext">Uses Winget community repo or custom manifest files</span>
</div></li>
<li>API to output to your own systems</li>
                    </ul>
					<h2>All multi-customer, multi-tenant</h2>
	</div>




<?php
include "footer.php";
?>