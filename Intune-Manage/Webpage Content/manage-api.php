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

if ($canmanageapi == 0) {
    echo "You do not have access to view this page";
    exit;
  }
?>
<?php
$sitename = "Intune Manager from EUC Toolbox";
$pagetitle = "Intune Manager";
include "header1.php";
?>

			<h2>Manage 3rd Party API Integrations</h2>
			
			<div class="block">
<?php    
$stmt = $con->prepare('SELECT role FROM accounts WHERE id = ?');
// Get the account info using the logged-in session ID
$stmt->bind_param('i', $_SESSION['id']);
$stmt->execute();
$stmt->bind_result($role2);
$stmt->fetch();
$stmt->close();
// Check if the user is an admin...
if ($role2 != 'Admin' && $role2 != 'SuperAdmin' && $role2 != 'SubAdmin') {
// Retrieve additional account info from the database because we don't have them stored in sessions
$stmt = $con->prepare('SELECT * FROM api_integrations WHERE accountID = ?');
// In this case, we can use the account ID to retrieve the account info.
$stmt->bind_param('i', $_SESSION['id']);
$stmt->execute();
$result = $stmt->get_result();
}
else {
// Retrieve additional account info from the database because we don't have them stored in sessions
$stmt = $con->prepare('SELECT * FROM api_integrations WHERE accountID = ?');
// In this case, we can use the account ID to retrieve the account info.
if ($role2 == "SubAdmin") {
	$stmt->bind_param('i', $primaryadmin);
}
else {
// In this case, we can use the account ID to retrieve the account info.
$stmt->bind_param('i', $_SESSION['id']);
}
$stmt->execute();
$result = $stmt->get_result();	
}

/* Get the number of rows */
$num_of_rows = $result->num_rows;

if ($num_of_rows == 0) {
//Add a new integration
?>
<form action="process-api.php" method="post">
    <input type="hidden" name="accountID" value="<?php echo $_SESSION['id']; ?>">
    <input type="hidden" name="type" value="new">
<table class="styled-table">
<tr><td>API Name</td><td>API Secret</td><td>API Client ID</td></tr>
<tr><td>
<select name="api_name">
<?php
$api_stmt = $con->prepare('SELECT Name FROM api_availability');
$api_stmt->execute();
$api_result = $api_stmt->get_result();
while ($api_row = $api_result->fetch_assoc()) {
    echo '<option value="' . htmlspecialchars($api_row['Name']) . '">' . htmlspecialchars($api_row['Name']) . '</option>';
}
$api_stmt->close();
?>
</select></td>
<td><input type="text" name="api_secret"></td>
<td><input type="text" name="api_clientID"></td>
</tr>
<tr><td><input class="profile-btn" type="submit" value="Add"></td></tr>
</table>
</form>
<?php
  
}
else {
?>
<h1>Add integration</h1>
<form action="process-api.php" method="post">
    <input type="hidden" name="accountID" value="<?php echo $_SESSION['id']; ?>">
    <input type="hidden" name="type" value="new">
<table class="styled-table">
<tr><th>API Name</th><th>API Secret</th><th>API Client ID</th></tr>
<tr><td>
<select name="api_name">
<?php
$api_stmt = $con->prepare('SELECT Name FROM api_availability');
$api_stmt->execute();
$api_result = $api_stmt->get_result();
while ($api_row = $api_result->fetch_assoc()) {
    echo '<option value="' . htmlspecialchars($api_row['Name']) . '">' . htmlspecialchars($api_row['Name']) . '</option>';
}
$api_stmt->close();
?>
</select></td>
<td><input type="text" name="api_secret"></td>
<td><input type="text" name="api_clientID"></td>
</tr>
<tr><td><input class="profile-btn" type="submit" value="Add"></td></tr>
</table>
</form>
<h1>Update Integration</h1>
<table class="styled-table">
<tr><th>API Name</th><th>API Secret</th><th>API Client ID</th></tr>

<form action="process-api.php" method="post">

    
<?php
while ($row = $result->fetch_assoc()) {
    $decrypted = decryptstring($row['apisecret']);
// Output the data
?>
<tr><input type="hidden" name="id" value="<?php echo $row['ID']; ?>">
<input type="hidden" name="accountID" value="<?php echo $row['accountID']; ?>">
<input type="hidden" name="type" value="update">
<td><input type="text" name="api_name" value="<?php echo $row['apiName']; ?>" readonly></td>
<td><input type="password" name="api_secret" value="<?php echo $decrypted; ?>"></td>
<td><input type="text" name="api_clientID" value="<?php echo $row['clientID']; ?>"></td>
<?php

}

    ?>
    <td><input class="profile-btn" type="submit" value="Update"></td></tr>
    </form>
    </table>
		
    
    <h1>Delete Integration</h1>
<table class="styled-table">

    
<?php
$stmt->execute();
$result = $stmt->get_result();	
while ($row = $result->fetch_assoc()) {
    $decrypted = decryptstring($row['apisecret']);
// Output the data
?>
<form action="process-api.php" method="post" onsubmit="return confirm('Are you sure you want to delete this API integration?');">

<tr>        <input type="hidden" name="id" value="<?php echo $row['ID']; ?>">
        <input type="hidden" name="type" value="delete">
        <td><?php echo $row['apiName']; ?></td>
        <td><input class="profile-btn" type="submit" value="Delete"></td></tr>
        </form>
<?php

}

    ?>

    </table>

			</div>
            
	
			<?php
}
$stmt->close();
include "footer.php";
?>