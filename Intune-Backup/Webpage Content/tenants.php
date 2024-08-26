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


?>
<?php
$sitename = "Intune Backup from EUC Toolbox";
$pagetitle = "Intune Backup";
include "header1.php";
?>
        <p>
	<?php
if (isset($_GET['updatemessage'])) {
	//Display Process Messages
	echo $_GET['updatemessage'];
}
	?>
</p>
			<h2>Edit Tenants</h2>
			
			<div class="block">
<?php    
// Retrieve additional account info from the database because we don't have them stored in sessions
$stmt = $con->prepare('SELECT ID, tenantname, tenantid FROM tenants WHERE ownerid = ?');
// In this case, we can use the account ID to retrieve the account info.
$stmt->bind_param('i', $_SESSION['id']);
$stmt->execute();
$result = $stmt->get_result();

/* Get the number of rows */
$num_of_rows = $result->num_rows;
echo "<table class=\"styled-table\">";
while ($row = $result->fetch_assoc()) {
    ?>
   <tr>
   <form action="processtenant.php" method="post">
    <input type = "hidden" name="ID" value="<?php echo $row['ID']; ?>">
    <input type = "hidden" name="type" value="update">
    <td>Tenant Name: <input type="text" name="tenantname" value="<?php echo $row['tenantname']; ?>"></td>
    <td>Tenant ID: <input type="text" name="tenantid" value="<?php echo $row['tenantid']; ?>"></td>
    <td><input class="profile-btn" type="submit" value="Update"></td>
    </form>
    <td>
    <form action="processtenant.php" method="post">
    <input type = "hidden" name="ID" value="<?php echo $row['ID']; ?>">
    <input type = "hidden" name="type" value="delete">
    <input class="profile-btn" type="submit" value="Delete">
</form>
    </td>
    <td>
    <form action="runtest.php" method="post">
    <input type = "hidden" name="tenantid" value="<?php echo $row['tenantid']; ?>">
    <input type = "hidden" name="testtype" value="graph">
    <input class="profile-btn" type="submit" value="Test Connection">
</form>
    </td>
   </tr>

    <?php
}
    $stmt->close();
    ?>
    </table>
				

			</div>
            <h2>Add New Tenant</h2>
    <div class="block">
        <table class="styled-table">
    <form action="processtenant.php" method="post">
    <input type = "hidden" name="type" value="add">
    <input type = "hidden" name="ownerid" value="<?php echo $_SESSION['id'] ?>">
<tr>
    <td><input type="text" value="tenantid" name="tenantid" id="tenantid" placeholder="tenantid"></td>
    <td><input type="tenantname" name="tenantname" id="tenantname" placeholder="tenantname"></td>
    <td><input class="profile-btn" type="submit" value="Add"></td>


</table>
</form>

    </div>
<div>
   
<h2>Onboard a Tenant</h2>
<?php
//Get App reg id
$stmt = $con->prepare('SELECT aadclient FROM accounts WHERE id = ?');
// In this case, we can use the account ID to retrieve the account info.
$stmt->bind_param('i', $_SESSION['id']);
$stmt->execute();
$stmt->bind_result($aadclient);
$stmt->fetch();
$stmt->close();

?>
<div class="block">
    <p>Use these details to onboard a tenant into your App Reg:</p>
    <p>Click this <a href="https://login.microsoftonline.com/organizations/v2.0/adminconsent?client_id=<?php echo $aadclient; ?>&scope=https://graph.microsoft.com/.default">Link</a></p>
    <p>Copy this link
<p><code>
https://login.microsoftonline.com/organizations/v2.0/adminconsent?client_id=<?php echo $aadclient; ?>&scope=https://graph.microsoft.com/.default
</code></p>
    </p>
    <p>Scan this code</p>
    <p><img src="https://quickchart.io/qr?text=https://login.microsoftonline.com/organizations/v2.0/adminconsent?client_id=<?php echo $aadclient; ?>&scope=https://graph.microsoft.com/.default"></img></p>
</div>

<p><?=$msg?></p>


		</div>
            
	
        <?php
include "footer.php";
?>