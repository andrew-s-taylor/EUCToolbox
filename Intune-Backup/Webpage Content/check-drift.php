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

			<h2>Check Drift - Select Tenant</h2>
			
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
?>
<h2>Drift from previous backup</h2>
<table class="styled-table">
<form action="displaydrift.php" method="post">
<input type="hidden" name="type" value="backup">

    <tr><td>
    <select name='tenantid'>
    
<?php
while ($row = $result->fetch_assoc()) {
    //Pass the URL as the value
    $tenantname = $row['tenantname'];
    $tenantid = $row['tenantid'];
    echo "<option value='$tenantid'>$tenantname</option>";

}
    $stmt->close();
    ?>
    </select>
       </td>
    <td><input class="profile-btn" type="submit" value="Check"></td></tr>
    </form>
    </table class="styled-table">
				<h2>Golden Tenant Comparison</h2>
    <table class="styled-table">
<form action="displaydrift.php" method="post">
<input type="hidden" name="type" value="gold">

    <tr><td>
    <select name='tenantid'>
    
<?php
// Retrieve additional account info from the database because we don't have them stored in sessions
$stmt = $con->prepare('SELECT ID, tenantname, tenantid FROM tenants WHERE ownerid = ?');
// In this case, we can use the account ID to retrieve the account info.
$stmt->bind_param('i', $_SESSION['id']);
$stmt->execute();
$result = $stmt->get_result();

/* Get the number of rows */
$num_of_rows = $result->num_rows;
while ($row = $result->fetch_assoc()) {
    //Pass the URL as the value
    $tenantname = $row['tenantname'];
    $tenantid = $row['tenantid'];
    echo "<option value='$tenantid'>$tenantname</option>";

}
    $stmt->close();
    ?>
    </select>
       </td>
       <td class="tableButton"><input class="profile-btn" type="submit" value="Check"></td></tr>
    </form>
    </table>
			</div>
            
            Manage Drift acknoledgements <a href="managedriftpolicies.php"><button class="button">here</button></a>
            <br>
            <table class="styled-table">
                <tr>
                <td class="tableButton">
<form action="cron.php" method="post">
<input type="hidden" name="owner" value="<?php echo $_SESSION['id']; ?>">
<input class="profile-btn" type="submit" value="Run manual drift check">
    </form>
</td>
                </tr>



	
    <?php
include "footer.php";
?>