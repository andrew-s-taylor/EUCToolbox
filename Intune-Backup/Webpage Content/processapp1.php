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


			<h2>Deploy App - Select Tenant</h2>
			
			<div class="block">
                <?php
//Get Form Data
$appidsent = $_POST['appid'];

//Split on ^
$appidarray = explode("^", $appidsent);
$appid = $appidarray[1];
$appname = $appidarray[0];

// Retrieve additional account info from the database because we don't have them stored in sessions
$stmt = $con->prepare('SELECT ID, tenantname, tenantid FROM tenants WHERE ownerid = ?');
// In this case, we can use the account ID to retrieve the account info.
$stmt->bind_param('i', $_SESSION['id']);
$stmt->execute();
$result = $stmt->get_result();

/* Get the number of rows */
$num_of_rows = $result->num_rows;
?>
<table class="styled-table">
<form action="processapp2.php" method="post">
    <input type="hidden" name="appid" value="<?php echo $appid; ?>">
    <input type="hidden" name="appname" value="<?php echo $appname; ?>">
    <tr><td>
    <select name='tenantid[]' multiple>
    
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
	   <tr><td colspan="2">	   <label for="checkbox">Custom Group Name?:</label>
    <input type="checkbox" id="checkbox" name="grpcheck" onchange="toggleTextField()">
    <div id="textfield" style="display: none;">
        <label for="text">Install Group Name:</label>
        <input type="text" id="installgroupname" name="installgroupname">
		<br>
		<label for="text">Uninstall Group Name:</label>
        <input type="text" id="uninstallgroupname" name="uninstallgroupname">
    </div>
    <script>
        function toggleTextField() {
            var checkbox = document.getElementById("checkbox");
            var textfield = document.getElementById("textfield");
            if (checkbox.checked) {
                textfield.style.display = "block";
            } else {
                textfield.style.display = "none";
            }
        }
    </script></td></tr>
        	   <tr><td colspan="2">	   <label for="checkbox">Make Available for users?:</label>
    <input type="checkbox" id="checkbox" name="useravailable">
</td></tr>
<tr>
<td colspan="2">	   <label for="checkbox">Make Available for devices?:</label>
    <input type="checkbox" id="checkbox" name="deviceavailable">
</td>
</tr>
    <td><input class="profile-btn" type="submit" value="Next"></td></tr>
    </form>
    </table>
				
    </div>
            
    <?php
include "footer.php";
?>