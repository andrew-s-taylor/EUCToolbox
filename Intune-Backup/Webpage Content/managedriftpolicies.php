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
			<h2>Edit Drift Acknowledgements</h2>
			
			<div class="block">
<?php    
// Retrieve additional account info from the database because we don't have them stored in sessions
$stmt = $con->prepare('SELECT ID, policyname, tenantid FROM driftack WHERE ownerid = ?');
// In this case, we can use the account ID to retrieve the account info.
$stmt->bind_param('i', $_SESSION['id']);
$stmt->execute();
$result = $stmt->get_result();

/* Get the number of rows */
$num_of_rows = $result->num_rows;
if ($num_of_rows == 0) {
    echo "No drift acknowledgements found.";
}
else {
echo "<table>";
while ($row = $result->fetch_assoc()) {
    ?>
   <tr>
   <form action="acknowledge.php" method="post">
    <input type = "hidden" name="ID" value="<?php echo $row['ID']; ?>">
    <input type = "hidden" name="type" value="delete">
    <td>Policy Name: <?php echo $row['policyname']; ?></td>
    <td>Tenant ID: <?php echo $row['tenantid']; ?></td>
    <td>
    <input class="profile-btn" type="submit" value="Delete">
</form>
    </td>
   </tr>

    <?php
}
    $stmt->close();
}
    ?>
    </table>
				

			</div>

    </div>
<div>


		</div>
            
	
        <?php
include "footer.php";
?>