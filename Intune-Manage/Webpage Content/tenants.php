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

// Fetch account details associated with the logged-in user
$stmt = $con->prepare('SELECT password, email, role, primaryid, primaryadmin FROM accounts WHERE id = ?');
// Get the account info using the logged-in session ID
$stmt->bind_param('i', $_SESSION['id']);
$stmt->execute();
$stmt->bind_result($password, $email, $role, $primaryid, $primaryadmin);
$stmt->fetch();
$stmt->close();

if ($canmanagetenants == 0) {
    echo "You do not have access to view this page";
    exit;
}
?>
<?php
$sitename = "Intune Manager from EUC Toolbox";
$pagetitle = "Intune Manager";
include "header1.php";
?>
        <p>
	<?php
if (isset($_GET['updatemessage'])) {
	//Display Process Messages
	echo $_GET['updatemessage'];
}

$tenantidposted = $_GET['tenant'];
	?>
</p>
			<h2>Edit Tenants</h2>
			
			<div class="block">
<?php    
// Check if the user is an admin...
if ($role != 'Admin' && $role != 'SuperAdmin' && $role != 'SubAdmin') {
    // Retrieve additional account info from the database because we don't have them stored in sessions
$stmt = $con->prepare('SELECT ID, tenantname, tenantid, customerid, ownerid FROM tenants WHERE ownerid = ?');
// In this case, we can use the account ID to retrieve the account info.
$stmt->bind_param('i', $_SESSION['id']);
$stmt->execute();
$result = $stmt->get_result();
}
else {
// Retrieve additional account info from the database because we don't have them stored in sessions
$stmt = $con->prepare('SELECT ID, tenantname, tenantid, customerid, ownerid FROM tenants WHERE customerid = ?');
// In this case, we can use the account ID to retrieve the account info.
if ($role == "SubAdmin") {
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
echo "<table class=\"styled-table\">";
while ($row = $result->fetch_assoc()) {
    $ownerid = $row['ownerid'];
    $currentcustomer = $row['customerid'];
    ?>
   <tr>
   <form action="processtenant.php" method="post">
    <input type = "hidden" name="ID" value="<?php echo $row['ID']; ?>">
    <input type = "hidden" name="type" value="update">
    <td>Tenant Name: <input type="text" name="tenantname" value="<?php echo $row['tenantname']; ?>"></td>
    <td>Tenant ID: <input type="text" name="tenantid" value="<?php echo $row['tenantid']; ?>"></td>
    <?php
    if ($role == 'Admin' || $role == 'SuperAdmin' || $role == 'SubAdmin') {
//Grab all customers assigned to the owner
$stmt1 = $con->prepare('SELECT id, email FROM accounts WHERE primaryid = ?');
if ($role == "SubAdmin") {
    $stmt1->bind_param('i', $primaryadmin);
}
else {
// In this case, we can use the account ID to retrieve the account info.
$stmt1->bind_param('i', $_SESSION['id']);
}
$stmt1->execute();
$result1 = $stmt1->get_result();
?>
<td>Customer: <select name='customerid'>
<?php
while ($row2 = $result1->fetch_assoc()) {
    //Pass the URL as the value
    $customerid = $row2['id'];
    $customername = $row2['email'];

    echo "<option value='$customerid'";
    //Show current as selected
    
    echo ">$customername</option>";
}
$stmt1->close();
$stmt2 = $con->prepare('SELECT email FROM accounts WHERE id = ?');
$stmt2->bind_param('i', $ownerid);
$stmt2->execute();
$stmt2->bind_result($email2);
$stmt2->fetch();
$stmt2->close();
echo "<option value='$customerid'";
echo " selected";
echo ">$email2</option>";
?>
</select></td>
<?php
    }
    else {
        ?>
        <input type = "hidden" name="customerid" value="<?php 
        		if ($role == "SubAdmin") {
                 echo $primaryadmin;
                }
                else {
                // In this case, we can use the account ID to retrieve the account info.
                echo $_SESSION['id'];
                }
                ?>">
        <?php
    }
    ?>
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
    <input type = "hidden" name="customerid" value="<?php echo $row['customerid']; ?>">
    <input type = "hidden" name="testtype" value="graph">
    <input class="profile-btn" type="submit" value="Test Connection">
</form>
    </td>
    <td>
    <form action="tenantsend.php" method="post">
    <input type="hidden" name="type" value="refresh">
    <input class="profile-btn" type="submit" value="Refresh">
</form>
    </td>
    <?php if ($regtype == 'paid' && $cangolddeploy == 1): ?>
        <td>
            <form action="deployintune.php" method="post">
                <input type="hidden" name="tenantid" value="<?php echo $row['tenantid']; ?>">
                <input type="hidden" name="customerid" value="intunemanage">
                <input class="profile-btn" type="submit" value="Deploy Intune">
            </form>
        </td>
    <?php endif; ?>
   </tr>

    <?php
}
    $stmt->close();
    ?>
    </table>
				

			</div>
            <?php
                if ($role == 'Admin' || $role == 'SuperAdmin' || $role == 'SubAdmin') {
if (isset($tenantidposted)) {

?>

            <h2>Add New Tenant</h2>
    <div class="block">
        <table class="styled-table">
    <form action="processtenant.php" method="post">
    <input type = "hidden" name="type" value="add">
    <input type = "hidden" name="ownerid" value="<?php 
        		if ($role == "SubAdmin") {
                 echo $primaryadmin;
                }
                else {
                // In this case, we can use the account ID to retrieve the account info.
                echo $_SESSION['id'];
                }
                ?>">
<tr>
<?php
//Grab all customers assigned to the owner
$stmt = $con->prepare('SELECT id, email FROM accounts WHERE primaryid = ?');
if ($role == "SubAdmin") {
    $stmt->bind_param('i', $primaryadmin);
}
else {
// In this case, we can use the account ID to retrieve the account info.
$stmt->bind_param('i', $_SESSION['id']);
}
$stmt->execute();
$result = $stmt->get_result();
?>
<td>Customer: <select name='customerid'>
<?php
while ($row2 = $result->fetch_assoc()) {
    //Pass the URL as the value
    $customerid = $row2['id'];
    $customername = $row2['email'];
    echo "<option value='$customerid'";
    echo ">$customername</option>";
}
$stmt->close();
?>
</select></td>
<?php

?>
    <td><input type="text" value="<?php
    if(isset($tenantidposted)) {
        echo $tenantidposted;
    }
    else {
        echo "tenantid";
    }

    
    ?>" name="tenantid" id="tenantid" placeholder="tenantid"></td>
    <td><input type="tenantname" name="tenantname" id="tenantname" placeholder="tenantname"></td>
    <td><input class="profile-btn" type="submit" value="Add"></td>
</tr>

</table>
</form>

    </div>
<div>
   <?php
}
else {
    ?>
<h2>Onboard a Tenant</h2>
<table class="styled-table"><tr><td>
<form action="tenantsend.php" method="post">
    <input type="hidden" name="type" value="new">
    <input class="profile-btn" type="submit" value="Onboard">
</form>
</td></tr></table>

<?php
}
                }
                ?>

<p><?=$msg?></p>


		</div>
            
	
        <?php
include "footer.php";
?>