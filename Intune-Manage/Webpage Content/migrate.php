<?php
include 'main.php';
// Check logged-in
check_loggedin($con);
// output message (errors, etc)
$msg = '';

if ($canmigrate == 0) {
    echo "You do not have access to view this page";
    exit;
  }
?>
<?php
$sitename = "Intune Manager from EUC Toolbox";
$pagetitle = "Intune Manager";
include "header1.php";
?>

			<h2>Migrate - Select Tenant</h2>
			
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
$stmt = $con->prepare('SELECT ID, tenantname, tenantid, customerid FROM tenants WHERE ownerid = ?');
// In this case, we can use the account ID to retrieve the account info.
$stmt->bind_param('i', $_SESSION['id']);
$stmt->execute();
$result = $stmt->get_result();
}
else {
// Retrieve additional account info from the database because we don't have them stored in sessions
$stmt = $con->prepare('SELECT ID, tenantname, tenantid, customerid FROM tenants WHERE customerid = ?');
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
?>
<table class="styled-table">
<form action="process.php" method="post">
<input type="hidden" name="type" value="migrate">

    <tr><td>Source: 
    <select name='tenantidsource'>
    
<?php
while ($row = $result->fetch_assoc()) {
    //Pass the URL as the value
    $tenantname = $row['tenantname'];
    $tenantid = $row['tenantid'];
	$customerid = $row['customerid'];
    echo "<option value='$tenantid'>$tenantname</option>";

}
    ?>
    </select>
       </td>
       <td>Destination:
    <select name='tenantiddestination'>
    
<?php
    $stmt->close();
if ($role2 != 'Admin' && $role2 != 'SuperAdmin' && $role2 != 'SubAdmin') {
    // Retrieve additional account info from the database because we don't have them stored in sessions
    $stmt = $con->prepare('SELECT ID, tenantname, tenantid, customerid FROM tenants WHERE ownerid = ?');
    // In this case, we can use the account ID to retrieve the account info.
    $stmt->bind_param('i', $_SESSION['id']);
    $stmt->execute();
    $result = $stmt->get_result();
    }
    else {
    // Retrieve additional account info from the database because we don't have them stored in sessions
    $stmt = $con->prepare('SELECT ID, tenantname, tenantid, customerid FROM tenants WHERE customerid = ?');
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
while ($row = $result->fetch_assoc()) {
    //Pass the URL as the value
    $tenantname = $row['tenantname'];
    $tenantid = $row['tenantid'];
	$customerid = $row['customerid'];
    echo "<option value='$tenantid'>$tenantname</option>";

}
    $stmt->close();
    ?>
    </select>
       </td>
    <td><input class="profile-btn" type="submit" value="Initial Migration"></td>
<td> <button type="submit" formaction="deltasync.php" class="button">Delta Sync</button></td></tr>
    </form>
    </table>
				

			</div>
            
	
			<?php
include "footer.php";
?>