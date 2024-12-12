<?php
include 'main.php';
// Check logged-in
check_loggedin($con);
// output message (errors, etc)
$msg = '';
// Retrieve additional account info from the database because we don't have them stored in sessions
$stmt = $con->prepare('SELECT role FROM accounts WHERE id = ?');
// In this case, we can use the account ID to retrieve the account info.
$stmt->bind_param('i', $_SESSION['id']);
$stmt->execute();
$stmt->bind_result($role);
$stmt->fetch();
$stmt->close();
if ($cancheckdrift == 0) {
    exit('You do not have permission to access this page!');
  }
?>
<?php
$sitename = "Intune Manager from EUC Toolbox";
$pagetitle = "Intune Manager";
include "header1.php";
?>

			<h2>Check Drift - Select Tenant</h2>
			
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
	$customerid = $row['customerid'];
    echo "<option value='$tenantid%%$customerid'>$tenantname</option>";

}
    $stmt->close();
    ?>
    </select>
       </td>
    <td><input class="profile-btn" type="submit" value="Check"></td></tr>
    </form>
    </table>
				<h2>Golden Tenant Comparison</h2>
    <table class="styled-table">
<form action="displaydrift.php" method="post">
<input type="hidden" name="type" value="gold">
    <tr><td>
    <select name='tenantid'>
    
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
while ($row = $result->fetch_assoc()) {
    //Pass the URL as the value
    $tenantname = $row['tenantname'];
    $tenantid = $row['tenantid'];
	$customerid = $row['customerid'];
    echo "<option value='$tenantid%%$customerid'>$tenantname</option>";
}
    $stmt->close();
    ?>
    </select>
       </td>
    <td><input class="profile-btn" type="submit" value="Check"></td></tr>
    </form>
    </table>
			</div>
            <?php if ($canmanagedrift == 1): ?>
            Manage Drift acknoledgements <a href="managedriftpolicies.php"><button class="button">Here</button></a>
            <?php endif; ?>
            <br>
<form action="cron.php" method="post">
    <table class="styled-table"><tr><td>
<input type="hidden" name="owner" value="<?php 
                if ($role2 == "SubAdmin") {
                 echo $primaryadmin;
                }
                else {
                // In this case, we can use the account ID to retrieve the account info.
                echo $_SESSION['id'];
                }
                ?>">
<button class="profile-btn" type="button" onclick="runManualDriftCheck()">Run manual drift check</button>
</td></tr></table>
</form>

<script>
function runManualDriftCheck() {
    alert('Manual drift check initiated.');
    const owner = document.querySelector('input[name="owner"]').value;
    const formData = new FormData();
    formData.append('owner', owner);

    fetch('cron.php', {
        method: 'POST',
        body: formData
    })
    .then(response => response.text())
    .then(data => {
        
    })
    .catch(error => {
        console.error('Error:', error);
     
    });
}
</script>


	
    <?php
include "footer.php";
?>
</html>