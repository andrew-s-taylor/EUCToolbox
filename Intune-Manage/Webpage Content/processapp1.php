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
if ($candeployapps == 0) {
    exit('You do not have permission to access this page!');
  }
?>
<?php
$sitename = "Intune Manager from EUC Toolbox";
$pagetitle = "Intune Manager";
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
$appversion = $appidarray[2];

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
<form action="processapp2.php" method="post">
    <input type="hidden" name="appid" value="<?php echo $appid; ?>">
    <input type="hidden" name="appname" value="<?php echo $appname; ?>">
    <input type="hidden" name="appversion" value="<?php echo $appversion; ?>">

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
    <td><input class="profile-btn" type="submit" value="Deploy"></td></tr>
    </form>
    </table>
				
    </div>
            
    <?php
include "footer.php";
?>