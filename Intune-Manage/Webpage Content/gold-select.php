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
if ($cangolddeploy == 0) {
    echo "You do not have access to view this page";
    exit;
  }

?>
<?php
$sitename = "Intune Manager from EUC Toolbox";
$pagetitle = "Intune Manager";
include "header1.php";
?>

			<h2>Gold - Select</h2>
			
			<div class="block">

<?php    
if (isset($_GET['updatemessage'])) {
	//Display Process Messages
	echo $_GET['updatemessage'];
}

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
$stmt = $con->prepare('SELECT ID, email FROM accounts WHERE id = ?');
// In this case, we can use the account ID to retrieve the account info.
$stmt->bind_param('i', $_SESSION['id']);
$stmt->execute();
$result = $stmt->get_result();
}
else {
// Retrieve additional account info from the database because we don't have them stored in sessions
$stmt = $con->prepare('SELECT ID, email FROM accounts WHERE (primaryid = ? OR primaryadmin = ?) AND role != "SubAdmin"');
// In this case, we can use the account ID to retrieve the account info.
if ($role2 == "SubAdmin") {
    $stmt->bind_param('ii', $primaryadmin, $primaryadmin);
}
else {
$stmt->bind_param('ii', $_SESSION['id'], $_SESSION['id']);
}
$stmt->execute();
$result = $stmt->get_result();
}


/* Get the number of rows */
$num_of_rows = $result->num_rows;
?>
<table class="styled-table">
<form action="gold.php" method="post">
    <tr><td>
    <select name='customerid'>
    
<?php
while ($row = $result->fetch_assoc()) {
    //Pass the URL as the value
    $profileid = $row['ID'];
    $profilename = $row['email'];
    echo "<option value='$profileid'>$profilename</option>";

}
    $stmt->close();
    ?>
    </select>
       </td>
    <td><input class="profile-btn" type="submit" value="Select"></td></tr>
    </form>
    </table>
				

			</div>
            
<?php
include "footer.php";
?>