<?php
include 'main.php';
// Check logged-in
check_loggedin($con);
// output message (errors, etc)
$msg = '';


?>
<?php
$sitename = "Intune Manager from EUC Toolbox";
$pagetitle = "Intune Manager";
include "header1.php";
?>

			<h2>Profile - Select</h2>
			
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
if ($role2 != 'Admin' && $role2 != 'SuperAdmin') {
// Retrieve additional account info from the database because we don't have them stored in sessions
$stmt = $con->prepare('SELECT ID, email FROM accounts WHERE id = ?');
// In this case, we can use the account ID to retrieve the account info.
$stmt->bind_param('i', $_SESSION['id']);
$stmt->execute();
$result = $stmt->get_result();
}
else {

// Retrieve additional account info from the database because we don't have them stored in sessions
$stmt = $con->prepare('SELECT ID, email FROM accounts WHERE primaryid = ? OR primaryadmin = ?');
// In this case, we can use the account ID to retrieve the account info.
$stmt->bind_param('ii', $_SESSION['id'], $_SESSION['id']);
$stmt->execute();
$result = $stmt->get_result();
}


/* Get the number of rows */
$num_of_rows = $result->num_rows;
?>
<table class="styled-table">
<form action="profile.php" method="post">
<input type="hidden" name="type" value="backup">

    <tr><td>
    <select name='profileid'>
    
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
    <td><input class="profile-btn" type="submit" value="Edit"></td></tr>
    </form>
    </table>
				

			</div>
            <?php
			if ($role2 == 'Admin' || $role2 == 'SuperAdmin') {
				?>
				<table class="styled-table"><tr><td>
    <form action="add-profile.php" method="post">
        <input type="hidden" name="primaryid" value="<?php echo $_SESSION['id']; ?>">
        <input type="submit" value="Add new customer">
    </form>
			</td><td>
	<form action="add-admin.php" method="post">
        <input type="hidden" name="primaryadmin" value="<?php echo $_SESSION['id']; ?>">
        <input type="submit" value="Add new admin">
    </form>
	</td></tr></table>
	<?php
			}
			?>
<?php
include "footer.php";
?>