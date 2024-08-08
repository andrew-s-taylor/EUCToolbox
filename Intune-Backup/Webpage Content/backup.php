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

			<h2>Backup - Select Tenant</h2>
			
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
<table class="styled-table">
<form action="process.php" method="post">
<input type="hidden" name="type" value="backup">

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
    <td><input class="profile-btn" type="submit" value="Backup"></td></tr>
    </form>
    </table>
				

			</div>
            
	
			<?php
include "footer.php";
?>