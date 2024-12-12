<?php
include 'main.php';
// Check logged-in
check_loggedin($con);
// output message (errors, etc)
$msg = '';

if ($canmanagedrift == 0) {
    echo "You do not have access to view this page";
    exit;
  }

// Retrieve additional account info from the database because we don't have them stored in sessions
$stmt = $con->prepare('SELECT role FROM accounts WHERE id = ?');
// In this case, we can use the account ID to retrieve the account info.
$stmt->bind_param('i', $_SESSION['id']);
$stmt->execute();
$stmt->bind_result($role);
$stmt->fetch();
$stmt->close();

$type = $_POST['type'];
$tenantid = $_POST['tenantid'];
$policyname = $_POST['policyname'];
$policyuri = $_POST['policyuri'];
$ownerid = $_POST['ownerid'];
$policyjson = base64_decode($_POST['policyjson']);
?>
<?php
$sitename = "Intune Manager from EUC Toolbox";
$pagetitle = "Intune Manager";
include "header1.php";
?>
			<h2>Check Drift - Results</h2>
			
			<div class="block">
            <table class="styled-table">
                <tr><td>JSON</td></tr>
<form action="createpolicy.php" method="POST">
<input type = "hidden" name="type" value="<?php echo $type; ?>">
<input type = "hidden" name="tenantid" value="<?php echo $tenantid; ?>">
<input type = "hidden" name="policyuri" value="<?php echo $policyuri; ?>">
<input type = "hidden" name="ownerid" value="<?php echo $ownerid; ?>">
<input type="hidden" name="policyname" value="<?php echo $policyname; ?>">
<tr>
<td>
<textarea name="policyjson" cols="80" rows="20"><?php echo $policyjson; ?></textarea>
</td></tr>
<tr><td colspan="2"><input type="submit" value="Submit"></td></tr>

</form>





<?php
include "footer.php";
?>