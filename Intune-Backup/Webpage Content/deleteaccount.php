<?php
include 'main.php';
// Check logged-in
check_loggedin($con);
// Handle edit profile post data
if (isset($_POST['accountid'])) {
$id = $_POST['accountid'];

$stmt = $con->prepare('DELETE FROM accounts WHERE id = ?');
$stmt->bind_param('i', $id);
$stmt->execute();
$stmt = $con->prepare('DELETE FROM tenants WHERE ownerid = ?');
$stmt->bind_param('i', $id);
$stmt->execute();
header('Location: logout.php');

}
else {
    header('Location: profile.php');
}

?>