<?php
include 'main.php';
// Check logged-in
check_loggedin($con);
// Handle edit profile post data
if (isset($_POST['type'])) {
	//DO FORM STUFF
switch ($_POST['type']) {
    case "delete":
        //DELETE
        $stmt = $con->prepare('DELETE FROM driftack WHERE ID = ?');
        $stmt->bind_param('i', $_POST['ID']);
        $stmt->execute();
        $stmt->close();
        break;
    case "add":
        //ADD
        $stmt = $con->prepare('INSERT INTO driftack (tenantid, policyname, ownerid) VALUES (?, ?, ?)');
        $stmt->bind_param('ssi', $_POST['tenantid'], $_POST['policyname'], $_POST['ownerid']);
        $stmt->execute();
        $stmt->close();
        break;
    }

}

header('Location: home.php?updatemessage=Drift Policy Updated');
?>