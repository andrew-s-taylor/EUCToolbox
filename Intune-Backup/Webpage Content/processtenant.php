<?php
include 'main.php';
// Check logged-in
check_loggedin($con);
// Handle edit profile post data
if (isset($_POST['type'])) {
	//DO FORM STUFF
switch ($_POST['type']) {
    case "update":
        //UPDATE
        $stmt = $con->prepare('UPDATE tenants SET tenantname = ?, tenantid = ? WHERE ID = ?');
        $stmt->bind_param('ssi', $_POST['tenantname'], $_POST['tenantid'], $_POST['ID']);
        $stmt->execute();
        $stmt->close();
        break;
    case "delete":
        //DELETE
        $stmt = $con->prepare('DELETE FROM tenants WHERE ID = ?');
        $stmt->bind_param('i', $_POST['ID']);
        $stmt->execute();
        $stmt->close();
        break;
    case "add":
        //ADD
        $stmt = $con->prepare('INSERT INTO tenants (tenantname, tenantid, ownerid) VALUES (?, ?, ?)');
        $stmt->bind_param('ssi', $_POST['tenantname'], $_POST['tenantid'], $_POST['ownerid']);
        $stmt->execute();
        $stmt->close();
        break;
    }

}

header('Location: tenants.php?updatemessage=Tenant Updated');
?>