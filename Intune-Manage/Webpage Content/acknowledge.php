<?php
include 'main.php';
// Check logged-in
check_loggedin($con);
// Handle edit profile post data
if (isset($_POST['type'])) {
	//DO FORM STUFF
switch ($_POST['type']) {
    case "delete":
        //Get tenantID and policyname from ID
                // Get tenantID and policyname from ID
                $stmt = $con->prepare('SELECT tenantid, policyname FROM driftack WHERE ID = ?');
                $stmt->bind_param('i', $_POST['ID']);
                $stmt->execute();
                $stmt->bind_result($tenantID, $policyname);
                $stmt->fetch();
                $stmt->close();

        //DELETE
        $stmt = $con->prepare('DELETE FROM driftack WHERE ID = ?');
        $stmt->bind_param('i', $_POST['ID']);
        $stmt->execute();
        $stmt->close();

        $auditlog_userID = $_SESSION['id'];
        $auditlog_ipAddress = $_SERVER['REMOTE_ADDR'];
        $auditlog_timestamp = date('Y-m-d H:i:s');
        $auditlog_message = "Drift acknowledgement $policyname deleted for $tenantID";
        $stmt = $con->prepare('INSERT INTO auditlog (UserID, IPAddress, Timestamp, Task) VALUES (?, ?, ?, ?)');
        $stmt->bind_param('isss', $auditlog_userID, $auditlog_ipAddress, $auditlog_timestamp, $auditlog_message);
        $stmt->execute();
        $stmt->close();
        break;
    case "add":
        //ADD
        $stmt = $con->prepare('INSERT INTO driftack (tenantid, policyname, ownerid) VALUES (?, ?, ?)');
        $stmt->bind_param('ssi', $_POST['tenantid'], $_POST['policyname'], $_POST['ownerid']);
        $stmt->execute();
        $stmt->close();
        $policyname = $_POST['policyname'];
        $tenantid = $_POST['tenantid'];
        $auditlog_userID = $_SESSION['id'];
        $auditlog_ipAddress = $_SERVER['REMOTE_ADDR'];
        $auditlog_timestamp = date('Y-m-d H:i:s');
        $auditlog_message = "Drift acknowledgement $policyname added for $tenantid";
        $stmt = $con->prepare('INSERT INTO auditlog (UserID, IPAddress, Timestamp, Task) VALUES (?, ?, ?, ?)');
        $stmt->bind_param('isss', $auditlog_userID, $auditlog_ipAddress, $auditlog_timestamp, $auditlog_message);
        $stmt->execute();
        $stmt->close();
        break;
    }

}

header('Location: home.php?updatemessage=Drift Policy Updated');
?>