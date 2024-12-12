<?php
/**
 * This file is part of a GPL-licensed project.
 *
 * Copyright (C) 2024 Andrew Taylor (andrew.taylor@andrewstaylor.com)
 * A special thanks to David at Codeshack.io for the basis of the login system!
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://github.com/andrew-s-taylor/public/blob/main/LICENSE>.
 */
?>
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