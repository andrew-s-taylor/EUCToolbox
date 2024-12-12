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
if (isset($_POST['accountid'])) {
$id = $_POST['accountid'];

$stmt = $con->prepare('SELECT * FROM accounts WHERE (primaryid = ? OR primaryadmin = ?) AND id = ?');
$stmt->bind_param('iii', $_SESSION['id'], $_SESSION['id'], $id);
$stmt->execute();
$result = $stmt->get_result();
if (($result->num_rows > 0) || ($id == $_SESSION['id'])){

    //Grab the email from the ID
    if ($row = $result->fetch_assoc()) {
        $adminemail = $row['email'];
    }
                            $auditlog_userID = $_SESSION['id'];
                            $auditlog_ipAddress = $_SERVER['REMOTE_ADDR'];
                            $auditlog_timestamp = date('Y-m-d H:i:s');
                            $auditlog_message = "Account deleted: " . $adminemail;
                            $stmt = $con->prepare('INSERT INTO auditlog (UserID, IPAddress, Timestamp, Task) VALUES (?, ?, ?, ?)');
                            $stmt->bind_param('isss', $auditlog_userID, $auditlog_ipAddress, $auditlog_timestamp, $auditlog_message);
                            $stmt->execute();
                            $stmt->close();
    // Account found, proceed with deletion
    $stmt = $con->prepare('DELETE FROM accounts WHERE id = ?');
    $stmt->bind_param('i', $id);
    $stmt->execute();
    $stmt = $con->prepare('DELETE FROM tenants WHERE ownerid = ?');
    $stmt->bind_param('i', $id);
    $stmt->execute();
    if ($id == $_SESSION['id']) {
        header('Location: logout.php');
    } else {
        header('Location: profile.php?updatemessage=account%20deleted');
    }
} else {
    // Account not found, redirect to profile page
    header('Location: profile.php');
}

}
else {
    header('Location: profile.php');
}

?>