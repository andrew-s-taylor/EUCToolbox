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


if ($canviewlogs == 0) {
  exit('You do not have permission to access this page!');
}


function adjustTimezoneOffset($time, $offset) {
  // Convert the timezone offset to the correct format for DateInterval
  $hours = floor(abs($offset) / 60);
  $minutes = abs($offset) % 60;
  $timezoneInterval = new DateInterval('PT' . $hours . 'H' . $minutes . 'M');

  // Create a DateTime object for the input time
  $dateTime = new DateTime($time);

  // Add or subtract the timezone offset from the input time
  if ($offset < 0) {
      $dateTime->sub($timezoneInterval);
  } else {
      $dateTime->add($timezoneInterval);
  }

  // Format the adjusted time as a string
  $adjustedTime = $dateTime->format('l, F jS Y - H:i');

  return $adjustedTime;
}

$sitename = "Intune Manager from EUC Toolbox";
$pagetitle = "Intune Manager";
include "header1.php";

?>
			<h2>Audit Logs</h2>
			
			<div class="block">

<table class="styled-table">
    <thead>
        <tr>
            <th>Task</th>
            <th>Timestamp</th>
            <th>Email</th>
            <th>IP Address</th>
        </tr>
    </thead>
    <tbody>
    <?php
    $stmt = $con->prepare('SELECT role FROM accounts WHERE id = ?');
    // Get the account info using the logged-in session ID
    $stmt->bind_param('i', $_SESSION['id']);
    $stmt->execute();
    $stmt->bind_result($role2);
    $stmt->fetch();
    $stmt->close();
    if ($role2 != 'Admin' && $role2 != 'SuperAdmin' && $role2 != 'SubAdmin') {
            $stmt = $con->prepare('SELECT auditlog.id, auditlog.timestamp, auditlog.Task, auditlog.IPAddress, accounts.email FROM auditlog INNER JOIN accounts ON auditlog.UserID = accounts.id WHERE auditlog.UserID = ? AND auditlog.timestamp >= DATE_SUB(NOW(), INTERVAL 30 DAY)');
            $stmt->bind_param('i', $_SESSION['id']);
            $stmt->execute();
            $stmt->bind_result($auditlogId, $timestamp, $task, $aip, $email);

            while ($stmt->fetch()) {
                    // Convert the timestamp to the adjusted timezone
                    $adjustedTimestamp = adjustTimezoneOffset($timestamp, $timezoneOffset);

                    // Display the audit log details
                    echo "<tr>";
                    echo "<td>$task</td>";
                    echo "<td>$adjustedTimestamp</td>";
                    echo "<td>$email</td>";
                    echo "<td>$aip</td>";
                    echo "</tr>";
            }

            $stmt->close();

    }
    else {
        //If account is a SubAdmin, grab the primary admin
        if ($role2 == "SubAdmin") {
            $lookup = $primaryadmin;
        }
        else {
            $lookup = $_SESSION['id'];
        }
        $stmt = $con->prepare('SELECT auditlog.id, auditlog.timestamp, auditlog.Task, auditlog.IPAddress, accounts.email FROM auditlog INNER JOIN accounts ON auditlog.UserID = accounts.id WHERE auditlog.UserID = ? OR (accounts.primaryid = ? OR accounts.primaryadmin = ?)');
        $stmt->bind_param('iii', $lookup, $lookup, $lookup);
        $stmt->execute();
        $stmt->bind_result($auditlogId, $timestamp, $task, $aip, $email);

        while ($stmt->fetch()) {
            // Convert the timestamp to the adjusted timezone
            $adjustedTimestamp = adjustTimezoneOffset($timestamp, $timezoneOffset);

            // Display the audit log details
            echo "<tr>";
            echo "<td>$task</td>";
            echo "<td>$adjustedTimestamp</td>";
            echo "<td>$email</td>";
            echo "<td>$aip</td>";
            echo "</tr>";
        }

        $stmt->close();

    }
    ?>
    </tbody>

</table>


			</div>
            
	
      <?php
include "footer.php";
?>