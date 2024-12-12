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
// output message (errors, etc)
$msg = '';
// Retrieve additional account info from the database because we don't have them stored in sessions
$stmt = $con->prepare('SELECT role FROM accounts WHERE id = ?');
// In this case, we can use the account ID to retrieve the account info.
$stmt->bind_param('i', $_SESSION['id']);
$stmt->execute();
$stmt->bind_result($role);
$stmt->fetch();
$stmt->close();
if ($candeployapps == 0) {
    exit('You do not have permission to access this page!');
  }

?>
<?php
$sitename = "Intune Manager from EUC Toolbox";
$pagetitle = "Intune Manager";
include "header1.php";

// Connect to the MySQL database using MySQLi
$con2 = mysqli_connect(db_hostappaz, db_userappaz, db_passappaz, db_nameappaz);
// If there is an error with the MySQL connection, stop the script and output the error
if (mysqli_connect_errno()) {
	exit('Failed to connect to MySQL: ' . mysqli_connect_error());
}
// Update the charset
mysqli_set_charset($con2, db_charset);
?>

			<h2>Deploy Application - Select App</h2>
			
			<div class="block">
<html>
<head>
    <title>MyIntunePortal - Add App</title>

<body>
<h2>Winget Community Deployment</h2>
<form action="listapps.php" method="post">
    <input type="hidden" name="sent" value="confirm">
   <table class="styled-table">
    <tr><td colspan="2">
    <label for="appid">Select an app:</label>
<?php
// Retrieve data from the database
$query = "SELECT appid, appdisplayname, appversion FROM appsnew";
$result = mysqli_query($con2, $query);

// Check if the query was successful
if ($result) {
    // Create an array to store the data
    $apps = array();

    // Fetch the data and store it in the array
    while ($row = mysqli_fetch_assoc($result)) {
        $apps[] = $row;
    }

    // Sort the array by appname
    usort($apps, function($a, $b) {
        return $a['appdisplayname'] <=> $b['appdisplayname'];
    });

    // Loop through the array and create the select dropdown
    echo "<select name='appid' id='appid'>";
//If sent is confirmed, add selected app as first option here
$confirmed = $_POST['sent'];
if ($confirmed == "confirm") {
    $appidsent = $_POST['appid'];
    $appdetails = explode("^", $appidsent);
    $appid = $appdetails[0];
    $appname = $appdetails[1];
    $appversion = $appdetails[2];
    echo "<option value='" . $appidsent . "'>" . $appname . " - " . $appversion . "</option>";
}

    foreach ($apps as $app) {
        //If appdisplayname is blank, set to appid
        if ($app['appdisplayname'] == "") {
            $app['appdisplayname'] = $app['appid'];
        }
        // Combine the appid and appname into a single value
        $value = $app['appid'] . "^" . $app['appdisplayname'] . "^" . $app['appversion'];

        echo "<option value='" . $value . "'>" . $app['appdisplayname'] . " - " . $app['appversion'] . "</option>";
    }
    echo "</select>";
} else {
    // Handle the error if the query fails
    echo "Failed to retrieve data from the database.";
}

?>
</td>
</tr>
    <tr><td class="tableButton" colspan="2" align="center"><input class="profile-btn" type="submit" value="Show Details"></td></tr>
    </form>
    </table>

<?php
$confirmed = $_POST['sent'];
if ($confirmed == "confirm") {
    $appidsent = $_POST['appid'];
    $appdetails = explode("^", $appidsent);
    $appid = $appdetails[0];
    $appname = $appdetails[1];
    $appversion = $appdetails[2];
    ?>


    <h2>App Details</h2>
    <table class="styled-table">
    <tr>
        <td colspan="2">
            <h2>App Details</h2>
            <?php
            // Retrieve the selected app details from the database
            $query = "SELECT * FROM appsnew WHERE appid = '$appid' and appversion = '$appversion'";
            $result = mysqli_query($con2, $query);

            // Check if the query was successful
            if ($result && mysqli_num_rows($result) > 0) {
                $app = mysqli_fetch_assoc($result);
                // Display the app details in a table
                echo "<table>";
                echo "<tr><td>App ID:</td><td>" . $app['appid'] . "</td></tr>";
                echo "<tr><td>App Description:</td><td>" . $app['appdescription'] . "</td></tr>";
                echo "<tr><td>App Version:</td><td>" . $app['appversion'] . "</td></tr>";
                echo "<tr><td>App Scope:</td><td>" . $app['appscope'] . "</td></tr>";
                echo "<tr><td>App Display Name:</td><td>" . $app['appdisplayname'] . "</td></tr>";
                echo "<tr><td>App Publisher:</td><td>" . $app['apppublisher'] . "</td></tr>";
                echo "<tr><td>App Silent Command:</td><td>" . $app['appsilent'] . "</td></tr>";
                echo "<tr><td>App URL:</td><td>" . $app['apppackage'] . "</td></tr>";
                echo "<tr><td>App Architecture:</td><td>" . $app['apparchitecture'] . "</td></tr>";
                echo "<tr><td>App Info:</td><td>" . $app['appinfourl'] . "</td></tr>";
                echo "<tr><td>App Developer:</td><td>" . $app['appdeveloper'] . "</td></tr>";
                echo "<tr><td>App Owner:</td><td>" . $app['appowner'] . "</td></tr>";
                echo "</table>";
            } else {
                // Handle the error if the query fails or no app is found
                echo "Failed to retrieve app details.";
            }
            ?>
        </td>
    </tr>
</table>

    <form action="processapp1.php" method="post">
    <table class="styled-table">
        <tr><td>
    <input type="hidden" name="appid" value="<?php echo $appidsent; ?>">
<input type="submit" name="submit" value="Select Tenant"/>
</td>
            </tr>
        </table>
</form>

<?php
}
$stmt = $con->prepare('SELECT role FROM accounts WHERE id = ?');
// Get the account info using the logged-in session ID
$stmt->bind_param('i', $_SESSION['id']);
$stmt->execute();
$stmt->bind_result($role2);
$stmt->fetch();
$stmt->close();
// Check if the user is an admin...
if ($role2 != 'Admin' && $role2 != 'SuperAdmin' && $role2 != 'SubAdmin') {
// Retrieve additional account info from the database because we don't have them stored in sessions
$stmt = $con->prepare('SELECT ID, accountID, apiName, apisecret, clientID FROM api_integrations WHERE accountID = ?');
// In this case, we can use the account ID to retrieve the account info.
$stmt->bind_param('i', $_SESSION['id']);
$stmt->execute();
$result = $stmt->get_result();
}
else {
// Retrieve additional account info from the database because we don't have them stored in sessions
$stmt = $con->prepare('SELECT ID, accountID, apiName, apisecret, clientID FROM api_integrations WHERE accountID = ?');
// In this case, we can use the account ID to retrieve the account info.
if ($role2 == "SubAdmin") {
	$stmt->bind_param('i', $primaryadmin);
}
else {
// In this case, we can use the account ID to retrieve the account info.
$stmt->bind_param('i', $_SESSION['id']);
}
$stmt->execute();
$result = $stmt->get_result();	
}

//Check if there is an apiName called "Robopack" with an apisecret set
while ($row = $result->fetch_assoc()) {
    $apiName = $row['apiName'];
    $apisecret = $row['apisecret'];
    $clientID = $row['clientID'];
    $accountID = $row['accountID'];
    $apiID = $row['ID'];
    if ($apiName == "Robopack" && $apisecret != "") {
        $robopack = 1;
    }
}
$stmt->close();
if ($robopack == 1) {
?>
<h2>Robopack App Deployment</h2>
<table class="styled-table">
      <tr>
        <td>
            <form action="robopack-search.php" method="post">
              <?php
              $stmt = $con->prepare('SELECT role FROM accounts WHERE id = ?');
              // Get the account info using the logged-in session ID
              $stmt->bind_param('i', $_SESSION['id']);
              $stmt->execute();
              $stmt->bind_result($role2);
              $stmt->fetch();
              $stmt->close();
              // Check if the user is an admin...
              if ($role2 != 'Admin' && $role2 != 'SuperAdmin' && $role2 != 'SubAdmin') {
              // Retrieve additional account info from the database because we don't have them stored in sessions
              $stmt = $con->prepare('SELECT ID, tenantname, tenantid, customerid FROM tenants WHERE ownerid = ?');
              // In this case, we can use the account ID to retrieve the account info.
              $stmt->bind_param('i', $_SESSION['id']);
              $stmt->execute();
              $result = $stmt->get_result();
              }
              else {
              // Retrieve additional account info from the database because we don't have them stored in sessions
              $stmt = $con->prepare('SELECT ID, tenantname, tenantid, customerid FROM tenants WHERE customerid = ?');
              // In this case, we can use the account ID to retrieve the account info.
              if ($role2 == "SubAdmin") {
                $stmt->bind_param('i', $primaryadmin);
              }
              else {
              // In this case, we can use the account ID to retrieve the account info.
              $stmt->bind_param('i', $_SESSION['id']);
              }
              $stmt->execute();
              $result = $stmt->get_result();	
              }
              
              /* Get the number of rows */
              $num_of_rows = $result->num_rows;
              ?>
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
      </tr>
      <tr>
        <td>
        <input type="text" name="search" placeholder="Search...">
        </td>
      </tr>
      <tr>
    <td>
                <input class="profile-btn" type="submit" value="Search">
            </form>
        </td>
  </tr>
  </table>
            <?php
}

?>
</div>
               <!-- Script -->
               <script>
        $(document).ready(function(){
            
            // Initialize select2
            $("#appid").select2();

            // Read selected option
            $('#but_read').click(function(){
                var username = $('#selUser option:selected').text();
                var userid = $('#selUser').val();
           
                $('#result').html("id : " + userid + ", name : " + username);
            });
        });
        </script>
	
            <?php
include "footer.php";
?>