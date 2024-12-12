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
if (isset($_POST['tenantid'])) {
$senttype = $_POST['type'];
    // Retrieve additional account info from the database because we don't have them stored in sessions
$stmt = $con->prepare('SELECT role, reponame, golden FROM accounts WHERE id = ?');
// In this case, we can use the account ID to retrieve the account info.
$stmt->bind_param('i', $_SESSION['id']);
$stmt->execute();
$stmt->bind_result($role, $reponame, $golden);
$stmt->fetch();
$stmt->close();

	//DO FORM STUFF

    $changetype = $_POST['type'];
    $tenantid = $_POST['tenantid'];
    $policyname = $_POST['policyname'];
    $policyuri = $_POST['policyuri'];
    if (($_POST['policyjson']) == "DELETE")
    {
    $changetype = "delete";
    }
    else {
    $policyjson = $_POST['policyjson'];
    }

    //Create a Graph access token using aadclient and secret
    $clientId = appID; 
    $clientSecret = appSecret;


    $token_Body = array(
        'grant_type' => 'client_credentials',
        'scope' => 'https://graph.microsoft.com/.default',
        'client_id' => $clientId,
        'client_secret' => $clientSecret
    );

    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, "https://login.microsoftonline.com/$tenantid/oauth2/v2.0/token");
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($ch, CURLOPT_POST, 1);
    curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($token_Body));

    $headers = array();
    $headers[] = 'Content-Type: application/x-www-form-urlencoded';
    curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);

    $result = curl_exec($ch);
    if (curl_errno($ch)) {
        echo 'Error:' . curl_error($ch);
    }
    curl_close($ch);

    $token_Response = json_decode($result, true);
    $authentication = $token_Response['access_token'];
    $headers = array(
        'Content-Type: application/json',
        'Authorization: Bearer ' . $authentication . ''
    );


if ($changetype == "Add") {
//Send a Graph POST request to $policyuri with the body as $policyjson
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $policyuri);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
curl_setopt($ch, CURLOPT_POST, 1);
curl_setopt($ch, CURLOPT_POSTFIELDS, $policyjson);
curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
$result = curl_exec($ch);

$auditlog_userID = $_SESSION['id'];
$auditlog_ipAddress = $_SERVER['REMOTE_ADDR'];
$auditlog_timestamp = date('Y-m-d H:i:s');
$auditlog_message = "Policy $policyname added to $tenantid";
$stmt = $con->prepare('INSERT INTO auditlog (UserID, IPAddress, Timestamp, Task) VALUES (?, ?, ?, ?)');
$stmt->bind_param('isss', $auditlog_userID, $auditlog_ipAddress, $auditlog_timestamp, $auditlog_message);
$stmt->execute();
$stmt->close();

}

if ($changetype == "Update") {

//Get the existing policy ID

//Encode $policyname for web use
$policyname = urlencode($policyname);

$geturi = $policyuri . '?$filter=(startswith(displayName,' . "'" . $policyname . "'))";
$geturi2 = $policyuri . '?$filter=(startswith(name,' . "'" . $policyname . "'))";

$curl = curl_init();
curl_setopt_array($curl, array(
    CURLOPT_URL => "$geturi",
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_ENCODING => '',
    CURLOPT_MAXREDIRS => 10,
    CURLOPT_TIMEOUT => 0,
    CURLOPT_FOLLOWLOCATION => true,
    CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
    CURLOPT_SSL_VERIFYHOST => false,
    CURLOPT_SSL_VERIFYPEER => true,
    CURLOPT_CUSTOMREQUEST => 'GET',
    CURLOPT_HTTPHEADER => array(
      'Content-Type: application/json',
      'Authorization: Bearer ' . $authentication . ''
    ),
  ));

// Initialize the cURL session
$result = curl_exec($curl);

//If that gives error 400, try the other URI
if (strpos($result, '400') !== false) {
    $options = [
        CURLOPT_URL => "$geturi2",
        CURLOPT_HTTPHEADER => $headers,
        CURLOPT_CUSTOMREQUEST => 'GET',
        CURLOPT_RETURNTRANSFER => 'true',
    ];
    // Initialize the cURL session
    $curl = curl_init();
    curl_setopt_array($curl, $options);
    $result = curl_exec($curl);

}
  // Close the cURL session
  curl_close($curl);

//Grab the ID within value of the array
$policyid = json_decode($result, true)['value'][0]['id'];

$posturi = $policyuri . "/" . $policyid;

$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $posturi);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'UPDATE');
curl_setopt($ch, CURLOPT_POSTFIELDS, $policyjson);
curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
$result = curl_exec($ch);


$auditlog_userID = $_SESSION['id'];
$auditlog_ipAddress = $_SERVER['REMOTE_ADDR'];
$auditlog_timestamp = date('Y-m-d H:i:s');
$auditlog_message = "Policy $policyname updated on $tenantid";
$stmt = $con->prepare('INSERT INTO auditlog (UserID, IPAddress, Timestamp, Task) VALUES (?, ?, ?, ?)');
$stmt->bind_param('isss', $auditlog_userID, $auditlog_ipAddress, $auditlog_timestamp, $auditlog_message);
$stmt->execute();
$stmt->close();
}


if ($changetype == "delete") {

    //Get the existing policy ID
    
    //Encode $policyname for web use
    $policyname = urlencode($policyname);
    
    $geturi = $policyuri . '?$filter=(startswith(displayName,' . "'" . $policyname . "'))";
    $geturi2 = $policyuri . '?$filter=(startswith(name,' . "'" . $policyname . "'))";
    
    $curl = curl_init();
    curl_setopt_array($curl, array(
        CURLOPT_URL => "$geturi",
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_ENCODING => '',
        CURLOPT_MAXREDIRS => 10,
        CURLOPT_TIMEOUT => 0,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
        CURLOPT_SSL_VERIFYHOST => false,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_CUSTOMREQUEST => 'GET',
        CURLOPT_HTTPHEADER => array(
          'Content-Type: application/json',
          'Authorization: Bearer ' . $authentication . ''
        ),
      ));
    
    // Initialize the cURL session
    $result = curl_exec($curl);
    
    //If that gives error 400, try the other URI
    if (strpos($result, '400') !== false || strpos($result, 'Invalid filter clause') !== false) {
        $options = [
            CURLOPT_URL => "$geturi2",
            CURLOPT_HTTPHEADER => $headers,
            CURLOPT_CUSTOMREQUEST => 'GET',
            CURLOPT_RETURNTRANSFER => 'true',
        ];
        // Initialize the cURL session
        $curl = curl_init();
        curl_setopt_array($curl, $options);
        $result = curl_exec($curl);
    
    }
      // Close the cURL session
      curl_close($curl);
 
    //Grab the ID within value of the array
    $policyid = json_decode($result, true)['value'][0]['id'];
    
    $posturi = $policyuri . "/" . $policyid;
    
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $posturi);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'DELETE');
    curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
    $result = curl_exec($ch);
    
    $auditlog_userID = $_SESSION['id'];
    $auditlog_ipAddress = $_SERVER['REMOTE_ADDR'];
    $auditlog_timestamp = date('Y-m-d H:i:s');
    $auditlog_message = "Policy $policyname deleted from $tenantid";
    $stmt = $con->prepare('INSERT INTO auditlog (UserID, IPAddress, Timestamp, Task) VALUES (?, ?, ?, ?)');
    $stmt->bind_param('isss', $auditlog_userID, $auditlog_ipAddress, $auditlog_timestamp, $auditlog_message);
    $stmt->execute();
    $stmt->close();

    }
if ($changetype == "delete") {
    header('Location: home.php?deletemessage=Policy Deleted');
}
else {
    header('Location: home.php?updatemessage=Policy Deployed');
}

    }

?>