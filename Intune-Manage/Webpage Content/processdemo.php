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
$filename2 = $_POST['filename'];
    // Retrieve additional account info from the database because we don't have them stored in sessions
    $stmt = $con->prepare('SELECT password, email, activation_code, role, registered, reponame, golden FROM accounts WHERE id = ?');
    // In this case, we can use the account ID to retrieve the account info.
    $stmt->bind_param('i', $_SESSION['id']);
    $stmt->execute();
    $stmt->bind_result($password, $email, $activation_code, $role, $registered_date, $reponame, $golden);
    $stmt->fetch();
    $stmt->close();
	//DO FORM STUFF
    $tenantarray2 = $_POST['tenantid'];
//Check if $tenantarray is an array
if(is_array($tenantarray2)){
    //Loop through the array
    $tenantarray = $tenantarray2;

}
else {
//Create an arry with the single value
$tenantarray = array($tenantarray2);
}


foreach ($tenantarray as $tenant){

if ($filename2 == "ibpolicies") {
    $filename = "baseline.json";
$repotype = "github";
$ownername = "andrew-s-taylor";
$reponame = "IntuneBaseline";
$token = mygittoken;
}
elseif ($filename2 == "openbaseline") {
    $filename = "OpenIntuneBaseline.json";
$repotype = "github";
$ownername = "andrew-s-taylor";
$reponame = "IntuneBaseline";
$token = mygittoken;
}
else {
    $filename = $_POST['filename'];
    if ($gittype == "github") {
        $repotype = "github";
        }
        if ($gittype == "azure") {
        $repotype = "azuredevops";
        }
        if ($gittype == "gitlab") {
            $repotype = "gitlab";
            }

            $ownername = $repoowner;
$reponame = $reponame;
$token = $gittoken;
$project = $gitproject;
}
$type = "restore";
$clientid = appID;
$selected = "all";
$clientsecret = appSecret;
$project = "github";
    $assignments = "yes";  
    $groupcreate = "yes";  
    $data = array(
        array("type" => "$type"),
        array("tenant" => "$tenant"),
        array("repotype" => "$repotype"),
        array("selected" => "$selected"),
        array("ownername" => "$ownername"),
        array("reponame" => "$reponame"),
        array("token" => "$token"),
        array("project" => "$project"),
        array("clientid" => "$clientid"),
        array("clientsecret" => "$clientsecret"),
        array("policyid" => "$policyid"),
        array("filename" => "$filename"),
        array("assignments" => "$assignments"),
        array("groupcreate" => "$groupcreate")
    );

//Add to array

}

//Encode it
$body = base64_encode(json_encode($data));

    $header = array("message" => "Policy transfer to $tenant");

//Setup CURL
$ch = curl_init();
$url = $webhookuri;
curl_setopt($ch, CURLOPT_URL, $url);
curl_setopt($ch, CURLOPT_CUSTOMREQUEST, "POST");
curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
curl_setopt($ch, CURLOPT_HTTPHEADER, $header);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

$result = curl_exec($ch);
curl_close($ch);

$auditlog_userID = $_SESSION['id'];
$auditlog_ipAddress = $_SERVER['REMOTE_ADDR'];
$auditlog_timestamp = date('Y-m-d H:i:s');
$auditlog_message = "Template $filename deployed to $tenant";
$stmt = $con->prepare('INSERT INTO auditlog (UserID, IPAddress, Timestamp, Task) VALUES (?, ?, ?, ?)');
$stmt->bind_param('isss', $auditlog_userID, $auditlog_ipAddress, $auditlog_timestamp, $auditlog_message);
$stmt->execute();
$stmt->close();

}

    header('Location: home.php?updatemessage=Build Underway');


?>