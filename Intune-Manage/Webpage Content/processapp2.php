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

// Handle edit profile post data
if (isset($_POST['tenantid'])) {


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
    // Retrieve additional account info from the database because we don't have them stored in sessions
    $stmt = $con->prepare('SELECT a.password, a.email, a.activation_code, a.role, a.registered, a.reponame, a.golden FROM accounts a INNER JOIN tenants t ON a.id = t.customerid WHERE t.tenantid = ?');
    $stmt->bind_param('s', $tenant);
    $stmt->execute();
    $stmt->bind_result($password, $email, $activation_code, $role, $registered_date, $reponame, $golden);
    $stmt->fetch();
    $stmt->close();

$appid = $_POST['appid'];
$appname = $_POST['appname'];
$appversion = $_POST['appversion'];
$clientid = appID;
$clientsecret = appSecret;

$ownername = $repoowner;
$reponame = $reponame;
$token = $gittoken;
$project = $gitproject;
if ($gittype == "github") {
    $repotype = "github";
    }
    if ($gittype == "azure") {
    $repotype = "azuredevops";
    }
    if ($gittype == "gitlab") {
        $repotype = "gitlab";
        }
//Check if useravailable, deviceavailable or both checkboxes are selected
if (isset($_POST['useravailable']) && isset($_POST['deviceavailable'])) {
    // Both are selected
    $availableinstall = "both";
} else if (isset($_POST['useravailable'])) {
    // Only useravailable is selected
    $availableinstall = "User";
} else if (isset($_POST['deviceavailable'])) {
    // Only deviceavailable is selected
    $availableinstall = "Device";
} else {
    // None are selected
    $availableinstall = "None";
}

if (isset($_POST['grpcheck'])) {


    // Checkbox is checked
    $installgroupname = $_POST['installgroupname'];
    $uninstallgroupname = $_POST['uninstallgroupname'];
//Add to array
$data = array(
    array("tenant" => "$tenant"),
    array("clientid" => "$clientid"),
    array("clientsecret" => "$clientsecret"),
    array("appid" => "$appid"),
    array("appname" => "$appname"),
    array("appversion" => "$appversion"),
    array("installgroupname" => "$installgroupname"),
    array("repotype" => "$repotype"),
    array("ownername" => "$ownername"),
    array("reponame" => "$reponame"),
    array("token" => "$token"),
    array("project" => "$project"),
    array("uninstallgroupname" => "$uninstallgroupname"),
    array("availableinstall" => "$availableinstall")
);
} else {
//Add to array
$data = array(
    array("tenant" => "$tenant"),
    array("clientid" => "$clientid"),
    array("clientsecret" => "$clientsecret"),
    array("appid" => "$appid"),
    array("repotype" => "$repotype"),
    array("ownername" => "$ownername"),
    array("reponame" => "$reponame"),
    array("token" => "$token"),
    array("project" => "$project"),
    array("appname" => "$appname"),
    array("appversion" => "$appversion"),
    array("availableinstall" => "$availableinstall")
);
}


//Encode it
$body = base64_encode(json_encode($data));

    $header = array("message" => "App Deployed to $tenant");


//Setup CURL
$ch = curl_init();
$url = $appwebhookuri;
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
$auditlog_message = "App $appname deployed to $tenant";
$stmt = $con->prepare('INSERT INTO auditlog (UserID, IPAddress, Timestamp, Task) VALUES (?, ?, ?, ?)');
$stmt->bind_param('isss', $auditlog_userID, $auditlog_ipAddress, $auditlog_timestamp, $auditlog_message);
$stmt->execute();
$stmt->close();

}

}

    header('Location: home.php?updatemessage=App Installing');


?>