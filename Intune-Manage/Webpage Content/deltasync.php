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

@include dirname( __FILE__ ) . '/main.php';



$tenantsource = $_POST['tenantidsource'];
$tenantdestination = $_POST['tenantiddestination'];
$clientid = appID;
$clientsecret = appSecret;

if (isset($_POST['tenantidsource'])) {
    //Drift Check

    $data = array(
        array("tenant" => "$tenantsource"),
        array("clientid" => "$clientid"),
        array("clientsecret" => "$clientsecret"),
        array("secondtenant" => "$tenantdestination"),
        array("livemigration" => "yes")
    );

//Encode it
$body = base64_encode(json_encode($data));

    $header = array("message" => "Delta sync from $tenantsource to $tenantdestination");

//Setup CURL
$ch = curl_init();
$url = $driftwebookuri;
curl_setopt($ch, CURLOPT_URL, $url);
curl_setopt($ch, CURLOPT_CUSTOMREQUEST, "POST");
curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
curl_setopt($ch, CURLOPT_HTTPHEADER, $header);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

$resultch = curl_exec($ch);
curl_close($ch);
$auditlog_userID = $_SESSION['id'];
$auditlog_ipAddress = $_SERVER['REMOTE_ADDR'];
$auditlog_timestamp = date('Y-m-d H:i:s');
$auditlog_message = "Delta sync sent from $tenantsource to $tenantdestination";
$stmt = $con->prepare('INSERT INTO auditlog (UserID, IPAddress, Timestamp, Task) VALUES (?, ?, ?, ?)');
$stmt->bind_param('isss', $auditlog_userID, $auditlog_ipAddress, $auditlog_timestamp, $auditlog_message);
$stmt->execute();
$stmt->close();
    
}


header('Location: home.php?updatemessage=Delta sync underway');

    ?>