<?php
/**
 * This file is part of a GPL-licensed project.
 *
 * Copyright (C) 2024 Andrew Taylor (andrew.taylor@andrewstaylor.com)
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
include('config.php');

$tenant = $_POST['tenant'];

$email = $_POST['email'];


// Handle edit profile post data
if (isset($_GET['tenant'])) {


	//DO FORM STUFF
    
$clientid = appID;
$clientsecret = appSecret;
$sendgridtoken = sendgridtoken;

$sender = "security@euctoolbox.com";


    //Add to array
    $data = array(
        array("tenant" => "$tenant"),
        array("clientid" => "$clientid"),
        array("clientsecret" => "$clientsecret"),
        array("email" => "$sender"),
        array("recipient" => "$email"),
        array("sendgridtoken" => "$sendgridtoken"),

        );
        $header = array("message" => "Check sent to $tenant");
    
    //Encode it
    $body = base64_encode(json_encode($data));
    
    //Setup CURL
    $ch = curl_init();
    $url = webhook;
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_CUSTOMREQUEST, "POST");
    curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
    curl_setopt($ch, CURLOPT_HTTPHEADER, $header);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    
    $result = curl_exec($ch);
    curl_close($ch);



header('Location: index.php?message=Report Generating');
die();



}




?>