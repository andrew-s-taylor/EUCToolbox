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
$clientid = appID;
$clientsecret = appSecret;
$sendgridtoken = sendgridtoken;
$htmltemplate = htmltemplate;

$tenantid = $_POST['tenant'];
$email = $_POST['email'];

//Add to array
$data = array(
     array("tenant" => "$tenantid"),
     array("EmailAddress" => "$email"),
     array("clientid" => "$clientid"),
     array("clientsecret" => "$clientsecret"),
     array("portal" => "No"),
     array("htmltemplate" => "$htmltemplate"),
     array("sendgridtoken" => "$sendgridtoken")
 );
 
 
 $body = base64_encode(json_encode($data));
 
     $header = array("message" => "Cron for $tenantid");
 
     //Setup CURL for daily check
 $ch = curl_init();
 $url = webhook;
 curl_setopt($ch, CURLOPT_URL, $url);
 curl_setopt($ch, CURLOPT_CUSTOMREQUEST, "POST");
 curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
 curl_setopt($ch, CURLOPT_HTTPHEADER, $header);
 curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
 
 $result1 = curl_exec($ch);
 curl_close($ch);
?>