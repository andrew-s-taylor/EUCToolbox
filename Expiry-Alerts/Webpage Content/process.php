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