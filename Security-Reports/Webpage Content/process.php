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