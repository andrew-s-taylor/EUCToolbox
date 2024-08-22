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
$tenant = $_GET['tenant'];
$appid = $_GET['appid'];
$appversion = $_GET['appversion'];
$appname = $_GET['appname'];
$grpcheck = $_GET['grpcheck'];
$installgroupname = $_GET['installgroupname'];
//Convert $installgroupname to base64 and store in $installgroupname1
$installgroupname1 = base64_encode($installgroupname);
$uninstallgroupname = $_GET['uninstallgroupname'];
$useravailable = $_GET['useravailable'];
$deviceavailable = $_GET['deviceavailable'];
$email = $_GET['email'];
$appdeploytype = $_GET['appdeploytype'];

// Handle edit profile post data
if (isset($_GET['tenant'])) {
    $clientid = appID;
    $clientsecret = appSecret;
    

    if ($appdeploytype == "community") {

//Check if useravailable, deviceavailable or both checkboxes are selected
if ($useravailable !== "off" && $deviceavailable !== "off") {
    // Both are selected
    $availableinstall = "both";
} else if (isset($useravailable)) {
    // Only useravailable is selected
    $availableinstall = "User";
} else if (isset($deviceavailable)) {
    // Only deviceavailable is selected
    $availableinstall = "Device";
} else {
    // None are selected
    $availableinstall = "None";
}

if ($grpcheck !== "off") {
    // Code to be executed if $grpcheck doesn't equal "off"


    // Checkbox is checked
//Add to array
$data = array(
    array("tenant" => "$tenant"),
    array("clientid" => "$clientid"),
    array("clientsecret" => "$clientsecret"),
    array("appid" => "$appid"),
    array("appname" => "$appname"),
    array("installgroupname" => "$installgroupname"),
    array("uninstallgroupname" => "$uninstallgroupname"),
    array("availableinstall" => "$availableinstall"),
    array("appversion" => $appversion),
    array("email" => "$email")
);
} else {
//Add to array
$data = array(
    array("tenant" => "$tenant"),
    array("clientid" => "$clientid"),
    array("clientsecret" => "$clientsecret"),
    array("appid" => "$appid"),
    array("appname" => "$appname"),
    array("availableinstall" => "$availableinstall"),
    array("appversion" => $appversion),
    array("email" => "$email")
);
}


//Encode it
$body = base64_encode(json_encode($data));

    $header = array("message" => "App Deployed to $tenant");


//Setup CURL
$ch = curl_init();
$url = webhookcommunity;
curl_setopt($ch, CURLOPT_URL, $url);
curl_setopt($ch, CURLOPT_CUSTOMREQUEST, "POST");
curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
curl_setopt($ch, CURLOPT_HTTPHEADER, $header);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

$result = curl_exec($ch);
curl_close($ch);


}

    else {

        $data = array(
            array("tenant" => "$tenant"),
            array("clientid" => "$clientid"),
            array("clientsecret" => "$clientsecret"),
            array("yamlFile" => "$installgroupname1"),
            array("email" => "$email")
        );
        
        
        
        //Encode it
        $body = base64_encode(json_encode($data));
                
            $header = array("message" => "App Deployed to $tenant");
        
        
        //Setup CURL
        $ch = curl_init();
        $url = webhookmanifest;
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, "POST");
        curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
        curl_setopt($ch, CURLOPT_HTTPHEADER, $header);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        
        $result = curl_exec($ch);
        curl_close($ch);
        

    }

    header('Location: index.php?message=App Installing');
}

?>