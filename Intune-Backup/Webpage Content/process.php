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
$stmt = $con->prepare('SELECT password, email, activation_code, role, registered, repoowner, reponame, gitproject, aadclient, gittype, gittoken, aadsecret, golden FROM accounts WHERE id = ?');
// In this case, we can use the account ID to retrieve the account info.
$stmt->bind_param('i', $_SESSION['id']);
$stmt->execute();
$stmt->bind_result($password, $email, $activation_code, $role, $registered_date, $repoowner, $reponame, $gitproject, $aadclient, $gittype, $gittoken, $aadsecret, $golden);
$stmt->fetch();
$stmt->close();
	//DO FORM STUFF
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
//Check if $tenantarray is an array
if(is_array($tenantarray2)){
    //Loop through the array
    $tenantarray = $tenantarray2;

}
else {
//Create an arry with the single value
$tenantarray = array($tenantarray2);
print_r($tenantarray);
}

foreach ($tenantarray as $tenant){


    if ($senttype == "restore") {
        $filename = $_POST['filename'];
        $checkbox1=$_POST['policy'];  
        $policyid="";  
        //Add each checkbox submitted to the $chk variable
        foreach($checkbox1 as $chk1)  
           {  
              $policyid .= $chk1.",";  
           }  
           $policyid = substr($policyid, 0, -1);
            }

            if ($senttype == "template") {
                $filename = $_POST['filename'];
                $checkbox1=$_POST['policy'];  
                $templatename = $_POST['templatename'];
                $policyid="";  
                //Add each checkbox submitted to the $chk variable
                foreach($checkbox1 as $chk1)  
                   {  
                      $policyid .= $chk1.",";  
                   }  
                   $policyid = substr($policyid, 0, -1);
                    }



    //Set the parameters for the API call
    if ($senttype == "backup") {
        $type = "backup";
    }
    if ($senttype == "restore") {
        $type = "restore";
    }
    if ($senttype == "template") {
        $type = "backup";
    }

if ($senttype == "template") {
    $template = "yes";
}
else {
    $template = "no";
}


if ($gittype == "github") {
$repotype = "github";
}
if ($gittype == "azure") {
$repotype = "azuredevops";
}
if ($gittype == "gitlab") {
    $repotype = "gitlab";
    }
if ($senttype == "backup") {
$selected = "all";
}
if ($senttype == "restore") {
    $selected = "some";

}
$ownername = $repoowner;
$reponame = $reponame;
$token = decryptstring($gittoken);
$project = $gitproject;
$clientid = $aadclient;
$clientsecret = decryptstring($aadsecret);
if ($senttype == "restore") {
$policyid = $policyid;
}
if ($senttype == "template") {
    $policyid = $policyid;
}


if ($senttype == "restore") {
    //Check if the Assignment checkbox is checked
if(isset($_POST['assignment']))  
{
    $assignments = "yes";  
}
else
{
    $assignments = "no";
}
if(isset($_POST['groupcreate']))  
{
    $groupcreate = "yes";  
}
else
{
    $groupcreate = "no";
}
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
        array("groupcreate" => "$groupcreate"),
        array("template" => "$template")
    );

//Add to array

}
if ($senttype == "backup") {
    //Add to array
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
    array("template" => "$template")
);
}

if ($senttype == "template") {
    //Add to array
$data = array(
    array("type" => "$type"),
    array("tenant" => "$tenant"),
    array("repotype" => "$repotype"),
    array("selected" => "selected"),
    array("ownername" => "$ownername"),
    array("reponame" => "$reponame"),
    array("token" => "$token"),
    array("policyid" => "$policyid"),
    array("project" => "$project"),
    array("clientid" => "$clientid"),
    array("clientsecret" => "$clientsecret"),
    array("template" => "$template"),
    array("templatename" => "$templatename")
);
}

//Encode it
$body = base64_encode(json_encode($data));
if ($senttype == "restore") {
    $header = array("message" => "Policy transfer to $tenant");
}
if ($senttype == "backup") {
    $header = array("message" => "Policy backup of $tenant");
}
if ($senttype == "template") {
    $header = array("message" => "Template creation from $tenant");
}

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
}
}

if ($senttype == "restore") {
    header('Location: home.php?updatemessage=Restore Underway');}
if ($senttype == "backup") {
    header('Location: home.php?updatemessage=Backup Underway');}
    if ($senttype == "template") {
        header('Location: home.php?updatemessage=Template Underway');}


?>