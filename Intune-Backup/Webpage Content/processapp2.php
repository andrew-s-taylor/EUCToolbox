<?php
include 'main.php';

// Handle edit profile post data
if (isset($_POST['tenantid'])) {

    // Retrieve additional account info from the database because we don't have them stored in sessions
$stmt = $con->prepare('SELECT password, email, activation_code, role, registered, repoowner, reponame, gitproject, aadclient, gittype, gittoken, aadsecret, golden FROM accounts WHERE id = ?');
// In this case, we can use the account ID to retrieve the account info.
$stmt->bind_param('i', $_SESSION['id']);
$stmt->execute();
$stmt->bind_result($password, $email, $activation_code, $role, $registered_date, $repoowner, $reponame, $gitproject, $aadclient, $gittype, $gittoken, $aadsecret, $golden);
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
$appid = $_POST['appid'];
$appname = $_POST['appname'];
$clientid = $aadclient;
$clientsecret = decryptstring($aadsecret);

$ownername = $repoowner;
$reponame = $reponame;
$token = decryptstring($gittoken);
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
}

}

    header('Location: home.php?updatemessage=App Installing');


?>