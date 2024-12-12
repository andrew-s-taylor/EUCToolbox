<?php
include 'main.php';
// Check logged-in
check_loggedin($con);
// Handle edit profile post data
if (isset($_POST['tenantid'])) {
$senttype = $_POST['type'];

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

//If backup
if ($senttype == "backup") {
    //Retrieve the customer ID from the tenant ID
//Retrieve the customer ID from the tenant ID
foreach ($tenantarray as $tenant){
$tenantarray3 = explode("%%", $tenant);
$tenant = $tenantarray3[0];
$customerid = $tenantarray3[1];
}
}
else {
    $customerid = $_POST['customerid'];
}

    // Retrieve additional account info from the database because we don't have them stored in sessions
$stmt = $con->prepare('SELECT email, role, reponame, golden FROM accounts WHERE id = ?');
// In this case, we can use the account ID to retrieve the account info.
$stmt->bind_param('i', $customerid);
$stmt->execute();
$stmt->bind_result($email, $role, $reponame, $golden);
$stmt->fetch();
$stmt->close();


foreach ($tenantarray as $tenant){

    if ($senttype == "backup") {
        //Retrieve the customer ID from the tenant ID
    $tenantarray3 = explode("%%", $tenant);
    $tenantfinal = $tenantarray3[0];
    }
    else {
        $tenantfinal = $tenant;
    }

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
        $auditlog_userID = $_SESSION['id'];
$auditlog_ipAddress = $_SERVER['REMOTE_ADDR'];
$auditlog_timestamp = date('Y-m-d H:i:s');
$auditlog_message = "Backup initiated against $tenantfinal";
$stmt = $con->prepare('INSERT INTO auditlog (UserID, IPAddress, Timestamp, Task) VALUES (?, ?, ?, ?)');
$stmt->bind_param('isss', $auditlog_userID, $auditlog_ipAddress, $auditlog_timestamp, $auditlog_message);
$stmt->execute();
$stmt->close();
    }
    if ($senttype == "restore") {
        $type = "restore";
        $auditlog_userID = $_SESSION['id'];
$auditlog_ipAddress = $_SERVER['REMOTE_ADDR'];
$auditlog_timestamp = date('Y-m-d H:i:s');
$auditlog_message = "Restore $filename initiated against $tenantfinal";
$stmt = $con->prepare('INSERT INTO auditlog (UserID, IPAddress, Timestamp, Task) VALUES (?, ?, ?, ?)');
$stmt->bind_param('isss', $auditlog_userID, $auditlog_ipAddress, $auditlog_timestamp, $auditlog_message);
$stmt->execute();
$stmt->close();
    }
    if ($senttype == "template") {
        $type = "backup";
        $auditlog_userID = $_SESSION['id'];
$auditlog_ipAddress = $_SERVER['REMOTE_ADDR'];
$auditlog_timestamp = date('Y-m-d H:i:s');
$auditlog_message = "Template $templatename deployed to $tenantfinal";
$stmt = $con->prepare('INSERT INTO auditlog (UserID, IPAddress, Timestamp, Task) VALUES (?, ?, ?, ?)');
$stmt->bind_param('isss', $auditlog_userID, $auditlog_ipAddress, $auditlog_timestamp, $auditlog_message);
$stmt->execute();
$stmt->close();
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
$token = $gittoken;
$project = $gitproject;
$clientid = appID;
$clientsecret = appSecret;
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
        array("tenant" => "$tenantfinal"),
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
    array("tenant" => "$tenantfinal"),
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
    array("tenant" => "$tenantfinal"),
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
elseif (isset($_POST['tenantidsource'])) {
        $senttype = $_POST['type'];
        $tenantsource = $_POST['tenantidsource'];
        $tenantdestination = $_POST['tenantiddestination'];
        $clientid = appID;
$clientsecret = appSecret;



$data = array(
    array("type" => "livemigration"),
    array("tenant" => "$tenantsource"),
    array("selected" => "all"),
    array("clientid" => "$clientid"),
    array("clientsecret" => "$clientsecret"),
    array("assignments" => "yes"),
    array("groupcreate" => "no"),
    array("secondtenant" => "$tenantdestination")
);

$body = base64_encode(json_encode($data));

    $header = array("message" => "Policy migration from $tenantsource to $tenantdestination");

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

if ($senttype == "restore") {
    header('Location: home.php?updatemessage=Restore Underway');}
if ($senttype == "backup") {
    header('Location: home.php?updatemessage=Backup Underway');}
if ($senttype == "template") {
    header('Location: home.php?updatemessage=Template Underway');}
 if ($senttype == "migrate") {
    header('Location: home.php?updatemessage=Migration Underway');}

?>