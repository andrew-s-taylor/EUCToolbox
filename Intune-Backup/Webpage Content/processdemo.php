<?php
include 'main.php';
// Check logged-in
check_loggedin($con);
// Handle edit profile post data
if (isset($_POST['tenantid'])) {
$filename2 = $_POST['filename'];
    // Retrieve additional account info from the database because we don't have them stored in sessions
    $stmt = $con->prepare('SELECT password, email, activation_code, role, registered, repoowner, reponame, gitproject, aadclient, gittype, gittoken, aadsecret, golden FROM accounts WHERE id = ?');
    // In this case, we can use the account ID to retrieve the account info.
    $stmt->bind_param('i', $_SESSION['id']);
    $stmt->execute();
    $stmt->bind_result($password, $email, $activation_code, $role, $registered_date, $repoowner, $reponame, $gitproject, $aadclient, $gittype, $gittoken, $aadsecret, $golden);
    $stmt->fetch();
    $stmt->close();
	//DO FORM STUFF
    $tenant = $_POST['tenantid'];

    $filename = $_POST['filename'];
    if ($gittype == "github") {
        $repotype = "github";
        }
        if ($gittype == "azure") {
        $repotype = "azuredevops";
        }
        if ($gittype == "gitlab") {
            $repotype = "gitlab";
            }

            $ownername = $repoowner;
$reponame = $reponame;
$token = decryptstring($gittoken);
$project = $gitproject;
}
$type = "restore";
$clientid = $aadclient;
$selected = "all";
$clientsecret = decryptstring($aadsecret);
$project = "github";
    $assignments = "yes";  
    $groupcreate = "yes";  
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
        array("groupcreate" => "$groupcreate")
    );

//Add to array


//Encode it
$body = base64_encode(json_encode($data));
    $header = array("message" => "Policy transfer to $tenant");

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



    header('Location: home.php?updatemessage=Build Underway');


?>