<?php

@include dirname( __FILE__ ) . '/main.php';



$aadclient = appID;
$aadsecret = appSecret;
$repotype = gittype;
$repoowner = gitowner;
$gittoken = fullgittoken;
$gitproject = "GitHub";
$sendgridtoken = sendgridtoken;

//Add to logs
if (isset($_POST['owner'])) {
    $auditlog_userID = $_SESSION['id'];
    $auditlog_ipAddress = $_SERVER['REMOTE_ADDR'];
    $auditlog_timestamp = date('Y-m-d H:i:s');
    $auditlog_message = "Manual Drift Check inititated";
    $stmt = $con->prepare('INSERT INTO auditlog (UserID, IPAddress, Timestamp, Task) VALUES (?, ?, ?, ?)');
    $stmt->bind_param('isss', $auditlog_userID, $auditlog_ipAddress, $auditlog_timestamp, $auditlog_message);
    $stmt->execute();
    $stmt->close();
}

echo "Running daily checks<br>";
if (isset($_POST['owner'])) {
    ##Don't run
} else {

// Retrieve additional account info from the database because we don't have them stored in sessions
$stmt = $con->prepare('SELECT * FROM accounts JOIN tenants ON accounts.id = tenants.ownerid WHERE accounts.regtype != "expired"');
// $stmt->bind_param('i', $_SESSION['id']);
$stmt->execute();
$result = $stmt->get_result();

while ($row = $result->fetch_assoc()) {
    $tenantid = $row['tenantid'];
    $reponame = $row["reponame"];
    $clientsecret = $aadsecret;
    $token = $gittoken;

    // Check the role and get the email field accordingly
    if ($row["role"] == "Admin" || $row["role"] == "SuperAdmin") {
        $email = $row["alertsemail"];
    } elseif ($row["role"] == "Member") {
        $primaryid = $row["primaryid"];
        $stmt1 = $con->prepare('SELECT alertsemail FROM accounts WHERE id = ?');
        $stmt1->bind_param('i', $primaryid);
        $stmt1->execute();
        $result1 = $stmt1->get_result();
        $primaryAccount = $result1->fetch_assoc();
        $email = $primaryAccount["alertsemail"];
    }


    $data = array(
        array("tenant" => "$tenantid"),
        array("clientid" => "$aadclient"),
        array("clientsecret" => "$clientsecret"),
        array("repotype" => "$repotype"),
        array("ownername" => "$repoowner"),
        array("reponame" => "$reponame"),
        array("token" => "$token"),
        array("project" => "$gitproject"),
        array("EmailAddress" => "$email"),
        array("portal" => "yes"),
        array("sendgridtoken" => $sendgridtoken)
    );

    $body = base64_encode(json_encode($data));

    $header = array("message" => "Cron for $tenantid");

    //Setup CURL for daily check
$ch = curl_init();
$url = $dailywebhookuri;
curl_setopt($ch, CURLOPT_URL, $url);
curl_setopt($ch, CURLOPT_CUSTOMREQUEST, "POST");
curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
curl_setopt($ch, CURLOPT_HTTPHEADER, $header);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

$result1 = curl_exec($ch);
curl_close($ch);

//Sleep for 5 seconds to allow the webhook to complete
sleep(5);

    //Setup CURL for security check
    $ch = curl_init();
    $url = $securitywebhookuri;
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_CUSTOMREQUEST, "POST");
    curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
    curl_setopt($ch, CURLOPT_HTTPHEADER, $header);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    
    $result2 = curl_exec($ch);
    curl_close($ch);

    //Sleep for 5 seconds to allow the webhook to complete
sleep(5);
}
$stmt->close();
}


echo "Running drift checks<br>";
    //Drift Check

    //Check if owner has been sent
if (isset($_POST['owner'])) {
    $ownerid = $_POST['owner'];
} else {
    $ownerid = "no";
}
//Drift Check
if ($ownerid == "no") {
    $stmt = $con->prepare('SELECT * FROM accounts JOIN tenants ON accounts.id = tenants.ownerid WHERE accounts.regtype != "expired"');
}
else {
$stmt = $con->prepare('SELECT * FROM accounts JOIN tenants ON accounts.id = tenants.ownerid WHERE accounts.id = ?');
$stmt->bind_param('i', $ownerid);
}

// In this case, we can use the account ID to retrieve the account info.
$stmt->execute();
$result = $stmt->get_result();
/* Get the number of rows */
$num_of_rows = $result->num_rows;
echo $num_of_rows;
if ($num_of_rows > 0) {
    // output data of each row
    while ($row = $result->fetch_assoc()) {        
        $reponame = $row["reponame"];
        $tenant = $row["tenantid"];
        //DO FORM STUFF
$token = $gittoken;
$clientsecret = $aadsecret;

    // Check the role and get the email field accordingly
    if ($row["role"] == "Admin" || $row["role"] == "SuperAdmin") {
        $email = $row["alertsemail"];
    } elseif ($row["role"] == "Member") {
        $primaryid = $row["primaryid"];
        $stmt1 = $con->prepare('SELECT alertsemail FROM accounts WHERE id = ?');
        $stmt1->bind_param('i', $primaryid);
        $stmt1->execute();
        $result1 = $stmt1->get_result();
        $primaryAccount = $result1->fetch_assoc();
        $email = $primaryAccount["alertsemail"];
    }

//Check all fields are completed before continuing
if ($reponame == "" || $repoowner == "" || $gittoken == "" || $gitproject == "" || $tenant == "" || $repotype == "") {
    //Do nothing
} else {

    $data = array(
        array("tenant" => "$tenant"),
        array("repotype" => "$repotype"),
        array("ownername" => "$repoowner"),
        array("reponame" => "$reponame"),
        array("token" => "$token"),
        array("project" => "$gitproject"),
        array("clientid" => "$aadclient"),
        array("clientsecret" => "$clientsecret"),
        array("EmailAddress" => "$email"),
        array("sendgridtoken" => $sendgridtoken)
    );

//Encode it
   $body = base64_encode(json_encode($data));
   
   $header = array("message" => "Policy transfer to $tenant");

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
//Sleep for 5 seconds to allow the webhook to complete
sleep(5);
    }
}

} 
$stmt->close();


echo "Running Gold Drift checks<br>";
//Gold Drift

//Gold Drift
if (isset($_POST['owner'])) {
    $ownerid = $_POST['owner'];
} else {
    $ownerid = "no";
}
//Drift Check
if ($ownerid == "no") {
    $stmt = $con->prepare('SELECT * FROM accounts JOIN tenants ON accounts.id = tenants.ownerid WHERE accounts.regtype != "expired"');
}
    else {
    $stmt = $con->prepare('SELECT * FROM accounts JOIN tenants ON accounts.id = tenants.ownerid WHERE accounts.id = ?');
    $stmt->bind_param('i', $ownerid);
    }
    
// In this case, we can use the account ID to retrieve the account info.
$stmt->execute();
$result = $stmt->get_result();

/* Get the number of rows */
$num_of_rows = $result->num_rows;
if ($num_of_rows > 0) {
    // output data of each row
    while ($row = $result->fetch_assoc()) { 
        $reponame = $row["reponame"];
        $tenant = $row["tenantid"];
        $golden = $row["golden"];
        //DO FORM STUFF
$token = $gittoken;
$clientsecret = $aadsecret;
//Check all fields are completed before continuing

    // Check the role and get the email field accordingly
    if ($row["role"] == "Admin" || $row["role"] == "SuperAdmin") {
        $email = $row["alertsemail"];
    } elseif ($row["role"] == "Member") {
        $primaryid = $row["primaryid"];
        $stmt = $con->prepare('SELECT alertsemail FROM accounts WHERE id = ?');
        $stmt->bind_param('i', $primaryid);
        $stmt->execute();
        $result = $stmt->get_result();
        $primaryAccount = $result->fetch_assoc();
        $email = $primaryAccount["alertsemail"];
    }
if ($reponame == "" || $repoowner == "" || $gittoken == "" || $gitproject == "" || $tenant == "" || $repotype == "") {
    //Do nothing
} else {
    $data = array(
        array("tenant" => "$tenant"),
        array("repotype" => "$repotype"),
        array("ownername" => "$repoowner"),
        array("reponame" => "$reponame"),
        array("token" => "$token"),
        array("project" => "$gitproject"),
        array("clientid" => "$aadclient"),
        array("goldentenant" => "$golden"),
        array("clientsecret" => "$clientsecret"),
        array("EmailAddress" => "$email"),
        array("sendgridtoken" => $sendgridtoken)
    );

//Encode it
$body = base64_encode(json_encode($data));

$header = array("message" => "Policy transfer to $tenant");

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
//Sleep for 5 seconds to allow the webhook to complete
sleep(5);
    }
}

} 
$stmt->close();

$stmt->close();

header('Location: home.php?updatemessage=Drift Check Started');

    ?>