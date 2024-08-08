<?php
include 'main.php';
// Check logged-in
check_loggedin($con);
// Handle edit profile post data
if (isset($_POST['email'])) {

    // Retrieve additional account info from the database because we don't have them stored in sessions
$stmt = $con->prepare('SELECT password, email, activation_code, role, registered, repoowner, reponame, gitproject, aadclient, gittype, gittoken, aadsecret, golden FROM accounts WHERE id = ?');
// In this case, we can use the account ID to retrieve the account info.
$stmt->bind_param('i', $_SESSION['id']);
$stmt->execute();
$stmt->bind_result($password, $email, $activation_code, $role, $registered_date, $repoowner, $reponame, $gitproject, $aadclient, $gittype, $gittoken, $aadsecret, $golden);
$stmt->fetch();
$stmt->close();
	//DO FORM STUFF


    $email2 = $_POST['email'];
    $desttenant = $_POST['desttenant'];
    $clientsecret = decryptstring($aadsecret);
    $data = array(
        array("tenant" => "$desttenant"),
        array("clientid" => "$aadclient"),
        array("clientsecret" => "$clientsecret"),
        array("email" => "$email2"),
        array("recipient" => "$email")
        );
        $header = array("message" => "Check sent to $desttenant");

    //Encode it
    $body = base64_encode(json_encode($data));
        
    //Setup CURL
    $ch = curl_init();
    $url = licensewebhook;
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_CUSTOMREQUEST, "POST");
    curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
    curl_setopt($ch, CURLOPT_HTTPHEADER, $header);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    
    $result = curl_exec($ch);
    curl_close($ch);
    
}

    header('Location: home.php?updatemessage=Review Underway');


?>