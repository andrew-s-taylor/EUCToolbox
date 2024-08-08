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

    $changetype = $_POST['type'];
    $tenantid = $_POST['tenantid'];
    $policyname = $_POST['policyname'];
    $policyuri = $_POST['policyuri'];
    if (($_POST['policyjson']) == "DELETE")
    {
    $changetype = "delete";
    }
    else {
    $policyjson = base64_decode($_POST['policyjson']);
    }

    //Create a Graph access token using aadclient and secret
    $clientId = $aadclient; 
    $clientSecret = decryptstring($aadsecret);


    $token_Body = array(
        'grant_type' => 'client_credentials',
        'scope' => 'https://graph.microsoft.com/.default',
        'client_id' => $clientId,
        'client_secret' => $clientSecret
    );

    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, "https://login.microsoftonline.com/$tenantid/oauth2/v2.0/token");
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($ch, CURLOPT_POST, 1);
    curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($token_Body));

    $headers = array();
    $headers[] = 'Content-Type: application/x-www-form-urlencoded';
    curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);

    $result = curl_exec($ch);
    if (curl_errno($ch)) {
        echo 'Error:' . curl_error($ch);
    }
    curl_close($ch);

    $token_Response = json_decode($result, true);
    $authentication = $token_Response['access_token'];
    $headers = array(
        'Content-Type: application/json',
        'Authorization: Bearer ' . $authentication . ''
    );


if ($changetype == "Add") {
echo $policyjson;
//Send a Graph POST request to $policyuri with the body as $policyjson
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $policyuri);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
curl_setopt($ch, CURLOPT_POST, 1);
curl_setopt($ch, CURLOPT_POSTFIELDS, $policyjson);
curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
$result = curl_exec($ch);
print_r($result);
}

if ($changetype == "Update") {

//Get the existing policy ID

//Encode $policyname for web use
$policyname = urlencode($policyname);

$geturi = $policyuri . '?$filter=(startswith(displayName,' . "'" . $policyname . "'))";
$geturi2 = $policyuri . '?$filter=(startswith(name,' . "'" . $policyname . "'))";

$curl = curl_init();
curl_setopt_array($curl, array(
    CURLOPT_URL => "$geturi",
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_ENCODING => '',
    CURLOPT_MAXREDIRS => 10,
    CURLOPT_TIMEOUT => 0,
    CURLOPT_FOLLOWLOCATION => true,
    CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
    CURLOPT_SSL_VERIFYHOST => false,
    CURLOPT_SSL_VERIFYPEER => true,
    CURLOPT_CUSTOMREQUEST => 'GET',
    CURLOPT_HTTPHEADER => array(
      'Content-Type: application/json',
      'Authorization: Bearer ' . $authentication . ''
    ),
  ));

// Initialize the cURL session
$result = curl_exec($curl);

//If that gives error 400, try the other URI
if (strpos($result, '400') !== false) {
    $options = [
        CURLOPT_URL => "$geturi2",
        CURLOPT_HTTPHEADER => $headers,
        CURLOPT_CUSTOMREQUEST => 'GET',
        CURLOPT_RETURNTRANSFER => 'true',
    ];
    // Initialize the cURL session
    $curl = curl_init();
    curl_setopt_array($curl, $options);
    $result = curl_exec($curl);

}
  // Close the cURL session
  curl_close($curl);

//Grab the ID within value of the array
$policyid = json_decode($result, true)['value'][0]['id'];

$posturi = $policyuri . "/" . $policyid;

$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $posturi);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'UPDATE');
curl_setopt($ch, CURLOPT_POSTFIELDS, $policyjson);
curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
$result = curl_exec($ch);

}


if ($changetype == "delete") {

    //Get the existing policy ID
    
    //Encode $policyname for web use
    $policyname = urlencode($policyname);
    
    $geturi = $policyuri . '?$filter=(startswith(displayName,' . "'" . $policyname . "'))";
    $geturi2 = $policyuri . '?$filter=(startswith(name,' . "'" . $policyname . "'))";
    
    $curl = curl_init();
    curl_setopt_array($curl, array(
        CURLOPT_URL => "$geturi",
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_ENCODING => '',
        CURLOPT_MAXREDIRS => 10,
        CURLOPT_TIMEOUT => 0,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
        CURLOPT_SSL_VERIFYHOST => false,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_CUSTOMREQUEST => 'GET',
        CURLOPT_HTTPHEADER => array(
          'Content-Type: application/json',
          'Authorization: Bearer ' . $authentication . ''
        ),
      ));
    
    // Initialize the cURL session
    $result = curl_exec($curl);
    
    //If that gives error 400, try the other URI
    if (strpos($result, '400') !== false || strpos($result, 'Invalid filter clause') !== false) {
        $options = [
            CURLOPT_URL => "$geturi2",
            CURLOPT_HTTPHEADER => $headers,
            CURLOPT_CUSTOMREQUEST => 'GET',
            CURLOPT_RETURNTRANSFER => 'true',
        ];
        // Initialize the cURL session
        $curl = curl_init();
        curl_setopt_array($curl, $options);
        $result = curl_exec($curl);
    
    }
      // Close the cURL session
      curl_close($curl);
 
    //Grab the ID within value of the array
    $policyid = json_decode($result, true)['value'][0]['id'];
    
    $posturi = $policyuri . "/" . $policyid;
    
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $posturi);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'DELETE');
    curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
    $result = curl_exec($ch);
    
    }
if ($changetype == "delete") {
    header('Location: home.php?deletemessage=Policy Deleted');
}
else {
    header('Location: home.php?updatemessage=Policy Deployed');
}

    }

?>