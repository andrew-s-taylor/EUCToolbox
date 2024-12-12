<?php
include 'main.php';
$appid = $_POST['id'];
$tenants = is_array($_POST['tenantid']) ? $_POST['tenantid'] : array($_POST['tenantid']);

$api_url = "https://api.robopack.com/v1/app/import/$appid";


##Send a get request with headers
$curl = curl_init();
curl_setopt_array($curl, array(
    CURLOPT_URL => "$api_url",
    CURLOPT_RETURNTRANSFER => 1,
    CURLOPT_HEADER => 1,
    CURLOPT_ENCODING => '',
    CURLOPT_MAXREDIRS => 10,
    CURLOPT_TIMEOUT => 0,
    CURLOPT_FOLLOWLOCATION => true,
    CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
    CURLOPT_SSL_VERIFYHOST => false,
    CURLOPT_SSL_VERIFYPEER => true,
    CURLOPT_CUSTOMREQUEST => 'POST',
    CURLOPT_HTTPHEADER => array(
        "X-API-Key: $apikey",
        "Content-Length: 0"
    ),
  ));

// Initialize the cURL session
$result = curl_exec($curl);

//Grab the result, no headers
$split = explode("\r\n\r\n", $result);
$body = $split[1];

//Upload to Intune
    //API Key
    $stmt = $con->prepare('SELECT role FROM accounts WHERE id = ?');
// Get the account info using the logged-in session ID
$stmt->bind_param('i', $_SESSION['id']);
$stmt->execute();
$stmt->bind_result($role2);
$stmt->fetch();
$stmt->close();
// Check if the user is an admin...
if ($role2 != 'Admin' && $role2 != 'SuperAdmin' && $role2 != 'SubAdmin') {
// Retrieve additional account info from the database because we don't have them stored in sessions
$stmt = $con->prepare('SELECT ID, accountID, apiName, apisecret, clientID FROM api_integrations WHERE accountID = ? and apiName = "Robopack"');
// In this case, we can use the account ID to retrieve the account info.
$stmt->bind_param('i', $_SESSION['id']);
$stmt->execute();
$result = $stmt->get_result();
}
else {
// Retrieve additional account info from the database because we don't have them stored in sessions
$stmt = $con->prepare('SELECT ID, accountID, apiName, apisecret, clientID FROM api_integrations WHERE accountID = ? and apiName = "Robopack"');
// In this case, we can use the account ID to retrieve the account info.
if ($role2 == "SubAdmin") {
	$stmt->bind_param('i', $primaryadmin);
}
else {
// In this case, we can use the account ID to retrieve the account info.
$stmt->bind_param('i', $_SESSION['id']);
}
$stmt->execute();
$result = $stmt->get_result();	
}

//Check if there is an apiName called "Robopack" with an apisecret set
while ($row = $result->fetch_assoc()) {
    $apisecret = $row['apisecret'];
    $apikey = decryptstring($row['apisecret']);

}
$stmt->close();

//Loop through tenants
foreach ($tenants as $tenant) {
    //Upload to Intune
$uploaduri = "https://api.robopack.com/v1/tenant/$tenant/upload?packageId=$body&uploadMsixAsWin32=true&wait=false";

//Add body content
$body = json_encode(array('packageId' => $body, 'uploadMsixAsWin32' => true, 'wait' => false, 'id' => $tenant));

##Send a get request with headers
$curl = curl_init();
curl_setopt_array($curl, array(
    CURLOPT_URL => "$uploaduri",
    CURLOPT_RETURNTRANSFER => 1,
    CURLOPT_HEADER => 1,
    CURLOPT_ENCODING => '',
    CURLOPT_MAXREDIRS => 10,
    CURLOPT_TIMEOUT => 0,
    CURLOPT_FOLLOWLOCATION => true,
    CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
    CURLOPT_SSL_VERIFYHOST => false,
    CURLOPT_SSL_VERIFYPEER => true,
    CURLOPT_CUSTOMREQUEST => 'POST',
    CURLOPT_HTTPHEADER => array(
        "X-API-Key: $apikey",
        "Content-Length: 0"
    ),
  ));

// Initialize the cURL session
$result = curl_exec($curl);

}

    header('Location: home.php?updatemessage=App Installing');



?>