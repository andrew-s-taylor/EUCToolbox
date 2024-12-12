<?php

require_once '../../config/config.php';
// Connect to the MySQL database using MySQLi
$con = mysqli_connect(db_host, db_user, db_pass, db_name);
// If there is an error with the MySQL connection, stop the script and output the error
if (mysqli_connect_errno()) {
    exit('Failed to connect to MySQL: ' . mysqli_connect_error());
}
// Update the charset
mysqli_set_charset($con, db_charset);

header("Content-Type: application/json");

// Get the API key from the headers
$headers = getallheaders();
$apiKey = isset($headers['X-Api-Key']) ? $headers['X-Api-Key'] : '';

//Check API key has been sent
// Check if API key is empty
if (empty($apiKey)) {
    http_response_code(401);
    echo json_encode(['error' => 'Unauthorized']);
    exit();
}

// Validate the API key
$stmt = $con->prepare("SELECT id FROM accounts WHERE apikey = ? AND regtype != 'expired'");
$stmt->bind_param('s', $apiKey);
$stmt->execute();
$result = $stmt->get_result();
$user = $result->fetch_assoc();
$userID = $user['id'];
$stmt->close();
//Check if the user is valid
if (!$userID) {
    http_response_code(401);
    echo json_encode(['error' => 'Unauthorized']);
    exit();
}



// Handle the API request
$action = isset($_GET['action']) ? $_GET['action'] : '';

switch ($action) {
    case 'getall':
        $actiontaken = "Requested details for all tenants";
        $query = "SELECT tenantname, tenantid, tenantdrift, golddrift, updatedapps, adminevents, unusedlicenses, licensesonoldusers, securescore, noncompliantdevices, failedsignins, failedappinstalls, pushexpiry, vppexpiry, depexpiry, avissues, firewalloff, securitytasks, outdatedfeatureupdatepolicy, expiringsecrets, staledevices FROM tenants WHERE customerid = ?";
        $stmt = $con->prepare($query);
        $stmt->bind_param('i', $userID);
        $stmt->execute();
        $result = $stmt->get_result();

        // Check if the query was successful
        if ($result) {
            // Fetch the data as an associative array
            $data = mysqli_fetch_all($result, MYSQLI_ASSOC);

            // Convert the data to JSON format
            $json = json_encode($data);

            // Set the response headers
            header('Content-Type: application/json');

            // Output the JSON data
            echo $json;
        } else {
            // Output an error
            http_response_code(500);
            echo json_encode(['error' => 'Internal Server Error']);
        }
        break;
    case 'singletenant':
        $actiontaken = "Requested details for a single tenant " . $_GET['tenantid'] . "";
        $query = "SELECT tenantname, tenantid, tenantdrift, golddrift, updatedapps, adminevents, unusedlicenses, licensesonoldusers, securescore, noncompliantdevices, failedsignins, failedappinstalls, pushexpiry, vppexpiry, depexpiry, avissues, firewalloff, securitytasks, outdatedfeatureupdatepolicy, expiringsecrets, staledevices FROM tenants WHERE customerid = ? AND tenantid = ?";
        $stmt = $con->prepare($query);
        $stmt->bind_param('ii', $userID, $_GET['tenantid']);
        $stmt->execute();
        $result = $stmt->get_result();

        // Check if the query was successful
        if ($result) {
            // Fetch the data as an associative array
            $data = mysqli_fetch_all($result, MYSQLI_ASSOC);

            // Convert the data to JSON format
            $json = json_encode($data);

            // Set the response headers
            header('Content-Type: application/json');

            // Output the JSON data
            echo $json;
        } else {
            // Output an error
            http_response_code(500);
            echo json_encode(['error' => 'Internal Server Error']);
        }
        break;
    case 'auditlogs':
        $actiontaken = "Requested audit logs";
        $query = "SELECT auditlog.id, auditlog.timestamp, auditlog.Task, auditlog.IPAddress, accounts.email FROM auditlog INNER JOIN accounts ON auditlog.UserID = accounts.id WHERE auditlog.UserID = ? AND auditlog.timestamp >= DATE_SUB(NOW(), INTERVAL 30 DAY)";
        $stmt = $con->prepare($query);
        $stmt->bind_param('i', $userID);
        $stmt->execute();
        $result = $stmt->get_result();
        // Check if the query was successful
        if ($result) {
            // Fetch the data as an associative array
            $data = mysqli_fetch_all($result, MYSQLI_ASSOC);

            // Convert the data to JSON format
            $json = json_encode($data);

            // Set the response headers
            header('Content-Type: application/json');

            // Output the JSON data
            echo $json;
        } else {
            // Output an error
            http_response_code(500);
            echo json_encode(['error' => 'Internal Server Error']);
        }

        break;
    case 'backup':
        $actiontaken = "Requested backup for tenant " . $_GET['tenantid'] . "";
        $tenantfinal = $_GET['tenantid'];
        $type = "backup";
        $repotype = "github";
        $selected = "all";
        $ownername = gitowner;
        $token = fullgittoken;
        $project = "GitHub";
        $clientid = appID;
        $clientsecret = appSecret;
        $template = "no";
        $stmt = $con->prepare('SELECT reponame FROM accounts WHERE id = ?');
        // In this case, we can use the account ID to retrieve the account info.
        $stmt->bind_param('i', $userID);
        $stmt->execute();
        $stmt->bind_result($reponame);
        $stmt->fetch();
        $stmt->close();

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

        $body = base64_encode(json_encode($data));

        $header = array("message" => "Policy backup of $tenantfinal");

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

        echo json_encode(['message' => 'Backup request sent']);
        break;
    default:
        http_response_code(400);
        echo json_encode(['error' => 'Bad Request']);
        break;
}


//Add to audit logs
$auditlog_userID = $userID;
$auditlog_ipAddress = $_SERVER['REMOTE_ADDR'];
$auditlog_timestamp = date('Y-m-d H:i:s');
$auditlog_message = $actiontaken;
$stmt = $con->prepare('INSERT INTO auditlog (UserID, IPAddress, Timestamp, Task) VALUES (?, ?, ?, ?)');
$stmt->bind_param('isss', $auditlog_userID, $auditlog_ipAddress, $auditlog_timestamp, $auditlog_message);
$stmt->execute();
$stmt->close();

?>
