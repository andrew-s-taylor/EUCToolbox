<?php
include 'main.php';
// Check logged-in
check_loggedin($con);
// output message (errors, etc)
$msg = '';
// Retrieve additional account info from the database because we don't have them stored in sessions
$stmt = $con->prepare('SELECT role FROM accounts WHERE id = ?');
// In this case, we can use the account ID to retrieve the account info.
$stmt->bind_param('i', $_SESSION['id']);
$stmt->execute();
$stmt->bind_result($role);
$stmt->fetch();
$stmt->close();
if ($candeployapps == 0) {
    exit('You do not have permission to access this page!');
  }

?>
<?php
$sitename = "Intune Manager from EUC Toolbox";
$pagetitle = "Intune Manager";
include "header1.php";

// Connect to the MySQL database using MySQLi
$con2 = mysqli_connect(db_hostappaz, db_userappaz, db_passappaz, db_nameappaz);
// If there is an error with the MySQL connection, stop the script and output the error
if (mysqli_connect_errno()) {
	exit('Failed to connect to MySQL: ' . mysqli_connect_error());
}
// Update the charset
mysqli_set_charset($con2, db_charset);
?>

			<h2>Robopack - Select App</h2>
			
			<div class="block">
<html>
<head>
    <title>MyIntunePortal - Add App</title>

<body>

<?php
    $search = $_POST['search'];
    $tenantid = $_POST['tenantid'];

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


$api_url = "https://api.robopack.com/v1/app?search=$search&logo=true";


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
    CURLOPT_CUSTOMREQUEST => 'GET',
    CURLOPT_HTTPHEADER => array(
        "X-API-Key: $apikey"
    ),
  ));

// Initialize the cURL session
$result = curl_exec($curl);

// Get the response headers
$header_size = curl_getinfo($curl, CURLINFO_HEADER_SIZE);
$header = substr($result, 0, $header_size);
$headers = [];
foreach (explode("\r\n", $header) as $line) {
    if (strpos($line, ': ') !== false) {
        list($key, $value) = explode(': ', $line);
        $headers[$key] = $value;
    }
}

// Extract x-pagination header
$x_pagination = json_decode($headers['X-Pagination'],true);
$totalpages = $x_pagination['totalPages'];
$totalresults = $x_pagination['totalCount'];
echo "Number of Results: $totalresults <br><br>";

// Close cURL session
curl_close($curl);

// Decode the json data
// Extract the body from the result
$body = substr($result, $header_size);
$data = json_decode($body, true);



//Check total pages
if ($totalpages > 1) {
    for ($i = 2; $i <= $totalpages; $i++) {
        $api_url = "https://api.robopack.com/v1/app?search=$search&logo=true&page=$i";
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
            CURLOPT_CUSTOMREQUEST => 'GET',
            CURLOPT_HTTPHEADER => array(
                "X-API-Key: $apikey"
            ),
        ));

        // Initialize the cURL session
        $result = curl_exec($curl);

        // Get the response headers
        $header_size = curl_getinfo($curl, CURLINFO_HEADER_SIZE);
        $body = substr($result, $header_size);
        $data2 = json_decode($body, true);

        // Merge the new data with the main data array
        $data = array_merge($data, $data2);

        // Close cURL session
        curl_close($curl);
    }
}




    echo "<table class='styled-table'>";
    echo "<tr><th>Logo</th><th>Name</th><th>Publisher</th><th>Description</th><td>Deploy</td></tr>";
    foreach ($data as $key => $value) {
        echo "<form method='POST' action='processrobopack.php'>";
        $id = $value['id'];
        $publisherName = $value['publisherName'];
        $name = $value['name'];
        $description = wordwrap($value['description'], 50, "<br>\n", true);
        $logodata = $value['logoData'];
        echo "<tr>";
        echo "<td><img src='data:image/jpeg;base64," . $logodata . "' width='50' height='50'></td>";
        echo "<td>$name</td>";
        echo "<td>$publisherName</td>";
        echo "<td>$description</td>";
        echo "<input type='hidden' name='id' value='$id'>";
        echo "<input type='hidden' name='tenantid' value='$tenantid'>";
        echo "<td><input class=\"profile-btn\" type=\"submit\" value=\"Deploy\"></td>";
        echo "</tr>";

        echo "</form>";
    }
    echo "</table>";
    ?>

</div>
               <!-- Script -->
               <script>
        $(document).ready(function(){
            
            // Initialize select2
            $("#appid").select2();

            // Read selected option
            $('#but_read').click(function(){
                var username = $('#selUser option:selected').text();
                var userid = $('#selUser').val();
           
                $('#result').html("id : " + userid + ", name : " + username);
            });
        });
        </script>
	
            <?php
include "footer.php";
?>