<?php
include 'main.php';
// Check logged-in
check_loggedin($con);
// output message (errors, etc)
$msg = '';

function getAccessToken() {
    //Generate a token if it doesn't already exist and store it in a session. 
    if (!isset($_SESSION['access_token']) || !isset($_SESSION['expires_on'])) {
        $accessToken = generateAccessToken();
        $_SESSION['access_token'] = $accessToken['access_token'];
        $_SESSION['expires_on'] = $accessToken['expires_on'];
        return $accessToken;
    } else {
        //check if token is expired or not
        $expires_on = $_SESSION['expires_on']; // Unix timestamp
        $current_time = time();
        //Check if token expiry has passed and regenerate token. Othwerwise, return the stored token from the session variables.
        if($current_time >= $expires_on){
            $accessToken = generateAccessToken();
            $_SESSION['access_token'] = $accessToken['access_token'];
            $_SESSION['expires_on'] = $accessToken['expires_on'];
            return $accessToken;
        } Else {
            return $_SESSION;
        }
    }
}

function generateAccessToken() {        
    // Set up the request parameters
    global $clientId, $clientSecret, $tenant_id;

    $grantType = "client_credentials";
    $resource = "https://graph.microsoft.com";
    $tokenEndpoint = "https://login.microsoftonline.com/$tenant_id/oauth2/token";

    // Build the request body
    $requestBody = "client_id=$clientId&client_secret=$clientSecret&grant_type=$grantType&resource=$resource";

    // Set up the curl options
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $tokenEndpoint);
    curl_setopt($ch, CURLOPT_POST, 1);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $requestBody);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);

    // Execute the request
    $response = curl_exec($ch);
    curl_close($ch);

    // Extract the access token from the response
    $responseJson = json_decode($response, true);
    //$accessToken = $responseJson["access_token"];
    //return $accessToken;
    return $responseJson;
}
?>
<?php
$sitename = "Intune Backup from EUC Toolbox";
$pagetitle = "Intune Backup";
include "header1.php";
?>

			<h2>Test Results</h2>
			
			<div class="block">
                <?php



//Get Form Data
$testtype = $_POST['testtype'];

// Retrieve additional account info from the database because we don't have them stored in sessions
$stmt = $con->prepare('SELECT repoowner, reponame, gitproject, gittype, gittoken, aadclient, aadsecret FROM accounts WHERE id = ?');
// In this case, we can use the account ID to retrieve the account info.
$stmt->bind_param('i', $_SESSION['id']);
$stmt->execute();
$stmt->bind_result($repoowner, $reponame, $gitproject, $gittype, $gittoken, $clientId, $clientSecret1);
$stmt->fetch();
$stmt->close();
if ($testtype == "git") {
//Check What Git is being used
if ($gittype == "github") {

    //GitHub Repo
                //Github Details
    $githubowner = $repoowner;
    $githubrepo = $reponame;
    $githubtoken = decryptstring($gittoken);
    
    
    // Authenticate with GitHub using a personal access token
    $authentication = base64_encode("$githubowner:$githubtoken");
    
    
    // Set up the request headers
    $headers = [
      "Authorization: Basic $authentication",
      'Accept: application/vnd.github+json',
      "User-Agent: Intune-Build"
    ];
    
    // Set up the cURL options
    $options = [
      CURLOPT_URL => "https://api.github.com/repos/$githubowner/$githubrepo/contents",
      CURLOPT_HTTPHEADER => $headers,
      CURLOPT_CUSTOMREQUEST => 'GET',
      CURLOPT_RETURNTRANSFER => 'true',
    ];
    
    // Initialize the cURL session
    $curl = curl_init();
    curl_setopt_array($curl, $options);
    
    $result = curl_exec($curl);
    $httpcode = curl_getinfo($curl, CURLINFO_HTTP_CODE);
    $err = curl_error($curl);
    // Close the cURL session
    curl_close($curl);
    //Decode the json
    }
    
    if ($gittype == "gitlab") {
    
        //GitLab Repo
                    //GitLab Details
        $gitprojectid = $gitproject;
        $gitlabtoken = decryptstring($gittoken);
        
    
        // Set up the request headers
        $headers = [
            "PRIVATE-TOKEN:  $gitlabtoken"
        ];
        
        // Set up the cURL options
        $options = [
          CURLOPT_URL => "https://gitlab.com/api/v4/projects/$gitprojectid/repository/tree",
          CURLOPT_HTTPHEADER => $headers,
          CURLOPT_CUSTOMREQUEST => 'GET',
          CURLOPT_RETURNTRANSFER => 'true',
        ];
        
        // Initialize the cURL session
        $curl = curl_init();
        curl_setopt_array($curl, $options);
        
        $result = curl_exec($curl);
        $httpcode = curl_getinfo($curl, CURLINFO_HTTP_CODE);
    $err = curl_error($curl);
        // Close the cURL session
        curl_close($curl);
        //Decode the json
        }
    
    if ($gittype == "azure") {
        $org = $repoowner;
    $repo = $reponame;
    $project = $gitproject;
    $token = decryptstring($gittoken);
    
    // Set up the request headers
    $headers = array(
        "Content-Type:application/json",
        "Authorization: Basic ".base64_encode(":".$token)
    );
    
    // Set up the cURL options
    $options = [
      CURLOPT_URL => "https://dev.azure.com/$org/$project/_apis/git/repositories/$repo/items?recursionLevel=Full&versionDescriptor.version=master&api-version=5.0",
      CURLOPT_HTTPHEADER => $headers,
      CURLOPT_CUSTOMREQUEST => 'GET',
      CURLOPT_RETURNTRANSFER => 'true',
    ];
    
    // Initialize the cURL session
    $curl = curl_init();
    curl_setopt_array($curl, $options);
    
    $result = curl_exec($curl);
    $httpcode = curl_getinfo($curl, CURLINFO_HTTP_CODE);
    $err = curl_error($curl);
    // Close the cURL session
    curl_close($curl);
    
    }
        //Check if the request was successful or not
        if ($httpcode >= 200 && $httpcode < 300) {
            // All ok
            echo "Connected Successfully to $gittype";
        } else {
            // If the request failed, display the error
            echo $err;
        }
} elseif ($testtype == "graph") {
  $tenant_id = $_POST['tenantid'];
  $clientSecret = decryptstring($clientSecret1);

    $accessToken = getAccessToken();
    // Next, use the Microsoft Graph API to get the user's profile picture
    $ch = curl_init();
    $url = 'https://graph.microsoft.com/beta/deviceManagement/';
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($ch, CURLOPT_HTTPHEADER, array("Authorization: Bearer " . $accessToken['access_token']));
    $output = curl_exec($ch);
    $httpcode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $err = curl_error($ch);
    curl_close($ch);



    //Check if the request was successful or not
    if ($httpcode >= 200 && $httpcode < 300) {
        // All ok
        echo "Connected Successfully to tenant: $tenant_id";
    } else {
        // If the request failed, display the error
        echo $err;
        echo "Graph Connection failed for tenant $tenant_id<br>";
        print_r($accessToken);
    }

} else {
    echo "No Test Type Selected";
}
?>
    </div>
            
	
    <?php
include "footer.php";
?>