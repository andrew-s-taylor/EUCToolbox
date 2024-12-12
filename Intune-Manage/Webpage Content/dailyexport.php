<?php
include 'main.php';
// Check logged-in
check_loggedin($con);
// output message (errors, etc)
$msg = '';

$customerid = $_POST['customerid'];
$tenantid = $_POST['tenantid'];
$reporttype = $_POST['type'];

// Retrieve additional account info from the database because we don't have them stored in sessions
$stmt = $con->prepare('SELECT reponame FROM accounts WHERE id = ?');
// In this case, we can use the account ID to retrieve the account info.
$stmt->bind_param('i', $customerid);
$stmt->execute();
$stmt->bind_result($reponame);
$stmt->fetch();
$stmt->close();


if ($reporttype == "security") {
    $filename = $tenantid . '-intunereport.html';
}
elseif ($reporttype == "daily") {
    $filename = $tenantid . '-daily.html';
}


if ($gittype == "github") {

    //GitHub Repo
                //Github Details
    $githubowner = $repoowner;
    $githubrepo = $reponame;
    $githubtoken = $gittoken;

    // Authenticate with GitHub using a personal access token
$authentication = base64_encode("$githubowner:$githubtoken");


// Set up the request headers
$headers = [
  "Authorization: Basic $authentication",
  'Accept: application/vnd.github.v3.raw',
  "User-Agent: ManageIntune"
];

        // Set up the cURL options
$options = [
    CURLOPT_URL => "https://api.github.com/repos/$githubowner/$githubrepo/contents/$filename",
    CURLOPT_HTTPHEADER => $headers,
    CURLOPT_CUSTOMREQUEST => 'GET',
    CURLOPT_RETURNTRANSFER => 'true',
  ];
  
  // Initialize the cURL session
  $curl = curl_init();
  curl_setopt_array($curl, $options);
  
  $result = curl_exec($curl);


}

if ($gittype == "gitlab") {

    //Gitlab Repo
                //Gitlab Details
    $gitprojectid = $gitproject;
    $gitlabtoken = $gittoken;


	// Set up the request headers
	$headers = [
		"PRIVATE-TOKEN:  $gitlabtoken"
	];

        // Set up the cURL options
$options = [
    CURLOPT_URL => "https://gitlab.com/api/v4/projects/$gitprojectid/repository/files/$filename"."/raw?ref=main",
    CURLOPT_HTTPHEADER => $headers,
    CURLOPT_CUSTOMREQUEST => 'GET',
    CURLOPT_RETURNTRANSFER => 'true',
  ];
  // Initialize the cURL session
  $curl = curl_init();
  curl_setopt_array($curl, $options);
  
  $result = curl_exec($curl);


}

if ($gittype == "azure") {
	$org = $repoowner;
$repo = $reponame;
$project = $gitproject;
$token = $gittoken;

// Set up the request headers
$headers = array(
    "Content-Type:application/json",
    "Authorization: Basic ".base64_encode(":".$token)
);
// Set up the cURL options
$options = [
    CURLOPT_URL => "https://dev.azure.com/$org/$project/_apis/git/repositories/$repo/items?scopepath=$filename&api-version=5.0&version=master",
    CURLOPT_HTTPHEADER => $headers,
    CURLOPT_CUSTOMREQUEST => 'GET',
    CURLOPT_RETURNTRANSFER => 'true',
  ];
  
  // Initialize the cURL session
  $curl = curl_init();
  curl_setopt_array($curl, $options);
  
  $result = curl_exec($curl);
  // Close the cURL session
  curl_close($curl);


}
//Replace \n with line breaks
$result = str_replace('\n', '<br />', $result);

//Remove all items in <head> tag
$result = preg_replace('#<head>.*?</head>#s', '', $result);
$result = preg_replace('#<script>.*?</script>#s', '', $result);
$result = preg_replace('#<style>.*?</style>#s', '', $result);

// Include the Dompdf autoloader
require_once 'dompdf/autoload.inc.php';

// reference the Dompdf namespace
use Dompdf\Dompdf;

// instantiate and use the dompdf class
$dompdf = new Dompdf();
$dompdf->loadHtml($result);

// (Optional) Setup the paper size and orientation
$dompdf->setPaper('A4', 'landscape');

// Render the HTML as PDF
$dompdf->render();

// Output the generated PDF to Browser
$dompdf->stream();

?>