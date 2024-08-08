<?php
include 'main.php';
// Check logged-in
check_loggedin($con);
// output message (errors, etc)
$msg = '';

if (isset($_POST['tenantid'])) {
$tenantid2 = $_POST['tenantid'];
    // Retrieve additional account info from the database because we don't have them stored in sessions
$stmt = $con->prepare('SELECT repoowner, reponame, gitproject, gittype, gittoken, golden FROM accounts WHERE id = ?');
// In this case, we can use the account ID to retrieve the account info.
$stmt->bind_param('i', $_SESSION['id']);
$stmt->execute();
$stmt->bind_result($repoowner, $reponame, $gitproject, $gittype, $gittoken, $golden);
$stmt->fetch();
$stmt->close();

//Check every database item is present
$checkbox1=$_POST['policy'];  
//Add each checkbox submitted to the $chk variable
foreach($checkbox1 as $chk1)  
   {  

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

//Get the SHA
$sha3 = file_get_contents("https://api.github.com/repos/$githubowner/$githubrepo/contents/$chk1?ref=main", false, stream_context_create([
  'http' => [
    'method' => 'GET',
    'header' => $headers
  ]
]));

$sha2 = json_decode($sha3, true);
$sha = $sha2['sha'];
// Set up the cURL options to delete the file include sha and message
$options = [
  CURLOPT_URL => "https://api.github.com/repos/$githubowner/$githubrepo/contents/$chk1",
  CURLOPT_HTTPHEADER => $headers,
  CURLOPT_CUSTOMREQUEST => 'DELETE',
  CURLOPT_RETURNTRANSFER => 'true',
  CURLOPT_POSTFIELDS => '{"message": "Deleted by IntuneBackup", "sha": "'.$sha.'"}'
];


// Initialize the cURL session
$curl = curl_init();
curl_setopt_array($curl, $options);
$result = curl_exec($curl);
// Close the cURL session
curl_close($curl);
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

    //Convert $chk1 to URL-encoded
    $chk1 = urlencode($chk1);
	
	// Set up the cURL options to delete the file
    $options = [
      CURLOPT_URL => "https://gitlab.com/api/v4/projects/$gitprojectid/repository/files/$chk1",
      CURLOPT_HTTPHEADER => $headers,
      CURLOPT_CUSTOMREQUEST => 'DELETE',
      CURLOPT_RETURNTRANSFER => 'true',
      CURLOPT_POSTFIELDS => '{"branch": "main", "commit_message": "Deleted by IntuneBackup"}'
    ];
	
	// Initialize the cURL session
	$curl = curl_init();
	curl_setopt_array($curl, $options);
	$result = curl_exec($curl);
// Close the cURL session
curl_close($curl);
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

$options = [
    CURLOPT_URL => "https://dev.azure.com/$org/$project/_apis/git/repositories/$repo/items?scopepath=/&recursionLevel=Full&includeContentMetadata=true&api-version=7.1-preview.1&version=master",
    CURLOPT_HTTPHEADER => $headers,
    CURLOPT_CUSTOMREQUEST => 'GET',
    CURLOPT_RETURNTRANSFER => 'true',
  ];
  // Initialize the cURL session
  $curl = curl_init();
  curl_setopt_array($curl, $options);
  $result2 = curl_exec($curl);
  // Close the cURL session
  curl_close($curl);

    ////Look through the array to find this file
    //Decode the json
        $decodedcommit2 = json_decode($result2, true);
        $decodedcommit3 = $decodedcommit2['value'];
        foreach ($decodedcommit3 as $decodedcommit4) {
            $decodedcommit5 = $decodedcommit4['path'];
            if ($decodedcommit5 == $chk1) {
                $sha3 = $decodedcommit4['commitId'];
            }
        }

// Get the object ID of the latest commit on 'refs/heads/master'
$options = [
    CURLOPT_URL => "https://dev.azure.com/$org/$project/_apis/git/repositories/$repo/refs?filter=heads/master&api-version=6.0",
    CURLOPT_HTTPHEADER => $headers,
    CURLOPT_CUSTOMREQUEST => 'GET',
    CURLOPT_RETURNTRANSFER => 'true'
  ];
  $curl = curl_init();
  curl_setopt_array($curl, $options);
  $result3 = curl_exec($curl);
  curl_close($curl);
  $decodedcommit6 = json_decode($result3, true);

    $latestCommitObjectId = $decodedcommit6['value'][0]['objectId'];


  
  // Set up the cURL options to delete the file using a POST request for a new commit with the changeType as delete using the object ID
  $options = [
    CURLOPT_URL => "https://dev.azure.com/$org/$project/_apis/git/repositories/$repo/pushes?api-version=6.0",
    CURLOPT_HTTPHEADER => $headers,
    CURLOPT_CUSTOMREQUEST => 'POST',
    CURLOPT_RETURNTRANSFER => 'true',
    CURLOPT_POSTFIELDS => '{"refUpdates": [{"name": "refs/heads/master","oldObjectId": "'.$latestCommitObjectId.'"}],"commits": [{"comment": "Deleted by IntuneBackup","changes": [{"changeType": "delete","item": {"path": "'.$chk1.'"}}]}]}'
  ];
  $curl = curl_init();
  curl_setopt_array($curl, $options);
  $result = curl_exec($curl);
  curl_close($curl);

   }  
   }
   header('Location: home.php?updatemessage=File Deleted');
}
else {
    header("Location: manage-backups1.php");
}
?>