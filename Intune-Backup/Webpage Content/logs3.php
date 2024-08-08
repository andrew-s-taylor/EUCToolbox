<?php
include 'main.php';
// Check logged-in
check_loggedin($con);
// output message (errors, etc)
$msg = '';

if (isset($_POST['filename'])) {

$tenantid = $_POST['tenantid'];
$filename = $_POST['filename'];





    // Retrieve additional account info from the database because we don't have them stored in sessions
$stmt = $con->prepare('SELECT repoowner, reponame, gitproject, gittype, gittoken, golden FROM accounts WHERE id = ?');
// In this case, we can use the account ID to retrieve the account info.
$stmt->bind_param('i', $_SESSION['id']);
$stmt->execute();
$stmt->bind_result($repoowner, $reponame, $gitproject, $gittype, $gittoken, $golden);
$stmt->fetch();
$stmt->close();

//Check every database item is present

?>


<?php
$sitename = "Intune Backup from EUC Toolbox";
$pagetitle = "Intune Backup";
include "header1.php";
?>
       <table class="styled-table"><tr><td><form action="logs2.php" method="post">
<input type = "hidden" name="tenantid" value="<?php echo $tenantid; ?>">
<?php
//Check if $desttenant is set
if (!empty($_POST['desttenant'])) {
    ?>
<input type = "hidden" name="desttenant" value="display">
<?php
}
?>
<input class="profile-btn" type="submit" value="Back">
 </form></td></tr></table>
			<h2>Logs - View Log</h2>
			
			<div class="block">


        <?php

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
  'Accept: application/vnd.github.v3.raw',
  "User-Agent: Intune-Build"
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
    $gitlabtoken = decryptstring($gittoken);


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
$token = decryptstring($gittoken);

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
echo $result;

  ?>
				

			</div>
            
	
      <?php
include "footer.php";
?>

<?php
}
else {
    header("Location: logs2.php");
}
?>