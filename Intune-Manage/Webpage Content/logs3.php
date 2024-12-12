<?php
/**
 * This file is part of a GPL-licensed project.
 *
 * Copyright (C) 2024 Andrew Taylor (andrew.taylor@andrewstaylor.com)
 * A special thanks to David at Codeshack.io for the basis of the login system!
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://github.com/andrew-s-taylor/public/blob/main/LICENSE>.
 */
?>
<?php
include 'main.php';
// Check logged-in
check_loggedin($con);
// output message (errors, etc)
$msg = '';


if ($canviewlogs == 0) {
  exit('You do not have permission to access this page!');
}

if (isset($_POST['filename'])) {

$tenantid = $_POST['tenantid'];
$filename = $_POST['filename'];
$customerid = $_POST['customerid'];




    // Retrieve additional account info from the database because we don't have them stored in sessions
$stmt = $con->prepare('SELECT reponame, golden FROM accounts WHERE id = ?');
// In this case, we can use the account ID to retrieve the account info.
$stmt->bind_param('i', $customerid);
$stmt->execute();
$stmt->bind_result($reponame, $golden);
$stmt->fetch();
$stmt->close();

//Check every database item is present

?>

<?php
$sitename = "Intune Manager from EUC Toolbox";
$pagetitle = "Intune Manager";
include "header1.php";
?>
       <table class="styled-table"><tr><td><form action="logs.php" method="post">
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