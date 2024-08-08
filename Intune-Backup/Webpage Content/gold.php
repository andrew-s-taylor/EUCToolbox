<?php
include 'main.php';
// Check logged-in
check_loggedin($con);
function adjustTimezoneOffset($time, $offset) {
	// Convert the timezone offset to the correct format for DateInterval
	$hours = floor(abs($offset) / 60);
	$minutes = abs($offset) % 60;
	$timezoneInterval = new DateInterval('PT' . $hours . 'H' . $minutes . 'M');
  
	// Create a DateTime object for the input time
	$dateTime = new DateTime($time);
  
	// Add or subtract the timezone offset from the input time
	if ($offset < 0) {
		$dateTime->sub($timezoneInterval);
	} else {
		$dateTime->add($timezoneInterval);
	}
  
	// Format the adjusted time as a string
	$adjustedTime = $dateTime->format('l, F jS Y - H:i');
  
	return $adjustedTime;
  }
// output message (errors, etc)
$msg = '';

// Retrieve additional account info from the database because we don't have them stored in sessions
$stmt = $con->prepare('SELECT repoowner, reponame, gitproject, gittype, gittoken, golden FROM accounts WHERE id = ?');
// In this case, we can use the account ID to retrieve the account info.
$stmt->bind_param('i', $_SESSION['id']);
$stmt->execute();
$stmt->bind_result($repoowner, $reponame, $gitproject, $gittype, $gittoken, $golden);
$stmt->fetch();
$stmt->close();

//Check every database item is present


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
// Close the cURL session
curl_close($curl);
//Decode the json
$decodedcommit = json_decode($result, true);
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
// Close the cURL session
curl_close($curl);
//Decode the json
$decodedcommit2 = json_decode($result, true);
$decodedcommit = $decodedcommit2['value'];

$removeditem = array_shift($decodedcommit);
}

//Create an array of dates and tenant IDs
$tenantdates = array();
foreach ($decodedcommit as $commit) {
	if ($gittype == "azure") {
		$name = $commit['path'];
	} elseif ($gittype == "github") {
		$name = $commit['name'];
	}

  $datetimeraw = substr((explode("-", $name))[6], 0, -5);
  $day = substr($datetimeraw, 4, 2);
  $month = substr($datetimeraw, 2, 2);
  $year = substr($datetimeraw, 0, 2);
  $hour = substr($datetimeraw, 6, 2);
  $minute = substr($datetimeraw, 8, 2);
  $second = substr($datetimeraw, 10, 2);
  $datetimeraw2 = $year . "-" . $month . "-" . $day . " " . $hour . ":" . $minute . ":" . $second;
  //Convert to readable date
	$datetimeraw = strtotime($datetimeraw2);
  if ($gittype == "azure") {
	$tenantid = substr($name, 1, 36);
  } elseif ($gittype == "github") {
	$tenantid = substr($name, 0, 36);
  }
  $tenantdates[] = array('tenantidarray' => $tenantid, 'tenantdate' => $datetimeraw);
}

$result2 = array_filter($tenantdates, function ($item) use ($golden) {
	if (stripos($item['tenantidarray'], $golden) !== false) {
		return true;
	}
	return false;
  });
  if (empty($result2)) {
	$date = "No Backup Taken";

}
else {
  $alldates = array();
  foreach ($result2 as $item) {
	$alldates[] = $item['tenantdate'];
  }
  
  rsort($alldates);
  
  $mostrecent2 = $alldates[0];
  
  $date = date('l jS \o\f F Y h:i:s A',$mostrecent2); 
  $timezoneOffset = $_COOKIE['timezoneOffset'];
  $adjustedTime2 = date('Y-m-d H:i:s', $mostrecent2);
  
  $date2 = adjustTimezoneOffset($adjustedTime2, $timezoneOffset);
}
?>
<?php
$sitename = "Intune Backup from EUC Toolbox";
$pagetitle = "Intune Backup";
include "header1.php";
?>

			<h2>Intro</h2>
            <div class="block">


            <p>Here you can use your Gold Tenant backups to deploy policies to any of your onboarded customers</p>
            <p>Golden Tenant ID: <?php echo $golden; ?></p>

		</div>
            
            <h2>Backup</h2>
			<div class="block">

<p>Last backup: <?php echo $date2;?></p>
<table class="styled-table">
  <tr>
    <td>
<form action="process.php" method="post">
<input type = "hidden" name="tenantid" value="<?php echo $golden; ?>">
<input type="hidden" name="type" value="backup">
<input class="profile-btn" type="submit" value="Backup">
</form>
</td>
  </tr>
</table>


		</div>
            <h2>Deploy Policies/Create Template</h2>
			
			<div class="block">



<table class="styled-table">
  <tr>
    <td>
    <form action="restore2.php" method="post">
<input type = "hidden" name="tenantid" value="<?php echo $golden; ?>">
<input type = "hidden" name="desttenant" value="display">
<input type = "hidden" name="deployment" value="gold">
<input class="profile-btn" type="submit" value="Deploy">
 </form>
    </td>
  </tr>
</table>  



		</div>
            
	
    <?php
include "footer.php";
?>