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
	} elseif ($gittype == "gitlab") {
		$name = $commit['name'];
	}
//delete the word Template from $name
preg_match('/-Template(.*?)\.json/', $name, $matches);
//Create this if anything has been removed only
if (!empty($matches)) {
  $removed = $matches[1];
} else {
  $removed = '';
}

// remove the substring from $name
$name2 = preg_replace('/-Template.*?\.json/', '.json', $name);
	  //Convert to readable date
	$datetimeraw = substr((explode("-", $name2))[6], 0, -5);
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
	  $tenantid = substr($name2, 1, 36);
	} elseif ($gittype == "github") {
	  $tenantid = substr($name2, 0, 36);
  } elseif ($gittype == "gitlab") {
	  $tenantid = substr($name2, 0, 36);
	}
	$tenantdates[] = array('tenantidarray' => $tenantid, 'tenantdate' => $datetimeraw, 'filename' => $name);
  }

?>


<?php
$sitename = "Intune Backup from EUC Toolbox";
$pagetitle = "Intune Backup";
include "header1.php";
?>

		<div class="content profile">
            <?php

        echo "<p><form action=\"manage-backups1.php\" method=\"post\">";
        echo "<input class=\"profile-btn\" type=\"submit\" value=\"Back\">";
        echo "</form></p>";
    


    ?>

			<h2>Manage Backups - Select Backup</h2>
			
			<div class="block">

<table>
<form action="deletebackup.php" method="post">
    <input type="hidden" name="tenantid" value="<?php echo $tenantid2; ?>">
    <?php
    if (!empty($_POST['desttenant'])) {
        $desttenant = $_POST['desttenant'];
    echo "<input type=\"hidden\" name=\"desttenant\" value=\"$desttenant\">";
    }
    ?>
            <?php
               if (!empty($_POST['desttenant'])) {
            $result2 = array_filter($tenantdates, function ($item) use ($golden) {
                if (stripos($item['tenantidarray'], $golden) !== false) {
                    return true;
                }
                return false;
              });
            }
            else {
                $result2 = array_filter($tenantdates, function ($item) use ($tenantid2) {
                    if (stripos($item['tenantidarray'], $tenantid2) !== false) {
                        return true;
                    }
                    return false;
                  });  
            }
              
              foreach ($result2 as $item) {
                $date = date('l jS \o\f F Y h:i:s A',$item['tenantdate']); 
                $timezoneOffset = $_COOKIE['timezoneOffset'];
$adjustedTime2 = date('Y-m-d H:i:s', $item['tenantdate']);

$date2 = adjustTimezoneOffset($adjustedTime2, $timezoneOffset);
if (strpos($item['filename'], 'log') === false && 
strpos($item['filename'], 'Template') === false &&
strpos($item['filename'], 'daily') === false &&
strpos($item['filename'], 'intunereport') === false &&
strpos($item['filename'], 'drift') === false &&
strpos($item['filename'], 'golddrift') === false) {
                    $filename = $item['filename'];
                  echo "<tr>";  
                  echo "<td>";  
                  echo $date2;
                  echo "</td>";
                  echo "<td>";
                  echo "<input type=\"checkbox\" name=\"policy[]\" value=\"$filename\" class=\"tocheck\"></td>";
                  echo "</tr> ";           
                }
              }

              ?>
    <tr><td><input class="profile-btn" type="submit" value="Delete Backup"></td></tr>
    </form>
    </table>
			</div>
            
	
      <?php
include "footer.php";
?>

<?php
}
else {
    header("Location: manage-backups1.php");
}
?>