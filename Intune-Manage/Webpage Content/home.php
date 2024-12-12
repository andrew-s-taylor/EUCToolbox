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

?>
<?php
$sitename = "Intune Manager from EUC Toolbox";
$pagetitle = "Intune Manager";
include "header1.php";
?>

			<h2>Home</h2>
			<p>
	<?php
if (isset($_GET['updatemessage'])) {
	//Display Process Messages
	echo $_GET['updatemessage'];
}
	?>
</p>
			<?php
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
$stmt = $con->prepare('SELECT reponame, golden, outdated FROM accounts WHERE id = ?');
$stmt->bind_param('i', $_SESSION['id']);
$stmt->execute();
$stmt->bind_result($reponame, $golden, $daystocheck);
$stmt->fetch();
$stmt->close();
}

else {
	$customerid2 = $_POST['profileid'];
	if ($customerid2) {
		$stmt = $con->prepare('SELECT reponame, golden, outdated FROM accounts WHERE id = ? AND primaryid = ?');
		if ($role2 == "SubAdmin") {
			// Retrieve additional account info from the database because we don't have them stored in sessions
			// In this case, we can use the account ID to retrieve the account info.
			$stmt->bind_param('ii', $customerid2, $primaryadmin);			}
			else {
$stmt->bind_param('ii', $customerid2, $_SESSION['id']);
			}
			$stmt->execute();
$stmt->bind_result($reponame, $golden, $daystocheck);
$stmt->fetch();
$stmt->close();

?>
	<table class="styled-table">
	<form action="home.php" method="POST">
		<tr><td>
		<select name='profileid'>
	<?php
	//Get details for selected customer and add as an option with selected
	if ($role2 == "SubAdmin") {
		$stmt = $con->prepare('SELECT ID, email FROM accounts WHERE primaryid = ?');
		$stmt->bind_param('i', $primaryadmin);
	}
	else {
	$stmt = $con->prepare('SELECT ID, email FROM accounts WHERE primaryid = ?');
	$stmt->bind_param('i', $_SESSION['id']);
	}
	$stmt->execute();
	$result = $stmt->get_result();
	while ($row = $result->fetch_assoc()) {
		//Pass the URL as the value
		$profileid = $row['ID'];
		$profilename = $row['email'];
		if ($profileid == $customerid2) {
			echo "<option value='$profileid' selected>$profilename</option>";
		}
		else {
			echo "<option value='$profileid'>$profilename</option>";
		}

	
	}
		$stmt->close();
		?>
		</select>
		   </td>
		<td><input class="profile-btn" type="submit" value="Switch Customer"></td></tr>
		</form>
		</table>
		<?php
	}
	else {
	// Retrieve additional account info from the database because we don't have them stored in sessions
	$stmt = $con->prepare('SELECT ID, email FROM accounts WHERE primaryid = ?');
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
	
	/* Get the number of rows */
	$num_of_rows = $result->num_rows;
	?>
	<p>Please select a customer to view the details</p>
	<table class="styled-table">
	<form action="home.php" method="POST">
		<tr><td>
		<select name='profileid'>
		
	<?php
	while ($row = $result->fetch_assoc()) {
		//Pass the URL as the value
		$profileid = $row['ID'];
		$profilename = $row['email'];
		echo "<option value='$profileid'>$profilename</option>";
	
	}
		$stmt->close();
		?>
		</select>
		   </td>
		<td><input class="profile-btn" type="submit" value="Select Customer"></td></tr>
		</form>
		</table>
		<?php
	}

}
//Check every database item is present

if ($role2 != 'Admin' && $role2 != 'SuperAdmin' && $role2 != 'SubAdmin') {
	header('Location: profile-select.php');
} 

//Check What Git is being used
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
  'Accept: application/vnd.github+json',
  "User-Agent: ManageIntune"
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
	$gitlabtoken = $gittoken;
	

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
$token = $gittoken;

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
	elseif ($gittype == "gitlab") {
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
  elseif ($gittype == "gitlab") {
	$tenantid = substr($name, 0, 36);
  }
  $tenantdates[] = array('tenantidarray' => $tenantid, 'tenantdate' => $datetimeraw);
}

$outofdate = date('Y-m-d h:m:s', strtotime("-$daystocheck days"));


///GRAB DRIFT
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
	  'Accept: application/vnd.github+json',
	  "User-Agent: ManageIntune"
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
		$gitlabtoken = $gittoken;
		
	
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
	$token = $gittoken;
	
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
	$tenantdrift = array();
	foreach ($decodedcommit as $commit) {
		if ($gittype == "azure") {
			$name = $commit['path'];
		} elseif ($gittype == "github") {
			$name = $commit['name'];
		} elseif ($gittype == "gitlab") {
			$name = $commit['name'];
		}
	
		//Find the files with drift in the filename
		if (strpos($name, 'drift') !== false) {
			//Get the tenant ID from the filename
			$tenantid = substr($name, 0, 36);
			//Get the file content, convert from JSON and count the number of items
			if ($gittype == "azure") {
				$contents = $commit['content'];
				$decodedcontents = json_decode(base64_decode($contents), true);
				$rowcount = (!empty($decodedcontents)) ? (count($decodedcontents)/4) : 0;
			} elseif ($gittype == "github") {
				$contents = $commit['download_url'];
				$decodedcontents = json_decode(file_get_contents($contents), true);
				$rowcount = (!empty($decodedcontents)) ? (count($decodedcontents)/4) : 0;
			} elseif ($gittype == "gitlab") {
				$contents = $commit['url'];
				$decodedcontents = json_decode(file_get_contents($contents), true);
				$rowcount = (!empty($decodedcontents)) ? (count($decodedcontents)/4) : 0;
			}
			//Create an array with the tenant ID and count of rows
			$tenantdrift[$tenantid] = $rowcount;
		}
	}

	//END DRIFT


	//GOLD DRIFT
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
		  'Accept: application/vnd.github+json',
		  "User-Agent: ManageIntune"
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
			$gitlabtoken = $gittoken;
			
		
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
		$token = $gittoken;
		
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
		

	//END DRIFT
	if (($role2 == 'Admin' || $role2 == 'SuperAdmin' || $role2 == 'SubAdmin') && !$customerid2) {
echo "Please select a customer";
	}
	else {
	$stmt = $con->prepare('SELECT role FROM accounts WHERE id = ?');
	// Get the account info using the logged-in session ID
	$stmt->bind_param('i', $_SESSION['id']);
	$stmt->execute();
	$stmt->bind_result($role2);
	$stmt->fetch();
	$stmt->close();
	// Check if the user is an admin...
	if ($role2 != 'Admin' && $role2 != 'SuperAdmin' && $role2 !='SubAdmin') {
		// Retrieve additional account info from the database because we don't have them stored in sessions
		$stmt = $con->prepare('SELECT ID, tenantname, tenantid, customerid FROM tenants WHERE ownerid = ?');
		// In this case, we can use the account ID to retrieve the account info.
		$stmt->bind_param('i', $_SESSION['id']);
		$stmt->execute();
		$result = $stmt->get_result();

	}
	else {
		// Retrieve additional account info from the database because we don't have them stored in sessions
		$stmt = $con->prepare('SELECT ID, tenantname, tenantid, customerid FROM tenants WHERE ownerid = ?');
		// In this case, we can use the account ID to retrieve the account info.
		if ($role2 == "SubAdmin") {
			$stmt->bind_param('i', $customerid2);
		}
		else {
		// In this case, we can use the account ID to retrieve the account info.
		$stmt->bind_param('i', $customerid2);
		}
		$stmt->execute();
		$result = $stmt->get_result();	
	}

	/* Get the number of rows */
	$num_of_rows = $result->num_rows;
	echo "<h2>Your Tenant Status</h2>";
	echo "<table class=\"styled-table\">";
	echo "<thead>";
	echo "<tr><td>Tenant</td><td>Last Backup</td><td>Status</td><td>Drift</td><td>Gold Drift</td><td></td><td></td></tr>";
	echo "</thead>";
	$i = 1;

	while ($row = $result->fetch_assoc()) {
//Loop through each tenant ID and sort by most recent
$tenantid1 = $row['tenantid'];
$tenantname = $row['tenantname'];
$customerid3 = $row['customerid'];

echo "<tr>";
echo "<td>" . $tenantname . "</td>";

$result2 = array_filter($tenantdates, function ($item) use ($tenantid1) {
  if (stripos($item['tenantidarray'], $tenantid1) !== false) {
      return true;
  }
  return false;
});
if (empty($result2)) {
	echo "<td class=\"red\">No Backup</td>";
	echo "<td class=\"red\">No Backup</td>";

}
else {

$alldates = array();
foreach ($result2 as $item) {
  $alldates[] = $item['tenantdate'];
}

rsort($alldates);
$mostrecent2 = $alldates[0];
$date = date('l jS \o\f F Y h:i:s A',$mostrecent2); 
$checkdate = date('Y-m-d h:m:s', $mostrecent2);
$adjustedTime2 = date('Y-m-d H:i:s', $mostrecent2);

$date2 = adjustTimezoneOffset($adjustedTime2, $offset);
if ($mostrecent2 != "") {
	echo "<td>" . $date2 . "</td>";

} else {
	// Handle invalid datestamp
	echo "<td class=\"red\">No Backup</td>";
}

    
if ($checkdate < $outofdate) {

	echo "<td class=\"red\">Overdue</td>";
  } else {
	echo "<td class=\"green\">Ok</td>";
  }
}
//Get rowcount from $tenantdates for tenantid
$rowcount = $tenantdrift[$tenantid1];
if ($rowcount == 0) {
	echo "<td class=\"green\">No Drift</td>";
} else {
	?>
	<td class="red">
	<?php if ($cancheckdrift == 1): ?>
	<form action="displaydrift.php" method="post">
	<input type = "hidden" name="tenantid" value="<?php echo "$tenantid1%%$customerid3"; ?>">
	<input type = "hidden" name="type" value="backup">
	<input class="profile-btn" type="submit" value="Drift">
	 </form>
	 <?php endif; ?></td>
	 <?php
}
//Get rowcount from $tenantdates for tenantid
//Retrieve all records from driftack table in the database where tenantid = $tenantid
$stmt1 = $con->prepare('SELECT ID, tenantid, policyname FROM driftack WHERE tenantid = ?');
$stmt1->bind_param('s', $tenantid);
$stmt1->execute();
$result1 = $stmt1->get_result();

//Create an array of the policynames
$acknowledged = array();
while ($row1 = $result1->fetch_assoc()) {
    $acknowledged[] = $row1['policyname'];
}



foreach ($decodedcommit as $commit) {
	if ($gittype == "azure") {
		$name = $commit['path'];
	} elseif ($gittype == "github") {
		$name = $commit['name'];
	} elseif ($gittype == "gitlab") {
		$name = $commit['name'];
	}
        //Find the files with backup and $tenantid value in the filename and get the content
        if (strpos($name, "golddrift") !== false && strpos($name, $tenantid1) !== false) {
            if ($gittype == "azure") {
                $backupfile = $commit['url'];
            } elseif ($gittype == "github") {
                $backupfile = $commit['download_url'];
            } elseif ($gittype == "gitlab") {
                $backupfile = $commit['url'];
            }
            $decodedcontents = json_decode(file_get_contents($backupfile), true);
        }


}
if (empty($decodedcontents)) {
	$count = 0;
} else
{

$arcount = count($decodedcontents, COUNT_RECURSIVE) - count($decodedcontents);

if ($arcount <=2) {
	$decodedcontents = array($decodedcontents);
}

$count = 0;
//Loop through the JSON array and get the values
foreach ($decodedcontents as $content) {
    $policyname = $content['Name'];
    //If $policyname is in the $acknowledged array, don't count it
    if (in_array($policyname, $acknowledged)) {

    }
    else {
        $count++;

	}
}
}
if ($count == 0) {
	echo "<td class=\"green\">No Drift</td>";
} else {
	?>
	<td class="red">
	<?php if ($cancheckdrift == 1): ?>	
	<form action="displaydrift.php" method="post">
	<input type = "hidden" name="tenantid" value="<?php echo "$tenantid1%%$customerid3"; ?>">
	<input type = "hidden" name="type" value="gold">
	<input class="profile-btn" type="submit" value="Drift">
	 </form>
	<?php endif; ?>
	</td>
	 <?php
	 }
  ?>
<td>
<?php if ($canbackup == 1): ?>	
<form action="process.php" method="post">
<input type = "hidden" name="tenantid" value="<?php echo "$tenantid1%%$customerid3"; ?>">
<input type = "hidden" name="type" value="backup">
<input class="profile-btn" type="submit" value="Backup">
</form>
<?php endif; ?>
</td>
<td>
<?php if ($canrestore): ?>	
<form action="restore2.php" method="post">
<input type = "hidden" name="tenantid" value="<?php echo "$tenantid1%%$customerid3"; ?>">
<input class="profile-btn" type="submit" value="Restore">
 </form>
<?php endif; ?>
</td>
<?php
echo "</tr>";
$i++;
}
echo "</table>";
if ($_SESSION['role'] == 'Admin' || $_SESSION['role'] == 'SuperAdmin' || $_SESSION['role'] == 'SubAdmin'):
echo "<h2>Your Golden Tenant Status</h2>";
echo "<table class=\"styled-table\">";
echo "<thead>";
echo "<tr><td>Last Backup</td><td>Status</td><td></td><td></td></tr>";
echo "</thead>";
echo "<tr>";
$result2 = array_filter($tenantdates, function ($item) use ($golden) {
  if (stripos($item['tenantidarray'], $golden) !== false) {
      return true;
  }
  return false;
});
if (empty($result2)) {
	echo "<td>N/A</td><td class=\"red\">No Backup</td>";

}
else {
$alldates = array();
foreach ($result2 as $item) {
  $alldates[] = $item['tenantdate'];
}

rsort($alldates);

$mostrecent2 = $alldates[0];

$date = date('l jS \o\f F Y h:i:s A',$mostrecent2); 
$checkdate = date('Y-m-d h:m:s', $mostrecent2);
$timezoneOffset = $_COOKIE['timezoneOffset'];
$adjustedTime2 = date('Y-m-d H:i:s', $mostrecent2);

$date2 = adjustTimezoneOffset($adjustedTime2, $timezoneOffset);
echo "<td>" . $date2 . "</td>";
if ($checkdate < $outofdate) {
	echo "<td class=\"red\">Overdue</td>";
  } else {
	echo "<td class=\"green\">Ok</td>";
  }
}


  ?>
<td>
<?php if ($canbackup): ?>	
<form action="process.php" method="post">
<input type = "hidden" name="tenantid" value="<?php echo "$golden%%$customerid3"; ?>">
<input type = "hidden" name="type" value="backup">
<input class="profile-btn" type="submit" value="Backup">
</form>
<?php endif; ?>
</td>
<td>
<?php if ($cangolddeploy): ?>	
<form action="restore2.php" method="post">
<input type = "hidden" name="tenantid" value="<?php echo "$golden%%$customerid3"; ?>">
<input class="profile-btn" type="submit" value="Restore">
 </form>
<?php endif; ?>
</td>
<?php
echo "</tr>";
echo "</table>";
endif;
$stmt->close();
	}
?>

		</div>

	
		<?php
include "footer.php";
?>