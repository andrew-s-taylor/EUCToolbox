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

if ($canrestore == 0) {
  echo "You do not have access to view this page";
  exit;
}

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
  $sentID = $_POST['tenantid'];
  //split $sentID on %%
  $pieces = explode("%%", $sentID);
  $tenantid2 = $pieces[0];
  $customerid = $pieces[1];
$goldcheck = $_POST['deployment'];
    // Retrieve additional account info from the database because we don't have them stored in sessions
$stmt = $con->prepare('SELECT reponame, golden FROM accounts WHERE id = ?');
// In this case, we can use the account ID to retrieve the account info.
$stmt->bind_param('i', $customerid);
$stmt->execute();
$stmt->bind_result($reponame, $golden);
$stmt->fetch();
$stmt->close();

//Check every database item is present


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
$sitename = "Intune Manager from EUC Toolbox";
$pagetitle = "Intune Manager";
include "header1.php";
?>

            <?php
        if (!empty($_POST['desttenant'])) {
            echo "<table class=\"styled-table\"><tr><td><form action=\"gold.php\" method=\"post\">";
            echo "<input class=\"profile-btn\" type=\"submit\" value=\"Back\">";
             echo "</form></td></tr></table>";
                 }
    else {
        echo "<table class=\"styled-table\"><tr><td><form action=\"restore.php\" method=\"post\">";
        echo "<input class=\"profile-btn\" type=\"submit\" value=\"Back\">";
        echo "</form></td></tr></table>";
    }


    ?>

			<h2>Restore - Select Backup</h2>
			
			<div class="block">

<table class="styled-table">
<form action="restore3.php" method="post">
    <input type="hidden" name="tenantid" value="<?php echo $tenantid2; ?>">
    <input type="hidden" name="customerid" value="<?php echo $customerid; ?>">

    <?php
    if (!empty($_POST['desttenant'])) {
        $desttenant = $_POST['desttenant'];
    echo "<input type=\"hidden\" name=\"desttenant\" value=\"$desttenant\">";
    }
    ?>
    <tr>
        <td><select id="filename" name="filename">
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
$adjustedTime2 = date('Y-m-d H:i:s', $item['tenantdate']);

$date2 = adjustTimezoneOffset($adjustedTime2, $offset);
if (strpos($item['filename'], 'log') === false && 
strpos($item['filename'], 'Template') === false &&
strpos($item['filename'], 'daily') === false &&
strpos($item['filename'], 'intunereport') === false &&
strpos($item['filename'], 'drift') === false &&
strpos($item['filename'], 'golddrift') === false) {
$filename = $item['filename'];
                  echo "<option value=\"$filename\">$date2</option>";              
                }
              }

              ?>
              </select>
        </td>
    <td><input class="profile-btn" type="submit" value="Select Policy"></td></tr>
    </form>
    </table>
    <?php
    if ($goldcheck == "gold") {
      ?>
    
				<br>
        <table class="styled-table">
<form action="restore3a.php" method="post">
    <input type="hidden" name="tenantid" value="<?php echo $tenantid2; ?>">
    <input type="hidden" name="customerid" value="<?php echo $customerid; ?>">

    <?php
    if (!empty($_POST['desttenant'])) {
        $desttenant = $_POST['desttenant'];
    echo "<input type=\"hidden\" name=\"desttenant\" value=\"$desttenant\">";
    }
    ?>
    <tr>
        <td><select id="filename" name="filename">
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
strpos($item['filename'], 'template') === false &&
strpos($item['filename'], 'daily') === false &&
strpos($item['filename'], 'intunereport') === false &&
strpos($item['filename'], 'drift') === false &&
strpos($item['filename'], 'golddrift') === false) {
                    $filename = $item['filename'];
                  echo "<option value=\"$filename\">$date2</option>";              
                }
              }

              ?>
              </select>
        </td>
    <td><input class="profile-btn" type="submit" value="Select Policy"></td></tr>
    </form>
    </table>
<?php
    }
    ?>
			</div>
            
	
      <?php
include "footer.php";
?>

<?php
}
else {
    header("Location: restore.php");
}
?>