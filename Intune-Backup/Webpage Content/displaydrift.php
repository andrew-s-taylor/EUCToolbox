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
?>
<?php
$sitename = "Intune Backup from EUC Toolbox";
$pagetitle = "Intune Backup";
include "header1.php";
?>


			<h2>Check Drift - Results</h2>
			
			<div class="block">
<?php    
$stmt = $con->prepare('SELECT repoowner, reponame, gitproject, gittype, gittoken, golden, outdated FROM accounts WHERE id = ?');
// In this case, we can use the account ID to retrieve the account info.
$stmt->bind_param('i', $_SESSION['id']);
$stmt->execute();
$stmt->bind_result($repoowner, $reponame, $gitproject, $gittype, $gittoken, $golden, $daystocheck);
$stmt->fetch();
$stmt->close();

//Check every database item is present

if (empty($repoowner) || empty($reponame) || empty($gitproject) || empty($gittype) || empty($gittoken)) {
	header('Location: profile.php');
} 

// Retrieve additional account info from the database because we don't have them stored in sessions
$stmt = $con->prepare('SELECT ID, tenantname, tenantid FROM tenants WHERE ownerid = ?');
// In this case, we can use the account ID to retrieve the account info.
$stmt->bind_param('i', $_SESSION['id']);
$stmt->execute();
$result = $stmt->get_result();

/* Get the number of rows */
$num_of_rows = $result->num_rows;


$tenantid = $_REQUEST['tenantid'];
$type = $_REQUEST['type'];

//Retrieve all records from driftack table in the database where tenantid = $tenantid
$stmt = $con->prepare('SELECT ID, tenantid, policyname FROM driftack WHERE tenantid = ?');
$stmt->bind_param('s', $tenantid);
$stmt->execute();
$result = $stmt->get_result();

//Create an array of the policynames
$acknowledged = array();
while ($row = $result->fetch_assoc()) {
    $acknowledged[] = $row['policyname'];
}
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

//Loop through the decoded json and find the file with drift and $tenantid in the filename
foreach ($decodedcommit as $commit) {
	if ($gittype == "azure") {
		$name = $commit['path'];
	} elseif ($gittype == "github") {
		$name = $commit['name'];
	} elseif ($gittype == "gitlab") {
		$name = $commit['name'];
	}

    //Check if $type equals backup
    if ($type == "backup") {
        //Find the files with backup and $tenantid value in the filename and get the content
        if (strpos($name, "drift") !== false && strpos($name, $tenantid) !== false) {
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
    if ($type == "gold") {
        //Find the files with backup and $tenantid value in the filename and get the content
        if (strpos($name, "golddrift") !== false && strpos($name, $tenantid) !== false) {
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

}
if ($type == "backup") {
    $btype = "Last Backup";
}
if ($type == "gold") {
    $btype = "Gold Tenant";
}

if (empty($decodedcontents)) {
    echo "No drift detected";
}
else {
//If $decodedcontents only has one item, convert it to an array
if (count($decodedcontents) == count($decodedcontents, COUNT_RECURSIVE)) {
    $decodedcontents = array($decodedcontents);
}

$count = 0;
//Loop through the JSON array and get the values
foreach ($decodedcontents as $content) {
    $sourcejson = $content['Source'];
    $URL = $content['URL'];
    $destinationjson = $content['Destination'];

    //If URL is an array, grab first object
if (is_array($URL)) {
    $URL = $URL[0];
}
else {
    $URL = $URL;
}

// If $sourcejson is a nested array with an item called value, grab that. If not, grab the whole array
if (is_array($sourcejson) && isset($sourcejson['value'])) {
    $sourcejson = $sourcejson['value'];
}

// If $sourcejson is an array, convert it to a string
if (is_array($sourcejson)) {
    $sourcejson = json_encode($sourcejson);
}

if (is_array($destinationjson) && isset($destinationjson['value'])) {
    $destinationjson = $destinationjson['value'];
}

// If $destinationjson is an array, convert it to a string
if (is_array($destinationjson)) {
    $destinationjson = json_encode($destinationjson);
}


    $driftlocation = $content['Location'];
    $policyname = $content['Name'];
    $changetype = $content['Type'];

    //If $policyname is in the $acknowledged array, don't display it here
    if (in_array($policyname, $acknowledged) && $type == "gold") {

    }
    else {
        $count++;


?>
<table class="styled-table">
    <tr><td>Policy Name</td><td>Change Type</td><td></td><td></td><td></td></tr>
    <tr>
        <td><?php echo $policyname; ?> </td>


<td><?php echo $driftlocation; ?></td>
<?php
if ($type == "gold") {

    if ($driftlocation == "Added to Tenant") {
        $tenanttoupdate = $golden;
        $buttontext = "Deploy to Golden tenant $golden";
        
        $policyjson = base64_encode($sourcejson);
        $revert = $tenantid;
        if ($destinationjson == "Missing from Source") {
            $revertjson = "DELETE";
            $revertbuttontext = "Delete Policy";
        }
        else {
        $revertjson = base64_encode($destinationjson);
        $revertbuttontext = "Revert Policy";
        }
    }
    else {
        $tenanttoupdate = $tenantid;
        $buttontext = "Deploy to customer tenant $tenantid";
        $policyjson = base64_encode($destinationjson);
        $revert = $golden;
        if ($sourcejson == "Missing from Destination") {
            $revertjson = "DELETE";
            $revertbuttontext = "Delete Policy";
        }
        else {
        $revertjson = base64_encode($sourcejson);
        $revertbuttontext = "Revert Policy";
        }        
    }



    $ownerid = $_SESSION['id'];
?>
<td>
<form action="acknowledge.php" method="post">
<input type = "hidden" name="type" value="add">
<input type = "hidden" name="tenantid" value="<?php echo $tenantid; ?>">
<input type = "hidden" name="ownerid" value="<?php echo $ownerid; ?>">
<input type = "hidden" name="policyname" value="<?php echo $policyname; ?>">
<input class="profile-btn" type="submit" value="Acknowledge">
</form> 
</td>
<td>
<form action="createpolicy.php" method="post">
<input type = "hidden" name="type" value="<?php echo $changetype; ?>">
<input type = "hidden" name="tenantid" value="<?php echo $tenanttoupdate; ?>">
<input type = "hidden" name="policyname" value="<?php echo $policyname; ?>">
<input type = "hidden" name="policyuri" value="<?php echo $URL; ?>">
<input type = "hidden" name="ownerid" value="<?php echo $ownerid; ?>">
<input type = "hidden" name="policyjson" value="<?php echo $policyjson; ?>">
<input class="profile-btn" type="submit" value="<?php echo $buttontext; ?>">
</form> 
</td>
<td>
<form action="createpolicy.php" method="post">
<input type = "hidden" name="type" value="<?php echo $changetype; ?>">
<input type = "hidden" name="tenantid" value="<?php echo $revert; ?>">
<input type = "hidden" name="policyname" value="<?php echo $policyname; ?>">
<input type = "hidden" name="policyuri" value="<?php echo $URL; ?>">
<input type = "hidden" name="ownerid" value="<?php echo $ownerid; ?>">
<input type = "hidden" name="policyjson" value="<?php echo $revertjson; ?>">
<input class="profile-btn" type="submit" value="<?php echo $revertbuttontext; ?>">
</form> 
</td>
<?php
}
else {
    if ($driftlocation == "Added to Tenant") {
        $tenanttoupdate = $golden;
        $buttontext = "Deploy to Golden tenant $golden";
        
        $policyjson = base64_encode($sourcejson);
        $revert = $tenantid;
        if ($destinationjson == "Missing from Source") {
            $revertjson = "DELETE";
            $revertbuttontext = "Delete Policy";
        }
        else {
        $revertjson = base64_encode($destinationjson);
        $revertbuttontext = "Revert Policy";
        }
    }
    else {
        $tenanttoupdate = $tenantid;
        $buttontext = "Deploy to customer tenant $tenantid";
        $policyjson = base64_encode($destinationjson);
        $revert = $golden;
        if ($sourcejson == "Missing from Destination") {
            $revertjson = "DELETE";
            $revertbuttontext = "Delete Policy";
        }
        else {
        $revertjson = base64_encode($sourcejson);
        $revertbuttontext = "Revert Policy";
        }        
    }



    $ownerid = $_SESSION['id'];
    echo "<td></td><td></td>";
    ?>
    <td>
<form action="createpolicy.php" method="post">
<input type = "hidden" name="type" value="<?php echo $changetype; ?>">
<input type = "hidden" name="tenantid" value="<?php echo $revert; ?>">
<input type = "hidden" name="policyname" value="<?php echo $policyname; ?>">
<input type = "hidden" name="policyuri" value="<?php echo $URL; ?>">
<input type = "hidden" name="ownerid" value="<?php echo $ownerid; ?>">
<input type = "hidden" name="policyjson" value="<?php echo $revertjson; ?>">
<input class="profile-btn" type="submit" value="<?php echo $revertbuttontext; ?>">
</form> 
</td>
<?php
}
?>

</tr>
<tr><td>Live JSON</td>        <td colspan="4">
<div style="width:800px;overflow:auto"><pre>
<?php print_r($sourcejson); ?>
</pre></div></td></tr>
<tr><td><?php echo $btype; ?> JSON</td><td colspan="4">
<div style="width:800px;overflow:auto">
<pre>
<?php print_r($destinationjson); ?>
</pre>
</div></td></tr>
</table>

<?php
}
}



if ($type == "backup") {
?>
				

			</div>
            <table class="styled-table">
                <tr>
                    <td>
                    <input type = "hidden" name="tenantid" value="<?php echo $tenantid; ?>">
<input type = "hidden" name="type" value="backup">
<input class="profile-btn" type="submit" value="Acknowledge/Backup">
</form>    
                    </td>
                </tr>
            </table>
            <form action="process.php" method="post">
  
	<?php
}
else {
    echo "Manage Drift acknoledgements <a href=\"managedriftpolicies.php\"><button class=\"button\">here</button></a>";
    echo "</div>";

}
}
?>
<?php
include "footer.php";
?>