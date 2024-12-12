<?php
include 'main.php';
include 'TreeWalker.php';
$treewalker = new TreeWalker(array(
    "debug"=>true,                      //true => return the execution time, false => not
    "returntype"=>"jsonstring")         //Returntype = ["obj","jsonstring","array"]
  );
// Check logged-in
check_loggedin($con);
// output message (errors, etc)
$msg = '';

if ($cancheckdrift == 0) {
    echo "You do not have access to view this page";
    exit;
  }

// Retrieve additional account info from the database because we don't have them stored in sessions
$stmt = $con->prepare('SELECT role FROM accounts WHERE id = ?');
// In this case, we can use the account ID to retrieve the account info.
$stmt->bind_param('i', $_SESSION['id']);
$stmt->execute();
$stmt->bind_result($role);
$stmt->fetch();
$stmt->close();

if (isset($_POST['tenantidswitch'])) {
    $tenantid = $_POST['tenantidswitch'];
    $customerid = $_POST['customerid'];
}
else {
  $sentID = $_POST['tenantid'];
  //split $sentID on %%
  $pieces = explode("%%", $sentID);
  $tenantid = $pieces[0];
  $customerid = $pieces[1];
}
$type = $_POST['type'];

?>
<?php
$sitename = "Intune Manager from EUC Toolbox";
$pagetitle = "Intune Manager";
include "header1.php";
?>
			<h2>Check Drift - Results</h2>

			<div class="block">
            <table class="styled-table">
<form action="displaydrift.php" method="post">
<input type="hidden" name="type" value="<?php echo $type; ?>">
<input type="hidden" name="customerid" value="<?php echo $customerid; ?>">
    <tr><td>
    <select name='tenantidswitch'>
    
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
$stmt = $con->prepare('SELECT ID, tenantname, tenantid, customerid FROM tenants WHERE ownerid = ?');
// In this case, we can use the account ID to retrieve the account info.
$stmt->bind_param('i', $_SESSION['id']);
$stmt->execute();
$result = $stmt->get_result();
}
else {
// Retrieve additional account info from the database because we don't have them stored in sessions
$stmt = $con->prepare('SELECT ID, tenantname, tenantid, customerid FROM tenants WHERE customerid = ?');
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
}

/* Get the number of rows */
$num_of_rows = $result->num_rows;
while ($row = $result->fetch_assoc()) {
    //Pass the URL as the value
    $tenantname = $row['tenantname'];
    $tenantid1 = $row['tenantid'];
    echo "<option value='$tenantid1'>$tenantname</option>";

}

    $stmt->close();
    if (isset($tenantid)) {
        $stmt = $con->prepare('SELECT tenantname FROM tenants WHERE tenantid = ?');
        $stmt->bind_param('s', $tenantid);
        $stmt->execute();
        $stmt->bind_result($selectedTenantName);
        $stmt->fetch();
        $stmt->close();
        echo "<option value='$tenantid' selected>$selectedTenantName</option>";
    }
    ?>
    </select>
       </td>
    <td><input class="profile-btn" type="submit" value="Switch Tenant"></td></tr>
    </form>
    <input type="text" id="tableFilter" placeholder="Search for anything..." style="margin-bottom: 10px; width: 100%; padding: 8px;">
    </table>
    <table class="styled-table" id="drifttable">
        <thead>
            <tr>
                <th>Policy Name</th>
                <th>Policy Type</th>
                <th>Change Type</th>
                <th></th>
                <th></th>
                <th></th>
            </tr>
        </thead>
    <tbody>
<?php    

$stmt = $con->prepare('SELECT reponame, golden, outdated FROM accounts WHERE id = ?');
// In this case, we can use the account ID to retrieve the account info.
$stmt->bind_param('i', $customerid);
$stmt->execute();
$stmt->bind_result($reponame, $golden, $daystocheck);
$stmt->fetch();
$stmt->close();


// Retrieve additional account info from the database because we don't have them stored in sessions
$stmt = $con->prepare('SELECT ID, tenantname, tenantid FROM tenants WHERE customerid = ?');
// In this case, we can use the account ID to retrieve the account info.
$stmt->bind_param('i', $customerid);
$stmt->execute();
$result = $stmt->get_result();

/* Get the number of rows */
$num_of_rows = $result->num_rows;





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

//If URL is an array, grab first object
if (is_array($URL)) {
    $URL = $URL[0];
}
else {
    $URL = $URL;
}

    $destinationjson = $content['Destination'];

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
    switch ($URL) {
        case "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations":
            $ptype = "Config Policy";
            break;
        case "https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations":
            $ptype = "Admin Template";
            break;
        case "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies":
            $ptype = "Settings Catalog";
            break;
        case "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies":
            $ptype = "Compliance Policy";
            break;
        case "https://graph.microsoft.com/beta/deviceManagement/devicehealthscripts":
            $ptype = "Remediation";
            break;
        case "https://graph.microsoft.com/beta/deviceManagement/devicemanagementscripts":
            $ptype = "Platform Script";
            break;
        case "https://graph.microsoft.com/beta/deviceManagement/deviceComplianceScripts":
            $ptype = "Compliance Script";
            break;
        case "https://graph.microsoft.com/beta/deviceManagement/intents":
            $ptype = "Security Policy";
            break;
        case "https://graph.microsoft.com/beta/deviceManagement/windowsAutopilotDeploymentProfiles":
            $ptype = "Autopilot Profile";
            break;
        case "https://graph.microsoft.com/beta/deviceManagement/deviceEnrollmentConfigurationsESP":
            $ptype = "Autopilot ESP";
            break;
        case "https://graph.microsoft.com/beta/deviceManagement/deviceEnrollmentConfigurationswhfb":
            $ptype = "WHfB";
            break;
        case "https://graph.microsoft.com/beta/deviceManagement/managedAppPoliciesandroid":
            $ptype = "Android App Protection";
            break;
        case "https://graph.microsoft.com/beta/deviceManagement/managedAppPoliciesios":
            $ptype = "iOS App Protection";
            break;
        case "https://graph.microsoft.com/beta/groups":
            $ptype = "Entra Group";
            break;
        case "conditionalaccess":
            $ptype = "Conditional Access Policy";
            break;
        case "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps":
            $ptype = "Windows Store App";
            break;
        case "https://graph.microsoft.com/beta/deviceManagement/virtualEndpoint/userSettings":
            $ptype = "W365 User Settings";
            break;
        case "https://graph.microsoft.com/beta/deviceManagement/virtualEndpoint/provisioningPolicies":
            $ptype = "W365 Provisioning Policy";
            break;
        case "https://graph.microsoft.com/beta/deviceAppManagement/policySets":
            $ptype = "Policy Sets";
            break;
        case "https://graph.microsoft.com/beta/deviceManagement/deviceEnrollmentConfigurations":
            $ptype = "Device Enrollment Configuration";
            break;
        case "https://graph.microsoft.com/beta/deviceManagement/deviceCategories":
            $ptype = "Device Categories";
            break;
        case "https://graph.microsoft.com/beta/deviceManagement/assignmentFilters":
            $ptype = "Device Filter";
            break;
        case "https://graph.microsoft.com/beta/deviceManagement/intuneBrandingProfiles":
            $ptype = "Branding Profile";
            break;
        case "https://graph.microsoft.com/beta/deviceManagement/operationApprovalPolicies":
            $ptype = "Multi-Admin Approval";
            break;
        case "https://graph.microsoft.com/beta/deviceManagement/termsAndConditions":
            $ptype = "Terms and Conditions";
            break;
        case "https://graph.microsoft.com/beta/deviceManagement/roleDefinitions":
            $ptype = "Intune Role";
            break;
        case "https://graph.microsoft.com/beta/deviceManagement/windowsFeatureUpdateProfiles":
            $ptype = "Feature Update Profile";
            break;
        case "https://graph.microsoft.com/beta/deviceManagement/windowsQualityUpdateProfiles":
            $ptype = "Quality Update Profile";
            break;
        case "https://graph.microsoft.com/beta/deviceManagement/windowsDriverUpdateProfiles":
            $ptype = "Driver Update Profile";
            break;
        case "https://graph.microsoft.com/beta/deviceManagement/managedAppPolicies":
            $ptype = "App Protection Policy";
            break;
        case "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies";
            $ptype = "Autopilot Config Policy";
            break;
        default:
        if (strpos($policyurl, "https://graph.microsoft.com/beta/deviceManagement/templates") === 0) {
            $ptype = "Security Policy"; // replace with your actual result
        } else {
            $ptype = "Unknown Type";
        }
    }
    //If $policyname is in the $acknowledged array, don't display it here
    if (in_array($policyname, $acknowledged) && $type == "gold") {

    }
    else {
        $count++;

?>

    <tr>
        <td><?php echo $policyname; ?> </td>
        <td><?php echo $ptype; ?></td>


<td>			

    <?php


if ($type == "gold") {
echo $driftlocation;
}
else {
    echo $driftlocation;
} ?></td>
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
    <?php if ($canmanagedrift == 1): ?>
<form action="acknowledge.php" method="post">
<input type = "hidden" name="type" value="add">
<input type = "hidden" name="tenantid" value="<?php echo $tenantid; ?>">
<input type = "hidden" name="ownerid" value="<?php echo $ownerid; ?>">
<input type = "hidden" name="policyname" value="<?php echo $policyname; ?>">
<input class="profile-btn" type="submit" value="Acknowledge">
</form> 
<?php endif; ?>
</td>
<td>
<?php if ($canmanagedrift == 1): ?>
<form action="policyprocessor.php" method="post">
<input type = "hidden" name="type" value="<?php echo $changetype; ?>">
<input type = "hidden" name="tenantid" value="<?php echo $tenanttoupdate; ?>">
<input type = "hidden" name="policyname" value="<?php echo $policyname; ?>">
<input type = "hidden" name="policyuri" value="<?php echo $URL; ?>">
<input type = "hidden" name="ownerid" value="<?php echo $ownerid; ?>">
<input type = "hidden" name="policyjson" value="<?php echo $policyjson; ?>">
<input class="profile-btn" type="submit" value="<?php echo $buttontext; ?>">
</form> 
<?php endif; ?>
</td>
<td>
<?php if ($canmanagedrift == 1): ?>
<form action="policyprocessor.php" method="post">
<input type = "hidden" name="type" value="<?php echo $changetype; ?>">
<input type = "hidden" name="tenantid" value="<?php echo $revert; ?>">
<input type = "hidden" name="policyname" value="<?php echo $policyname; ?>">
<input type = "hidden" name="policyuri" value="<?php echo $URL; ?>">
<input type = "hidden" name="ownerid" value="<?php echo $ownerid; ?>">
<input type = "hidden" name="policyjson" value="<?php echo $revertjson; ?>">
<input class="profile-btn" type="submit" value="<?php echo $revertbuttontext; ?>">
</form> 
<?php endif; ?>
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
    <?php if ($canmanagedrift == 1): ?>
<form action="policyprocessor.php" method="post">
<input type = "hidden" name="type" value="<?php echo $changetype; ?>">
<input type = "hidden" name="tenantid" value="<?php echo $revert; ?>">
<input type = "hidden" name="policyname" value="<?php echo $policyname; ?>">
<input type = "hidden" name="policyuri" value="<?php echo $URL; ?>">
<input type = "hidden" name="ownerid" value="<?php echo $ownerid; ?>">
<input type = "hidden" name="policyjson" value="<?php echo $revertjson; ?>">
<input class="profile-btn" type="submit" value="<?php echo $revertbuttontext; ?>">
</form> 
<?php endif; ?>
</td>
<?php
}
?>

</tr>
<tr><td>Changes</td><td colspan="5">
    
<div style="width:100%; max-height:300px; overflow:auto">
<?php
    $changes = ($treewalker->getdiff($sourcejson, $destinationjson, false));
    // Decode JSON data to PHP array
$arrayData = json_decode($changes, true);

// Encode the array back to JSON with pretty print
$prettyJson = json_encode($arrayData, JSON_PRETTY_PRINT);

// Display the nicely formatted JSON
echo '<pre>' . $prettyJson . '</pre>';
?>
</div>
</td>
<td style="display: none;"></td>
<td style="display: none;"></td>
<td style="display: none;"></td>
<td style="display: none;"></td>
</tr>
<tr><td>Live JSON</td>        <td colspan="5">
<div style="width:100%; max-height:300px; overflow:auto"><pre>
<?php print_r($sourcejson); ?>
</pre></div></td>
<td style="display: none;"></td>
<td style="display: none;"></td>
<td style="display: none;"></td>
<td style="display: none;"></td>
</tr>
<tr><td><?php echo $btype; ?> JSON</td><td colspan="5">
<div style="width:100%; max-height:300px; overflow:auto">
<pre>
<?php print_r($destinationjson); ?>
</pre>
</div></td>
<td style="display: none;"></td>
<td style="display: none;"></td>
<td style="display: none;"></td>
<td style="display: none;"></td>
</tr>
<tr><td colspan="6">
<div style="width: 100%; border-top: 5px solid #EB5D2F; border-bottom: 5px solid #EB5D2F; height: 25px;"></div>
</td>
<td style="display: none;"></td>
<td style="display: none;"></td>
<td style="display: none;"></td>
<td style="display: none;"></td>
<td style="display: none;"></td>
</tr>
<?php
}
}

echo "</tbody>";
echo "</table>";

if ($type == "backup") {
?>


			</div>
            <?php if ($canmanagedrift == 1): ?>
                <table class="styled-table"><tr><td>
            <form action="process.php" method="post">
<input type = "hidden" name="tenantid" value="<?php echo $tenantid; ?>">
<input type = "hidden" name="type" value="backup">
<input class="profile-btn" type="submit" value="Acknowledge/Backup">
</form>
</td></tr></table>
<?php endif; ?>      
	<?php
}
else {
    if ($canmanagedrift == 1) {
    echo "Manage Drift acknoledgements <a href=\"managedriftpolicies.php\"><button class=\"button\">Here</button></a>";
    }
    echo "</div>";

}

}
?>
<script>
// JavaScript to filter table
$(document).ready(function() {
    $("#tableFilter").on("keyup", function() {
        var value = $(this).val().toLowerCase();
        $("#drifttable tbody tr").filter(function() {
            $(this).toggle($(this).text().toLowerCase().indexOf(value) > -1)
        });
    });
});
</script>
<?php
include "footer.php";
?>