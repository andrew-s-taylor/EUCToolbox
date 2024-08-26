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
        <script type="text/javascript"> 
            function checkAll() {
                var checkboxes = document.getElementsByName('policy[]');
                for (var i = 0; i < checkboxes.length; i++) {
                    checkboxes[i].checked = true;
                }
            }
            function uncheckAll() {
                var checkboxes = document.getElementsByName('policy[]');
                for (var i = 0; i < checkboxes.length; i++) {
                    checkboxes[i].checked = false;
                }
            }
        </script>
       <table class="styled-table"><tr><td><form action="restore2.php" method="post">
<input type = "hidden" name="tenantid" value="<?php echo $tenantid; ?>">
<input class="profile-btn" type="submit" value="Back">
 </form></td></tr></table>
			<h2>Restore - Select Policy</h2>
			
			<div class="block">

<table class="styled-table">
<form action="process.php" method="post">
    <input type="hidden" name="type" value="template">
    <input type="hidden" name="filename" value="<?php echo $filename; ?>">
    <button type="button" class="button" onclick="checkAll()">Check All</button>
    <button type="button" class="button" onclick="uncheckAll()">Uncheck All</button>
    <?php

    echo "<input type=\"hidden\" name=\"tenantid\" value=\"$tenantid\">";
    ?>
<tr>
    <td>Template Name</td>
    <td><input type="text" name="templatename"></td>
</tr>
    <tr>
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

  //Decode the JSON
  $decodedcommit = json_decode($result, true);

  $profilelist2 = $decodedcommit;
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

  //Decode the JSON
  //Decode the base64-encoded content
$decodedcommit2 = base64_decode($result);
  $decodedcommit = json_decode($decodedcommit2, true);
 

  $profilelist2 = $decodedcommit;
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
  //Decode the json
  $result2 = substr($result, 1);
  $profilelist2 = json_decode($result2, true);
  //print_r($decodedcommit2);
  //$decodedcommit = $decodedcommit2['value'];

}

//Count how many profiles in the backup
 $count = count($profilelist2);


if ($gittype == "github") {
$check = 2;
}
if ($gittype == "gitlab") {
    $check = 2;
    }
if ($gittype == "azure") {
$check = 1;
}
  //More than one profile, loop through and add checkbox for each
  if ($count > $check) {
    foreach ($profilelist2 as $policy) {
if (isset($policy['value'][3][0])) {
        $policyname = $policy['value'][2];
        $policyurl = $policy['value'][1];
        $policyid = $policy['value'][3][0];
        switch ($policyurl) {
            case "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations":
                $result = "Config Policy";
                break;
            case "https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations":
                $result = "Admin Template";
                break;
            case "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies":
                $result = "Settings Catalog";
                break;
            case "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies":
                $result = "Compliance Policy";
                break;
            case "https://graph.microsoft.com/beta/deviceManagement/devicehealthscripts":
                $result = "Remediation";
                break;
            case "https://graph.microsoft.com/beta/deviceManagement/devicemanagementscripts":
                $result = "Platform Script";
                break;
            case "https://graph.microsoft.com/beta/deviceManagement/deviceComplianceScripts":
                $result = "Compliance Script";
                break;
            case "https://graph.microsoft.com/beta/deviceManagement/intents":
                $result = "Security Policy";
                break;
            case "https://graph.microsoft.com/beta/deviceManagement/windowsAutopilotDeploymentProfiles":
                $result = "Autopilot Profile";
                break;
            case "https://graph.microsoft.com/beta/deviceManagement/deviceEnrollmentConfigurationsESP":
                $result = "Autopilot ESP";
                break;
            case "https://graph.microsoft.com/beta/deviceManagement/deviceEnrollmentConfigurationswhfb":
                $result = "WHfB";
                break;
            case "https://graph.microsoft.com/beta/deviceManagement/managedAppPoliciesandroid":
                $result = "Android App Protection";
                break;
            case "https://graph.microsoft.com/beta/deviceManagement/managedAppPoliciesios":
                $result = "iOS App Protection";
                break;
            case "https://graph.microsoft.com/beta/groups":
                $result = "Entra Group";
                break;
            case "conditionalaccess":
                $result = "Conditional Access Policy";
                break;
            case "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps":
                $result = "Windows Store App";
                break;
            case "https://graph.microsoft.com/beta/deviceManagement/virtualEndpoint/userSettings":
                $result = "W365 User Settings";
                break;
            case "https://graph.microsoft.com/beta/deviceManagement/virtualEndpoint/provisioningPolicies":
                $result = "W365 Provisioning Policy";
                break;
            case "https://graph.microsoft.com/beta/deviceAppManagement/policySets":
                $result = "Policy Sets";
                break;
            case "https://graph.microsoft.com/beta/deviceManagement/deviceEnrollmentConfigurations":
                $result = "Device Enrollment Configuration";
                break;
            case "https://graph.microsoft.com/beta/deviceManagement/deviceCategories":
                $result = "Device Categories";
                break;
            case "https://graph.microsoft.com/beta/deviceManagement/assignmentFilters":
                $result = "Device Filter";
                break;
            case "https://graph.microsoft.com/beta/deviceManagement/intuneBrandingProfiles":
                $result = "Branding Profile";
                break;
            case "https://graph.microsoft.com/beta/deviceManagement/operationApprovalPolicies":
                $result = "Multi-Admin Approval";
                break;
            case "https://graph.microsoft.com/beta/deviceManagement/termsAndConditions":
                $result = "Terms and Conditions";
                break;
            case "https://graph.microsoft.com/beta/deviceManagement/roleDefinitions":
                $result = "Intune Role";
                break;
                case "https://graph.microsoft.com/beta/deviceManagement/managedAppPolicies":
                    $result = "App Protection Policy";
                    break;
            default:
            if (strpos($policyurl, "https://graph.microsoft.com/beta/deviceManagement/templates") === 0) {
                $result = "Security Policy"; // replace with your actual result
            } else {
                $result = "Unknown query";
            }
        }
        echo "<tr>";  
        echo "<td>";  
        echo $policyname;
        echo "</td>";
        echo "<td>";
        echo $result;
        echo "</td>";
        echo "<td>";
        echo "<input type=\"checkbox\" name=\"policy[]\" value=\"$policyid\" class=\"tocheck\"></td>";
        echo "</tr> ";
}
    }

  } 
  //Only one, skip the loop and just add the checkbox
  else {
        $policyname = $profilelist2['value'][2];
        $policyid = $profilelist2['value'][3];
        $policyurl = $profilelist2['value'][1];
        switch ($policyurl) {
            case "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations":
                $result = "Config Policy";
                break;
            case "https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations":
                $result = "Admin Template";
                break;
            case "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies":
                $result = "Settings Catalog";
                break;
            case "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies":
                $result = "Compliance Policy";
                break;
            case "https://graph.microsoft.com/beta/deviceManagement/devicehealthscripts":
                $result = "Remediation";
                break;
            case "https://graph.microsoft.com/beta/deviceManagement/devicemanagementscripts":
                $result = "Platform Script";
                break;
            case "https://graph.microsoft.com/beta/deviceManagement/deviceComplianceScripts":
                $result = "Compliance Script";
                break;
            case "https://graph.microsoft.com/beta/deviceManagement/intents":
                $result = "Security Policy";
                break;
            case "https://graph.microsoft.com/beta/deviceManagement/windowsAutopilotDeploymentProfiles":
                $result = "Autopilot Profile";
                break;
            case "https://graph.microsoft.com/beta/deviceManagement/deviceEnrollmentConfigurationsESP":
                $result = "Autopilot ESP";
                break;
            case "https://graph.microsoft.com/beta/deviceManagement/deviceEnrollmentConfigurationswhfb":
                $result = "WHfB";
                break;
            case "https://graph.microsoft.com/beta/deviceManagement/managedAppPoliciesandroid":
                $result = "Android App Protection";
                break;
            case "https://graph.microsoft.com/beta/deviceManagement/managedAppPoliciesios":
                $result = "iOS App Protection";
                break;
            case "https://graph.microsoft.com/beta/groups":
                $result = "Entra Group";
                break;
            case "conditionalaccess":
                $result = "Conditional Access Policy";
                break;
            case "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps":
                $result = "Windows Store App";
                break;
            case "https://graph.microsoft.com/beta/deviceManagement/virtualEndpoint/userSettings":
                $result = "W365 User Settings";
                break;
            case "https://graph.microsoft.com/beta/deviceManagement/virtualEndpoint/provisioningPolicies":
                $result = "W365 Provisioning Policy";
                break;
            case "https://graph.microsoft.com/beta/deviceAppManagement/policySets":
                $result = "Policy Sets";
                break;
            case "https://graph.microsoft.com/beta/deviceManagement/deviceEnrollmentConfigurations":
                $result = "Device Enrollment Configuration";
                break;
            case "https://graph.microsoft.com/beta/deviceManagement/deviceCategories":
                $result = "Device Categories";
                break;
            case "https://graph.microsoft.com/beta/deviceManagement/assignmentFilters":
                $result = "Device Filter";
                break;
            case "https://graph.microsoft.com/beta/deviceManagement/intuneBrandingProfiles":
                $result = "Branding Profile";
                break;
            case "https://graph.microsoft.com/beta/deviceManagement/operationApprovalPolicies":
                $result = "Multi-Admin Approval";
                break;
            case "https://graph.microsoft.com/beta/deviceManagement/termsAndConditions":
                $result = "Terms and Conditions";
                break;
            case "https://graph.microsoft.com/beta/deviceManagement/roleDefinitions":
                $result = "Intune Role";
                break;
                case "https://graph.microsoft.com/beta/deviceManagement/managedAppPolicies":
                    $result = "App Protection Policy";
                    break;
            default:
            if (strpos($policyurl, "https://graph.microsoft.com/beta/deviceManagement/templates") === 0) {
                $result = "Security Policy"; // replace with your actual result
            } else {
                $result = "Unknown query";
            }
        }
        echo "<tr>";  
        echo "<td>";  
        echo $policyname;
        echo "</td>";
        echo "<td>";
        echo $result;
        echo "</td>";
        echo "<td>";
        echo "<input type=\"checkbox\" name=\"policy[]\" value=\"$policyid\" class=\"tocheck\"></td>";
        echo "</tr> ";
  }

  ?>
    <td>  
    <input class="profile-btn" type="submit" value="Create Template"></td></tr>
    </form>
    </table>
				

			</div>
            
	
            <?php
include "footer.php";
?>

<?php
}
else {
    header("Location: restore2.php");
}
?>