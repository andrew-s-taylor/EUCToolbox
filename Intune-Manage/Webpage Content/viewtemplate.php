<?php
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
include 'main.php';
// Check logged-in
check_loggedin($con);
// output message (errors, etc)
$msg = '';


$stmt = $con->prepare('SELECT role FROM accounts WHERE id = ?');
// Get the account info using the logged-in session ID
$stmt->bind_param('i', $_SESSION['id']);
$stmt->execute();
$stmt->bind_result($role2);
$stmt->fetch();
$stmt->close();
// Check if the user is an admin...
if ($candeploytemplates == 0) {
    exit('You do not have permission to access this page!');
}


 
  
  
  ?>
<?php
$sitename = "Intune Manager from EUC Toolbox";
$pagetitle = "Intune Manager";
include "header1.php";
?>


			<h2>View Template</h2>
			
			<div class="block">
            <input type="text" id="tableFilter" placeholder="Search for anything..." style="margin-bottom: 10px; width: 100%; padding: 8px;">

    <table class="styled-table" id="drifttable">
<tr>
    <th>Policy Name</th>
    <th>Policy Type</th>
</tr>
                <?php
            $filename2 = $_POST['filename'];
    // Retrieve additional account info from the database because we don't have them stored in sessions
    $stmt = $con->prepare('SELECT password, email, activation_code, role, registered, reponame, golden FROM accounts WHERE id = ?');
    // In this case, we can use the account ID to retrieve the account info.
    $stmt->bind_param('i', $_SESSION['id']);
    $stmt->execute();
    $stmt->bind_result($password, $email, $activation_code, $role, $registered_date, $reponame, $golden);
    $stmt->fetch();
    $stmt->close();

    $filename = $_POST['filename'];
    $githubowner = $repoowner;
    $githubrepo = $reponame;
    $githubtoken = $gittoken;




  
    //GitHub Repo
                //Github Details

    
    
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
    CURLOPT_URL => "https://api.github.com/repos/$githubowner/$githubrepo/contents/$filename",
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
    //Get download URL
    $downloadurl = $decodedcommit['download_url'];
    //Grab the content
    // Get content and convert from base64
    $filecontent = file_get_contents($downloadurl);
    $filearray = json_decode($filecontent, true);

    foreach ($filearray as $content) {
//Check if $content is an array first
if (is_array($content)) {

        //check if $content['value'] is 
        if (isset($content['value'])) {
            $policyname = $content['value'][1];
            $URL = $content['value'][2];
        }
        else {
    $policyname = $content[2];
        $URL = $content[1];
        }
    //If URL is an array, grab first object
    if (is_array($URL)) {
        $URL = $URL[0];
    }
    else {
        $URL = $URL;
    }

    
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
            case "https://graph.microsoft.com/beta/deviceAppManagement/managedAppPolicies":
                $ptype = "App Protection Policy";
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
                if (strpos($URL, "https://graph.microsoft.com/beta/deviceManagement/templates") === 0) {
                    $result = "Security Policy"; // replace with your actual result
                } else {
                    $result = "Unknown query";
                }
        }
        echo "<tr>";
        echo "<td>$policyname</td>";
        echo "<td>Type: $ptype</td>";
        echo "</tr>";
}

}

?>
    </table>
			</div>
            
	
			<?php
include "footer.php";
?>