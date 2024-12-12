<?php
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
  $stmt = $con->prepare('SELECT reponame, golden FROM accounts WHERE id = ?');
  // In this case, we can use the account ID to retrieve the account info.
  if ($role2 == "SubAdmin") {
	$stmt->bind_param('i', $primaryadmin);
}
else {
// In this case, we can use the account ID to retrieve the account info.
$stmt->bind_param('i', $_SESSION['id']);
}
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


			<h2>Deploy Base Config - Select Config & Tenant</h2>
			
			<div class="block">
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

  //Check if $result2 is empty
  if (empty($result2)) {
    echo "No templates found for this tenant";
  }
  
  else {
    
    //Check if the $result2 array includes any files with Template in the name
    $result3 = array_filter($result2, function ($item) {
      if (strpos($item['filename'], 'Template') !== false) {
          return true;
      }
      return false;
    });
    if (empty($result3)) {
      echo "No templates found for this tenant";
      exit;
    }
    else {
    //Display the form
?>
<table class="styled-table">
<form action="processdemo.php" method="post">
<tr><td>
<select id="filename" name="filename">
            <?php

              
              foreach ($result2 as $item) {
                $date = date('l jS \o\f F Y h:i:s A',$item['tenantdate']); 
                $timezoneOffset = $_COOKIE['timezoneOffset'];
$adjustedTime2 = date('Y-m-d H:i:s', $item['tenantdate']);

$date2 = adjustTimezoneOffset($adjustedTime2, $timezoneOffset);
        if (strpos($item['filename'], 'log') === false && strpos($item['filename'], 'Template') !== false) {
                  $filename = $item['filename'];
				  //delete the word Template from $name
preg_match('/-Template-(.*?)\.json/', $filename, $matches);
if (!empty($matches)) {
	$removed = $matches[1];
  } else {
	$removed = '';
  }
                  echo "<option value=\"$filename\">$removed</option>";              
                }
              }

              ?>
              </select>
</td></tr>


    <tr><td>
    <select name='tenantid[]' multiple>
    
<?php
while ($row = $result->fetch_assoc()) {
    //Pass the URL as the value
    $tenantname = $row['tenantname'];
    $tenantid = $row['tenantid'];
    echo "<option value='$tenantid'>$tenantname</option>";

}
    $stmt->close();
    ?>
    </select>
       </td>
    <td><input class="profile-btn" type="submit" value="Deploy" onclick="return confirm('Are you sure you want to deploy this template?');"></td></tr>
    </form>
    </table>
				

    <table class="styled-table">

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
                //Check if the $result2 array includes any files with Template in the name
                $result3 = array_filter($result2, function ($item) {
                  if (strpos($item['filename'], 'Template') !== false) {
                      return true;
                  }
                  return false;
                });
                if (empty($result3)) {
                  echo "No templates found for this tenant";
                  exit;
                }
              ?>
              <form action="viewtemplate.php" method="post">
<tr><td>
<select id="filename" name="filename">
  <?php
              foreach ($result2 as $item) {
                $date = date('l jS \o\f F Y h:i:s A',$item['tenantdate']); 
                $timezoneOffset = $_COOKIE['timezoneOffset'];
$adjustedTime2 = date('Y-m-d H:i:s', $item['tenantdate']);

$date2 = adjustTimezoneOffset($adjustedTime2, $timezoneOffset);
        if (strpos($item['filename'], 'log') === false && strpos($item['filename'], 'Template') !== false) {
                  $filename = $item['filename'];
				  //delete the word Template from $name
preg_match('/-Template-(.*?)\.json/', $filename, $matches);
if (!empty($matches)) {
	$removed = $matches[1];
  } else {
	$removed = '';
  }
                  echo "<option value=\"$filename\">$removed</option>";              
                }
              }

              ?>
              </select>
</td></tr>


    <tr>
    <td><input class="profile-btn" type="submit" value="View Contents"></td></tr>
    </form>
    </table>

<?php
    }
    ?>
    <?php if ($regtype == 'paid' && $cangolddeploy == 1): ?>
      <h2>Rapid Tenant Deployment with our Intune Deploy tool</h2>
      <table class="styled-table">
      <tr>
        <td>
            <form action="deployintune.php" method="post">
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
              ?>
                  <select name='tenantid'>
    
    <?php
    while ($row = $result->fetch_assoc()) {
        //Pass the URL as the value
        $tenantname = $row['tenantname'];
        $tenantid = $row['tenantid'];
        echo "<option value='$tenantid'>$tenantname</option>";
    
    }
        $stmt->close();
        ?>
        </select>
  </td>
    <td>
                <input type="hidden" name="customerid" value="intunemanage">
                <input class="profile-btn" type="submit" value="Deploy Intune">
            </form>
        </td>
  </tr>
  </table>
    <?php endif; ?>

<?php
  }
  ?>
			</div>
            
	
			<?php
include "footer.php";
?>