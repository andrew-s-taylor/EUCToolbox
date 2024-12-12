<?php

include 'main.php';
##if (!isset($_POST['token']) || $_POST['token'] != $_SESSION['token']) {
##	exit('Incorrect token provided!');
##}
// Now we check if the data was submitted, isset() function will check if the data exists.
if (!isset($_POST['password'], $_POST['cpassword'], $_POST['email'])) {
	// Could not get the data that should have been sent.
	exit('Please complete the registration form!');
}
// Make sure the submitted registration values are not empty.
if (empty($_POST['password']) || empty($_POST['email'])) {
	// One or more values are empty.
	exit('Please complete the registration form!');
}
// Check to see if the email is valid.
if (!filter_var($_POST['email'], FILTER_VALIDATE_EMAIL)) {
	exit('Please provide a valid email address!');
}
// Password must be between 5 and 20 characters long.
if (strlen($_POST['password']) > 20 || strlen($_POST['password']) < 5) {
	exit('Password must be between 5 and 20 characters long!');
}
// Check if both the password and confirm password fields match
if ($_POST['cpassword'] != $_POST['password']) {
	exit('Passwords do not match!');
}
// We need to check if the account with that username exists.
$stmt = $con->prepare('SELECT id, password FROM accounts WHERE email = ?');
// Bind parameters (s = string, i = int, b = blob, etc), hash the password using the PHP password_hash function.
$stmt->bind_param('s', $_POST['email']);
$stmt->execute();
$stmt->store_result();
// Store the result so we can check if the account exists in the database.
if ($stmt->num_rows > 0) {
	// Username already exists
	echo 'Email exists!';
} else {
//Create repo
$gittoken = fullgittoken;
$reponame2 = $_POST['email'];
$gitorg = gitorg;
//Remove any special characters from the email address
$reponame = preg_replace('/[^A-Za-z0-9\-]/', '', $reponame2);
$ch = curl_init();

curl_setopt($ch, CURLOPT_URL, "https://api.github.com/orgs/$gitorg/repos");
curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
curl_setopt($ch, CURLOPT_POST, 1);
curl_setopt($ch, CURLOPT_POSTFIELDS, '{"name":"' . $reponame . '","description":"Intune Manager Customer Repo","homepage":"https://manage.euctoolbox.com","private":true,"has_issues":false,"has_projects":false,"has_wiki":false}');
curl_setopt($ch, CURLOPT_HTTPHEADER, array(
    "Accept: application/vnd.github+json",
    "Authorization: Bearer $gittoken",
    "X-GitHub-Api-Version: 2022-11-28",
	"User-Agent: IntuneManager"
));

$result = curl_exec($ch);

if (curl_errno($ch)) {
    echo 'Error: ' . curl_error($ch);
}

curl_close($ch);

	$stmt->close();
	// Username doesnt exists, insert new account
	// We do not want to expose passwords in our database, so hash the password and use password_verify when a user logs in.
	$password = password_hash($_POST['password'], PASSWORD_DEFAULT);
	// Generate unique activation code
	$uniqid = account_activation ? uniqid() : 'activated';
	// Default role
	$role = 'Admin';
	// Current date
	$date = date('Y-m-d\TH:i:s');
	// Prepare query; prevents SQL injection
	$stmt = $con->prepare('INSERT IGNORE INTO accounts (password, email, activation_code, role, registered, last_seen, ip, regtype, reponame, plevel, canbackup, canrestore, canviewlogs, canmanagebackups, cancheckdrift, canmanagedrift, canmanagetenants, cangolddeploy, canviewreports, candeployapps, candeploytemplates, canmigrate, canmanageapi) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)');	// Bind our variables to the query
	$ip = $_SERVER['REMOTE_ADDR'];
	$trial = "paid";
	$level = "standard";
	$active1 = "1";
	$stmt->bind_param('ssssssssssiiiiiiiiiiiii', $password, $_POST['email'], $uniqid, $role, $date, $date, $ip, $trial, $reponame, $level, $active1, $active1, $active1, $active1, $active1, $active1, $active1, $active1, $active1, $active1, $active1, $active1, $active1);	$stmt->execute();
	$stmt->close();
	//Get the ID of the user we just created
	$stmt = $con->prepare('SELECT id FROM accounts WHERE email = ?');
	$stmt->bind_param('s', $_POST['email']);
	$stmt->execute();
	$stmt->store_result();
	$stmt->bind_result($id);
	$stmt->fetch();
	$stmt->close();
	//Update primaryID for the user to match the ID
	$stmt = $con->prepare('UPDATE accounts SET primaryid = ? WHERE id = ?');
	$stmt->bind_param('ii', $id, $id);
	$stmt->execute();
	$stmt->close();


	// If account activation is required, send activation email
	if (account_activation) {
		// Account activation required, send the user the activation email with the "send_activation_email" function from the "main.php" file
		send_activation_email($_POST['email'], $uniqid);
		echo 'Please check your email to activate your account!';
	} else {
		// Automatically authenticate the user if the option is enabled
		if (auto_login_after_register) {
			// Regenerate session ID
			session_regenerate_id();
			// Declare session variables
			$_SESSION['loggedin'] = TRUE;
			$_SESSION['name'] = $_POST['email'];
			$_SESSION['id'] = $con->insert_id;
			$_SESSION['role'] = $role;		
			header('Location: getstarted.php');
		} else {
			echo 'You have successfully registered! You can now login!';
			header('Location: getstarted.php');
		}
	}
}
?>