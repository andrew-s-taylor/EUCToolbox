<?php
include 'main.php';
// Output message
$msg = '';
// First we check if the email and code exists, these variables will appear as parameters in the URL
if (isset($_GET['email'], $_GET['code']) && !empty($_GET['code'])) {
	$stmt = $con->prepare('SELECT * FROM accounts WHERE email = ? AND activation_code = ?');
	$stmt->bind_param('ss', $_GET['email'], $_GET['code']);
	$stmt->execute();
	// Store the result so we can check if the account exists in the database.
	$stmt->store_result();
	if ($stmt->num_rows > 0) {
		$stmt->close();
		// Account exists with the requested email and code.
		$stmt = $con->prepare('UPDATE accounts SET activation_code = "activated" WHERE email = ? AND activation_code = ?');
		// Set the new activation code to 'activated', this is how we can check if the user has activated their account.
		$stmt->bind_param('ss', $_GET['email'], $_GET['code']);
		$stmt->execute();
		$stmt->close();
		$msg = 'Your account is now activated! You can now <a href="index.php">Login</a>.';
	} else {
		$msg = 'The account is already activated or doesn\'t exist!';
	}
} else {
	$msg = 'No code and/or email was specified!';
}
?>
<!DOCTYPE html>
<html>
	<head>
		<meta charset="utf-8">
		<meta name="viewport" content="width=device-width,minimum-scale=1">
		<title>Activate Account</title>
		<link href="style.css" rel="stylesheet" type="text/css">
	</head>
	<body class="loggedin">
		<div class="content">
			<p><?=$msg?></p>
		</div>
	</body>
</html>