<?php
include 'main.php';
// No need for the user to see the login form if they're logged-in, so redirect them to the home page
if (isset($_SESSION['loggedin'])) {
	// If the user is logged in, redirect to the home page.
	header('Location: home.php');
	exit;
}
// Also check if they are "remembered"
if (isset($_COOKIE['rememberme']) && !empty($_COOKIE['rememberme'])) {
	// If the remember me cookie matches one in the database then we can update the session variables.
	$stmt = $con->prepare('SELECT id, email, role FROM accounts WHERE rememberme = ?');
	$stmt->bind_param('s', $_COOKIE['rememberme']);
	$stmt->execute();
	$stmt->store_result();
	if ($stmt->num_rows > 0) {
		// Found a match
		$stmt->bind_result($id, $username, $role);
		$stmt->fetch();
		$stmt->close();
		// Authenticate the user
		session_regenerate_id();
		$_SESSION['loggedin'] = TRUE;
		$_SESSION['name'] = $username;
		$_SESSION['id'] = $id;
		$_SESSION['role'] = $role;
		// Update last seen date
		$date = date('Y-m-d\TH:i:s');
		$stmt = $con->prepare('UPDATE accounts SET last_seen = ? WHERE id = ?');
		$stmt->bind_param('si', $date, $id);
		$stmt->execute();
		$stmt->close();
		// Redirect to the home page
		header('Location: home.php');
		exit;
	}
}
$_SESSION['token'] = md5(uniqid(rand(), true));
?>
<?php
$sitename = "Intune Manager from EUC Toolbox";
$pagetitle = "Intune Manager";
include "header1.php";
?>

<div class="login">
			<h1>Login</h1>

			<div class="step-container">
			<form action="authenticate.php" method="post" autocomplete="off">
    <table class="styled-table">
        <tr>
            <td><label for="username">
					<i class="fas fa-user"></i>
				</label>
				<input type="text" name="email" placeholder="Email" id="email" required>
			</td>
	</tr>
	<tr>
            <td>				<label for="password">
					<i class="fas fa-lock"></i>
				</label>
				<input type="password" name="password" placeholder="Password" id="password" required>
			</td>
	</tr>
	<tr>
		<td>
		<label id="rememberme">
					<input type="checkbox" name="rememberme">Remember me
				</label>
		</td>
	</tr>
            <td class="tableButton">
			<input type="hidden" name="token" value="<?=$_SESSION['token']?>">
			<input class="profile-btn" type="submit" value="Login"></td>
        </tr>
		<tr>
			<td>Login with your Microsoft account<br>
			<a href="https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=<?php echo appID; ?>&response_type=code&redirect_uri=https://euctoolbox.com/processor.php&state=sso<>1&response_mode=query&scope=https://graph.microsoft.com/User.Read"><img src="mslogo.jpg"></img></a>
		</td>
		</tr>
		<tr>
			<td><br><Br><br><a href="forgotpassword.php">Forgot Password?</a></td>
		</tr>
    </table>
</form>
    </div>
	<div class="step-container">
	<a href="register.php"><button class="button">Register</button></a>
	</div>
		</div>

        <?php
include "footer.php";
?>