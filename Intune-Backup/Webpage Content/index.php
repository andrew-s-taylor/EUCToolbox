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
	$stmt = $con->prepare('SELECT id, username, role FROM accounts WHERE rememberme = ?');
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
$sitename = "Intune Backup from EUC Toolbox";
$pagetitle = "Intune Backup";
include "header.php";
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
				<input type="text" name="username" placeholder="Username" id="username" required>
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
			<td><a href="forgotpassword.php">Forgot Password?</a></td>
		</tr>
		<tr>
			
		</tr>
    </table>
</form>
    </div>
	<a href="register.php"><button class="button">Register</button></a>
		</div>

		<script>
		// AJAX code
		let loginForm = document.querySelector('.login form');
		loginForm.onsubmit = event => {
			event.preventDefault();
			fetch(loginForm.action, { method: 'POST', body: new FormData(loginForm) }).then(response => response.text()).then(result => {
				if (result.toLowerCase().includes('success')) {
					window.location.href = 'home.php';
				}  else {
					document.querySelector('.msg').innerHTML = result;
				}
			});
		};
		</script>
	
	<?php
include "footer.php";
?>