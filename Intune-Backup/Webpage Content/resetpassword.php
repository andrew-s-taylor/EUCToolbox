<?php
include 'main.php';
// Output message
$msg = '';
// Now we check if the data from the login form was submitted, isset() will check if the data exists.
if (isset($_GET['email'], $_GET['code']) && !empty($_GET['code'])) {
    // Prepare our SQL, preparing the SQL statement will prevent SQL injection.
    $stmt = $con->prepare('SELECT * FROM accounts WHERE email = ? AND reset = ?');
    $stmt->bind_param('ss', $_GET['email'], $_GET['code']);
    $stmt->execute();
    $stmt->store_result();
    // Check if the account exists...
    if ($stmt->num_rows > 0) {
        $stmt->close();
        if (isset($_POST['npassword'], $_POST['cpassword'])) {
            if (strlen($_POST['npassword']) > 20 || strlen($_POST['npassword']) < 5) {
            	$msg = 'Password must be between 5 and 20 characters long!';
            } else if ($_POST['npassword'] != $_POST['cpassword']) {
                $msg = 'Passwords must match!';
            } else {
                $stmt = $con->prepare('UPDATE accounts SET password = ?, reset = "" WHERE email = ?');
                $password = password_hash($_POST['npassword'], PASSWORD_DEFAULT);
                $stmt->bind_param('ss', $password, $_GET['email']);
                $stmt->execute();
                $stmt->close();
                $msg = 'Password has been reset! You can now <a href="index.php">login</a>!';
            }
        }
    } else {
        exit('Incorrect email and/or code!');
    }
} else {
    exit('Please provide the email and code!');
}
?>
<?php
$sitename = "Intune Backup from EUC Toolbox";
$pagetitle = "Intune Backup";
include "header.php";
?>

    <h1>Reset Password</h1>
    <div class="step-container">
    <div class="msg"><?=$msg?></div>
    <form action="resetpassword.php?email=<?=$_GET['email']?>&code=<?=$_GET['code']?>" method="post">
    <table class="styled-table">
        <tr>
            <td>                
                <label for="npassword">
					<i class="fas fa-lock"></i>
				</label>
				<input type="password" name="npassword" placeholder="New Password" id="npassword" required>
			</td>
	</tr>
    <tr>
        <td>
        <label for="cpassword">
					<i class="fas fa-lock"></i>
				</label>
				<input type="password" name="cpassword" placeholder="Confirm Password" id="cpassword" required>
        </td>
    </tr>
    <tr>
            <td class="tableButton">
			<input type="hidden" name="token" value="<?=$_SESSION['token']?>">
			<input class="profile-btn" type="submit" value="Reset"></td>
        </tr>
    </table>
    </form>

    </div>
    

    <?php
include "footer.php";
?>