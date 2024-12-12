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
$sitename = "Intune Manager from EUC Toolbox";
$pagetitle = "Intune Manager";
include "header.php";
?>
		<div class="login">
			<h1>Reset Password</h1>
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
<tr><td>
                <label for="cpassword">
					<i class="fas fa-lock"></i>
				</label>
				<input type="password" name="cpassword" placeholder="Confirm Password" id="cpassword" required>
                </td></tr>
                <tr><td>
				<div class="msg"><?=$msg?></div>
				<input type="submit" value="Submit" class="profile-btn">
                </td></tr>
                </table>
            </form>
		</div>
        <?php
include "footer.php";
?>