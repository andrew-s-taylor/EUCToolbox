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
// Now we check if the email from the resend activation form was submitted, isset() will check if the email exists.
if (isset($_POST['email'])) {
    // Prepare our SQL, preparing the SQL statement will prevent SQL injection.
    $stmt = $con->prepare('SELECT activation_code FROM accounts WHERE email = ? AND activation_code != "" AND activation_code != "activated"');
    // In this case we can use the account ID to get the account info.
    $stmt->bind_param('s', $_POST['email']);
    $stmt->execute();
    $stmt->store_result();
    // Check if the account exists:
    if ($stmt->num_rows > 0) {
        // account exists
        $stmt->bind_result($activation_code);
        $stmt->fetch();
        $stmt->close();
        // Account exist, the $msg variable will be used to show the output message (on the HTML form)
        send_activation_email($_POST['email'], $activation_code);
        $msg = 'Activaton link has been sent to your email!';
    } else {
        $msg = 'We do not have an account with that email!';
    }
}
?>
<?php
$sitename = "Intune Backup from EUC Toolbox";
$pagetitle = "Intune Backup";
include "header1.php";
?>

			<h1>Resend Activation Email</h1>
			<div class="step-container">
            <div class="msg"><?=$msg?></div>
            <form action="" method="post">
            <table class="styled-table">
        <tr>
            <td><label for="email">
    <i class="fas fa-envelope"></i>
</label>
<input type="email" name="email" placeholder="Your Email" id="email" required>
			</td>
            <td class="tableButton">
			<input type="hidden" name="token" value="<?=$_SESSION['token']?>">
			<input class="profile-btn" type="submit" value="Register"></td>
	</tr>
            </table>
</form>
			</div>
            <?php
include "footer.php";
?>