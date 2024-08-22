<?php
/**
 * This file is part of a GPL-licensed project.
 *
 * Copyright (C) 2024 Andrew Taylor (andrew.taylor@andrewstaylor.com)
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
include('config.php');
$sitename = "Intune Security Check from EUC Toolbox";
$pagetitle = "Intune Security Check";
include "header.php";
?>

<?php
if (webhook == "WEBHOOKHERE") {
    ?>
    <form action="update_config.php" method="post">
        <label for="webhook">Webhook:</label>
        <input type="text" id="webhook" name="webhook" required><br><br>
        
        <label for="appid">App ID:</label>
        <input type="text" id="eappid" name="eappid" required><br><br>
        
        <label for="appsecret">App Secret:</label>
        <input type="text" id="eappsecret" name="eappsecret" required><br><br>

        <label for="sendgridtoken">Sendgrid Token:</label>
        <input type="text" id="sendgridtoken" name="sendgridtoken" required><br><br>
        
        <input type="submit" value="Update Config">
    </form>

    <?php
}
else {
//Check for any POST messages and if found, display them
if (isset($_GET['message'])) {
    $message = $_GET['message'];
    echo "<div class='alert alert-success' role='alert'>$message</div>";
}
?>   
         <h1>Welcome to Intune Security Check from EUC Toolbox</h1>
         <div class="step-container">
   <p>This free service will send you an email with a report which queries your tenant against:</p>
    <ul>
         <li>CIS Baselines</li>
         <li>NCSC Baselines</li>
    </ul>
   <p>Please enter your email and tenant ID and click submit.</p>
</div>
   <form action="process.php" method="post">
   <table class="styled-table">
    <tr><td><label for="email">Recipient Email:</label></td>
    <td><input type="email" name="email" id="email" required></td></tr>
    <tr><td><label for="tenant">Tenant ID:</label></td>
    <td><input type="text" name="tenant" id="tenant" required></td></tr>
<tr><td class="tableButton"><input class="profile-btn" type="submit" value="Next"></td></tr>
    </form>
    </table>  
    <?php
}
?>
    <?php
include "footer.php";
?>