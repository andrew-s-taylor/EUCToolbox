<?php
/* This file is part of a GPL-licensed project.
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
$webhookcommunity = $_POST['webhook'];
$appid = $_POST['eappid'];
$appsecret = $_POST['eappsecret'];
$sendgridtoken = $_POST['sendgridtoken'];

$contents = file_get_contents('config.php');
$contents = preg_replace('/define\(\'WEBHOOKHERE\'\, ?(.*?)\)/s', 'define(\'WEBHOOKHERE\',\'' . $webhookcommunity . '\')', $contents);
$contents = preg_replace('/define\(\'appID\'\, ?(.*?)\)/s', 'define(\'appID\',\'' . $appid . '\')', $contents);
$contents = preg_replace('/define\(\'appSecret\'\, ?(.*?)\)/s', 'define(\'appSecret\',\'' . $appsecret . '\')', $contents);
$contents = preg_replace('/define\(\'sendgridtoken\'\, ?(.*?)\)/s', 'define(\'sendgridtoken\',\'' . $sendgridtoken . '\')', $contents);
if (!file_put_contents('config.php', $contents)) {
    // Could not write to config.php file
    exit('Failed to automatically assign the webhook secrets! Please set them manually in the config.php file.');
}
else {
    // Redirect to the same page to ensure the cookies are cleared
    header("Location: index.php");
    exit();
}
    ?>