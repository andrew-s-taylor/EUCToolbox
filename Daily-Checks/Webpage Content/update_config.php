<?php
$webhookcommunity = $_POST['webhook'];
$appid = $_POST['eappid'];
$appsecret = $_POST['eappsecret'];
$sendgridtoken = $_POST['sendgridtoken'];
$htmltemplate = $_POST['templatepath'];

$contents = file_get_contents('config.php');
$contents = preg_replace('/define\(\'WEBHOOKHERE\'\, ?(.*?)\)/s', 'define(\'WEBHOOKHERE\',\'' . $webhookcommunity . '\')', $contents);
$contents = preg_replace('/define\(\'appID\'\, ?(.*?)\)/s', 'define(\'appID\',\'' . $appid . '\')', $contents);
$contents = preg_replace('/define\(\'appSecret\'\, ?(.*?)\)/s', 'define(\'appSecret\',\'' . $appsecret . '\')', $contents);
$contents = preg_replace('/define\(\'htmltemplate\'\, ?(.*?)\)/s', 'define(\'htmltemplate\',\'' . $htmltemplate . '\')', $contents);
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