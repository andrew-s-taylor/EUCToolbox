<?php
// Your MySQL database hostname.
define('db_host','');
// Your MySQL database username.
define('db_user','');
// Your MySQL database password.
define('db_pass','');
// Your MySQL database name.
define('db_name','');
define('db_charset','utf8');
define('domainname','');
/* Registration */
// If enabled, the user will be redirected to the homepage automatically upon registration.
define('auto_login_after_register',true);
/* Account Activation */
// If enabled, the account will require email activation before the user can login.
define('account_activation',false);
// Change "Your Company Name" and "yourdomain.com" - do not remove the < and > characters.
define('mail_from','EUCToolbox <noreply@euctoolbox.com>');
// The link to the activation file.
define('activation_link','');
//Encryption key
define('encryption_key','');
//Webhook URL
define('webhook',"");
//App Webhook URL
define('appwebhook',"");
//Drift Webhook URL
define('driftwebhook',"");
    //DailyChecks Webhook URL
define('dailywebhook',"");
    //Security Checks Webhook URL
define('securitywebhook',"");
define('appID','');
define('appSecret','');
define('fullgittoken', '');
define('gittype','');
define('gitowner','');
define('sendgridtoken', '');
define('gitorg','');
?>