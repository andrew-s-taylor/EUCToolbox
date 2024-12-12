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