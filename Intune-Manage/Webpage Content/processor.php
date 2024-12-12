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
//Include config file
include 'config.php';
//Get domain name
$domainname = domainname;

$tenant = $_GET['tenant'];

$source = $_GET['state'];

$scope = $_GET['scope'];
$code = $_GET['code'];
//Split $source on %%
$split = explode('<>', $source);
$state = $split[0];
$customerid = $split[1];

//Check if scope contains graph.microsoft.com
if ((strpos($scope, 'graph.microsoft.com') !== false) || ($code)) {

    //Add a switch statement to handle the different sources
    switch ($state) {
        case 'manage':
            $url = "https://$domainname/tenants.php?tenant=" . $tenant;
            header('Location: ' . $url);
            break;
        case 'managerefresh':
            $customerid2 = base64_decode($customerid);
            $url = "https://$domainname/tenants.php?updatemessage=ConnectionRefreshed";
            header('Location: ' . $url);
            break;
        case 'sso':
            $url = "https://$domainname/sso.php?code=$code";
            header('Location: ' . $url);
            break;
    }
} else {
    exit('Invalid scope');
}

?>