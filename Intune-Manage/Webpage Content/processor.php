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