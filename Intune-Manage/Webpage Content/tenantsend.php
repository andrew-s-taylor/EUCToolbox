<?php
include 'main.php';
$appid = appID;
$type = $_POST['type'];
// Check if the form has been submitted
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Process the form data here
    if ($type == "refresh") {
    // Check if the referer is from the same server
    if (isset($_SERVER['HTTP_REFERER']) && parse_url($_SERVER['HTTP_REFERER'], PHP_URL_HOST) === $_SERVER['HTTP_HOST']) {
        // The form has been accessed from a link on the same server
        header("Location: https://login.microsoftonline.com/organizations/v2.0/adminconsent?client_id=$appid&scope=https://graph.microsoft.com/.default&state=managerefresh");
    } else {
        echo "The form has not been accessed from a link on the same server";
    }
}
else {
        // Check if the referer is from the same server
        if (isset($_SERVER['HTTP_REFERER']) && parse_url($_SERVER['HTTP_REFERER'], PHP_URL_HOST) === $_SERVER['HTTP_HOST']) {
            // The form has been accessed from a link on the same server
            header("Location: https://login.microsoftonline.com/organizations/v2.0/adminconsent?client_id=$appid&scope=https://graph.microsoft.com/.default&state=manage");
        } else {
            echo "The form has not been accessed from a link on the same server";
        }
}
}

?>
