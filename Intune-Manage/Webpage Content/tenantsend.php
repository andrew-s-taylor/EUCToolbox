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
