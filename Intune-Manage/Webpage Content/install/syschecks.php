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
// PHP Version
if (@version_compare(phpversion(), '8.0.0') > -1) {
$PHP = "ON";
}
else {
$PHP = "OFF";
}


// Sessions
if (function_exists('session_start')) {
$Session = "ON";
}
else {
$Session = "OFF";
}

// MD5
if (function_exists('md5')) {
$MD5 = "ON";
}
else {
$MD5 = "OFF";
}

// MySQL
if (function_exists('mysqli_connect')) {
$MySQL = "ON";
}
else {
$MySQL = "OFF";
}


// Write to dbdetails

// Linux
$address = $_SERVER['DOCUMENT_ROOT'];
$includes = "/";
$location = $address . $includes;
    $file = "config.php";
    $filename = $location . $file;
if (is_writable($filename)) {
    $writable = "ON";
} else {
    $writable = "OFF";
}





// Server
    if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN') {
// Windows
$server = "Windows";
} else {
// Linux
$server = "Linux";
}


?>