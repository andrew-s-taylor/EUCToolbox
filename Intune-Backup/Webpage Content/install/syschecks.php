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