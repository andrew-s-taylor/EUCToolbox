<?php
session_start();
// Destroy the session associated with the user
session_destroy();
// If the user is remembered, delete the cookie
if (isset($_COOKIE['rememberme'])) {
    unset($_COOKIE['rememberme']);
    setcookie('rememberme', '', time() - 3600);
}
// Redirect to the login page:
header('Location: index.php');
?>