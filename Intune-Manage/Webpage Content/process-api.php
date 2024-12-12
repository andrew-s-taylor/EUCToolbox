<?php
include 'main.php';

$type = $_POST['type'];
$api_name = $_POST['api_name'];
$api_secret = $_POST['api_secret'];
$encrypted = encryptstring($api_secret);
$api_clientID = $_POST['api_clientID'];
$accountID = $_POST['accountID'];
$id = $_POST['id'];

if ($type == 'update') {
    $stmt = $con->prepare('UPDATE api_integrations SET apiName = ?, apisecret = ?, clientID = ? WHERE ID = ?');
    $stmt->bind_param('sssi', $api_name, $encrypted, $api_clientID, $id);
    $stmt->execute();
    $stmt->close();
    header('Location: manage-api.php');
} else if ($type == 'delete') {
    $stmt = $con->prepare('DELETE FROM api_integrations WHERE ID = ?');
    $stmt->bind_param('i', $id);
    $stmt->execute();
    $stmt->close();
    header('Location: manage-api.php');
} else {
    $stmt = $con->prepare('INSERT INTO api_integrations (apiName, apisecret, clientID, accountID) VALUES (?, ?, ?, ?)');
    $stmt->bind_param('sssi', $api_name, $encrypted, $api_clientID, $accountID);
    $stmt->execute();
    $stmt->close();
    header('Location: manage-api.php');
}