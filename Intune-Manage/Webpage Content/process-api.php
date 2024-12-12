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