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
// Check logged-in
check_loggedin($con);
// Handle edit profile post data
if (isset($_POST['type'])) {
	//DO FORM STUFF
switch ($_POST['type']) {
    case "update":
        //UPDATE
        $stmt = $con->prepare('UPDATE tenants SET tenantname = ?, tenantid = ? WHERE ID = ?');
        $stmt->bind_param('ssi', $_POST['tenantname'], $_POST['tenantid'], $_POST['ID']);
        $stmt->execute();
        $stmt->close();
        break;
    case "delete":
        //DELETE
        $stmt = $con->prepare('DELETE FROM tenants WHERE ID = ?');
        $stmt->bind_param('i', $_POST['ID']);
        $stmt->execute();
        $stmt->close();
        break;
    case "add":
        //ADD
        $stmt = $con->prepare('INSERT INTO tenants (tenantname, tenantid, ownerid) VALUES (?, ?, ?)');
        $stmt->bind_param('ssi', $_POST['tenantname'], $_POST['tenantid'], $_POST['ownerid']);
        $stmt->execute();
        $stmt->close();
        break;
    }

}

header('Location: tenants.php?updatemessage=Tenant Updated');
?>