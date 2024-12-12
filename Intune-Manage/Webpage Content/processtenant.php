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
        $stmt = $con->prepare('UPDATE tenants SET tenantname = ?, tenantid = ?, ownerid = ? WHERE ID = ?');
        $stmt->bind_param('ssii', $_POST['tenantname'], $_POST['tenantid'], $_POST['customerid'], $_POST['ID']);
        $stmt->execute();
        $stmt->close();
        			// Write to auditlog with userID, IP address, timestamp and update message
            $tenantname = $_POST['tenantname'];
            $tenantid = $_POST['tenantid'];
			$auditlog_message = "Tenant $tenantname ($tenantid) updated";
			$auditlog_userID = $_SESSION['id'];
			$auditlog_ipAddress = $_SERVER['REMOTE_ADDR'];
			$auditlog_timestamp = date('Y-m-d H:i:s');
			$stmt = $con->prepare('INSERT INTO auditlog (UserID, IPAddress, Timestamp, Task) VALUES (?, ?, ?, ?)');
			$stmt->bind_param('isss', $auditlog_userID, $auditlog_ipAddress, $auditlog_timestamp, $auditlog_message);
			$stmt->execute();
			$stmt->close();
        break;
    case "delete":
        //Get Tenant Name and ID from database
        $stmt = $con->prepare('SELECT tenantname, tenantid FROM tenants WHERE ID = ?');
        $stmt->bind_param('i', $_POST['ID']);
        $stmt->execute();
        $stmt->bind_result($tenantname, $tenantid);
        $stmt->fetch();
        $stmt->close();
        //DELETE
        $stmt = $con->prepare('DELETE FROM tenants WHERE ID = ?');
        $stmt->bind_param('i', $_POST['ID']);
        $stmt->execute();
        $stmt->close();
            // Write to auditlog with userID, IP address, timestamp and update message
            $auditlog_message = "Tenant $tenantname ($tenantid) deleted";
            $auditlog_userID = $_SESSION['id'];
            $auditlog_ipAddress = $_SERVER['REMOTE_ADDR'];
            $auditlog_timestamp = date('Y-m-d H:i:s');
            $stmt = $con->prepare('INSERT INTO auditlog (UserID, IPAddress, Timestamp, Task) VALUES (?, ?, ?, ?)');
            $stmt->bind_param('isss', $auditlog_userID, $auditlog_ipAddress, $auditlog_timestamp, $auditlog_message);
            $stmt->execute();
            $stmt->close();
        break;
    case "add":
        //ADD
        $stmt = $con->prepare('INSERT INTO tenants (tenantname, tenantid, customerid, ownerid) VALUES (?, ?, ?, ?)');
        $stmt->bind_param('ssii', $_POST['tenantname'], $_POST['tenantid'], $_POST['ownerid'], $_POST['customerid']);
        $stmt->execute();
        $stmt->close();
                			// Write to auditlog with userID, IP address, timestamp and update message
                            $tenantname = $_POST['tenantname'];
                            $tenantid = $_POST['tenantid'];
                            $auditlog_message = "Tenant $tenantname ($tenantid) added";
                            $auditlog_userID = $_SESSION['id'];
                            $auditlog_ipAddress = $_SERVER['REMOTE_ADDR'];
                            $auditlog_timestamp = date('Y-m-d H:i:s');
                            $stmt = $con->prepare('INSERT INTO auditlog (UserID, IPAddress, Timestamp, Task) VALUES (?, ?, ?, ?)');
                            $stmt->bind_param('isss', $auditlog_userID, $auditlog_ipAddress, $auditlog_timestamp, $auditlog_message);
                            $stmt->execute();
                            $stmt->close();

                            //Get the reponame from the database
                            $stmt = $con->prepare('SELECT reponame FROM accounts WHERE id = ?');
                            $stmt->bind_param('i', $_POST['ownerid']);
                            $stmt->execute();
                            $stmt->bind_result($reponame);
                            $stmt->fetch();
                            $stmt->close();
                            

                            $aadclient = appID;
                            $aadsecret = appSecret;
                            $repotype = gittype;
                            $repoowner = gitowner;
                            $gittoken = fullgittoken;
                            $gitproject = "GitHub";
                            $tenantid = $_POST['tenantid'];
                            $data = array(
                                array("tenant" => "$tenantid"),
                                array("clientid" => "$aadclient"),
                                array("clientsecret" => "$aadsecret"),
                                array("repotype" => "$repotype"),
                                array("ownername" => "$repoowner"),
                                array("reponame" => "$reponame"),
                                array("token" => "$gittoken"),
                                array("project" => "$gitproject"),
                                array("portal" => "yes")
                            );
                        
                            $body = base64_encode(json_encode($data));
                        
                            $header = array("message" => "Cron for $tenantid");
                        
                            //Setup CURL for daily check
                        $ch = curl_init();
                        $url = $dailywebhookuri;
                        curl_setopt($ch, CURLOPT_URL, $url);
                        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, "POST");
                        curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
                        curl_setopt($ch, CURLOPT_HTTPHEADER, $header);
                        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
                        
                        $result1 = curl_exec($ch);
                        curl_close($ch);
                        
                            //Setup CURL for security check
                            $ch = curl_init();
                            $url = $securitywebhookuri;
                            curl_setopt($ch, CURLOPT_URL, $url);
                            curl_setopt($ch, CURLOPT_CUSTOMREQUEST, "POST");
                            curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
                            curl_setopt($ch, CURLOPT_HTTPHEADER, $header);
                            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
                            
                            $result2 = curl_exec($ch);
                            curl_close($ch);

        break;
    }

}

header('Location: tenants.php?updatemessage=Tenant Updated');
?>