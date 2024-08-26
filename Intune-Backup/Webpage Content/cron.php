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
@include dirname( __FILE__ ) . '/main.php';

//Check if owner has been sent
if (isset($_POST['owner'])) {
    $ownerid = $_POST['owner'];
} else {
    $ownerid = "no";
}
//Drift Check
if ($ownerid == "no") {
$stmt = $con->prepare('SELECT * FROM accounts INNER JOIN tenants ON accounts.id = tenants.ownerid');
}
else {
$stmt = $con->prepare('SELECT * FROM accounts INNER JOIN tenants ON accounts.id = tenants.ownerid WHERE accounts.id = ?');
$stmt->bind_param('i', $ownerid);
}
// In this case, we can use the account ID to retrieve the account info.
$stmt->execute();
$result = $stmt->get_result();
/* Get the number of rows */
$num_of_rows = $result->num_rows;
echo $num_of_rows;
if ($num_of_rows > 0) {
    // output data of each row
    while ($row = $result->fetch_assoc()) {        
        $reponame = $row["reponame"];
        $repoowner = $row["repoowner"];
        $gittoken = $row["gittoken"];
        $gitproject = $row["gitproject"];
        $aadclient = $row["aadclient"];
        $aadsecret = $row["aadsecret"];
        $tenant = $row["tenantid"];
        $repotype = $row["gittype"];
        //DO FORM STUFF
$token = decryptstring($gittoken);
$clientsecret = decryptstring($aadsecret);

//Check all fields are completed before continuing
if ($reponame == "" || $repoowner == "" || $gittoken == "" || $gitproject == "" || $aadclient == "" || $aadsecret == "" || $tenant == "" || $repotype == "") {
    //Do nothing
} else {

    $data = array(
        array("tenant" => "$tenant"),
        array("repotype" => "$repotype"),
        array("ownername" => "$repoowner"),
        array("reponame" => "$reponame"),
        array("token" => "$token"),
        array("project" => "$gitproject"),
        array("clientid" => "$aadclient"),
        array("clientsecret" => "$clientsecret")
    );

//Encode it
$body = base64_encode(json_encode($data));

$header = array("message" => "Policy transfer to $tenant");

//Setup CURL
$ch = curl_init();
$url = $driftwebookuri;
curl_setopt($ch, CURLOPT_URL, $url);
curl_setopt($ch, CURLOPT_CUSTOMREQUEST, "POST");
curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
curl_setopt($ch, CURLOPT_HTTPHEADER, $header);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

$resultch = curl_exec($ch);
curl_close($ch);

    }
}
} 
$stmt->close();



//Gold Drift
if ($ownerid == "no") {
    $stmt = $con->prepare('SELECT * FROM accounts INNER JOIN tenants ON accounts.id = tenants.ownerid');
    }
    else {
    $stmt = $con->prepare('SELECT * FROM accounts INNER JOIN tenants ON accounts.id = tenants.ownerid WHERE accounts.id = ?');
    $stmt->bind_param('i', $ownerid);
    }
    // In this case, we can use the account ID to retrieve the account info.
$stmt->execute();
$result = $stmt->get_result();

/* Get the number of rows */
$num_of_rows = $result->num_rows;
if ($num_of_rows > 0) {
    // output data of each row
    while ($row = $result->fetch_assoc()) { 
        $reponame = $row["reponame"];
        $repoowner = $row["repoowner"];
        $gittoken = $row["gittoken"];
        $gitproject = $row["gitproject"];
        $aadclient = $row["aadclient"];
        $aadsecret = $row["aadsecret"];
        $tenant = $row["tenantid"];
        $repotype = $row["gittype"];
        $golden = $row["golden"];
        //DO FORM STUFF
$token = decryptstring($gittoken);
$clientsecret = decryptstring($aadsecret);
//Check all fields are completed before continuing
if ($reponame == "" || $repoowner == "" || $gittoken == "" || $gitproject == "" || $aadclient == "" || $aadsecret == "" || $tenant == "" || $repotype == "") {
    //Do nothing
} else {
    $data = array(
        array("tenant" => "$tenant"),
        array("repotype" => "$repotype"),
        array("ownername" => "$repoowner"),
        array("reponame" => "$reponame"),
        array("token" => "$token"),
        array("project" => "$gitproject"),
        array("clientid" => "$aadclient"),
        array("goldentenant" => "$golden"),
        array("clientsecret" => "$clientsecret")
    );

//Encode it
$body = base64_encode(json_encode($data));

$header = array("message" => "Policy transfer to $tenant");

//Setup CURL
$ch = curl_init();
$url = $driftwebookuri;
curl_setopt($ch, CURLOPT_URL, $url);
curl_setopt($ch, CURLOPT_CUSTOMREQUEST, "POST");
curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
curl_setopt($ch, CURLOPT_HTTPHEADER, $header);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

$resultch = curl_exec($ch);
curl_close($ch);

    }
}
} 
$stmt->close();

header('Location: home.php?updatemessage=Drift Check Started');
?>