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


$aadclient = appID;
$aadsecret = appSecret;
$repotype = gittype;
$repoowner = gitowner;
$gittoken = fullgittoken;
$gitproject = "GitHub";

$stmt = $con->prepare('SELECT * FROM accounts JOIN tenants ON accounts.id = tenants.ownerid WHERE accounts.regtype != "expired"');
// $stmt->bind_param('i', $_SESSION['id']);
$stmt->execute();
$result = $stmt->get_result();

while ($row = $result->fetch_assoc()) {
    $tenantid = $row['tenantid'];
    $reponame = $row["reponame"];
    $alertsemail = $row['alertsemail'];
    //Grab the current details to compare later
        $oldsecurescore = $row['securescore'];
        $oldnoncompliantdevices =  $row['noncompliantdevices'];
        $windowscisold = $row['windowscis'];
        $windowsncscold = $row['windowsncsc'];
        $iosold = $row['ios'];
        $androidold = $row['android'];



    //Grab the contents of the file called $tenantid-drift.json from Github
    $url = "https://api.github.com/repos/{$repoowner}/{$reponame}/contents/{$tenantid}-drift.json";
    $headers = array(
        'Authorization: token ' . $gittoken,
        'User-Agent: PHP'
    );

    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
    $response = curl_exec($ch);
    curl_close($ch);

    $fileContents = json_decode($response, true);
    $driftData = base64_decode($fileContents['content']);

    //If the file has contents, set to yes
    if ($driftData != "") {
        $tenantdrift = "yes";
    } else {
        $tenantdrift = "no";
    }


    //Also the golddrift
    $url = "https://api.github.com/repos/{$repoowner}/{$reponame}/contents/{$tenantid}-golddrift.json";
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
    $response = curl_exec($ch);
    curl_close($ch);

    $fileContents = json_decode($response, true);
    $golddriftData = base64_decode($fileContents['content']);

     //If the file has contents, set to yes
     if ($golddriftData != "") {
        $golddrift = "yes";
    } else {
        $golddrift = "no";
    }

    //Grab contents of daily checks api
    $url = "https://api.github.com/repos/{$repoowner}/{$reponame}/contents/{$tenantid}-dailyapi.json";
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
    $response = curl_exec($ch);
    curl_close($ch);

    $fileContents = json_decode($response, true);
    $dailyapiData = base64_decode($fileContents['content']);
    //Convert to array
    $dailyapiData = json_decode($dailyapiData, true);
    $updatedapps = $dailyapiData['UpdatedApps'];
    $adminevents = $dailyapiData['AdminEvents'];
    $unusedlicenses = $dailyapiData['UnusedLicenses'];
    $licensesonoldusers = $dailyapiData['LicensesonOldUsers'];
    $securescore = $dailyapiData['SecureScore'];
    $noncompliantdevices = $dailyapiData['NonCompliantDevices'];
    $failedsignins = $dailyapiData['FailedSignIns'];
    $failedappinstalls = $dailyapiData['FailedAppInstalls'];
    $pushexpiry = $dailyapiData['Push-Expiry'];
    $vppexpiry = $dailyapiData['VPP-Expiry'];
    $depexpiry = $dailyapiData['DEPExpiry'];
    $avissues = $dailyapiData['AV-Issues'];
    $firewalloff = $dailyapiData['FirewallOff'];
    $securitytasks = $dailyapiData['Security Tasks'];
    $outdatedfeatureupdatepolicy = $dailyapiData['OutdatedFeatureUpdatePolicy'];
    $expiringsecrets = $dailyapiData['ExpiringSecrets'];
    $staledevices = $dailyapiData['StaleDevices'];


        //Grab contents of security checks api
        $url = "https://api.github.com/repos/{$repoowner}/{$reponame}/contents/{$tenantid}-securityapi.json";
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        $securityresponse = curl_exec($ch);
        curl_close($ch);
    
        $securityfileContents = json_decode($securityresponse, true);
        $securityapidata = base64_decode($securityfileContents['content']);
        //Convert to array
        $securityapidata = json_decode($securityapidata, true);
        $windowsncsc = $securityapidata['windowsncsc'];
        $windowscis = $securityapidata['windowscis'];
        $android = $securityapidata['android'];
        $ios = $securityapidata['ios'];

    //Update the database
    $stmt = $con->prepare('UPDATE tenants SET tenantdrift = ?, golddrift = ?, updatedapps = ?, adminevents = ?, unusedlicenses = ?, licensesonoldusers = ?, securescore = ?, noncompliantdevices = ?, failedsignins = ?, failedappinstalls = ?, pushexpiry = ?, vppexpiry = ?, depexpiry = ?, avissues = ?, firewalloff = ?, securitytasks = ?, outdatedfeatureupdatepolicy = ?, expiringsecrets = ?, staledevices = ?, windowsncsc = ?, windowscis = ?, android = ?, ios = ? WHERE tenantid = ?');
    $stmt->bind_param('ssssssssssssssssssssssss', $tenantdrift, $golddrift, $updatedapps, $adminevents, $unusedlicenses, $licensesonoldusers, $securescore, $noncompliantdevices, $failedsignins, $failedappinstalls, $pushexpiry, $vppexpiry, $depexpiry, $avissues, $firewalloff, $securitytasks, $outdatedfeatureupdatepolicy, $expiringsecrets, $staledevices, $tenantid, $windowscis, $windowsncsc, $android, $ios);
    $stmt->execute();


    ##Compare old and new values
    ##Create an array to store the message
    $message = array();

    // Compare old and new values
    if ($oldsecurescore != $securescore) {
        $message[] = "Secure score has changed for tenant $tenantid from $oldsecurescore to $newsecurescore";
    }

    if ($oldnoncompliantdevices != $noncompliantdevices) {
        $message[] = "Number of non-compliant devices has changed for tenant $tenantid from $oldnoncompliantdevices to $noncompliantdevices";
    }

    if ($windowscisold != $windowscis) {
        $message[] = "Windows CIS score has changed for tenant $tenantid from $windowscisold to $windowscis";
    }

    if ($windowsncscold != $windowsncsc) {
        $message[] = "Windows NCSC score has changed for tenant $tenantid from $windowsncscold to $windowsncsc";
    }

    if ($iosold != $ios) {
        $message[] = "iOS score has changed for tenant $tenantid from $iosold to $ios";
    }

    if ($androidold != $android) {
        $message[] = "Android score has changed for tenant $tenantid from $androidold to $android";
    }

    if ($tenantdrift = "yes") {
        $message[] = "Tenant drift detected on $tenantid";

    }

    ##Check if alertsemail is populated in accounts
    if (!empty($alertsemail)) {
        $to = $alertsemail;
        $subject = "Tenant Alerts";
        $message = implode("\n", $message);
        $headers = "From: alerts@euctoolbox.com" . "\r\n" .
            "Reply-To: alerts@euctoolbox.com" . "\r\n" .
            "X-Mailer: PHP/" . phpversion();

        mail($to, $subject, $message, $headers);
    }


}

$stmt->close();
?>