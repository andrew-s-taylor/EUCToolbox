<?php
/**
 * This file is part of a GPL-licensed project.
 *
 * Copyright (C) 2024 Andrew Taylor (andrew.taylor@andrewstaylor.com)
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
<div id="appSwitcherPopUp">
    <?php

//Use the api to grab apps
$api_url = 'https://euctoolbox.com/api?action=menu';

// Grab them via CURL
$curl = curl_init();
curl_setopt_array($curl, array(
    CURLOPT_URL => "$api_url",
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_ENCODING => '',
    CURLOPT_MAXREDIRS => 10,
    CURLOPT_TIMEOUT => 0,
    CURLOPT_FOLLOWLOCATION => true,
    CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
    CURLOPT_SSL_VERIFYHOST => false,
    CURLOPT_SSL_VERIFYPEER => true,
    CURLOPT_CUSTOMREQUEST => 'GET',
    CURLOPT_HTTPHEADER => array(
      'Content-Type: application/json'
    ),
  ));

// Initialize the cURL session
$result = curl_exec($curl);

// Decode the JSON output
$menuitems = json_decode($result, true);


//Remove duplicates on appdisplayname, ignore other fields


foreach ($menuitems as $rownav){
        $urlnav = $rownav['URL'];
    $url2nav = $rownav['URL'];
        $namenav = $rownav['Name'];
        $logo2nav = $rownav['Logo'];

        //Check if current URL
$servernamenav = $_SERVER['SERVER_NAME'];
$servernamelivenav = $_SERVER['SERVER_NAME'];

if ($servernamelivenav == 'backup.euctoolbox.com' || $servernamelivenav == 'intunebackup.com' || $servernamelivenav == 'backupintune.com'){
    $servername2nav = 'backup.euctoolbox.com';
}
elseif ($servernamelivenav == 'deploy.euctoolbox.com' || $servernamelivenav == 'deployintune.com'){
    $servername2nav = 'deploy.euctoolbox.com';
}
else {
    $servername2nav = $servernamenav;
}
        //Remove https://
        $urlnav = str_replace('https://', '', $urlnav);
        //Remove http://
        $url = str_replace('http://', '', $urlnav);
        //Remove www.
        $urlnav = str_replace('www.', '', $urlnav);
        //Remove trailing slash
        $urlnav = rtrim($urlnav, '/');


        if($servername2nav== $urlnav){
            echo '<a href="'.$url2nav.'" class="activeApp">'.$namenav.'</a>';
        }else{
        echo '<a href="'.$url2nav.'">'.$namenav.'</a>';
        }
    }

?>

</div>
