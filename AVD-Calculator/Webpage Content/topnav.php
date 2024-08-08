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
