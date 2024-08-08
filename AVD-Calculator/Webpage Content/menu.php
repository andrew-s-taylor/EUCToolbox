<div id="menu">
        <button onclick="closeMenu()"><img width="16px" height="16px" src="https://euctoolbox.com/images/Menu Icons/close.svg"></button>
<nav class="menu">
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


foreach ($menuitems as $row){
        $url = $row['URL'];
    $url2 = $row['URL'];
        $name = $row['Name'];
        $logo2 = $row['Logo'];
        //Check if current URL
        $servername = $_SERVER['SERVER_NAME'];
        //Remove https://
        $url = str_replace('https://', '', $url);
        //Remove http://
        $url = str_replace('http://', '', $url);
        //Remove www.
        $url = str_replace('www.', '', $url);
        //Remove trailing slash
        $url = rtrim($url, '/');
        if ($servername == 'backup.euctoolbox.com' || $servername == 'intunebackup.com' || $servername == 'backupintune.com'){
            $servername2 = 'backup.euctoolbox.com';
            
        }
        elseif ($servername == 'deploy.euctoolbox.com' || $servername == 'deployintune.com'){
            $servername2 = 'deploy.euctoolbox.com';
        }
        else {
            $servername2 = $servername;
        }

        if($servername2== $url){
            echo '<a href="'.$url2.'" class="active"><img class="menuIcon" alt="'.$name.' Icon" width="22px" height="18px" src="'.$logo2.'">'.$name.'</a>';
        }else{
        echo '<a href="'.$url2.'"><img class="menuIcon" alt="'.$name.' Icon" width="22px" height="18px" src="'.$logo2.'">'.$name.'</a>';
        }
    }

?>

</nav>
</div>		

<button id="menuButton" onclick="openMenu()"><img width="20px" height="20pxs" src="https://euctoolbox.com/images/Menu Icons/menu.svg">Menu</button>