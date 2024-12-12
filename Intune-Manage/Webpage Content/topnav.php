<div id="appSwitcherPopUp">
    <?php

// Your MySQL database hostname.

$connav = mysqli_connect(db_host, db_userhost, db_passhost, db_namehost);
// If there is an error with the MySQL connection, stop the script and output the error
if (mysqli_connect_errno()) {
	exit('Failed to connect to MySQL: ' . mysqli_connect_error());
}
// Update the charset
mysqli_set_charset($connav, db_charset);

//Loop through the menu table and retrieve everything
$sqlnav = "SELECT * FROM menu";
$resultnav = mysqli_query($connav, $sqlnav);
if (mysqli_num_rows($resultnav) > 0) {
    while($rownav = mysqli_fetch_assoc($resultnav)) {
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
}

?>

</div>
