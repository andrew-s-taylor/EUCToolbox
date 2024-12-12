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
</div>
  <div class="footer">
  <div class="sponsors">
        Sponsored by: 
        <?php

//Use the api to grab apps
$api_url = 'https://euctoolbox.com/api?action=sponsors';

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
$sponsors = json_decode($result, true);


//Remove duplicates on appdisplayname, ignore other fields


foreach ($sponsors as $row){
        $url = $row['url'];
        $name = $row['name'];
        $logo2 = $row['logo'];
echo "<a href=\"$url\"><img src=\"$logo2\" alt=\"$name\" class=\"responsive-image\"></a>";
    }

?>

    </div>
		<div class="footerCopyright">
			<p>EUC Toolbox from AndrewSTaylor.com Ltd</p>
			<p>Registered company: 15261781</p>
			<p>Registered Address: Verdemar House, 230 Park View, Whitley Bay, England, NE26 3QR </p>
			<p><a href="https://andrewstaylor.com/privacy-policy/">Privacy Policy</a></p>
		</div>
	</div>

    <!-- <div id="footer"><p>© Copyright 2023 <a href="https://andrewstaylor.com">Andrew Taylor</a></p></div> -->
    <!-- Code injected by live-server -->
    <script>
    // <![CDATA[  <-- For SVG support
    if ('WebSocket' in window) {
        (function () {
            function refreshCSS() {
                var sheets = [].slice.call(document.getElementsByTagName("link"));
                var head = document.getElementsByTagName("head")[0];
                for (var i = 0; i < sheets.length; ++i) {
                    var elem = sheets[i];
                    var parent = elem.parentElement || head;
                    parent.removeChild(elem);
                    var rel = elem.rel;
                    if (elem.href && typeof rel != "string" || rel.length == 0 || rel.toLowerCase() == "stylesheet") {
                        var url = elem.href.replace(/(&|\?)_cacheOverride=\d+/, '');
                        elem.href = url + (url.indexOf('?') >= 0 ? '&' : '?') + '_cacheOverride=' + (new Date().valueOf());
                    }
                    parent.appendChild(elem);
                }
            }
            var protocol = window.location.protocol === 'http:' ? 'ws://' : 'wss://';
            var address = protocol + window.location.host + window.location.pathname + '/ws';
            var socket = new WebSocket(address);
            socket.onmessage = function (msg) {
                if (msg.data == 'reload') window.location.reload();
                else if (msg.data == 'refreshcss') refreshCSS();
            };
            if (sessionStorage && !sessionStorage.getItem('IsThisFirstTime_Log_From_LiveServer')) {
                console.log('Live reload enabled.');
                sessionStorage.setItem('IsThisFirstTime_Log_From_LiveServer', true);
            }
        })();
    }
    else {
        console.error('Upgrade your browser. This Browser is NOT supported WebSocket for Live-Reloading.');
    }
    // ]]>
    </script>
    
    <!-- Code injected by live-server -->
    <script>
        // <![CDATA[  <-- For SVG support
        if ('WebSocket' in window) {
            (function () {
                function refreshCSS() {
                    var sheets = [].slice.call(document.getElementsByTagName("link"));
                    var head = document.getElementsByTagName("head")[0];
                    for (var i = 0; i < sheets.length; ++i) {
                        var elem = sheets[i];
                        var parent = elem.parentElement || head;
                        parent.removeChild(elem);
                        var rel = elem.rel;
                        if (elem.href && typeof rel != "string" || rel.length == 0 || rel.toLowerCase() == "stylesheet") {
                            var url = elem.href.replace(/(&|\?)_cacheOverride=\d+/, '');
                            elem.href = url + (url.indexOf('?') >= 0 ? '&' : '?') + '_cacheOverride=' + (new Date().valueOf());
                        }
                        parent.appendChild(elem);
                    }
                }
                var protocol = window.location.protocol === 'http:' ? 'ws://' : 'wss://';
                var address = protocol + window.location.host + window.location.pathname + '/ws';
                var socket = new WebSocket(address);
                socket.onmessage = function (msg) {
                    if (msg.data == 'reload') window.location.reload();
                    else if (msg.data == 'refreshcss') refreshCSS();
                };
                if (sessionStorage && !sessionStorage.getItem('IsThisFirstTime_Log_From_LiveServer')) {
                    console.log('Live reload enabled.');
                    sessionStorage.setItem('IsThisFirstTime_Log_From_LiveServer', true);
                }
            })();
        }
        else {
            console.error('Upgrade your browser. This Browser is NOT supported WebSocket for Live-Reloading.');
        }
        // ]]>
    </script>
    <!-- Code injected by live-server -->
    <script>
        // <![CDATA[  <-- For SVG support
        if ('WebSocket' in window) {
            (function () {
                function refreshCSS() {
                    var sheets = [].slice.call(document.getElementsByTagName("link"));
                    var head = document.getElementsByTagName("head")[0];
                    for (var i = 0; i < sheets.length; ++i) {
                        var elem = sheets[i];
                        var parent = elem.parentElement || head;
                        parent.removeChild(elem);
                        var rel = elem.rel;
                        if (elem.href && typeof rel != "string" || rel.length == 0 || rel.toLowerCase() == "stylesheet") {
                            var url = elem.href.replace(/(&|\?)_cacheOverride=\d+/, '');
                            elem.href = url + (url.indexOf('?') >= 0 ? '&' : '?') + '_cacheOverride=' + (new Date().valueOf());
                        }
                        parent.appendChild(elem);
                    }
                }
                var protocol = window.location.protocol === 'http:' ? 'ws://' : 'wss://';
                var address = protocol + window.location.host + window.location.pathname + '/ws';
                var socket = new WebSocket(address);
                socket.onmessage = function (msg) {
                    if (msg.data == 'reload') window.location.reload();
                    else if (msg.data == 'refreshcss') refreshCSS();
                };
                if (sessionStorage && !sessionStorage.getItem('IsThisFirstTime_Log_From_LiveServer')) {
                    console.log('Live reload enabled.');
                    sessionStorage.setItem('IsThisFirstTime_Log_From_LiveServer', true);
                }
            })();
        }
        else {
            console.error('Upgrade your browser. This Browser is NOT supported WebSocket for Live-Reloading.');
        }
        // ]]>
    
        function toggleAppSwitcher(){
            var appSwitcher = document.getElementById("appSwitcherPopUp");
            appSwitcher.classList.toggle("appSwitcherOpened")
        }
        function openMenu() {
            var menu = document.getElementById("menu");
            menu.classList.add("open"); // Toggle the 'open' class on the menu
        }
    
        function closeMenu() {
            var menu = document.getElementById("menu");
            menu.classList.remove("open"); // Toggle the 'open' class on the menu
        }
        document.addEventListener('click', function(event) {
      var appSwitcherContainer = document.querySelector('.appSwitcherContainer');
      var appSwitcherPopUp = document.getElementById('appSwitcherPopUp');
      var menu = document.getElementById('menu');
      var menuButton = document.getElementById('menuButton');
    
      if (!appSwitcherContainer.contains(event.target) && appSwitcherPopUp.classList.contains('appSwitcherOpened')) {
        appSwitcherPopUp.classList.remove('appSwitcherOpened');
      }
    
      if (!menu.contains(event.target) && event.target !== menuButton && menu.classList.contains('open')) {
        menu.classList.remove('open');
      }
    });
    </script>
    <script>
        document.addEventListener("DOMContentLoaded", function() {
  function adjustHeight() {
    var menu = document.getElementById("menu");
    var menuHeight = menu.offsetHeight;
    var additionalHeight = window.innerWidth >= 1100 ? 230 : 0;
  
    document.documentElement.style.height = menuHeight + additionalHeight + "px";
    document.body.style.height = menuHeight + additionalHeight + "px";
  }

  adjustHeight();

  window.addEventListener("scroll", adjustHeight);
  window.addEventListener("resize", adjustHeight);
});
    </script>
    </body></html>