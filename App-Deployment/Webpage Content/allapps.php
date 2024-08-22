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
<style>
.step-containerapps {
    overflow-x: auto;
    white-space: nowrap;
}
</style>
<?php
include('config.php');
$sitename = "App Deploy from EUC Toolbox";
$pagetitle = "App Deploy";
include "header.php";
?>

    <script>
      $(window).bind("load", function () {
        $('#work-in-progress').fadeOut(100);
    });
</script>
<?php
//Check for any POST messages and if found, display them
if (isset($_GET['message'])) {
    $message = $_GET['message'];
    echo "<div class='alert alert-success' role='alert'>$message</div>";
}
?>   
   <h1>All Available Apps</h1>

   <input type="text" id="myInput" onkeyup="myFunction()" placeholder="Search for appid..">
<table id="myTable" style="border-collapse: collapse;">
 <tr>
      <th style="border: 1px solid black;">App ID</th>
      <th style="border: 1px solid black;">App Version</th>
      <th style="border: 1px solid black;">App Description</th>
      <th style="border: 1px solid black;">App Scope</th>
      <th style="border: 1px solid black;">App Display Name</th>
      <th style="border: 1px solid black;">App Publisher</th>
      <th style="border: 1px solid black;">App Silent Command</th>
      <th style="border: 1px solid black;">App URL</th>
      <th style="border: 1px solid black;">App Architecture</th>
      <th style="border: 1px solid black;">App Info</th>
      <th style="border: 1px solid black;">App Developer</th>
      <th style="border: 1px solid black;">App Owner</th>
 </tr>
 <?php
 // Get all the apps from the database
//Use the api to grab apps
$api_url = 'https://appdeploy.euctoolbox.com/api?distinct';

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

// Decode the JSON output
$apps = json_decode($result, true);
//Sort alphabetically by appdisplayname
usort($apps, function($a, $b) {
    return $a['appdisplayname'] <=> $b['appdisplayname'];
});

//Remove duplicates on appdisplayname, ignore other fields


foreach ($apps as $row){
      echo "<tr>";
      echo "<td style='border: 1px solid black;'>" . $row['appid'] . "</td>";
      echo "<td style='border: 1px solid black;'>" . $row['appversion'] . "</td>";
      echo "<td style='border: 1px solid black;'>" . $row['appdescription'] . "</td>";
      echo "<td style='border: 1px solid black;'>" . $row['appscope'] . "</td>";
      echo "<td style='border: 1px solid black;'>" . $row['appdisplayname'] . "</td>";
      echo "<td style='border: 1px solid black;'>" . $row['apppublisher'] . "</td>";
      echo "<td style='border: 1px solid black;'>" . $row['appsilent'] . "</td>";
      echo "<td style='border: 1px solid black;'>" . $row['apppackage'] . "</td>";
      echo "<td style='border: 1px solid black;'>" . $row['apparchitecture'] . "</td>";
      echo "<td style='border: 1px solid black;'>" . $row['appinfourl'] . "</td>";
      echo "<td style='border: 1px solid black;'>" . $row['appdeveloper'] . "</td>";
      echo "<td style='border: 1px solid black;'>" . $row['appowner'] . "</td>";
      echo "</tr>";
 }
 ?>
</table>
<script>
function myFunction() {
  // Declare variables
  var input, filter, table, tr, td, i, txtValue;
  input = document.getElementById("myInput");
  filter = input.value.toUpperCase();
  table = document.getElementById("myTable");
  tr = table.getElementsByTagName("tr");

  // Loop through all table rows, and hide those who don't match the search query
  for (i = 0; i < tr.length; i++) {
    td = tr[i].getElementsByTagName("td")[0];
    if (td) {
      txtValue = td.textContent || td.innerText;
      if (txtValue.toUpperCase().indexOf(filter) > -1) {
        tr[i].style.display = "";
      } else {
        tr[i].style.display = "none";
      }
    }
  }
}
</script>

<?php
include "footer.php";
?>