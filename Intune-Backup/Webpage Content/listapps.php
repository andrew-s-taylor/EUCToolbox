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
// output message (errors, etc)
$msg = '';


?>
<?php
$sitename = "Intune Backup from EUC Toolbox";
$pagetitle = "Intune Backup";
include "header1.php";
?>

<h1>Add Application</h1>
<div class="step-container">
    <form action="processapp1.php" method="post">
        <table class="styled-table"><tr><td>
<?php

      

$file_name= "wingetapps.csv";


//Import CSV into an array
$csv = array_map('str_getcsv', file($file_name));

//Remove the first two rows
array_shift($csv);
array_shift($csv);

//Sort by name row[0]
usort($csv, function($a, $b) {
    return $a[0] <=> $b[0];
});

//Loop through the array into an html select dropdown displaying the appname and appid
echo "<select name='appid' id='appid'>";
foreach ($csv as $row) {
//Combine the appname and appid into a single value
    $app = $row[0] . "^" . $row[1];

    echo "<option value='" . $app . "'>" . $row[0] . "</option>";
}
echo "</select>";

?>
</td><td>
<input type="submit" name="submit" value="Select Tenant" class="profile-btn"/>
</td></tr></table>
</form>

               <!-- Script -->
               <script>
        $(document).ready(function(){
            
            // Initialize select2
            $("#appid").select2();

            // Read selected option
            $('#but_read').click(function(){
                var username = $('#selUser option:selected').text();
                var userid = $('#selUser').val();
           
                $('#result').html("id : " + userid + ", name : " + username);
            });
        });
        </script>
			</div>
            
	
            <?php
include "footer.php";
?>