<?php
###########################################
### AVD Pricing Calculator
### Written by Andrew Taylor
### https://andrewstaylor.com
###########################################

// Recursive function to search by key
function search_recursive_by_key($arr, $searchkey){
    $uniqueValues = array();
    foreach ($arr as $key => $val) {
        if (is_array($val)) {
            search_recursive_by_key($val, $searchkey);
        } else {
            if ($searchkey == $key) {
                $val2 = str_replace(' ', '%20', $val);
                if (!in_array($val2, $uniqueValues)) {
                    $uniqueValues[] = $val2;
                    echo("<option value=" . $val2 . ">$val</option>");
                }
            }
        }
    }
    return;
}
     function search_recursive_by_keyfinal($arr, $searchkey){
        foreach ($arr as $key => $val) {
            if (is_array($val)) {
                  search_recursive_by_keyfinal($val, $searchkey);
         
               } else {
                  if ($searchkey == $key) {
                     echo("<td>" . $val . "</td>");
                  }
               }
            }
         return;
         }

     ?>
<?php
$sitename = "AVD Calc from EUC Toolbox";
$pagetitle = "AVD Calculator";
include "header.php";
?>


        <h1>Azure Virtual Desktop Pricing</h1>
        <h2>
            Fill in the form for quick indicative AVD pricing
        </h2>
        <form action="output.php" method="post">
        <table class="styled-table">
                <tr>
                     <td>
                          <label for="numberOfUsers">
                            Number of users
                          </label>
                     </td>
                     <td>
                          <input type="number" id="numberofusers" name="numberofusers" min="1" max="10000" value="1">
                     </td>
                </tr>
                <tr>
                        <td>
                            <label for="machinetype">
                                User Type
                            </label>
                        </td>
                        <td>
                            <select id="usertype" name="usertype">
                                <option value="light">
                                    Light
                                </option>
                                <option value="medium">
                                    Medium
                                </option>
                                <option value="heavy">
                                    Heavy
                                </option>
                                <option value="heavygpu">
                                    Heavy with GPU
                                </option>
                            </select>
                        </td>
                </tr>
                <tr>
                     <td>
                          <label for="peakconcurrency">
                            How many users will be connected at the busiest time (%)
                          </label>
                     </td>
                     <td>
                          <input type="number" id="peakconcurrency" name="peakconcurrency" min="1" max="100" value="1">%
                     </td>
                </tr>
                <tr>
                     <td>
                          <label for="vmredundancy">
                            VM Redundancy
                          </label>
                     </td>
                     <td>
                         <select name ="vmredundancy" id="vmredundancy">
                             <option value="none">None</option>
                             <option value="basic">Basic</option>
                             <option value="high">High</option>
                             <option value="extra">Extra</option>
                         </select>
                     </td>
                </tr>
                <tr>
                     <td>
                          <label for="maxpeakhours">
                            Will the machines need to be left on out of hours (working on 40 hour week)?
                          </label>
                     </td>
                     <td>
                         <input type="checkbox" name="maxpeakhours" id="maxpeakhours">
                     </td>
                </tr>
                <tr>
                     <td>
                          <label for="Type">
                            Reserved or Pay-as-you-go?
                          </label>
                     </td>
                     <td>
                         <select id="type" name="type">
                             <option value="Reservation1">
                                 Reserved 1 Year
                             </option>
                             <option value="Reservation3">
                                 Reserved 3 Year
                             </option>
                             <option value="Consumption">
                                 Pay-as-you-go
                             </option>
                         </select>
                     </td>
                </tr>
                <tr>
                        <td>
                            <label for="Currency">
                                Currency
                            </label>
                        </td>
                        <td>
                        <select id="currency" placeholder="Select Currency" name="currency">
    <option value="">Select Currency</option>
    <option>select currency</option>
    <option value="USD">US dollar</option>
<option value="AUD">Australian dollar</option>
<option value="BRL">Brazilian real</option>
<option value="CAD">Canadian dollar</option>
<option value="CHF">Swiss franc</option>
<option value="CNY">Chinese yuan</option>
<option value="DKK">Danish krone</option>
<option value="EUR">Euro</option>
<option value="GBP">British pound</option>
<option value="INR">Indian rupee</option>
<option value="JPY">Japanese yen</option>
<option value="KRW">Korean won</option>
<option value="NOK">Norwegian krone</option>
<option value="NZD">New Zealand dollar</option>
<option value="RUB">Russian ruble</option>
<option value="SEK">Swedish krona</option>
<option value="TWD">Taiwan dollar</option>
                        </select>                        </td>
                </tr>
                <tr>
                        <td>
                            <label for="region">
                                Region
                            </label>
                        </td>
                        <td>
                            <?php
                                $allregionsurl = "https://prices.azure.com/api/retail/prices?currencyCode=%27GBP%27&\$filter=skuName%20eq%20%27D4s%20v3%27%20and%20priceType%20eq%20%27Reservation%27";
                                $jsonregion = file_get_contents($allregionsurl);
                                $regionlist = json_decode($jsonregion, true);
                                ?>
                                        <select name ="region" id="region">
<?php search_recursive_by_key($regionlist, 'armRegionName'); ?>
        </select>
                        </td>
                </tr>
                <tr>
                    <td>
                        <label for="disk">
                            Disk Type
                        </label>
                    </td>
                    <td>
                        <select name="disk" id="disk">
                            <option value="">Select Disk</option>
                            <option value="P10%20LRS">128Gb</option>
                            <option value="P15%20LRS">256Gb</option>
                            <option value="P20%20LRS">521Gb</option>
                            <option value="P30%20LRS">1Tb</option>
                            <option value="P40%20LRS">2Tb</option>
                            <option value="P50%20LRS">4Tb</option>
                            <option value="P60%20LRS">8Tb</option>
                            <option value="P70%20LRS">16Tb</option>
                            <option value="P80%20LRS">32Tb</option>
                        </select>
                    </td>
                </tr>
                <tr>
                    <td colspan="2" class="tableButton">
                        <center><input class="profile-btn" type="submit" value="Submit"></center>
                    </td>
                </tr>
           </table>
       </form>
       <h1>Privacy</h1>
    <div class="step-container">
   <p>No data is stored when using this service, it all runs through the official Azure API</p>
</div> 

               <!-- Script -->
               <script>
        $(document).ready(function(){
            
            // Initialize select2
            $("#currency").select2();
            $("#type").select2();
            $("#disk").select2();

                        // Initialize select2
                        $("#usertype").select2();

                                    // Initialize select2
            $("#region").select2();

            // Read selected option
            $('#but_read').click(function(){
                var username = $('#selUser option:selected').text();
                var userid = $('#selUser').val();
           
                $('#result').html("id : " + userid + ", name : " + username);
            });
        });
        </script>
 <?php
include "footer.php";
?>