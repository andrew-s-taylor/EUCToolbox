<?php

$sitename = "AVD Calc from EUC Toolbox";
$pagetitle = "AVD Calculator";
include "header.php";
?>

        <h1>Azure Virtual Desktop Pricing Results</h1>
        <div class="step-container">
<?php

###########################################
### AVD Pricing Calculator
### Written by Andrew Taylor
### https://andrewstaylor.com
###########################################


################ SET FUNCTIONS #####################
function search_recursive_by_key($arr, $searchkey){
    foreach ($arr as $key => $val) {
        if (is_array($val)) {
              search_recursive_by_key($val, $searchkey);
     
           } else {
              if ($searchkey == $key) {
                $val2 = str_replace(' ', '%20', $val);
                 echo("<option value=" . $val2 . ">$val</option>");
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


################ GET FORM OUTPUT #####################
$currency = $_POST['currency'];
$region = $_POST['region'];
$disktype = $_POST['disk'];
$users = $_POST['numberofusers'];
$usertype = $_POST['usertype'];
$concurrency = $_POST['peakconcurrency'];
$redundancy2 = $_POST['vmredundancy'];
$peakhours2 = $_POST['maxpeakhours'];
$consumption2 = $_POST['type'];


#Check if machines need to be on overnight
if (isset($peakhours2)) {
#Yes, set to maximum hours in a month
$peakhours = 730;
}
else {
#No, set to 40 hours per week
#Worst case 255 working days in a year
#Machines remain on during lunch
#Peak hours 8am - 6pm = 10 hours
$hoursperyear = 255 * 10;
$hourspermonth = $hoursperyear /12;
$peakhours = $hourspermonth;
}

##Replace spaces with html char for URL
$region = str_replace(" ", "%20", $region);

##Sort redundancy
##Sort if PAYG or 1/3 year reserved


##Sort if PAYG or 1/3 year reserved
switch($consumption2){
    case "Reservation1":
        $consumption = "Reservation";
        $length = "1";
        break;
    case "Reservation3":
        $consumption = "Reservation";
        $length = "3";
        break;
    case "Consumption":
        $consumption = "Consumption";
        $length = "0";
        break;
        default:
        $consumption = "Consumption";
        $length = "0";
}


###Set Variables depending on user workload
##Guidelines taken from
# https://docs.microsoft.com/en-us/windows-server/remote/remote-desktop-services/virtual-machine-recs

switch($usertype){
    case "light":
        $sku = "D8as%20v4";
        $vcpu = 8;
        $ram = 16;
        $egress = 0.045;
        $userspercpu = 6;
        $profile = 6;
        break;
    case "medium":
        $sku = "D8as%20v4";
        $vcpu = 8;
        $ram = 16;
        $egress = 0.09;
        $userspercpu = 4;
        $profile = 8;
        break;
    case "heavy":
        $sku = "D16as%20v4";
        $vcpu = 16;
        $ram = 64;
        $egress = 0.225;
        $userspercpu = 2;
        $profile = 12;
        break;
    case "heavygpu":
        $sku = "NV12s%20v3";
        $vcpu = 12;
        $ram = 112;
        $egress = 0.45;
        $userspercpu = 1;
        $profile = 20;
        break;
        default:
        $sku = "D8as%20v4";
        $vcpu = 8;
        $ram = 16;
        $egress = 0.045;
        $userspercpu = 6;
        $profile = 6;
}

############# VM INFO #############
############ HOURLY #############

#### Azure Pricing API URL passing currency, SKU, Region and Reservation Type
$url = "https://prices.azure.com/api/retail/prices?currencyCode='$currency'&\$filter=skuName%20eq%20'$sku'%20and%20armRegionName%20eq%20'$region'%20and%20priceType%20eq%20'$consumption'";
### Get URL contents
$json = file_get_contents($url);
### Extract to JSON
$finallist = json_decode($json);

### Get VM details depending on reservation type
switch ($length) {
    ### PAYG
    case 0:
        foreach( $finallist->Items as $item ) {
            $pricetype = $item->type;
            $vmprice = $item->retailPrice;
            $vmprodname = $item->productName;
            $vmsku = $item->skuName;
            $vmpricepermonth = $vmprice * $peakhours;
            }
        break;

    ### 1 YEAR
    case 1:
        foreach( $finallist->Items as $item ) {
            $pricetype = $item->type;
            $term = $item->reservationTerm;
            if ($term == "1 Year") {
                $vmprice2 = $item->retailPrice;
                $vmprice = $vmprice2 / 12;
                $vmprice = number_format((float)$vmprice, 5, '.', '');
                $vmprodname = $item->productName;
                $vmsku = $item->skuName;
                $vmpricepermonth = $vmprice;
            }            
            }
        break;
    ### 3 YEARS    
    case 3:
        foreach( $finallist->Items as $item ) {
            $pricetype = $item->type;
            $term = $item->reservationTerm;
            if ($term == "3 Years") {
                $vmprice2 = $item->retailPrice;
                $vmprice = $vmprice2 / 36;
                $vmprice = number_format((float)$vmprice, 5, '.', '');
                $vmprodname = $item->productName;
                $vmsku = $item->skuName;
                $vmpricepermonth = $vmprice;
            }            
            }
        break;
    default:
    foreach( $finallist->Items as $item ) {
        $pricetype = $item->type;
        $vmprice = $item->retailPrice;
        $vmprodname = $item->productName;
        $vmsku = $item->skuName;
        $vmpricepermonth = $vmprice * $peakhours;
        }
}




############# DISK INFO #############
############## MONTHLY ##############
#### Azure Pricing API URL passing currency, Region and Disk Type

#Get Disk Type from SKU
$pdisk = substr($disktype,0,3);

$diskurl = "https://prices.azure.com/api/retail/prices?currencyCode='$currency'&\$filter=serviceName%20eq%20%27Storage%27%20and%20armRegionName%20eq%20'$region'%20and%20skuName%20eq%20'$disktype'%20and%20productName%20eq%20%27Premium%20SSD%20Managed%20Disks%27%20and%20meterName%20eq%20%27$pdisk%20Disks%27";
### Get URL contents
$json = file_get_contents($diskurl);
### Export to JSON
$finallist = json_decode($json);

### Grab Disk Details
foreach( $finallist->Items as $item ) {
    $diskprice = $item->retailPrice;
    $currency2 = $item->currencyCode;
    $diskprodname = $item->productName;
    $disksku = $item->skuName;
    }


############## STORAGE ACCOUNT INFO ##############
############## MONTHLY ##############
#### Azure Pricing API URL passing currency and Region (always defaults to Files Premium)
$storageurl = "https://prices.azure.com/api/retail/prices?currencyCode='$currency'&\$filter=serviceName%20eq%20%27Storage%27%20and%20armRegionName%20eq%20'$region'%20and%20skuName%20eq%20%27Premium%20LRS%27%20and%20productName%20eq%20%27Premium%20Files%27%20and%20meterName%20eq%20%27LRS%20Provisioned%27";
### Get URL contents
$json = file_get_contents($storageurl);
### Convert to JSON
$finallist = json_decode($json);

### Get Details
foreach( $finallist->Items as $item ) {
    $storageprice = $item->retailPrice;
    $currency2 = $item->currencyCode;
    $storageprodname = $item->productName;
    $storagesku = $item->skuName;
    }






############# NETWORK INFO #############
############# HOURLY ###########
### Work out totals (needed for pricing)
$egresstotalperuser = $egress * $peakhours;
$totalegressusage = $egresstotalperuser * $users;
#### Azure Pricing API URL passing currency and Region
$networkurl = "https://prices.azure.com/api/retail/prices?currencyCode='$currency'&\$filter=serviceFamily%20eq%20%27Networking%27%20and%20armRegionName%20eq%20'$region'%20and%20productName%20eq%20%27Bandwidth%27%20and%20skuName%20eq%20%27Standard%27%20and%20meterName%20eq%20%27Data%20Transfer%20Out%27";
### Get URL Contents
$json = file_get_contents($networkurl);
### Dump to JSON
$finallist = json_decode($json);
### Create array to find best price
$networkprices = array();
### Network egress pricing depends on minimum units.  We need to work out which applies and ignore free tier
### Grab all tiers which apply and dump into array
### Find lowest value in array
foreach( $finallist->Items as $item ) {    
    $currency2 = $item->currencyCode;
    $networkunits = $item->tierMinimumUnits;
    if ($networkunits == 0) {
        #Ignore free tier
    }
    else {
    if ($networkunits < $totalegressusage) {
        $networkprice2 = $item->retailPrice;
        $networkprices[]+=$networkprice2;
    }
}


    }
    $egresspergb = min($networkprices);

############# CALCULATION #############

######Egress Costs

##Gb per user per hour x number of hours
$egresscostperuserpermonth = $egresstotalperuser * $egresspergb;
#Total Price = cost per user x number of users
$totalegresscost = $egresscostperuserpermonth * $users;
#Total Egress = total per users x number of users
$totalegress = $egresstotalperuser * $users;


##### Virtual Machines

#Number of VMs required = total users / (vcpu * users per CPU)

$userspervm = $vcpu * $userspercpu;

#Maximum number of VMs (number of users divided by users per vm)
$maxvms = $users / $userspervm;

#Maximum concurrent VMs depending on % concurrency set
$maxconcurrent = ($maxvms / 100) * $concurrency;

switch($redundancy2){
    case "none":
        $redundancy = 0;
        break;
    case "basic":
        $redundancy = 2;
        break;
    case "high":
        $redundancy = ceil(($maxconcurrent / 100) * 10);
        break;
    case "extra":
        $redundancy = ceil(($maxconcurrent / 100) * 25);
        break;
        default:
        $redundancy = 2;
}



#Add any redundancy and round (UP) to give a total
$totalvms = ceil($maxconcurrent+$redundancy);

#Number of VMs x their cost
$totalvmcost = $vmpricepermonth * $totalvms;




######Disks
#Cost per disk * VMs
$totaldiskcost = $diskprice * $totalvms;


##### Storage Account
#Price * Gb per user * Users
$totalgb = $profile * $users;
$totalstoragecost = $totalgb * $storageprice;

#Compute price is VM and Disk
$computeprice = $totalvmcost + $totaldiskcost;

#How much RAM each user gets
$ramperuser = $ram / $userspervm;

#THE TOTALS
$finalprice = $totalstoragecost + $totaldiskcost + $totalvmcost + $totalegresscost;
$finalpriceperuser = round($finalprice / $users,2);


#####Tidy Up
$sku2 = str_replace("%20", " ", $sku);

############# OUTPUT #############

echo "<p>Total price for " . $users . " " . $usertype . " users is " . number_format(ceil($finalprice)) . $currency . " per month</p>";
echo "<p>The cost per user is " . $finalpriceperuser . $currency . " per month</p>";
echo "<h2>Details:</h2>";
echo "<p>" . $totalvms . "(" . $sku2 . ")" . " VMs with " . $vcpu . " vCPU and " . $ram . "Gb RAM with " . $diskprodname . "(" . $disksku . ")" . " @ " . number_format(ceil($computeprice)) . $currency . " per month</p>";
echo "<p>Each VM will host " . $userspervm . " users who will each have " . round($ramperuser,2) . "Gb RAM</p>";
echo "<p>" . $totalgb . "Gb storage for user profiles stored in " . $storageprodname . " @ " . number_format($totalstoragecost) . $currency . "</p>";
echo "<p>" . $totalegress . " Gb network traffic (outgoing) @ " . number_format($totalegresscost) . $currency . "</p>";

?>
</div>
  <?php
include "footer.php";
?>