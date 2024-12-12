<?php
include('config.php');
//Update these
//Runbook URL
$runbookurl = webhook;
//Entra ID App ID
$clientid = appID;
//Entra ID App Secret
$clientsecret = appSecret;


function clean($string) {
    $string = str_replace(' ', '-', $string); // Replaces all spaces with hyphens.
 
    return preg_replace('/[^A-Za-z0-9\-]/', '', $string); // Removes special chars.
 }

$companyname = $_POST['name'];
$companynameupload = clean($companyname);
$email = $_POST['email'];
$homepage = $_POST['homepage'];
$customerid = $_POST['customerid'];
$prefix = $_POST['prefix'];
$prefix = strtoupper($prefix);
$prefix = str_replace(' ', '', $prefix);
$prefix = str_replace('-', '', $prefix);
$prefix = str_replace('_', '', $prefix);
$prefix = str_replace('.', '', $prefix);
$prefix = str_replace(',', '', $prefix);
$prefix = str_replace(';', '', $prefix);
$prefix = str_replace(':', '', $prefix);
$prefix = str_replace('!', '', $prefix);
$prefix = str_replace('?', '', $prefix);
$prefix = $prefix . "-";
if (empty($prefix)) {
    $prefix = "ID-";
}
$noupload = "yes";
if (isset($_POST['CAD'])) {
    $conditionals = "Yes";
} else {
    $conditionals = 'No';
}
if (isset($_POST['fresh'])) {
  $fresh = "Yes";
} else {
  $fresh = 'No';
}
$tenant = $_POST['tenant'];
$companysize = $_POST['company-size'];

if(isset($_POST['tenant']))
{ 

$target_file2 = ($_FILES["fileToUpload"]["name"]);
$imageFileType = strtolower(pathinfo($target_file2,PATHINFO_EXTENSION));
$imgname = uniqid(rand(), true) . "." .  $imageFileType;
$target_file = $imgname;

$uploadOk = 1;


if(isset($_POST['name']))
{ 
    $check = getimagesize($_FILES["fileToUpload"]["tmp_name"]);
    if($check !== false) {
      echo "";
      $uploadOk = 1;
    } else {
      echo "File is not an image.";
      $uploadOk = 0;
    }
  }
  
  // Check if file already exists
  if (file_exists($target_file)) {
    echo "Sorry, file already exists.";
    $uploadOk = 0;
  }
  
  // Check file size
  if ($_FILES["fileToUpload"]["size"] > 50000000) {
    echo "Sorry, your file is too large.";
    $uploadOk = 0;
  }
  
  // Allow certain file formats
  if($imageFileType != "jpg" && $imageFileType != "png" && $imageFileType != "jpeg"
  && $imageFileType != "gif" ) {
    echo "Sorry, only JPG, JPEG, PNG & GIF files are allowed.";
    $uploadOk = 0;
  }
  
  // Check if $uploadOk is set to 0 by an error
  if ($uploadOk == 0) {
    echo "Sorry, your file was not uploaded.";
  // if everything is ok, try to upload file
  } else {

//Convert the Image to base64
$base64 = base64_encode(file_get_contents($_FILES["fileToUpload"]["tmp_name"]));



    //Add to array
$data = array(
    array("tenant" => "$tenant"),
    array("clientid" => "$clientid"),
    array("clientsecret" => "$clientsecret"),
    array("homepage" => "$homepage"),
    array("imagebase64" => "$base64"),
    array("companyname" => "$companyname"),
    array("cad" => "$conditionals"),
    array("emailsend" => "$email"),
    array("whitelabel" => "$prefix"),
    array("noupload" => "$noupload"),
    array("fresh" => "$fresh")
);
}
$header = array("message" => "Intune Deployed to $tenant");
//Encode it
$body = base64_encode(json_encode($data));
//Setup CURL
$ch = curl_init();
$url = "$runbookurl";
curl_setopt($ch, CURLOPT_URL, $runbookurl);
curl_setopt($ch, CURLOPT_CUSTOMREQUEST, "POST");
curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
curl_setopt($ch, CURLOPT_HTTPHEADER, $header);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

$result = curl_exec($ch);
curl_close($ch);



// Redirect to the thank you page





header("Location: https://euctoolbox.com/consultancy.php");
die();

}
else {
    echo "Please complete the form";
}




?>