<?php
include ("../config.php");

// Do not edit below this line

// Make connection
$conn = mysqli_connect(db_host, db_user, db_pass, db_name);
if (mysqli_connect_errno()) {
    header("Location: database.php?error=conn");

}
else {
header("Location: install.php");
}


?>