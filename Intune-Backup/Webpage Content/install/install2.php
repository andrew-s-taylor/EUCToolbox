<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>

<head>
  <?php
  // Connect to database
  include("../config.php");
  ?>
  <link rel="stylesheet" href="install.css" type="text/css">
</head>

<body>
  <div id="container">
    <div id="installbox">

      <div id="installtitle">
        <h5>Success</h5>
      </div>
      <div id="installleft">
        &nbsp;
        <?php
        include_once '../config.php';
        // Connect to the MySQL database using MySQLi
        $con = mysqli_connect(db_host, db_user, db_pass, db_name);
        // If there is an error with the MySQL connection, stop the script and output the error
        if (mysqli_connect_errno()) {
          exit('Failed to connect to MySQL: ' . mysqli_connect_error());
        }
        // Update the charset
        mysqli_set_charset($con, db_charset);


        $rawpassword = $_POST['password'];
        $password = password_hash($_POST['password'], PASSWORD_DEFAULT);
        $registered = date('Y-m-d\TH:i:s');
        $last_seen = date('Y-m-d\TH:i:s');
        $email = ($_POST['email']);

        $sql = "CREATE TABLE accounts (
  id int(11) NOT NULL,
  username varchar(50) NOT NULL,
  password varchar(255) NOT NULL,
  email varchar(100) NOT NULL,
  activation_code varchar(50) NOT NULL DEFAULT '',
  rememberme varchar(255) NOT NULL DEFAULT '',
  role enum('Member','Admin') NOT NULL DEFAULT 'Member',
  registered datetime NOT NULL,
  last_seen datetime NOT NULL,
  reset varchar(50) NOT NULL DEFAULT '',
  tfa_code varchar(255) NOT NULL DEFAULT '',
  ip varchar(255) NOT NULL DEFAULT '',
  repoowner varchar(255) DEFAULT NULL,
  reponame varchar(255) DEFAULT NULL,
  gittoken varchar(255) DEFAULT NULL,
  gitproject varchar(255) DEFAULT NULL,
  aadclient varchar(255) DEFAULT NULL,
  aadsecret varchar(255) DEFAULT NULL,
  gittype varchar(255) DEFAULT NULL,
  golden varchar(255) DEFAULT NULL,
  outdated int(11) NOT NULL DEFAULT 7
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_general_ci;";

        if ($con->query($sql) === TRUE) {
          echo "Table Accounts created successfully<br>";
        } else {
          echo "<br>Error creating table: " . $con->error;
        }


        $sql2 = "INSERT INTO accounts (id, username, password, email, activation_code, rememberme, role, registered, last_seen, reset, tfa_code, ip, repoowner, reponame, gittoken, gitproject, aadclient, aadsecret, gittype, golden, outdated) VALUES
  (1, 'admin', '$password', '$email', 'activated', '', 'Admin', '$registered', '$last_seen', '', '', '', '', '', '', '', '', '', '', '', 7);";


        if ($con->query($sql2) === TRUE) {
          echo "New record created successfully<br>";
        } else {
          echo "<br>Error: " . $sql2 . "<br>" . $con->error;
        }




        $sql3 = "CREATE TABLE `login_attempts` (
  `id` int(11) NOT NULL,
  `ip_address` varchar(255) NOT NULL,
  `attempts_left` tinyint(1) NOT NULL DEFAULT 5,
  `date` datetime NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_general_ci;";

        if ($con->query($sql3) === TRUE) {
          echo "Table login_attempts created successfully<br>";
        } else {
          echo "<br>Error creating table: " . $con->error;
        }


        $sql4 = "CREATE TABLE `tenants` (
    `ID` int(11) NOT NULL,
    `tenantid` varchar(255) NOT NULL,
    `ownerid` varchar(255) NOT NULL,
    `tenantname` varchar(255) NOT NULL
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_general_ci;";

        if ($con->query($sql4) === TRUE) {
          echo "Table tenants created successfully<br>";
        } else {
          echo "<br>Error creating table: " . $con->error;
        }


        $sql5 = "ALTER TABLE `accounts`
    ADD PRIMARY KEY (`id`);";

        if ($con->query($sql5) === TRUE) {
          echo "Table accounts altered successfully<br>";
        } else {
          echo "<br>Error altering table: " . $con->error;
        }


        $sql6 = "ALTER TABLE `login_attempts`
      ADD PRIMARY KEY (`id`),
      ADD UNIQUE KEY `ip_address` (`ip_address`);";

        if ($con->query($sql6) === TRUE) {
          echo "Table login_attempts altered successfully<br>";
        } else {
          echo "<br>Error altering table: " . $con->error;
        }

        $sql7 = "ALTER TABLE `tenants`
        ADD PRIMARY KEY (`ID`);";

        if ($con->query($sql7) === TRUE) {
          echo "Table tenants altered successfully<br>";
        } else {
          echo "<br>Error altering table: " . $con->error;
        }


        $sql8 = "ALTER TABLE `accounts`
          MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;";

        if ($con->query($sql8) === TRUE) {
          echo "Table accounts altered successfully<br>";
        } else {
          echo "<br>Error altering table: " . $con->error;
        }


        $sql9 = "ALTER TABLE `login_attempts`
            MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;";

        if ($con->query($sql9) === TRUE) {
          echo "Table login_attempts altered successfully<br>";
        } else {
          echo "<br>Error altering table: " . $con->error;
        }



        $sql10 = "ALTER TABLE `tenants`
              MODIFY `ID` int(11) NOT NULL AUTO_INCREMENT;";

        if ($con->query($sql10) === TRUE) {
          echo "Table tenants altered successfully<br>";
        } else {
          echo "<br>Error altering table: " . $con->error;
        }

        $sql11 = "CREATE TABLE `driftack` (
          `ID` int(11) NOT NULL,
          `tenantid` varchar(255) NOT NULL,
          `ownerid` varchar(255) NOT NULL,
          `policyname` varchar(255) NOT NULL
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_general_ci;";
      
              if ($con->query($sql11) === TRUE) {
                echo "Table driftack created successfully<br>";
              } else {
                echo "<br>Error creating table: " . $con->error;
              }


              $sql13 = "ALTER TABLE `driftack`
              ADD PRIMARY KEY (`ID`);";

if ($con->query($sql13) === TRUE) {
  echo "Table driftack altered successfully<br>";
} else {
  echo "<br>Error altering table: " . $con->error;
}
      
        $sql12 = "ALTER TABLE `driftack`
              MODIFY `ID` int(11) NOT NULL AUTO_INCREMENT;";

        if ($con->query($sql12) === TRUE) {
          echo "Table driftack altered successfully<br>";
        } else {
          echo "<br>Error altering table: " . $con->error;
        }
        $con->close();


        ?>
<br><br>
        Congratulations, IntuneBackup has successfully installed<br> <br>
        Please remove the Install directory for security reasons<br><br>
        Username: admin<br>
        Password: <?php echo $rawpassword; ?><br> <br>
        Please Click below to log in to your new website<br><br>
        <a href="../index.php"><input type="submit" value="        Login        "></a> <br><br>


      </div>
    </div>
  </div>
</body>