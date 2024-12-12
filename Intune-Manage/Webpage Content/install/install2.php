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
  `id` int(11) NOT NULL,
  `password` varchar(255) NOT NULL,
  `email` varchar(100) NOT NULL,
  `activation_code` varchar(50) NOT NULL,
  `rememberme` varchar(255) NOT NULL,
  `role` enum('Member','Admin','SuperAdmin','SubAdmin') NOT NULL DEFAULT 'Member',
  `registered` datetime NOT NULL,
  `last_seen` datetime NOT NULL,
  `reset` varchar(50) NOT NULL,
  `tfa_code` varchar(255) NOT NULL,
  `ip` varchar(255) NOT NULL,
  `reponame` varchar(255) DEFAULT NULL,
  `golden` varchar(255) DEFAULT NULL,
  `outdated` int(11) NOT NULL DEFAULT 7,
  `primaryid` varchar(255) NOT NULL,
  `regtype` enum('trial','paid','expired','') NOT NULL,
  `plevel` enum('standard','premium') NOT NULL,
  `primaryadmin` varchar(255) NOT NULL,
  `canbackup` tinyint(4) NOT NULL,
  `canrestore` tinyint(4) NOT NULL,
  `canviewlogs` tinyint(4) NOT NULL,
  `canmanagebackups` tinyint(4) NOT NULL,
  `cancheckdrift` tinyint(4) NOT NULL,
  `canmanagedrift` tinyint(4) NOT NULL,
  `canmanagetenants` tinyint(4) NOT NULL,
  `cangolddeploy` tinyint(4) NOT NULL,
  `canviewreports` tinyint(4) NOT NULL,
  `candeployapps` tinyint(4) NOT NULL,
  `candeploytemplates` tinyint(4) NOT NULL,
  `canmigrate` tinyint(11) NOT NULL,
  `gocardless` varchar(255) NOT NULL,
  `apikey` varchar(255) DEFAULT NULL,
  `alertsemail` varchar(255) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_general_ci;";

        if ($con->query($sql) === TRUE) {
          echo "Table Accounts created successfully<br>";
        } else {
          echo "<br>Error creating table: " . $con->error;
        }


        $sql2 = "INSERT INTO accounts (id, username, password, email, activation_code, rememberme, role, registered, last_seen, reset, tfa_code, ip, reponame, golden, outdated, primaryid, regtype, plevel, primaryadmin, canbackup, canrestore, canviewlogs, canmanagebackups, cancheckdrift, canmanagedrift, canmanagetenants, cangolddeploy, canviewreports, candeployapps, candeploytemplates, canmigrate, gocardless, apikey, alertsemail) VALUES (1, 'admin', '$password', '$email', 'activated', '', 'Admin', '$registered', '$last_seen', '', '', '', '', '', 7, '', 'trial', 'standard', '', 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, '', '', '')";


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
  `tenantname` varchar(255) NOT NULL,
  `customerid` varchar(255) NOT NULL,
  `tenantdrift` varchar(255) DEFAULT NULL,
  `golddrift` varchar(255) DEFAULT NULL,
  `updatedapps` varchar(255) DEFAULT NULL,
  `adminevents` varchar(255) DEFAULT NULL,
  `unusedlicenses` varchar(255) DEFAULT NULL,
  `licensesonoldusers` varchar(255) DEFAULT NULL,
  `securescore` varchar(255) DEFAULT NULL,
  `noncompliantdevices` varchar(255) DEFAULT NULL,
  `failedsignins` varchar(255) DEFAULT NULL,
  `failedappinstalls` varchar(255) DEFAULT NULL,
  `pushexpiry` varchar(255) DEFAULT NULL,
  `vppexpiry` varchar(255) DEFAULT NULL,
  `depexpiry` varchar(255) DEFAULT NULL,
  `avissues` varchar(255) DEFAULT NULL,
  `firewalloff` varchar(255) DEFAULT NULL,
  `securitytasks` varchar(255) DEFAULT NULL,
  `outdatedfeatureupdatepolicy` varchar(255) DEFAULT NULL,
  `expiringsecrets` varchar(255) DEFAULT NULL,
  `staledevices` varchar(255) DEFAULT NULL,
  `windowscis` varchar(255) DEFAULT NULL,
  `windowsncsc` varchar(255) DEFAULT NULL,
  `android` varchar(255) DEFAULT NULL,
  `ios` varchar(255) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_general_ci;";

        if ($con->query($sql4) === TRUE) {
          echo "Table tenants created successfully<br>";
        } else {
          echo "<br>Error creating table: " . $con->error;
        }

        $sql4a = "CREATE TABLE `auditlog` (
  `ID` int(11) NOT NULL,
  `UserID` int(11) NOT NULL,
  `Task` varchar(255) NOT NULL,
  `Timestamp` datetime NOT NULL,
  `IPAddress` varchar(255) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;";

if ($con->query($sql4a) === TRUE) {
  echo "Table auditlog created successfully<br>";
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

        $sql10aa = "ALTER TABLE `auditlog`
        MODIFY `ID` int(11) NOT NULL AUTO_INCREMENT;";

  if ($con->query($sql10aa) === TRUE) {
    echo "Table Audit Log altered successfully<br>";
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


        $sqlapi1 = "CREATE TABLE `api_integrations` (
          `ID` int(11) NOT NULL,
          `accountID` int(11) NOT NULL,
          `apiName` varchar(255) NULL,
          `apisecret` varchar(255) NULL,
          `clientID` varchar(255) NULL
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;";
        
        if ($con->query($sqlapi1) === TRUE) {
          echo "Table api_integrations created successfully<br>";
        } else {
          echo "<br>Error creating table: " . $con->error;
        }
        
        
                $sqlapi2 = "ALTER TABLE `api_integrations`
            ADD PRIMARY KEY (`ID`);";
        
                if ($con->query($sqlapi2) === TRUE) {
                  echo "Table api_integrations altered successfully<br>";
                } else {
                  echo "<br>Error altering table: " . $con->error;
                }

                $sqlapi3 = "CREATE TABLE `api_availability` (
                  `ID` int(11) NOT NULL,
                  `apiName` varchar(255) NOT NULL,
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;";
                
                if ($con->query($sqlapi3) === TRUE) {
                  echo "Table api_availability created successfully<br>";
                } else {
                  echo "<br>Error creating table: " . $con->error;
                }
                
                
                        $sqlapi4 = "ALTER TABLE `api_availability`
                    ADD PRIMARY KEY (`ID`);";
                
                        if ($con->query($sqlapi4) === TRUE) {
                          echo "Table api_availability altered successfully<br>";
                        } else {
                          echo "<br>Error altering table: " . $con->error;
                        }


        $con->close();


        ?>
<br><br>
        Congratulations, Intune Manager from EUCToolbox has successfully installed<br> <br>
        Please remove the Install directory for security reasons<br><br>
        Username: admin<br>
        Password: <?php echo $rawpassword; ?><br> <br>
        Please Click below to log in to your new website<br><br>
        <a href="../index.php"><input type="submit" value="        Login        "></a> <br><br>


      </div>
    </div>
  </div>
</body>