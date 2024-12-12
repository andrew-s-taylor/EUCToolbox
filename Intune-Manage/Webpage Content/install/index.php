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
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN"
    "http://www.w3.org/TR/html4/loose.dtd">
<html>

<head>
<link rel="stylesheet" href="install.css" type="text/css">
</head>
<body>
<div id="container">
<div class="content2">
<div id="installbox">

<div id="installleft">
<table id="main">
<tr class="toprow">
<td colspan="3"><font color="#FFFFFF">Welcome to the EUCToolbox Intune Manage Installer.
<br>Before the installation begins, your webspace will be tested for compatibility:</font></td>
</tr>
<?php include ("syschecks.php"); ?>
  <tr>
    <td><h6>Checking for PHP Version 8.0+...</h6></td>
    <td><?php if ($PHP == "ON") {echo "<img src=\"tick.jpg\" width=\"50\" height=\"25\" alt=\"Tick\">"; } else { echo "<img src=\"cross.jpg\" width=\"50\" height=\"25\" alt=\"Cross\">"; } ?></td>
  </tr>
  <tr>
    <td><h6>Checking for MySQL...</h6></td>
    <td><?php if ($MySQL == "ON") {echo "<img src=\"tick.jpg\" width=\"50\" height=\"25\" alt=\"Tick\">"; } else { echo "<img src=\"cross.jpg\" width=\"50\" height=\"25\" alt=\"Cross\">"; } ?></td>
  </tr>
  <tr>
    <td><h6>Checking for MD5...</h6></td>
     <td><?php if ($MD5 == "ON") {echo "<img src=\"tick.jpg\" width=\"50\" height=\"25\" alt=\"Tick\">"; } else { echo "<img src=\"cross.jpg\" width=\"50\" height=\"25\" alt=\"Cross\">"; }?></td>
  </tr>
  <tr>
    <td><h6>Checking for Session...</h6></td>
     <td><?php if ($Session == "ON") {echo "<img src=\"tick.jpg\" width=\"50\" height=\"25\" alt=\"Tick\">"; } else { echo "<img src=\"cross.jpg\" width=\"50\" height=\"25\" alt=\"Cross\">"; } ?></td>
  </tr>
   <tr>
    <td><h6>Checking for writable config file...</h6></td>
     <td><?php if ($writable == "ON") {echo "<img src=\"tick.jpg\" width=\"50\" height=\"25\" alt=\"Tick\">"; } else { echo "<img src=\"cross.jpg\" width=\"50\" height=\"25\" alt=\"Cross\">"; } ?></td>
  </tr>

  <tr>
    <td><h6>Checking Server Type...</h6></td>
<td><h6><?php echo $server; ?></h6></td>
  </tr>
</table>
</div>
<div id="installright">

    <?php
    if ($PHP == "ON" and $MySQL == "ON" and $writable == "ON" and $MD5 == "ON" and $Session == "ON") {
    echo
    <<<EOD
    <center>
    <FORM METHOD="LINK" ACTION="database.php">
    <input type="submit" value="        Next        "> </center></FORM>
EOD;
}
else {
echo "<b><font color=\"#FF0000\">Your server has failed the initial test, please ensure that:<br><ul>";
if ($PHP == "OFF") {
echo "<li>PHP is enabled on your hosting plan";
}
if ($MySQL == "OFF") {
echo "<li>MySQL is enabled on your hosting plan";
}

if ($writeable == "OFF") {
echo "<li>The file &quot;../config.php&quot; is writable (CHMOD 777 on Linux)";
}
if ($writeable2 == "OFF") {
echo "<li>The file &quot;/robots.txt&quot; is writable (CHMOD 777 on Linux)";
}
if ($Session == "OFF") {
echo "<li>Sessions are enabled (for login)";
}
if ($MD5 == "OFF") {
echo "<li>MD5 is enabled (for passwords)";
}
echo "</font></b>";
}
?>
</div>
</div>

 </body>