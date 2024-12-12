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

<div id="installtitle">
<h5>Website Settings</h5>
</div>
<div id="installleft">
<form method="post" action="install2.php" enctype="multipart/form-data">
<table>
  <tr>
    <td>Password:</td>
    <td><input name="password"></td>
  </tr>
  <tr>
    <td>Email Address</td>
    <td><input name="email"></td>
  </tr>
  </table>

</div>

<input type="submit" value="        Install        "></form>
<FORM METHOD="LINK" ACTION="database.php">
<input type="submit" value="        Back        "></FORM>
</div>
</div>
</div>
</div>
 </body>