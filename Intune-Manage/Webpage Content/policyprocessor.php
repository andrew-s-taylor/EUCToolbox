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

$type = $_POST['type'];
$tenantid = $_POST['tenantid'];
$policyname = $_POST['policyname'];
$policyuri = $_POST['policyuri'];
$ownerid = $_POST['ownerid'];
$policyjson = $_POST['policyjson'];
if ($type == "delete")
{
   
?>
<form action="createpolicy.php" method="POST">
<?php
}
else {
    ?>
<form action="editpolicy.php" method="POST" name="fr">
<?php
}
?>
<input type = "hidden" name="type" value="<?php echo $type; ?>">
<input type = "hidden" name="tenantid" value="<?php echo $tenantid; ?>">
<input type = "hidden" name="policyname" value="<?php echo $policyname; ?>">
<input type = "hidden" name="policyuri" value="<?php echo $policyuri; ?>">
<input type = "hidden" name="ownerid" value="<?php echo $ownerid; ?>">
<input type = "hidden" name="policyjson" value="<?php echo $policyjson; ?>">
</form>
<script type='text/javascript'>
document.fr.submit();
</script>