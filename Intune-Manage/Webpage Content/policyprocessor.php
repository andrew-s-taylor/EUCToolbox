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