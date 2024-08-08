<?php
include 'main.php';
// Check logged-in
check_loggedin($con);
// output message (errors, etc)
$msg = '';


?>
<?php
$sitename = "Intune Backup from EUC Toolbox";
$pagetitle = "Intune Backup";
include "header1.php";
?>


			<h2>Request License Review</h2>
			
			<div class="block">
<table class="styled-table">
<form action="review2.php" method="post">
<?php
    if (!empty($_POST['desttenant'])) {
        $desttenant = $_POST['desttenant'];
    echo "<input type=\"hidden\" name=\"desttenant\" value=\"$desttenant\">";
    }
    ?>
    <tr>
        <td>
        <input id="email" class="input" type="text" placeholder=" " name="email" />
              <div class="cut"></div>
              <label for="email" class="placeholder">Please enter sending email in source tenant</label>
        </td>
    </tr>
    <tr>
    <td><input class="profile-btn" type="submit" value="Next"></td></tr>
    </form>
    </table>
				

			</div>
            
	
			<?php
include "footer.php";
?>