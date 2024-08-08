<?php
include('config.php');
$sitename = "Expiry Alerts from EUC Toolbox";
$pagetitle = "Expiry Alerts";
include "header.php";
?>


<?php


//Check for any POST messages and if found, display them
if (isset($_GET['message'])) {
    $message = $_GET['message'];
    echo "<div class='alert alert-success' role='alert'>$message</div>";
}
?>   
      <h1>Welcome to Expiry Alerts from EUC Toolbox</h1>
      <div class="step-container">
   <p>This free service will send you an email when you have:</p>
    <ul>
         <li>Expiring Apple Certificates</li>
         <li>Expiring App registration secrets</li>
         <li>Stale devices in Entra</li>
    </ul>
   <p>Simply enter your email and tenant and click submit</p>
</div>
<form action="process.php" method="post">
    <table class="styled-table">
        <tr>
            <td>Email Address:</td>
            <td><input type="email" name="email" id="email" required></td>
</tr>
<tr>
<td>Tenant ID:</td>
<td><input type="text" name="tenant" id="tenant" required></td>
</tr>
<tr>
            <td class="tableButton"><input class="profile-btn" type="submit" value="Submit"></td>
        </tr>
    </table>
</form>
<script>
    // JavaScript logic to check email format
    var emailInput = document.getElementById('email');
    emailInput.addEventListener('input', function() {
        var email = emailInput.value;
        var emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            emailInput.setCustomValidity('Please enter a valid email address');
        } else {
            emailInput.setCustomValidity('');
        }
    });
</script>
                
    </div>
            
    
<?php
include "footer.php";
?>