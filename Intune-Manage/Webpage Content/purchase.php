<?php
include 'main.php';


if ($accountrole != 'Admin' && $accountrole != 'SuperAdmin' && $accountrole != 'SubAdmin')  {
    echo "You do not have access to view this page";
    exit;
  }
?>
<?php
$sitename = "Intune Manager from EUC Toolbox";
$pagetitle = "Intune Manager";
include "header1.php";
?>

			<h2>Purchase</h2>
            <?php
            if (isset($_GET['msg'])) {
                $msg = $_GET['msg'];
                if ($msg == 'success') {
                    echo "<h1>Thank you, our purchase was successful</h1>";
                } else {
                    echo "<h1>There was an error with your purchase</h1>";
                }
            }
            ?>
            <div class="block">
<p>You can subscribe to the service using the links below</p>
<p>If you would rather pay via invoice, please <a href="https://contact.euctoolbox.com">Contact Us</a> and we would be happy to arrange it</p>
<p>Please note the prices could fluctuate due to exchange rates</p>			
<div class="block">
<h2>SME (up to 10 tenants) / Edu / Non-Profit</h2>
<p>£125 / $150 / €145 per month</p>
<a href="https://pay.gocardless.com/BRT00035ADPD9M8"><button class="button">Subscribe with GoCardless</button></a>


</div>

<div class="block">
<h2>Enterprise (Unlimited tenants)</h2>
<p>£200 / $250 / €230 per month</p>
<a href="https://pay.gocardless.com/BRT00035ADW37EK"><button class="button">Subscribe with GoCardless</button></a>
</div>

<div class="block">
<h2>Premium (includes IntuneDeploy)</h2>
<p>£450 / $575 / €530</p>
<a href="https://pay.gocardless.com/BRT000371MHVQRG"><button class="button">Subscribe with GoCardless</button></a>
</div>


</div>

			</div>
            
	
			<?php
include "footer.php";
?>