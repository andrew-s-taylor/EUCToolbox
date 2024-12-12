<?php
include 'main.php';
echo $webhooksecret . "here";
// New accounts created on the current date
$accounts = $con->query('SELECT * FROM accounts WHERE cast(registered as DATE) = cast(now() as DATE) ORDER BY registered DESC')->fetch_all(MYSQLI_ASSOC);
// Total accounts
$accounts_total = $con->query('SELECT COUNT(*) AS total FROM accounts')->fetch_object()->total;
// Total accounts that were last active over a month ago
$inactive_accounts = $con->query('SELECT COUNT(*) AS total FROM accounts WHERE last_seen < date_sub(now(), interval 1 month)')->fetch_object()->total;
// Accounts that are active in the last day
$active_accounts = $con->query('SELECT * FROM accounts WHERE last_seen > date_sub(now(), interval 1 day) ORDER BY last_seen DESC')->fetch_all(MYSQLI_ASSOC);
// Total accounts that are active in the last month
$active_accounts2 = $con->query('SELECT COUNT(*) AS total FROM accounts WHERE last_seen > date_sub(now(), interval 1 month)')->fetch_object()->total;
?>
<?=template_admin_header('Dashboard', 'dashboard')?>

<div class="content-title">
    <div class="title">
        <i class="fa-solid fa-gauge-high"></i>
        <div class="txt">
            <h2>Dashboard</h2>
            <p>View statistics, new accounts, and more.</p>
        </div>
    </div>
</div>

<div class="dashboard">
    <div class="content-block stat">
        <div class="data">
            <h3>New Accounts (&lt;1 day)</h3>
            <p><?=number_format(count($accounts))?></p>
        </div>
        <i class="fas fa-user-plus"></i>
        <div class="footer">
            <i class="fa-solid fa-rotate fa-xs"></i>Total accounts created today
        </div>
    </div>

    <div class="content-block stat">
        <div class="data">
            <h3>Total Accounts</h3>
            <p><?=number_format($accounts_total)?></p>
        </div>
        <i class="fas fa-users"></i>
        <div class="footer">
            <i class="fa-solid fa-rotate fa-xs"></i>Total accounts
        </div>
    </div>

    <div class="content-block stat">
        <div class="data">
            <h3>Active Accounts (&lt;30 days)</h3>
            <p><?=number_format($active_accounts2)?></p>
        </div>
        <i class="fas fa-user-clock"></i>
        <div class="footer">
            <i class="fa-solid fa-rotate fa-xs"></i>Total active accounts
        </div>
    </div>

    <div class="content-block stat">
        <div class="data">
            <h3>Inactive Accounts (&gt;30 days)</h3>
            <p><?=number_format($inactive_accounts)?></p>
        </div>
        <i class="fas fa-user-clock"></i>
        <div class="footer">
            <i class="fa-solid fa-rotate fa-xs"></i>Total inactive accounts
        </div>
    </div>
</div>

<div class="content-title">
    <div class="title">
        <i class="fas fa-user-plus alt"></i>
        <div class="txt">
            <h2>New Accounts</h2>
            <p>Accounts created in the last &lt;1 day.</p>
        </div>
    </div>
</div>

<div class="content-block">
    <div class="table">
        <table>
            <thead>
                <tr>
                    <td>#</td>
                    <td>Username</td>
                    <td class="responsive-hidden">Email</td>
                    <td class="responsive-hidden">Activation Code</td>
                    <td class="responsive-hidden">Role</td>
                    <td class="responsive-hidden">Registered Date</td>
                    <td class="responsive-hidden">Last Seen</td>
                    <td>Actions</td>
                </tr>
            </thead>
            <tbody>
                <?php if (!$accounts): ?>
                <tr>
                    <td colspan="8" style="text-align:center;">There are no newly registered accounts</td>
                </tr>
                <?php endif; ?>
                <?php foreach ($accounts as $account): ?>
                <tr>
                    <td><?=$account['id']?></td>
                    <td><?=htmlspecialchars($account['username'], ENT_QUOTES)?></td>
                    <td class="responsive-hidden"><?=htmlspecialchars($account['email'], ENT_QUOTES)?></td>
                    <td class="responsive-hidden"><?=$account['activation_code'] ? $account['activation_code'] : '--'?></td>
                    <td class="responsive-hidden"><?=$account['role']?></td>
                    <td class="responsive-hidden"><?=date('Y-m-d H:ia', strtotime($account['registered']))?></td>
                    <td class="responsive-hidden" title="<?=$account['last_seen']?>"><?=time_elapsed_string($account['last_seen'])?></td>
                    <td>
                        <a href="account.php?id=<?=$account['id']?>" class="link1">Edit</a>
                        <a href="accounts.php?delete=<?=$account['id']?>" class="link1" onclick="return confirm('Are you sure you want to delete this account?')">Delete</a>
                    </td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    </div>
</div>

<div class="content-title" style="margin-top:40px">
    <div class="title">
        <i class="fas fa-user-clock alt"></i>
        <div class="txt">
            <h2>Active Accounts</h2>
            <p>Accounts active in the last &lt;1 day.</p>
        </div>
    </div>
</div>

<div class="content-block">
    <div class="table">
        <table>
            <thead>
                <tr>
                    <td>#</td>
                    <td>Username</td>
                    <td class="responsive-hidden">Email</td>
                    <td class="responsive-hidden">Activation Code</td>
                    <td class="responsive-hidden">Role</td>
                    <td class="responsive-hidden">Registered Date</td>
                    <td class="responsive-hidden">Last Seen</td>
                    <td>Actions</td>
                </tr>
            </thead>
            <tbody>
                <?php if (!$active_accounts): ?>
                <tr>
                    <td colspan="8" style="text-align:center;">There are no active accounts</td>
                </tr>
                <?php endif; ?>
                <?php foreach ($active_accounts as $account): ?>
                <tr>
                    <td><?=$account['id']?></td>
                    <td><?=htmlspecialchars($account['username'], ENT_QUOTES)?></td>
                    <td class="responsive-hidden"><?=htmlspecialchars($account['email'], ENT_QUOTES)?></td>
                    <td class="responsive-hidden"><?=$account['activation_code'] ? $account['activation_code'] : '--'?></td>
                    <td class="responsive-hidden"><?=$account['role']?></td>
                    <td class="responsive-hidden"><?=date('Y-m-d H:ia', strtotime($account['registered']))?></td>
                    <td class="responsive-hidden" title="<?=$account['last_seen']?>"><?=time_elapsed_string($account['last_seen'])?></td>
                    <td>
                        <a href="account.php?id=<?=$account['id']?>" class="link1">Edit</a>
                        <a href="accounts.php?delete=<?=$account['id']?>" onclick="return confirm('Are you sure you want to delete this account?')" class="link1">Delete</a>
                    </td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    </div>
</div>

<?=template_admin_footer()?>