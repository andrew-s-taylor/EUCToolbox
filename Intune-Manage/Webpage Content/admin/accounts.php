<?php
include 'main.php';
// Retrieve the GET request parameters (if specified)
$page = isset($_GET['page']) ? $_GET['page'] : 1;
$search = isset($_GET['search']) ? $_GET['search'] : '';
// Filters parameters
$status = isset($_GET['status']) ? $_GET['status'] : '';
$activation = isset($_GET['activation']) ? $_GET['activation'] : '';
$role = isset($_GET['role']) ? $_GET['role'] : '';
// Order by column
$order = isset($_GET['order']) && $_GET['order'] == 'DESC' ? 'DESC' : 'ASC';
// Add/remove columns to the whitelist array
$order_by_whitelist = ['id','username','email','activation_code','role','registered','last_seen'];
$order_by = isset($_GET['order_by']) && in_array($_GET['order_by'], $order_by_whitelist) ? $_GET['order_by'] : 'id';
// Number of results per pagination page
$results_per_page = 20;
// Accounts array
$accounts = [];
// Declare query param variables
$param1 = ($page - 1) * $results_per_page;
$param2 = $results_per_page;
$param3 = '%' . $search . '%';
// SQL where clause
$where = '';
$where .= $search ? 'WHERE (username LIKE ? OR email LIKE ?) ' : '';
// Add filters
if ($status == 'active') {
    $where .= $where ? 'AND last_seen > date_sub(now(), interval 1 month) ' : 'WHERE last_seen > date_sub(now(), interval 1 month) ';
}
if ($status == 'inactive') {
    $where .= $where ? 'AND last_seen < date_sub(now(), interval 1 month) ' : 'WHERE last_seen < date_sub(now(), interval 1 month) ';
}
if ($activation == 'pending') {
    $where .= $where ? 'AND activation_code != "activated" ' : 'WHERE activation_code != "activated" ';
}
if ($role) {
    $where .= $where ? 'AND role = ? ' : 'WHERE role = ? ';
}
// Retrieve the total number of accounts
$stmt = $con->prepare('SELECT COUNT(*) AS total FROM accounts ' . $where);
if ($search && $role) {
    $stmt->bind_param('sss', $param3, $param3, $role);
} else if ($search) {
    $stmt->bind_param('ss', $param3, $param3);
} else if ($role) {
    $stmt->bind_param('s', $role);
}
$stmt->execute();
$stmt->bind_result($accounts_total);
$stmt->fetch();
$stmt->close();
// Prepare search results query
$stmt = $con->prepare('SELECT id, username, email, activation_code, role, registered, last_seen FROM accounts ' . $where . ' ORDER BY ' . $order_by . ' ' . $order . ' LIMIT ?,?');
$types = '';
$params = [];
if ($search) {
    $params[] = &$param3;
    $params[] = &$param3;
    $types .= 'ss';
}
if ($role) {
    $params[] = &$role;
    $types .= 's';
}
$params[] = &$param1;
$params[] = &$param2;
$types .= 'ii';
call_user_func_array([$stmt, 'bind_param'], array_merge([$types], $params));
// Retrieve query results
$stmt->execute();
$stmt->bind_result($result_id, $result_username, $result_email, $result_activation_code, $result_role, $result_registered, $result_last_seen);
// Iterate the results
while($stmt->fetch()) {
    // Add result to accounts array
    $accounts[] = ['id' => $result_id, 'username' => $result_username, 'email' => $result_email, 'activation_code' => $result_activation_code, 'role' => $result_role, 'registered' => $result_registered, 'last_seen' => $result_last_seen];
}
// Delete account
if (isset($_GET['delete'])) {
    // Delete the account
    $stmt = $con->prepare('DELETE FROM accounts WHERE id = ?');
    $stmt->bind_param('i', $_GET['delete']);
    $stmt->execute();
    $stmt = $con->prepare('DELETE FROM tenants WHERE ownerid = ?');
    $stmt->bind_param('i', $_GET['delete']);
    $stmt->execute();
    header('Location: accounts.php?success_msg=3');
    exit;
}
// Handle success messages
if (isset($_GET['success_msg'])) {
    if ($_GET['success_msg'] == 1) {
        $success_msg = 'Account created successfully!';
    }
    if ($_GET['success_msg'] == 2) {
        $success_msg = 'Account updated successfully!';
    }
    if ($_GET['success_msg'] == 3) {
        $success_msg = 'Account deleted successfully!';
    }
}
// Create URL
$url = 'accounts.php?search=' . $search . '&status=' . $status . '&activation=' . $activation . '&role=' . $role;
?>
<?=template_admin_header('Accounts', 'accounts', 'view')?>

<div class="content-title">
    <div class="title">
        <i class="fa-solid fa-users"></i>
        <div class="txt">
            <h2>Accounts</h2>
            <p>View, edit, and create accounts.</p>
        </div>
    </div>
</div>

<?php if (isset($success_msg)): ?>
<div class="msg success">
    <i class="fas fa-check-circle"></i>
    <p><?=$success_msg?></p>
    <i class="fas fa-times"></i>
</div>
<?php endif; ?>

<div class="content-header responsive-flex-column pad-top-5">
    <a href="account.php" class="btn">Create Account</a>
    <form action="" method="get">
        <div class="filters">
            <a href="#"><i class="fas fa-filter"></i> Filters</a>
            <div class="list">
                <label><input type="checkbox" name="status" value="active"<?=$status=='active'?' checked':''?>>Active</label>
                <label><input type="checkbox" name="status" value="inactive"<?=$status=='inactive'?' checked':''?>>Inactive</label>
                <label><input type="checkbox" name="activation" value="pending"<?=$activation=='pending'?' checked':''?>>Pending Activation</label>
                <?php if ($role): ?>
                <label><input type="checkbox" name="role" value="<?=$role?>" checked><?=$role?></label>
                <?php endif; ?>
                <button type="submit">Apply</button>
            </div>
        </div>
        <div class="search">
            <label for="search">
                <input id="search" type="text" name="search" placeholder="Search username or email..." value="<?=htmlspecialchars($search, ENT_QUOTES)?>" class="responsive-width-100">
                <i class="fas fa-search"></i>
            </label>
        </div>
    </form>
</div>

<div class="content-block">
    <div class="table">
        <table>
            <thead>
                <tr>
                    <td><a href="<?=$url . '&order=' . ($order=='ASC'?'DESC':'ASC') . '&order_by=id'?>">#<?php if ($order_by=='id'): ?><i class="fas fa-level-<?=str_replace(['ASC', 'DESC'], ['up','down'], $order)?>-alt fa-xs"></i><?php endif; ?></a></td>
                    <td><a href="<?=$url . '&order=' . ($order=='ASC'?'DESC':'ASC') . '&order_by=username'?>">Username<?php if ($order_by=='username'): ?><i class="fas fa-level-<?=str_replace(['ASC', 'DESC'], ['up','down'], $order)?>-alt fa-xs"></i><?php endif; ?></a></td>
                    <td class="responsive-hidden"><a href="<?=$url . '&order=' . ($order=='ASC'?'DESC':'ASC') . '&order_by=email'?>">Email<?php if ($order_by=='email'): ?><i class="fas fa-level-<?=str_replace(['ASC', 'DESC'], ['up','down'], $order)?>-alt fa-xs"></i><?php endif; ?></a></td>
                    <td class="responsive-hidden"><a href="<?=$url . '&order=' . ($order=='ASC'?'DESC':'ASC') . '&order_by=activation_code'?>">Activation Code<?php if ($order_by=='activation_code'): ?><i class="fas fa-level-<?=str_replace(['ASC', 'DESC'], ['up','down'], $order)?>-alt fa-xs"></i><?php endif; ?></a></td>
                    <td class="responsive-hidden"><a href="<?=$url . '&order=' . ($order=='ASC'?'DESC':'ASC') . '&order_by=role'?>">Role<?php if ($order_by=='role'): ?><i class="fas fa-level-<?=str_replace(['ASC', 'DESC'], ['up','down'], $order)?>-alt fa-xs"></i><?php endif; ?></a></td>
                    <td class="responsive-hidden"><a href="<?=$url . '&order=' . ($order=='ASC'?'DESC':'ASC') . '&order_by=registered'?>">Registered Date<?php if ($order_by=='registered'): ?><i class="fas fa-level-<?=str_replace(['ASC', 'DESC'], ['up','down'], $order)?>-alt fa-xs"></i><?php endif; ?></a></td>
                    <td class="responsive-hidden"><a href="<?=$url . '&order=' . ($order=='ASC'?'DESC':'ASC') . '&order_by=last_seen'?>">Last Seen<?php if ($order_by=='last_seen'): ?><i class="fas fa-level-<?=str_replace(['ASC', 'DESC'], ['up','down'], $order)?>-alt fa-xs"></i><?php endif; ?></a></td>
                    <td>Actions</td>
                </tr>
            </thead>
            <tbody>
                <?php if (!$accounts): ?>
                <tr>
                    <td colspan="8" style="text-align:center;">There are no accounts</td>
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

<div class="pagination">
    <?php if ($page > 1): ?>
    <a href="<?=$url?>&page=<?=$page-1?>&order=<?=$order?>&order_by=<?=$order_by?>">Prev</a>
    <?php endif; ?>
    <span>Page <?=$page?> of <?=ceil($accounts_total / $results_per_page) == 0 ? 1 : ceil($accounts_total / $results_per_page)?></span>
    <?php if ($page * $results_per_page < $accounts_total): ?>
    <a href="<?=$url?>&page=<?=$page+1?>&order=<?=$order?>&order_by=<?=$order_by?>">Next</a>
    <?php endif; ?>
</div>

<?=template_admin_footer()?>