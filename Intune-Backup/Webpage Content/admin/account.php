<?php
include 'main.php';
// Default account values
$account = [
    'username' => '',
    'password' => '',
    'email' => '',
    'activation_code' => '',
    'rememberme' => '',
    'role' => 'Member',
    'registered' => date('Y-m-d\TH:i'),
    'last_seen' => date('Y-m-d\TH:i')
];
// If editing an account
if (isset($_GET['id'])) {
    // Get the account from the database
    $stmt = $con->prepare('SELECT username, password, email, activation_code, rememberme, role, registered, last_seen FROM accounts WHERE id = ?');
    $stmt->bind_param('i', $_GET['id']);
    $stmt->execute();
    $stmt->bind_result($account['username'], $account['password'], $account['email'], $account['activation_code'], $account['rememberme'], $account['role'], $account['registered'], $account['last_seen']);
    $stmt->fetch();
    $stmt->close();
    // ID param exists, edit an existing account
    $page = 'Edit';
    if (isset($_POST['submit'])) {
        // Check to see if username already exists
        $stmt = $con->prepare('SELECT id FROM accounts WHERE username = ? AND username != ?');
        $stmt->bind_param('ss', $_POST['username'], $account['username']);
        $stmt->execute();
        $stmt->store_result();
        if ($stmt->num_rows > 0) {
            $error_msg = 'Username already exists!';
        }
        // Check to see if email already exists
        $stmt = $con->prepare('SELECT id FROM accounts WHERE email = ? AND email != ?');
        $stmt->bind_param('ss', $_POST['email'], $account['email']);
        $stmt->execute();
        $stmt->store_result();
        if ($stmt->num_rows > 0) {
            $error_msg = 'Email already exists!';
        }
        // Update the account
        if (!isset($error_msg)) {
            $password = !empty($_POST['password']) ? password_hash($_POST['password'], PASSWORD_DEFAULT) : $account['password'];
            $stmt = $con->prepare('UPDATE accounts SET username = ?, password = ?, email = ?, activation_code = ?, rememberme = ?, role = ?, registered = ?, last_seen = ? WHERE id = ?');
            $stmt->bind_param('ssssssssi', $_POST['username'], $password, $_POST['email'], $_POST['activation_code'], $_POST['rememberme'], $_POST['role'], $_POST['registered'], $_POST['last_seen'], $_GET['id']);
            $stmt->execute();
            header('Location: accounts.php?success_msg=2');
            exit;
        } else {
            // Update the account variables
            $account = [
                'username' => $_POST['username'],
                'password' => $_POST['password'],
                'email' => $_POST['email'],
                'activation_code' => $_POST['activation_code'],
                'rememberme' => $_POST['rememberme'],
                'role' => $_POST['role'],
                'registered' => $_POST['registered'],
                'last_seen' => $_POST['last_seen']
            ];
        }
    }
    if (isset($_POST['delete'])) {
        // Redirect and delete the account
        header('Location: accounts.php?delete=' . $_GET['id']);
        exit;
    }
} else {
    // Create a new account
    $page = 'Create';
    if (isset($_POST['submit'])) {
        // Check to see if username already exists
        $stmt = $con->prepare('SELECT id FROM accounts WHERE username = ?');
        $stmt->bind_param('s', $_POST['username']);
        $stmt->execute();
        $stmt->store_result();
        if ($stmt->num_rows > 0) {
            $error_msg = 'Username already exists!';
        }
        // Check to see if email already exists
        $stmt = $con->prepare('SELECT id FROM accounts WHERE email = ?');
        $stmt->bind_param('s', $_POST['email']);
        $stmt->execute();
        $stmt->store_result();
        if ($stmt->num_rows > 0) {
            $error_msg = 'Email already exists!';
        }
        // Insert new account into the database
        if (!isset($error_msg)) {
            $password = password_hash($_POST['password'], PASSWORD_DEFAULT);
            $stmt = $con->prepare('INSERT IGNORE INTO accounts (username,password,email,activation_code,rememberme,role,registered,last_seen) VALUES (?,?,?,?,?,?,?,?)');
            $stmt->bind_param('ssssssss', $_POST['username'], $password, $_POST['email'], $_POST['activation_code'], $_POST['rememberme'], $_POST['role'], $_POST['registered'], $_POST['last_seen']);
            $stmt->execute();
            header('Location: accounts.php?success_msg=1');
            exit;
        } else {
            // Update the account variables
            $account = [
                'username' => $_POST['username'],
                'password' => $_POST['password'],
                'email' => $_POST['email'],
                'activation_code' => $_POST['activation_code'],
                'rememberme' => $_POST['rememberme'],
                'role' => $_POST['role'],
                'registered' => $_POST['registered'],
                'last_seen' => $_POST['last_seen']
            ];
        }
    }
}
?>
<?=template_admin_header($page . ' Account', 'accounts', 'manage')?>

<form action="" method="post" enctype="multipart/form-data">

    <div class="content-title responsive-flex-wrap responsive-pad-bot-3">
        <h2 class="responsive-width-100"><?=$page?> Account</h2>
        <a href="accounts.php" class="btn alt mar-right-2">Cancel</a>
        <?php if ($page == 'Edit'): ?>
        <input type="submit" name="delete" value="Delete" class="btn red mar-right-2" onclick="return confirm('Are you sure you want to delete this account?')">
        <?php endif; ?>
        <input type="submit" name="submit" value="Save" class="btn">
    </div>

    <?php if (isset($error_msg)): ?>
    <div class="msg error">
        <i class="fa-solid fa-circle-exclamation"></i>
        <p><?=$error_msg?></p>
        <i class="fas fa-times"></i>
    </div>
    <?php endif; ?>

    <div class="content-block">

        <div class="form responsive-width-100">

            <label for="username">Username</label>
            <input type="text" id="username" name="username" placeholder="Username" value="<?=$account['username']?>" required>

            <label for="password"><?=$page == 'Edit' ? 'New ' : ''?>Password</label>
            <input type="text" id="password" name="password" placeholder="<?=$page == 'Edit' ? 'New ' : ''?>Password" value=""<?=$page == 'Edit' ? '' : ' required'?>>

            <label for="email">Email</label>
            <input type="text" id="email" name="email" placeholder="Email" value="<?=$account['email']?>" required>

            <label for="activation_code">Activation Code</label>
            <input type="text" id="activation_code" name="activation_code" placeholder="Activation Code" value="<?=$account['activation_code']?>">

            <label for="rememberme">Remember Me Code</label>
            <input type="text" id="rememberme" name="rememberme" placeholder="Remember Me Code" value="<?=$account['rememberme']?>">

            <label for="role">Role</label>
            <select id="role" name="role" style="margin-bottom: 30px;">
                <?php foreach ($roles_list as $role): ?>
                <option value="<?=$role?>"<?=$role==$account['role']?' selected':''?>><?=$role?></option>
                <?php endforeach; ?>
            </select>

            <label for="registered">Registered Date</label>
            <input id="registered" type="datetime-local" name="registered" value="<?=date('Y-m-d\TH:i', strtotime($account['registered']))?>" required>
        
            <label for="last_seen">Last Seen Date</label>
            <input id="last_seen" type="datetime-local" name="last_seen" value="<?=date('Y-m-d\TH:i', strtotime($account['last_seen']))?>" required>

        </div>

    </div>

</form>

<?=template_admin_footer()?>