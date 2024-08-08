<div id="menu">
        <button onclick="closeMenu()"><img width="16px" height="16px" src="https://euctoolbox.com/images/Menu Icons/close.svg"></button>
<nav class="menu">
    <?php
    $currentFile = $_SERVER["PHP_SELF"];
    $currentPage = basename($currentFile);
    ?>
    <a href="home.php" <?php if ($currentPage == 'home.php') echo 'class="active"'; ?>><img class="menuIcon" alt="Home Icon" width="22px" height="18px" src="https://euctoolbox.com/images/Menu Icons/Home.svg">Home</a>
    <a href="backup.php" <?php if ($currentPage == 'backup.php') echo 'class="active"'; ?>><img class="menuIcon" alt="Home Icon" width="22px" height="18px" src="https://euctoolbox.com/images/Menu Icons/Backup.svg">Backup</a>
    <a href="restore.php" <?php if ($currentPage == 'restore.php') echo 'class="active"'; ?>><img class="menuIcon" alt="Home Icon" width="22px" height="18px" src="https://euctoolbox.com/images/Menu Icons/Restore.svg">Restore</a>
    <a href="listapps.php" <?php if ($currentPage == 'listapps.php') echo 'class="active"'; ?>><img class="menuIcon" alt="Home Icon" width="22px" height="18px" src="https://euctoolbox.com/images/Menu Icons/DeployApps.svg">Deploy Apps</a>
    <a href="deploydemo.php" <?php if ($currentPage == 'deploydemo.php') echo 'class="active"'; ?>><img class="menuIcon" alt="Home Icon" width="22px" height="18px" src="https://euctoolbox.com/images/Menu Icons/DailyChecks.svg">Template Deployment</a>
    <div class="menuGroupDivider"><span>Manage</span><hr></div>
    <a href="logs.php" <?php if ($currentPage == 'logs.php') echo 'class="active"'; ?>><img class="menuIcon" alt="Home Icon" width="22px" height="18px" src="https://euctoolbox.com/images/Menu Icons/ViewLogs.svg">View Logs</a>
    <a href="manage-backups1.php" <?php if ($currentPage == 'manage-backups1.php') echo 'class="active"'; ?>><img class="menuIcon" alt="Home Icon" width="22px" height="18px" src="https://euctoolbox.com/images/Menu Icons/ManageBackups.svg">Manage Backups</a>
    <a href="check-drift.php" <?php if ($currentPage == 'check-drift.php') echo 'class="active"'; ?>><img class="menuIcon" alt="Home Icon" width="22px" height="18px" src="https://euctoolbox.com/images/Menu Icons/CheckDrift.svg">Check Drift</a>
    <div class="menuGroupDivider"><span>Account</span><hr></div>
    <a href="profile.php" <?php if ($currentPage == 'profile.php') echo 'class="active"'; ?>><img class="menuIcon" alt="Home Icon" width="22px" height="18px" src="https://euctoolbox.com/images/Menu Icons/Profile.svg">Profile</a>
    <a href="tenants.php" <?php if ($currentPage == 'tenants.php') echo 'class="active"'; ?>><img class="menuIcon" alt="Home Icon" width="22px" height="18px" src="https://euctoolbox.com/images/Menu Icons/ManageTenants.svg">Manage Tenants</a>
    <a href="gold.php" <?php if ($currentPage == 'gold.php') echo 'class="active"'; ?>><img class="menuIcon" alt="Home Icon" width="22px" height="18px" src="https://euctoolbox.com/images/Menu Icons/GoldTenants.svg">Gold Tenant</a>
    <?php if ($_SESSION['role'] == 'Admin'): ?>
        <a href="admin/index.php" target="_blank" <?php if ($currentPage == 'admin/index.php') echo 'class="active"'; ?>><img class="menuIcon" alt="Home Icon" width="22px" height="18px" src="https://euctoolbox.com/images/Menu Icons/Profile.svg">Admin</a>
    <?php endif; ?>                    
    <a href="logout.php" <?php if ($currentPage == 'logout.php') echo 'class="active"'; ?>><img class="menuIcon" alt="Home Icon" width="22px" height="18px" src="https://euctoolbox.com/images/Menu Icons/LogOut.svg">Logout</a>
    <div class="menuGroupDivider"><span>Help</span><hr></div>
    <a href="../setup.php" target="blank"><img class="menuIcon" alt="Home Icon" width="22px" height="18px" src="https://euctoolbox.com/images/Menu Icons/ViewLogs.svg">SetupGuide</a>
    <a href="../userguide.php" target="blank"><img class="menuIcon" alt="Home Icon" width="22px" height="18px" src="https://euctoolbox.com/images/Menu Icons/ViewLogs.svg">UserGuide</a>
    <a href="https://pricing.euctoolbox.com" target="blank"><img class="menuIcon" alt="Home Icon" width="22px" height="18px" src="https://euctoolbox.com/images/Menu Icons/GoldTenants.svg">Sponsorship</a>
    <a href="https://euctoolbox.com/changelog.php" target="blank"><img class="menuIcon" alt="Home Icon" width="22px" height="18px" src="https://euctoolbox.com/images/Menu Icons/ViewLogs.svg">What's New</a>


</nav>
</div>		

<button id="menuButton" onclick="openMenu()"><img width="20px" height="20pxs" src="https://euctoolbox.com/images/Menu Icons/menu.svg">Menu</button>