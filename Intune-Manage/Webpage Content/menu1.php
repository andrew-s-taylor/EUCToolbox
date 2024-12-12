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
<div id="menu">
        <button onclick="closeMenu()"><img width="16px" height="16px" src="https://euctoolbox.com/images/Menu Icons/close.svg"></button>

		<?php
		$activePage = basename($_SERVER['PHP_SELF']);
		?>
<nav class="menu">
					<a href="home.php" <?php if ($activePage == 'home.php') echo 'class="active"'; ?>><img class="menuIcon" alt="Home Icon" width="22px" height="18px" src="https://euctoolbox.com/images/Menu Icons/Home.svg">Home</a>
					<?php if ($canbackup == 1): ?>
					<a href="backup.php" <?php if ($activePage == 'backup.php') echo 'class="active"'; ?>><img class="menuIcon" alt="Home Icon" width="22px" height="18px" src="https://euctoolbox.com/images/Menu Icons/Backup.svg">Backup</a>
					<?php endif; ?>
					<?php if ($canrestore == 1): ?>
					<a href="restore.php" <?php if ($activePage == 'restore.php') echo 'class="active"'; ?>><img class="menuIcon" alt="Home Icon" width="22px" height="18px" src="https://euctoolbox.com/images/Menu Icons/Restore.svg">Restore</a>
					<?php endif; ?>
					<?php if ($candeployapps == 1): ?>
					<a href="listapps.php" <?php if ($activePage == 'listapps.php') echo 'class="active"'; ?>><img class="menuIcon" alt="Home Icon" width="22px" height="18px" src="https://euctoolbox.com/images/Menu Icons/DeployApps.svg">Deploy Apps</a>
					<?php endif; ?>
					<?php if ($candeploytemplates == 1): ?>
					<a href="deploydemo.php" <?php if ($activePage == 'deploydemo.php') echo 'class="active"'; ?>><img class="menuIcon" alt="Home Icon" width="22px" height="18px" src="https://euctoolbox.com/images/Menu Icons/DeployApps.svg">Deploy Template</a>
					<?php endif; ?>
					<?php if ($canmigrate == 1): ?>
					<a href="migrate.php" <?php if ($activePage == 'migrate.php') echo 'class="active"'; ?>><img class="menuIcon" alt="Home Icon" width="22px" height="18px" src="https://euctoolbox.com/images/Menu Icons/Restore.svg">Tenant Migration</a>
					<?php endif; ?>

					<div class="menuGroupDivider"><span>Manage</span><hr></div>

					<?php if ($canviewlogs == 1): ?>
					<a href="logs.php" <?php if ($activePage == 'logs.php') echo 'class="active"'; ?>><img class="menuIcon" alt="Home Icon" width="22px" height="18px" src="https://euctoolbox.com/images/Menu Icons/ViewLogs.svg">View Logs</a>
					<a href="auditlog.php" <?php if ($activePage == 'auditlog.php') echo 'class="active"'; ?>><img class="menuIcon" alt="Home Icon" width="22px" height="18px" src="https://euctoolbox.com/images/Menu Icons/ViewLogs.svg">View Audit Logs</a>

					<?php endif; ?>
					<?php if ($canmanagebackups == 1): ?>
					<a href="manage-backups1.php" <?php if ($activePage == 'manage-backups.php') echo 'class="active"'; ?>><img class="menuIcon" alt="Home Icon" width="22px" height="18px" src="https://euctoolbox.com/images/Menu Icons/ManageBackups.svg">Manage Backups</a>
					<?php endif; ?>
					<?php if ($cancheckdrift == 1): ?>
						<a href="check-drift.php" <?php if ($activePage == 'check-drift.php') echo 'class="active"'; ?>><img class="menuIcon" alt="Home Icon" width="22px" height="18px" src="https://euctoolbox.com/images/Menu Icons/CheckDrift.svg">Check Drift</a>
					<?php endif; ?>
					<?php if ($canviewreports == 1): ?>
					<a href="daily-select.php" <?php if ($activePage == 'daily-select.php') echo 'class="active"'; ?>><img class="menuIcon" alt="Home Icon" width="22px" height="18px" src="https://euctoolbox.com/images/Menu Icons/DailyChecks.svg">Daily Checks</a>
					<a href="security-select.php" <?php if ($activePage == 'security-select.php') echo 'class="active"'; ?>><img class="menuIcon" alt="Home Icon" width="22px" height="18px" src="https://euctoolbox.com/images/Menu Icons/SecurityChecks.svg">Security Checks</a>
					<?php endif; ?>

					<div class="menuGroupDivider"><span>Account</span><hr></div>

					<a href="profile-select.php" <?php if ($activePage == 'profile-select.php') echo 'class="active"'; ?>><img class="menuIcon" alt="Home Icon" width="22px" height="18px" src="https://euctoolbox.com/images/Menu Icons/Profile.svg">Profile</a>
					<?php if ($canmanagetenants == 1): ?>
					<a href="tenants.php" <?php if ($activePage == 'tenants.php') echo 'class="active"'; ?>><img class="menuIcon" alt="Home Icon" width="22px" height="18px" src="https://euctoolbox.com/images/Menu Icons/ManageTenants.svg">Manage Tenants</a>
					<?php endif; ?>
					<?php if ($cangolddeploy == 1): ?>
					<a href="gold-select.php" <?php if ($activePage == 'gold.php') echo 'class="active"'; ?>><img class="menuIcon" alt="Home Icon" width="22px" height="18px" src="https://euctoolbox.com/images/Menu Icons/GoldTenants.svg">Gold Tenant</a>
					<?php endif; ?>
					<a href="logout.php" <?php if ($activePage == 'logout.php') echo 'class="active"'; ?>><img class="menuIcon" alt="Home Icon" width="22px" height="18px" src="https://euctoolbox.com/images/Menu Icons/LogOut.svg">Logout</a>
					<?php if ($_SESSION['role'] == 'SuperAdmin'): ?>					
						<a href="admin/index.php" target="_blank"><i class="fas fa-user-cog"></i>Admin</a>
					<?php endif; ?>

					<div class="menuGroupDivider"><span>Info</span><hr></div>
					<a href="getstarted.php" <?php if ($activePage == 'getstarted.php') echo 'class="active"'; ?>><img class="menuIcon" alt="Home Icon" width="22px" height="18px" src="https://euctoolbox.com/images/Menu Icons/ViewLogs.svg">Getting Started</a>
					<a href="https://euctoolbox.com/changelog.php" target="_blank" <?php if ($activePage == 'https://euctoolbox.com/changelog.php') echo 'class="active"'; ?>><img class="menuIcon" alt="Home Icon" width="22px" height="18px" src="https://euctoolbox.com/images/Menu Icons/ViewLogs.svg">What's New</a>

						<div class="menuGroupDivider"><span>Integrations</span><hr></div>
						<?php if ($canmanageapi == 1): ?>
					<a href="manage-api.php" <?php if ($activePage == 'manage-api.php') echo 'class="active"'; ?>><img class="menuIcon" alt="Home Icon" width="22px" height="18px" src="https://euctoolbox.com/images/Menu Icons/GoldTenants.svg">Manage 3rd Party APIs</a>
					<?php endif; ?>

</div>		

<button id="menuButton" onclick="openMenu()"><img width="20px" height="20pxs" src="https://euctoolbox.com/images/Menu Icons/menu.svg">Menu</button>
