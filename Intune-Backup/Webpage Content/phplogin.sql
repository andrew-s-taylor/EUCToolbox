-- phpMyAdmin SQL Dump
-- version 5.2.0
-- https://www.phpmyadmin.net/
--
-- Host: 127.0.0.1
-- Generation Time: Mar 04, 2023 at 10:44 PM
-- Server version: 10.4.27-MariaDB
-- PHP Version: 8.2.0

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `intunebackup`
--

-- --------------------------------------------------------

--
-- Table structure for table `accounts`
--

CREATE TABLE `accounts` (
  `id` int(11) NOT NULL,
  `username` varchar(50) NOT NULL,
  `password` varchar(255) NOT NULL,
  `email` varchar(100) NOT NULL,
  `activation_code` varchar(50) NOT NULL DEFAULT '',
  `rememberme` varchar(255) NOT NULL DEFAULT '',
  `role` enum('Member','Admin') NOT NULL DEFAULT 'Member',
  `registered` datetime NOT NULL,
  `last_seen` datetime NOT NULL,
  `reset` varchar(50) NOT NULL DEFAULT '',
  `tfa_code` varchar(255) NOT NULL DEFAULT '',
  `ip` varchar(255) NOT NULL DEFAULT '',
  `repoowner` varchar(255) NOT NULL,
  `reponame` varchar(255) NOT NULL,
  `gittoken` varchar(255) NOT NULL,
  `gitproject` varchar(255) NOT NULL,
  `aadclient` varchar(255) NOT NULL,
  `aadsecret` varchar(255) NOT NULL,
  `gittype` varchar(255) NOT NULL,
  `golden` varchar(255) NOT NULL,
  `outdated` int(11) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_general_ci;

--
-- Dumping data for table `accounts`
--

INSERT INTO `accounts` (`id`, `username`, `password`, `email`, `activation_code`, `rememberme`, `role`, `registered`, `last_seen`, `reset`, `tfa_code`, `ip`, `repoowner`, `reponame`, `gittoken`, `gitproject`, `aadclient`, `aadsecret`, `gittype`, `golden`, `outdated`) VALUES
(1, 'admin', '$2y$10$WHtEip2PfLfx7CXZt/RiBOVmN49cChmUL4ghoE45LfDq6ZdyUvzgy', 'admin@example.com', 'activated', '', 'Admin', '2023-01-01 00:00:00', '2023-02-28 12:36:35', '', '9A608C', '127.0.0.1', 'andrew-s-taylor', 'backup-restore-2', 'Tmg4ZEhQZUd1WGRMUkkwWm1XYUU4U3VZQ21vWGpmL05qZ3hGNktCb0JYandPeHIzWkpJaWxla1JObzg1TmtpNTo69/0RwKVGImE2JaIn3MUQfw==', 'GitHub', 'fda1052c-fe80-4345-a682-b9d25177d7fc', 'ZitxRWtaeFRrWVN3ZnFjVnZjcEI4S3hOWm90SnNnckpxYlJObkw5VEhJcmxDbHl0UUJpUXhBZzgrWjNRY0FRRjo6IEAAmZSps/iSZ9tabt7Rxg==', 'github', '46cd9aae-0d0e-45e1-83b5-154b8efeb92f', 7);

-- --------------------------------------------------------

--
-- Table structure for table `login_attempts`
--

CREATE TABLE `login_attempts` (
  `id` int(11) NOT NULL,
  `ip_address` varchar(255) NOT NULL,
  `attempts_left` tinyint(1) NOT NULL DEFAULT 5,
  `date` datetime NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `tenants`
--

CREATE TABLE `tenants` (
  `ID` int(11) NOT NULL,
  `tenantid` varchar(255) NOT NULL,
  `ownerid` varchar(255) NOT NULL,
  `tenantname` varchar(255) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_general_ci;

--
-- Dumping data for table `tenants`
--

INSERT INTO `tenants` (`ID`, `tenantid`, `ownerid`, `tenantname`) VALUES
(1, '2ed176fd-fd5a-4a4f-ac91-54d48d4bac7b', '1', 'testlab'),
(0, '46cd9aae-0d0e-45e1-83b5-154b8efeb92f', '1', 'homelab');

--
-- Indexes for dumped tables
--

--
-- Indexes for table `accounts`
--
ALTER TABLE `accounts`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `login_attempts`
--
ALTER TABLE `login_attempts`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `ip_address` (`ip_address`);

--
-- AUTO_INCREMENT for dumped tables
--

--
-- AUTO_INCREMENT for table `accounts`
--
ALTER TABLE `accounts`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=3;

--
-- AUTO_INCREMENT for table `login_attempts`
--
ALTER TABLE `login_attempts`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
