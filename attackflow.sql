-- AttackFlow Database Schema
-- Version 2.0 - Complete schema with annotations, tags, and attack flows

-- Create database if not exists
CREATE DATABASE IF NOT EXISTS `attackflow` DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE `attackflow`;

-- =====================================================
-- Drop existing tables (in correct order for foreign keys)
-- =====================================================
DROP TABLE IF EXISTS `attack_flows`;
DROP TABLE IF EXISTS `annotations`;
DROP TABLE IF EXISTS `tags`;
DROP TABLE IF EXISTS `files`;
DROP TABLE IF EXISTS `users`;

-- =====================================================
-- Users Table
-- =====================================================
CREATE TABLE `users` (
  `userID` INT NOT NULL AUTO_INCREMENT,
  `email` VARCHAR(255) NOT NULL,
  `password` VARCHAR(255) NOT NULL,
  `username` VARCHAR(64) NOT NULL,
  `access` ENUM('admin', 'client', 'annotator') NOT NULL DEFAULT 'annotator',
  `createdAt` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  `updatedAt` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`userID`),
  UNIQUE KEY `email_unique` (`email`),
  UNIQUE KEY `username_unique` (`username`),
  INDEX `idx_access` (`access`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =====================================================
-- Files Table
-- =====================================================
CREATE TABLE `files` (
  `fileID` INT NOT NULL AUTO_INCREMENT,
  `userID` INT NOT NULL,
  `fileName` VARCHAR(255) NOT NULL,
  `originalName` VARCHAR(255) DEFAULT NULL,
  `fileType` VARCHAR(50) DEFAULT 'pdf',
  `fileSize` INT DEFAULT 0,
  `status` ENUM('Unvalidated', 'Pending', 'Approved', 'Rejected') DEFAULT 'Unvalidated',
  `createdAt` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  `updatedAt` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`fileID`),
  INDEX `idx_userID` (`userID`),
  INDEX `idx_status` (`status`),
  CONSTRAINT `fk_files_user` FOREIGN KEY (`userID`) REFERENCES `users` (`userID`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =====================================================
-- Tags Table (MITRE ATT&CK Techniques)
-- =====================================================
CREATE TABLE `tags` (
  `tagID` INT NOT NULL AUTO_INCREMENT,
  `techniqueID` VARCHAR(20) NOT NULL,
  `name` VARCHAR(255) NOT NULL,
  `category` VARCHAR(100) NOT NULL,
  `description` TEXT,
  `url` VARCHAR(500) DEFAULT NULL,
  `isCustom` TINYINT(1) DEFAULT 0,
  `createdBy` INT DEFAULT NULL,
  `createdAt` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`tagID`),
  UNIQUE KEY `techniqueID_unique` (`techniqueID`),
  INDEX `idx_category` (`category`),
  INDEX `idx_name` (`name`),
  CONSTRAINT `fk_tags_creator` FOREIGN KEY (`createdBy`) REFERENCES `users` (`userID`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =====================================================
-- Annotations Table
-- =====================================================
CREATE TABLE `annotations` (
  `annotationID` INT NOT NULL AUTO_INCREMENT,
  `fileID` INT NOT NULL,
  `tagID` INT DEFAULT NULL,
  `customTag` VARCHAR(255) DEFAULT NULL,
  `selectedText` TEXT,
  `startOffset` INT DEFAULT 0,
  `endOffset` INT DEFAULT 0,
  `pageNumber` INT DEFAULT 1,
  `notes` TEXT,
  `orderIndex` INT DEFAULT 0,
  `createdBy` INT DEFAULT NULL,
  `createdAt` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  `updatedBy` INT DEFAULT NULL,
  `updatedAt` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`annotationID`),
  INDEX `idx_fileID` (`fileID`),
  INDEX `idx_tagID` (`tagID`),
  INDEX `idx_orderIndex` (`orderIndex`),
  CONSTRAINT `fk_annotations_file` FOREIGN KEY (`fileID`) REFERENCES `files` (`fileID`) ON DELETE CASCADE,
  CONSTRAINT `fk_annotations_tag` FOREIGN KEY (`tagID`) REFERENCES `tags` (`tagID`) ON DELETE SET NULL,
  CONSTRAINT `fk_annotations_creator` FOREIGN KEY (`createdBy`) REFERENCES `users` (`userID`) ON DELETE SET NULL,
  CONSTRAINT `fk_annotations_updater` FOREIGN KEY (`updatedBy`) REFERENCES `users` (`userID`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =====================================================
-- Attack Flows Table
-- =====================================================
CREATE TABLE `attack_flows` (
  `flowID` INT NOT NULL AUTO_INCREMENT,
  `fileID` INT NOT NULL,
  `flowName` VARCHAR(255) NOT NULL,
  `flowDescription` TEXT,
  `flowJSON` LONGTEXT NOT NULL,
  `status` ENUM('Pending', 'Approved', 'Rejected') DEFAULT 'Pending',
  `feedback` TEXT,
  `createdBy` INT DEFAULT NULL,
  `createdAt` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  `validatedBy` INT DEFAULT NULL,
  `validatedAt` TIMESTAMP NULL DEFAULT NULL,
  `version` INT DEFAULT 1,
  PRIMARY KEY (`flowID`),
  INDEX `idx_fileID` (`fileID`),
  INDEX `idx_status` (`status`),
  INDEX `idx_createdBy` (`createdBy`),
  CONSTRAINT `fk_flows_file` FOREIGN KEY (`fileID`) REFERENCES `files` (`fileID`) ON DELETE CASCADE,
  CONSTRAINT `fk_flows_creator` FOREIGN KEY (`createdBy`) REFERENCES `users` (`userID`) ON DELETE SET NULL,
  CONSTRAINT `fk_flows_validator` FOREIGN KEY (`validatedBy`) REFERENCES `users` (`userID`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- =====================================================
-- Insert Default Users (passwords will be hashed on first login with new system)
-- =====================================================
INSERT INTO `users` (`email`, `password`, `username`, `access`) VALUES
('admin@attackflow.local', 'admin123', 'admin', 'admin'),
('validator@attackflow.local', 'validator123', 'validator', 'client'),
('annotator@attackflow.local', 'annotator123', 'annotator', 'annotator');

-- =====================================================
-- Insert MITRE ATT&CK Techniques (Predefined Tags)
-- Based on MITRE ATT&CK Framework Enterprise Tactics and Techniques
-- =====================================================

-- Reconnaissance (TA0043)
INSERT INTO `tags` (`techniqueID`, `name`, `category`, `description`, `url`) VALUES
('T1595', 'Active Scanning', 'Reconnaissance', 'Adversaries may execute active reconnaissance scans to gather information that can be used during targeting.', 'https://attack.mitre.org/techniques/T1595'),
('T1592', 'Gather Victim Host Information', 'Reconnaissance', 'Adversaries may gather information about the victim host hardware that can be used during targeting.', 'https://attack.mitre.org/techniques/T1592'),
('T1589', 'Gather Victim Identity Information', 'Reconnaissance', 'Adversaries may gather information about the victim identity that can be used during targeting.', 'https://attack.mitre.org/techniques/T1589'),
('T1590', 'Gather Victim Network Information', 'Reconnaissance', 'Adversaries may gather information about the victim network that can be used during targeting.', 'https://attack.mitre.org/techniques/T1590'),
('T1591', 'Gather Victim Org Information', 'Reconnaissance', 'Adversaries may gather information about the victim organization that can be used during targeting.', 'https://attack.mitre.org/techniques/T1591'),
('T1598', 'Phishing for Information', 'Reconnaissance', 'Adversaries may send phishing messages to elicit sensitive information that can be used during targeting.', 'https://attack.mitre.org/techniques/T1598'),
('T1597', 'Search Closed Sources', 'Reconnaissance', 'Adversaries may search and gather information about victims from closed sources that can be used during targeting.', 'https://attack.mitre.org/techniques/T1597'),
('T1596', 'Search Open Technical Databases', 'Reconnaissance', 'Adversaries may search freely available technical databases for information about victims that can be used during targeting.', 'https://attack.mitre.org/techniques/T1596'),
('T1593', 'Search Open Websites/Domains', 'Reconnaissance', 'Adversaries may search freely available websites and/or domains for information about victims that can be used during targeting.', 'https://attack.mitre.org/techniques/T1593'),
('T1594', 'Search Victim-Owned Websites', 'Reconnaissance', 'Adversaries may search websites owned by the victim for information that can be used during targeting.', 'https://attack.mitre.org/techniques/T1594');

-- Resource Development (TA0042)
INSERT INTO `tags` (`techniqueID`, `name`, `category`, `description`, `url`) VALUES
('T1583', 'Acquire Infrastructure', 'Resource Development', 'Adversaries may buy, lease, or rent infrastructure that can be used during targeting.', 'https://attack.mitre.org/techniques/T1583'),
('T1586', 'Compromise Accounts', 'Resource Development', 'Adversaries may compromise accounts with services that can be used during targeting.', 'https://attack.mitre.org/techniques/T1586'),
('T1584', 'Compromise Infrastructure', 'Resource Development', 'Adversaries may compromise third-party infrastructure that can be used during targeting.', 'https://attack.mitre.org/techniques/T1584'),
('T1587', 'Develop Capabilities', 'Resource Development', 'Adversaries may build capabilities that can be used during targeting.', 'https://attack.mitre.org/techniques/T1587'),
('T1585', 'Establish Accounts', 'Resource Development', 'Adversaries may create and cultivate accounts with services that can be used during targeting.', 'https://attack.mitre.org/techniques/T1585'),
('T1588', 'Obtain Capabilities', 'Resource Development', 'Adversaries may buy and/or steal capabilities that can be used during targeting.', 'https://attack.mitre.org/techniques/T1588'),
('T1608', 'Stage Capabilities', 'Resource Development', 'Adversaries may upload, install, or otherwise set up capabilities that can be used during targeting.', 'https://attack.mitre.org/techniques/T1608');

-- Initial Access (TA0001)
INSERT INTO `tags` (`techniqueID`, `name`, `category`, `description`, `url`) VALUES
('T1189', 'Drive-by Compromise', 'Initial Access', 'Adversaries may gain access to a system through a user visiting a website over the normal course of browsing.', 'https://attack.mitre.org/techniques/T1189'),
('T1190', 'Exploit Public-Facing Application', 'Initial Access', 'Adversaries may attempt to exploit a weakness in an Internet-facing host or system to initially access a network.', 'https://attack.mitre.org/techniques/T1190'),
('T1133', 'External Remote Services', 'Initial Access', 'Adversaries may leverage external-facing remote services to initially access and/or persist within a network.', 'https://attack.mitre.org/techniques/T1133'),
('T1200', 'Hardware Additions', 'Initial Access', 'Adversaries may introduce computer accessories, networking hardware, or other computing devices into a system or network.', 'https://attack.mitre.org/techniques/T1200'),
('T1566', 'Phishing', 'Initial Access', 'Adversaries may send phishing messages to gain access to victim systems.', 'https://attack.mitre.org/techniques/T1566'),
('T1091', 'Replication Through Removable Media', 'Initial Access', 'Adversaries may move onto systems by copying malware to removable media and taking advantage of Autorun features.', 'https://attack.mitre.org/techniques/T1091'),
('T1195', 'Supply Chain Compromise', 'Initial Access', 'Adversaries may manipulate products or product delivery mechanisms prior to receipt by a final consumer.', 'https://attack.mitre.org/techniques/T1195'),
('T1199', 'Trusted Relationship', 'Initial Access', 'Adversaries may breach or otherwise leverage organizations who have access to intended victims.', 'https://attack.mitre.org/techniques/T1199'),
('T1078', 'Valid Accounts', 'Initial Access', 'Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access.', 'https://attack.mitre.org/techniques/T1078');

-- Execution (TA0002)
INSERT INTO `tags` (`techniqueID`, `name`, `category`, `description`, `url`) VALUES
('T1059', 'Command and Scripting Interpreter', 'Execution', 'Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries.', 'https://attack.mitre.org/techniques/T1059'),
('T1609', 'Container Administration Command', 'Execution', 'Adversaries may abuse a container administration service to execute commands within a container.', 'https://attack.mitre.org/techniques/T1609'),
('T1610', 'Deploy Container', 'Execution', 'Adversaries may deploy a container into an environment to facilitate execution or evade defenses.', 'https://attack.mitre.org/techniques/T1610'),
('T1203', 'Exploitation for Client Execution', 'Execution', 'Adversaries may exploit software vulnerabilities in client applications to execute code.', 'https://attack.mitre.org/techniques/T1203'),
('T1559', 'Inter-Process Communication', 'Execution', 'Adversaries may abuse inter-process communication (IPC) mechanisms for local code or command execution.', 'https://attack.mitre.org/techniques/T1559'),
('T1106', 'Native API', 'Execution', 'Adversaries may interact with the native OS application programming interface (API) to execute behaviors.', 'https://attack.mitre.org/techniques/T1106'),
('T1053', 'Scheduled Task/Job', 'Execution', 'Adversaries may abuse task scheduling functionality to facilitate initial or recurring execution of malicious code.', 'https://attack.mitre.org/techniques/T1053'),
('T1129', 'Shared Modules', 'Execution', 'Adversaries may execute malicious payloads via loading shared modules.', 'https://attack.mitre.org/techniques/T1129'),
('T1072', 'Software Deployment Tools', 'Execution', 'Adversaries may gain access to and use third-party software suites installed within an enterprise network.', 'https://attack.mitre.org/techniques/T1072'),
('T1569', 'System Services', 'Execution', 'Adversaries may abuse system services or daemons to execute commands or programs.', 'https://attack.mitre.org/techniques/T1569'),
('T1204', 'User Execution', 'Execution', 'An adversary may rely upon specific actions by a user in order to gain execution.', 'https://attack.mitre.org/techniques/T1204'),
('T1047', 'Windows Management Instrumentation', 'Execution', 'Adversaries may abuse Windows Management Instrumentation (WMI) to execute malicious commands and payloads.', 'https://attack.mitre.org/techniques/T1047');

-- Persistence (TA0003)
INSERT INTO `tags` (`techniqueID`, `name`, `category`, `description`, `url`) VALUES
('T1098', 'Account Manipulation', 'Persistence', 'Adversaries may manipulate accounts to maintain and/or elevate access to victim systems.', 'https://attack.mitre.org/techniques/T1098'),
('T1197', 'BITS Jobs', 'Persistence', 'Adversaries may abuse BITS jobs to persistently execute code and perform various background tasks.', 'https://attack.mitre.org/techniques/T1197'),
('T1547', 'Boot or Logon Autostart Execution', 'Persistence', 'Adversaries may configure system settings to automatically execute a program during system boot or logon.', 'https://attack.mitre.org/techniques/T1547'),
('T1037', 'Boot or Logon Initialization Scripts', 'Persistence', 'Adversaries may use scripts automatically executed at boot or logon initialization to establish persistence.', 'https://attack.mitre.org/techniques/T1037'),
('T1176', 'Browser Extensions', 'Persistence', 'Adversaries may abuse Internet browser extensions to establish persistent access to victim systems.', 'https://attack.mitre.org/techniques/T1176'),
('T1554', 'Compromise Client Software Binary', 'Persistence', 'Adversaries may modify client software binaries to establish persistent access to systems.', 'https://attack.mitre.org/techniques/T1554'),
('T1136', 'Create Account', 'Persistence', 'Adversaries may create an account to maintain access to victim systems.', 'https://attack.mitre.org/techniques/T1136'),
('T1543', 'Create or Modify System Process', 'Persistence', 'Adversaries may create or modify system-level processes to repeatedly execute malicious payloads.', 'https://attack.mitre.org/techniques/T1543'),
('T1546', 'Event Triggered Execution', 'Persistence', 'Adversaries may establish persistence and/or elevate privileges using system mechanisms that trigger execution.', 'https://attack.mitre.org/techniques/T1546'),
('T1133', 'External Remote Services', 'Persistence', 'Adversaries may leverage external-facing remote services to initially access and/or persist within a network.', 'https://attack.mitre.org/techniques/T1133'),
('T1574', 'Hijack Execution Flow', 'Persistence', 'Adversaries may execute their own malicious payloads by hijacking the way operating systems run programs.', 'https://attack.mitre.org/techniques/T1574'),
('T1525', 'Implant Internal Image', 'Persistence', 'Adversaries may implant cloud or container images with malicious code to establish persistence.', 'https://attack.mitre.org/techniques/T1525'),
('T1556', 'Modify Authentication Process', 'Persistence', 'Adversaries may modify authentication mechanisms to access user credentials or enable access to accounts.', 'https://attack.mitre.org/techniques/T1556'),
('T1137', 'Office Application Startup', 'Persistence', 'Adversaries may leverage Microsoft Office-based applications for persistence between startups.', 'https://attack.mitre.org/techniques/T1137'),
('T1542', 'Pre-OS Boot', 'Persistence', 'Adversaries may abuse Pre-OS Boot mechanisms as a way to establish persistence on a system.', 'https://attack.mitre.org/techniques/T1542'),
('T1505', 'Server Software Component', 'Persistence', 'Adversaries may abuse legitimate extensible development features of servers to establish persistent access.', 'https://attack.mitre.org/techniques/T1505'),
('T1205', 'Traffic Signaling', 'Persistence', 'Adversaries may use traffic signaling to hide open ports or other malicious functionality.', 'https://attack.mitre.org/techniques/T1205');

-- Privilege Escalation (TA0004)
INSERT INTO `tags` (`techniqueID`, `name`, `category`, `description`, `url`) VALUES
('T1548', 'Abuse Elevation Control Mechanism', 'Privilege Escalation', 'Adversaries may circumvent mechanisms designed to control elevated privileges to gain higher-level permissions.', 'https://attack.mitre.org/techniques/T1548'),
('T1134', 'Access Token Manipulation', 'Privilege Escalation', 'Adversaries may modify access tokens to operate under a different user or system security context.', 'https://attack.mitre.org/techniques/T1134'),
('T1068', 'Exploitation for Privilege Escalation', 'Privilege Escalation', 'Adversaries may exploit software vulnerabilities in an attempt to elevate privileges.', 'https://attack.mitre.org/techniques/T1068'),
('T1484', 'Domain Policy Modification', 'Privilege Escalation', 'Adversaries may modify the configuration settings of a domain to evade defenses and/or escalate privileges.', 'https://attack.mitre.org/techniques/T1484'),
('T1611', 'Escape to Host', 'Privilege Escalation', 'Adversaries may break out of a container to gain access to the underlying host.', 'https://attack.mitre.org/techniques/T1611'),
('T1055', 'Process Injection', 'Privilege Escalation', 'Adversaries may inject code into processes in order to evade process-based defenses as well as possibly elevate privileges.', 'https://attack.mitre.org/techniques/T1055');

-- Defense Evasion (TA0005)
INSERT INTO `tags` (`techniqueID`, `name`, `category`, `description`, `url`) VALUES
('T1140', 'Deobfuscate/Decode Files or Information', 'Defense Evasion', 'Adversaries may use obfuscated files or information to hide artifacts of an intrusion from analysis.', 'https://attack.mitre.org/techniques/T1140'),
('T1480', 'Execution Guardrails', 'Defense Evasion', 'Adversaries may use execution guardrails to constrain execution or actions based on adversary supplied and environment specific conditions.', 'https://attack.mitre.org/techniques/T1480'),
('T1211', 'Exploitation for Defense Evasion', 'Defense Evasion', 'Adversaries may exploit a system or application vulnerability to bypass security features.', 'https://attack.mitre.org/techniques/T1211'),
('T1222', 'File and Directory Permissions Modification', 'Defense Evasion', 'Adversaries may modify file or directory permissions/attributes to evade access control lists (ACLs).', 'https://attack.mitre.org/techniques/T1222'),
('T1564', 'Hide Artifacts', 'Defense Evasion', 'Adversaries may attempt to hide artifacts associated with their behaviors to evade detection.', 'https://attack.mitre.org/techniques/T1564'),
('T1562', 'Impair Defenses', 'Defense Evasion', 'Adversaries may maliciously modify components of a victim environment in order to hinder or disable defensive mechanisms.', 'https://attack.mitre.org/techniques/T1562'),
('T1070', 'Indicator Removal', 'Defense Evasion', 'Adversaries may delete or modify artifacts generated within systems to remove evidence.', 'https://attack.mitre.org/techniques/T1070'),
('T1202', 'Indirect Command Execution', 'Defense Evasion', 'Adversaries may abuse utilities that allow for command execution to bypass security restrictions.', 'https://attack.mitre.org/techniques/T1202'),
('T1036', 'Masquerading', 'Defense Evasion', 'Adversaries may attempt to manipulate features of their artifacts to make them appear legitimate or benign to users.', 'https://attack.mitre.org/techniques/T1036'),
('T1112', 'Modify Registry', 'Defense Evasion', 'Adversaries may interact with the Windows Registry to hide configuration information.', 'https://attack.mitre.org/techniques/T1112'),
('T1027', 'Obfuscated Files or Information', 'Defense Evasion', 'Adversaries may attempt to make an executable or file difficult to discover or analyze.', 'https://attack.mitre.org/techniques/T1027'),
('T1207', 'Rogue Domain Controller', 'Defense Evasion', 'Adversaries may register a rogue Domain Controller to enable manipulation of Active Directory data.', 'https://attack.mitre.org/techniques/T1207'),
('T1014', 'Rootkit', 'Defense Evasion', 'Adversaries may use rootkits to hide the presence of programs, files, network connections, services, drivers, and other system components.', 'https://attack.mitre.org/techniques/T1014'),
('T1218', 'System Binary Proxy Execution', 'Defense Evasion', 'Adversaries may bypass process and/or signature-based defenses by proxying execution of malicious content.', 'https://attack.mitre.org/techniques/T1218'),
('T1216', 'System Script Proxy Execution', 'Defense Evasion', 'Adversaries may use trusted scripts to proxy the execution of malicious files.', 'https://attack.mitre.org/techniques/T1216'),
('T1221', 'Template Injection', 'Defense Evasion', 'Adversaries may create or modify references in user document templates to conceal malicious code.', 'https://attack.mitre.org/techniques/T1221'),
('T1127', 'Trusted Developer Utilities Proxy Execution', 'Defense Evasion', 'Adversaries may take advantage of trusted developer utilities to proxy execution of malicious payloads.', 'https://attack.mitre.org/techniques/T1127'),
('T1535', 'Unused/Unsupported Cloud Regions', 'Defense Evasion', 'Adversaries may create cloud instances in unused geographic regions to evade detection.', 'https://attack.mitre.org/techniques/T1535'),
('T1550', 'Use Alternate Authentication Material', 'Defense Evasion', 'Adversaries may use alternate authentication material to move laterally within an environment.', 'https://attack.mitre.org/techniques/T1550'),
('T1497', 'Virtualization/Sandbox Evasion', 'Defense Evasion', 'Adversaries may employ various means to detect and avoid virtualization and analysis environments.', 'https://attack.mitre.org/techniques/T1497'),
('T1600', 'Weaken Encryption', 'Defense Evasion', 'Adversaries may compromise a network device encryption capability in order to bypass encryption.', 'https://attack.mitre.org/techniques/T1600'),
('T1220', 'XSL Script Processing', 'Defense Evasion', 'Adversaries may bypass application control and obscure execution of code by embedding scripts inside XSL files.', 'https://attack.mitre.org/techniques/T1220');

-- Credential Access (TA0006)
INSERT INTO `tags` (`techniqueID`, `name`, `category`, `description`, `url`) VALUES
('T1557', 'Adversary-in-the-Middle', 'Credential Access', 'Adversaries may attempt to position themselves between two or more networked devices to intercept traffic.', 'https://attack.mitre.org/techniques/T1557'),
('T1110', 'Brute Force', 'Credential Access', 'Adversaries may use brute force techniques to gain access to accounts when passwords are unknown.', 'https://attack.mitre.org/techniques/T1110'),
('T1555', 'Credentials from Password Stores', 'Credential Access', 'Adversaries may search for common password storage locations to obtain user credentials.', 'https://attack.mitre.org/techniques/T1555'),
('T1212', 'Exploitation for Credential Access', 'Credential Access', 'Adversaries may exploit software vulnerabilities in an attempt to collect credentials.', 'https://attack.mitre.org/techniques/T1212'),
('T1187', 'Forced Authentication', 'Credential Access', 'Adversaries may gather credential material by invoking or forcing a user to automatically provide authentication.', 'https://attack.mitre.org/techniques/T1187'),
('T1606', 'Forge Web Credentials', 'Credential Access', 'Adversaries may forge credential materials that can be used to gain access to web applications.', 'https://attack.mitre.org/techniques/T1606'),
('T1056', 'Input Capture', 'Credential Access', 'Adversaries may use methods of capturing user input to obtain credentials.', 'https://attack.mitre.org/techniques/T1056'),
('T1556', 'Modify Authentication Process', 'Credential Access', 'Adversaries may modify authentication mechanisms to access user credentials.', 'https://attack.mitre.org/techniques/T1556'),
('T1040', 'Network Sniffing', 'Credential Access', 'Adversaries may sniff network traffic to capture information about an environment.', 'https://attack.mitre.org/techniques/T1040'),
('T1003', 'OS Credential Dumping', 'Credential Access', 'Adversaries may attempt to dump credentials to obtain account login and credential material.', 'https://attack.mitre.org/techniques/T1003'),
('T1528', 'Steal Application Access Token', 'Credential Access', 'Adversaries can steal user application access tokens as a means of acquiring credentials.', 'https://attack.mitre.org/techniques/T1528'),
('T1558', 'Steal or Forge Kerberos Tickets', 'Credential Access', 'Adversaries may attempt to subvert Kerberos authentication for credential access.', 'https://attack.mitre.org/techniques/T1558'),
('T1539', 'Steal Web Session Cookie', 'Credential Access', 'Adversaries may steal web application or service session cookies to gain access.', 'https://attack.mitre.org/techniques/T1539'),
('T1111', 'Multi-Factor Authentication Interception', 'Credential Access', 'Adversaries may target multi-factor authentication (MFA) mechanisms to gain access to credentials.', 'https://attack.mitre.org/techniques/T1111');

-- Discovery (TA0007)
INSERT INTO `tags` (`techniqueID`, `name`, `category`, `description`, `url`) VALUES
('T1087', 'Account Discovery', 'Discovery', 'Adversaries may attempt to get a listing of accounts on a system or within an environment.', 'https://attack.mitre.org/techniques/T1087'),
('T1010', 'Application Window Discovery', 'Discovery', 'Adversaries may attempt to get a listing of open application windows.', 'https://attack.mitre.org/techniques/T1010'),
('T1217', 'Browser Information Discovery', 'Discovery', 'Adversaries may enumerate information about browsers to learn more about compromised environments.', 'https://attack.mitre.org/techniques/T1217'),
('T1580', 'Cloud Infrastructure Discovery', 'Discovery', 'An adversary may attempt to discover infrastructure and resources that are available within an IaaS environment.', 'https://attack.mitre.org/techniques/T1580'),
('T1538', 'Cloud Service Dashboard', 'Discovery', 'Adversaries may use a cloud service dashboard GUI to discover information about services.', 'https://attack.mitre.org/techniques/T1538'),
('T1526', 'Cloud Service Discovery', 'Discovery', 'Adversaries may attempt to enumerate the cloud services running on a system after gaining access.', 'https://attack.mitre.org/techniques/T1526'),
('T1613', 'Container and Resource Discovery', 'Discovery', 'Adversaries may attempt to discover containers and other resources that are available within a containers environment.', 'https://attack.mitre.org/techniques/T1613'),
('T1482', 'Domain Trust Discovery', 'Discovery', 'Adversaries may attempt to gather information on domain trust relationships.', 'https://attack.mitre.org/techniques/T1482'),
('T1083', 'File and Directory Discovery', 'Discovery', 'Adversaries may enumerate files and directories or may search in specific locations of a host.', 'https://attack.mitre.org/techniques/T1083'),
('T1615', 'Group Policy Discovery', 'Discovery', 'Adversaries may gather information on Group Policy settings to identify paths for privilege escalation.', 'https://attack.mitre.org/techniques/T1615'),
('T1046', 'Network Service Discovery', 'Discovery', 'Adversaries may attempt to get a listing of services running on remote hosts.', 'https://attack.mitre.org/techniques/T1046'),
('T1135', 'Network Share Discovery', 'Discovery', 'Adversaries may look for folders and drives shared on remote systems.', 'https://attack.mitre.org/techniques/T1135'),
('T1040', 'Network Sniffing', 'Discovery', 'Adversaries may sniff network traffic to capture information about an environment.', 'https://attack.mitre.org/techniques/T1040'),
('T1201', 'Password Policy Discovery', 'Discovery', 'Adversaries may attempt to access detailed information about the password policy used within an enterprise network.', 'https://attack.mitre.org/techniques/T1201'),
('T1120', 'Peripheral Device Discovery', 'Discovery', 'Adversaries may attempt to gather information about attached peripheral devices.', 'https://attack.mitre.org/techniques/T1120'),
('T1069', 'Permission Groups Discovery', 'Discovery', 'Adversaries may attempt to discover group and permission settings.', 'https://attack.mitre.org/techniques/T1069'),
('T1057', 'Process Discovery', 'Discovery', 'Adversaries may attempt to get information about running processes on a system.', 'https://attack.mitre.org/techniques/T1057'),
('T1012', 'Query Registry', 'Discovery', 'Adversaries may interact with the Windows Registry to gather information about the system.', 'https://attack.mitre.org/techniques/T1012'),
('T1018', 'Remote System Discovery', 'Discovery', 'Adversaries may attempt to get a listing of other systems by IP address, hostname, or other identifier.', 'https://attack.mitre.org/techniques/T1018'),
('T1518', 'Software Discovery', 'Discovery', 'Adversaries may attempt to get a listing of software and software versions that are installed.', 'https://attack.mitre.org/techniques/T1518'),
('T1082', 'System Information Discovery', 'Discovery', 'Adversaries may attempt to get detailed information about the operating system and hardware.', 'https://attack.mitre.org/techniques/T1082'),
('T1614', 'System Location Discovery', 'Discovery', 'Adversaries may gather information in an attempt to calculate the geographical location of a victim host.', 'https://attack.mitre.org/techniques/T1614'),
('T1016', 'System Network Configuration Discovery', 'Discovery', 'Adversaries may look for details about the network configuration and settings.', 'https://attack.mitre.org/techniques/T1016'),
('T1049', 'System Network Connections Discovery', 'Discovery', 'Adversaries may attempt to get a listing of network connections to or from the compromised system.', 'https://attack.mitre.org/techniques/T1049'),
('T1033', 'System Owner/User Discovery', 'Discovery', 'Adversaries may attempt to identify the primary user, logged in user, or set of users.', 'https://attack.mitre.org/techniques/T1033'),
('T1007', 'System Service Discovery', 'Discovery', 'Adversaries may try to gather information about registered local system services.', 'https://attack.mitre.org/techniques/T1007'),
('T1124', 'System Time Discovery', 'Discovery', 'Adversaries may gather the system time and/or time zone from a local or remote system.', 'https://attack.mitre.org/techniques/T1124'),
('T1497', 'Virtualization/Sandbox Evasion', 'Discovery', 'Adversaries may employ various means to detect and avoid virtualization and analysis environments.', 'https://attack.mitre.org/techniques/T1497');

-- Lateral Movement (TA0008)
INSERT INTO `tags` (`techniqueID`, `name`, `category`, `description`, `url`) VALUES
('T1210', 'Exploitation of Remote Services', 'Lateral Movement', 'Adversaries may exploit remote services to gain unauthorized access to internal systems.', 'https://attack.mitre.org/techniques/T1210'),
('T1534', 'Internal Spearphishing', 'Lateral Movement', 'Adversaries may use internal spearphishing to gain access to additional information or exploit other users.', 'https://attack.mitre.org/techniques/T1534'),
('T1570', 'Lateral Tool Transfer', 'Lateral Movement', 'Adversaries may transfer tools or other files between systems in a compromised environment.', 'https://attack.mitre.org/techniques/T1570'),
('T1563', 'Remote Service Session Hijacking', 'Lateral Movement', 'Adversaries may take control of preexisting sessions with remote services to move laterally.', 'https://attack.mitre.org/techniques/T1563'),
('T1021', 'Remote Services', 'Lateral Movement', 'Adversaries may use remote services to gain access to and execute commands on remote systems.', 'https://attack.mitre.org/techniques/T1021'),
('T1091', 'Replication Through Removable Media', 'Lateral Movement', 'Adversaries may move onto systems by copying malware to removable media.', 'https://attack.mitre.org/techniques/T1091'),
('T1072', 'Software Deployment Tools', 'Lateral Movement', 'Adversaries may gain access to and use third-party software suites installed within an enterprise network.', 'https://attack.mitre.org/techniques/T1072'),
('T1080', 'Taint Shared Content', 'Lateral Movement', 'Adversaries may deliver payloads to remote systems by adding content to shared storage locations.', 'https://attack.mitre.org/techniques/T1080'),
('T1550', 'Use Alternate Authentication Material', 'Lateral Movement', 'Adversaries may use alternate authentication material to move laterally within an environment.', 'https://attack.mitre.org/techniques/T1550');

-- Collection (TA0009)
INSERT INTO `tags` (`techniqueID`, `name`, `category`, `description`, `url`) VALUES
('T1560', 'Archive Collected Data', 'Collection', 'An adversary may compress and/or encrypt data that is collected prior to exfiltration.', 'https://attack.mitre.org/techniques/T1560'),
('T1123', 'Audio Capture', 'Collection', 'Adversaries may use peripheral devices such as microphones to capture audio recordings.', 'https://attack.mitre.org/techniques/T1123'),
('T1119', 'Automated Collection', 'Collection', 'Once established within a system or network, adversaries may use automated techniques for collecting internal data.', 'https://attack.mitre.org/techniques/T1119'),
('T1185', 'Browser Session Hijacking', 'Collection', 'Adversaries may take advantage of security vulnerabilities and inherent functionality in browser software to change content.', 'https://attack.mitre.org/techniques/T1185'),
('T1115', 'Clipboard Data', 'Collection', 'Adversaries may collect data stored in the clipboard from users copying information within or between applications.', 'https://attack.mitre.org/techniques/T1115'),
('T1530', 'Data from Cloud Storage', 'Collection', 'Adversaries may access data from improperly secured cloud storage.', 'https://attack.mitre.org/techniques/T1530'),
('T1602', 'Data from Configuration Repository', 'Collection', 'Adversaries may collect data related to managed devices from configuration repositories.', 'https://attack.mitre.org/techniques/T1602'),
('T1213', 'Data from Information Repositories', 'Collection', 'Adversaries may leverage information repositories to mine valuable information.', 'https://attack.mitre.org/techniques/T1213'),
('T1005', 'Data from Local System', 'Collection', 'Adversaries may search local system sources to find files of interest.', 'https://attack.mitre.org/techniques/T1005'),
('T1039', 'Data from Network Shared Drive', 'Collection', 'Adversaries may search network shares on computers to find files of interest.', 'https://attack.mitre.org/techniques/T1039'),
('T1025', 'Data from Removable Media', 'Collection', 'Adversaries may search connected removable media on computers for files of interest.', 'https://attack.mitre.org/techniques/T1025'),
('T1074', 'Data Staged', 'Collection', 'Adversaries may stage collected data in a central location or directory prior to exfiltration.', 'https://attack.mitre.org/techniques/T1074'),
('T1114', 'Email Collection', 'Collection', 'Adversaries may target user email to collect sensitive information.', 'https://attack.mitre.org/techniques/T1114'),
('T1056', 'Input Capture', 'Collection', 'Adversaries may use methods of capturing user input to obtain credentials or collect information.', 'https://attack.mitre.org/techniques/T1056'),
('T1113', 'Screen Capture', 'Collection', 'Adversaries may attempt to take screen captures of the desktop.', 'https://attack.mitre.org/techniques/T1113'),
('T1125', 'Video Capture', 'Collection', 'Adversaries may use peripheral devices such as webcams or external cameras to capture video.', 'https://attack.mitre.org/techniques/T1125');

-- Command and Control (TA0011)
INSERT INTO `tags` (`techniqueID`, `name`, `category`, `description`, `url`) VALUES
('T1071', 'Application Layer Protocol', 'Command and Control', 'Adversaries may communicate using application layer protocols to avoid detection.', 'https://attack.mitre.org/techniques/T1071'),
('T1092', 'Communication Through Removable Media', 'Command and Control', 'Adversaries can perform command and control between compromised hosts on disconnected networks.', 'https://attack.mitre.org/techniques/T1092'),
('T1132', 'Data Encoding', 'Command and Control', 'Adversaries may encode data to make the content of command and control traffic more difficult to detect.', 'https://attack.mitre.org/techniques/T1132'),
('T1001', 'Data Obfuscation', 'Command and Control', 'Adversaries may obfuscate command and control traffic to make it more difficult to detect.', 'https://attack.mitre.org/techniques/T1001'),
('T1568', 'Dynamic Resolution', 'Command and Control', 'Adversaries may dynamically establish connections to command and control infrastructure.', 'https://attack.mitre.org/techniques/T1568'),
('T1573', 'Encrypted Channel', 'Command and Control', 'Adversaries may employ a known encryption algorithm to conceal command and control traffic.', 'https://attack.mitre.org/techniques/T1573'),
('T1008', 'Fallback Channels', 'Command and Control', 'Adversaries may use fallback or alternate communication channels if the primary channel is compromised.', 'https://attack.mitre.org/techniques/T1008'),
('T1105', 'Ingress Tool Transfer', 'Command and Control', 'Adversaries may transfer tools or other files from an external system into a compromised environment.', 'https://attack.mitre.org/techniques/T1105'),
('T1104', 'Multi-Stage Channels', 'Command and Control', 'Adversaries may create multiple stages for command and control that are employed under different conditions.', 'https://attack.mitre.org/techniques/T1104'),
('T1095', 'Non-Application Layer Protocol', 'Command and Control', 'Adversaries may use a non-application layer protocol for communication between host and C2 server.', 'https://attack.mitre.org/techniques/T1095'),
('T1571', 'Non-Standard Port', 'Command and Control', 'Adversaries may communicate using a protocol and port pairing that are typically not associated.', 'https://attack.mitre.org/techniques/T1571'),
('T1572', 'Protocol Tunneling', 'Command and Control', 'Adversaries may tunnel network communications to and from a victim system within a separate protocol.', 'https://attack.mitre.org/techniques/T1572'),
('T1090', 'Proxy', 'Command and Control', 'Adversaries may use a connection proxy to direct network traffic between systems.', 'https://attack.mitre.org/techniques/T1090'),
('T1219', 'Remote Access Software', 'Command and Control', 'An adversary may use legitimate desktop support and remote access software to establish command and control.', 'https://attack.mitre.org/techniques/T1219'),
('T1205', 'Traffic Signaling', 'Command and Control', 'Adversaries may use traffic signaling to hide open ports or other malicious functionality.', 'https://attack.mitre.org/techniques/T1205'),
('T1102', 'Web Service', 'Command and Control', 'Adversaries may use an existing, legitimate external Web service as a means for relaying data.', 'https://attack.mitre.org/techniques/T1102');

-- Exfiltration (TA0010)
INSERT INTO `tags` (`techniqueID`, `name`, `category`, `description`, `url`) VALUES
('T1020', 'Automated Exfiltration', 'Exfiltration', 'Adversaries may exfiltrate data, such as sensitive documents, through the use of automated processing.', 'https://attack.mitre.org/techniques/T1020'),
('T1030', 'Data Transfer Size Limits', 'Exfiltration', 'Adversaries may exfiltrate data in fixed size chunks instead of whole files.', 'https://attack.mitre.org/techniques/T1030'),
('T1048', 'Exfiltration Over Alternative Protocol', 'Exfiltration', 'Adversaries may steal data by exfiltrating it over a different protocol than the existing command and control channel.', 'https://attack.mitre.org/techniques/T1048'),
('T1041', 'Exfiltration Over C2 Channel', 'Exfiltration', 'Adversaries may steal data by exfiltrating it over an existing command and control channel.', 'https://attack.mitre.org/techniques/T1041'),
('T1011', 'Exfiltration Over Other Network Medium', 'Exfiltration', 'Adversaries may attempt to exfiltrate data over a different network medium than the command and control channel.', 'https://attack.mitre.org/techniques/T1011'),
('T1052', 'Exfiltration Over Physical Medium', 'Exfiltration', 'Adversaries may attempt to exfiltrate data via a physical medium.', 'https://attack.mitre.org/techniques/T1052'),
('T1567', 'Exfiltration Over Web Service', 'Exfiltration', 'Adversaries may use an existing, legitimate external Web service to exfiltrate data.', 'https://attack.mitre.org/techniques/T1567'),
('T1029', 'Scheduled Transfer', 'Exfiltration', 'Adversaries may schedule data exfiltration to be performed only at certain times of day.', 'https://attack.mitre.org/techniques/T1029'),
('T1537', 'Transfer Data to Cloud Account', 'Exfiltration', 'Adversaries may exfiltrate data by transferring the data to another cloud account.', 'https://attack.mitre.org/techniques/T1537');

-- Impact (TA0040)
INSERT INTO `tags` (`techniqueID`, `name`, `category`, `description`, `url`) VALUES
('T1531', 'Account Access Removal', 'Impact', 'Adversaries may interrupt availability of system and network resources by inhibiting access to accounts.', 'https://attack.mitre.org/techniques/T1531'),
('T1485', 'Data Destruction', 'Impact', 'Adversaries may destroy data and files on specific systems or in large numbers on a network.', 'https://attack.mitre.org/techniques/T1485'),
('T1486', 'Data Encrypted for Impact', 'Impact', 'Adversaries may encrypt data on target systems or on large numbers of systems in a network to interrupt availability.', 'https://attack.mitre.org/techniques/T1486'),
('T1565', 'Data Manipulation', 'Impact', 'Adversaries may insert, delete, or manipulate data in order to influence external outcomes.', 'https://attack.mitre.org/techniques/T1565'),
('T1491', 'Defacement', 'Impact', 'Adversaries may modify visual content available internally or externally to an enterprise network.', 'https://attack.mitre.org/techniques/T1491'),
('T1561', 'Disk Wipe', 'Impact', 'Adversaries may wipe or corrupt raw disk data on specific systems or in large numbers on a network.', 'https://attack.mitre.org/techniques/T1561'),
('T1499', 'Endpoint Denial of Service', 'Impact', 'Adversaries may perform Endpoint Denial of Service (DoS) attacks to degrade or block the availability of services.', 'https://attack.mitre.org/techniques/T1499'),
('T1495', 'Firmware Corruption', 'Impact', 'Adversaries may overwrite or corrupt the flash memory contents of system BIOS or other firmware.', 'https://attack.mitre.org/techniques/T1495'),
('T1490', 'Inhibit System Recovery', 'Impact', 'Adversaries may delete or remove built-in data and turn off services designed to aid in recovery.', 'https://attack.mitre.org/techniques/T1490'),
('T1498', 'Network Denial of Service', 'Impact', 'Adversaries may perform Network Denial of Service (DoS) attacks to degrade or block the availability of targeted resources.', 'https://attack.mitre.org/techniques/T1498'),
('T1496', 'Resource Hijacking', 'Impact', 'Adversaries may leverage the resources of co-opted systems in order to solve resource intensive problems.', 'https://attack.mitre.org/techniques/T1496'),
('T1489', 'Service Stop', 'Impact', 'Adversaries may stop or disable services on a system to render those services unavailable.', 'https://attack.mitre.org/techniques/T1489'),
('T1529', 'System Shutdown/Reboot', 'Impact', 'Adversaries may shutdown/reboot systems to interrupt access to, or aid in the destruction of, those systems.', 'https://attack.mitre.org/techniques/T1529');

-- =====================================================
-- Summary
-- =====================================================
-- Users: 3 default accounts (admin, validator, annotator)
-- Tags: 140+ MITRE ATT&CK techniques across all tactics
-- Ready for annotations and attack flow generation
