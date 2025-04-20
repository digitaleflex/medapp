-- Migration pour unifier le système d'authentification
-- Ce script doit être exécuté dans phpMyAdmin pour mettre à jour la structure de la base de données

-- 1. Création de la table users centralisée
CREATE TABLE IF NOT EXISTS `users` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `nom` varchar(100) NOT NULL,
  `prenom` varchar(100) NOT NULL,
  `email` varchar(100) NOT NULL UNIQUE,
  `password` varchar(255) NULL,
  `google_id` varchar(100) NULL,
  `role` enum('patient', 'medecin', 'admin') NOT NULL,
  `date_creation` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- 2. Création des tables relationnelles
CREATE TABLE IF NOT EXISTS `patients` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `user_id` int(11) NOT NULL UNIQUE,
  `datenais` date DEFAULT NULL,
  `contact` varchar(20) DEFAULT NULL,
  PRIMARY KEY (`id`),
  CONSTRAINT `fk_patients_users` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE IF NOT EXISTS `medecins` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `user_id` int(11) NOT NULL UNIQUE,
  `datenais` date DEFAULT NULL,
  `contact` varchar(20) DEFAULT NULL,
  `specialite` varchar(100) DEFAULT NULL,
  PRIMARY KEY (`id`),
  CONSTRAINT `fk_medecins_users` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE IF NOT EXISTS `admins` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `user_id` int(11) NOT NULL UNIQUE,
  `datenais` date DEFAULT NULL,
  `contact` varchar(20) DEFAULT NULL,
  PRIMARY KEY (`id`),
  CONSTRAINT `fk_admins_users` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- 3. Table pour stocker les sessions actives
CREATE TABLE IF NOT EXISTS `sessions` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `session_id` varchar(255) NOT NULL UNIQUE,
  `user_id` int(11) NOT NULL,
  `user_agent` varchar(255) DEFAULT NULL,
  `ip_address` varchar(45) DEFAULT NULL,
  `last_activity` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  CONSTRAINT `fk_sessions_users` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- 4. Ajout des index pour optimiser les recherches
CREATE INDEX `idx_users_email` ON `users` (`email`);
CREATE INDEX `idx_users_google_id` ON `users` (`google_id`);
CREATE INDEX `idx_sessions_last_activity` ON `sessions` (`last_activity`);

-- 5. Migration des données existantes (à exécuter seulement si les anciennes tables contiennent des données)

-- 5.1 Migration des patients
INSERT INTO `users` (`nom`, `prenom`, `email`, `password`, `role`)
SELECT `nom`, `prenom`, `email`, `password`, 'patient'
FROM `patient`
WHERE `email` NOT IN (SELECT `email` FROM `users`);

INSERT INTO `patients` (`user_id`, `datenais`, `contact`)
SELECT u.`id`, p.`datenais`, p.`contact`
FROM `users` u
JOIN `patient` p ON u.`email` = p.`email`
WHERE u.`role` = 'patient'
AND NOT EXISTS (SELECT 1 FROM `patients` WHERE `user_id` = u.`id`);

-- 5.2 Migration des médecins
INSERT INTO `users` (`nom`, `prenom`, `email`, `password`, `role`)
SELECT `nom`, `prenom`, `email`, `password`, 'medecin'
FROM `medecin`
WHERE `email` NOT IN (SELECT `email` FROM `users`);

INSERT INTO `medecins` (`user_id`, `datenais`, `contact`)
SELECT u.`id`, m.`datenais`, m.`contact`
FROM `users` u
JOIN `medecin` m ON u.`email` = m.`email`
WHERE u.`role` = 'medecin'
AND NOT EXISTS (SELECT 1 FROM `medecins` WHERE `user_id` = u.`id`);

-- 5.3 Migration des admins
INSERT INTO `users` (`nom`, `prenom`, `email`, `password`, `role`)
SELECT `nom`, `prenom`, `email`, `password`, 'admin'
FROM `admin`
WHERE `email` NOT IN (SELECT `email` FROM `users`);

INSERT INTO `admins` (`user_id`, `datenais`, `contact`)
SELECT u.`id`, a.`datenais`, a.`contact`
FROM `users` u
JOIN `admin` a ON u.`email` = a.`email`
WHERE u.`role` = 'admin'
AND NOT EXISTS (SELECT 1 FROM `admins` WHERE `user_id` = u.`id`);

-- 6. Mise à jour des relations dans les autres tables pour pointer vers la nouvelle structure
-- Note: Ce code est un exemple et devra être ajusté en fonction de votre schéma spécifique

-- Exemple pour la table rendezvous (ajustez selon votre schéma)
/*
ALTER TABLE `rendezvous` 
ADD COLUMN `patient_user_id` int(11) AFTER `idpatient`,
ADD COLUMN `medecin_user_id` int(11) AFTER `idmedecin`;

UPDATE `rendezvous` r
JOIN `patients` p ON r.`idpatient` = p.`id`
SET r.`patient_user_id` = p.`user_id`;

UPDATE `rendezvous` r
JOIN `medecins` m ON r.`idmedecin` = m.`id`
SET r.`medecin_user_id` = m.`user_id`;

ALTER TABLE `rendezvous`
DROP FOREIGN KEY `rendezvous_ibfk_1`,
DROP FOREIGN KEY `rendezvous_ibfk_2`;

ALTER TABLE `rendezvous`
ADD CONSTRAINT `rendezvous_ibfk_1` FOREIGN KEY (`patient_user_id`) REFERENCES `users` (`id`),
ADD CONSTRAINT `rendezvous_ibfk_2` FOREIGN KEY (`medecin_user_id`) REFERENCES `users` (`id`);
*/

-- 7. Ajout d'une table pour les tentatives de connexion échouées (sécurité)
CREATE TABLE IF NOT EXISTS `login_attempts` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `email` varchar(100) NOT NULL,
  `ip_address` varchar(45) NOT NULL,
  `attempted_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `success` tinyint(1) NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE INDEX `idx_login_email_ip` ON `login_attempts` (`email`, `ip_address`);
CREATE INDEX `idx_login_attempted_at` ON `login_attempts` (`attempted_at`);

-- 8. Ajouter une colonne pour suivre la méthode d'authentification
ALTER TABLE `users` ADD COLUMN `auth_method` enum('standard', 'google') DEFAULT 'standard' AFTER `role`;

-- IMPORTANT: Conserver les anciennes tables jusqu'à ce que la migration soit entièrement testée et validée 