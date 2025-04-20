-- phpMyAdmin SQL Dump
-- version 5.2.1
-- https://www.phpmyadmin.net/
--
-- Hôte : 127.0.0.1
-- Généré le : dim. 20 avr. 2025 à 14:31
-- Version du serveur : 10.4.32-MariaDB
-- Version de PHP : 8.0.30

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Base de données : `medconnectdb`
--

-- --------------------------------------------------------

--
-- Structure de la table `admin`
--

CREATE TABLE `admin` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `nom` varchar(100) NOT NULL,
  `prenom` varchar(100) NOT NULL,
  `datenais` date NOT NULL,
  `email` varchar(100) NOT NULL,
  `contact` varchar(20) NOT NULL,
  `password` varchar(500) NOT NULL,
  `role` varchar(100) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- Structure de la table `carnetsante`
--

CREATE TABLE `carnetsante` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `groupesanguin` varchar(10) DEFAULT NULL,
  `taille` float DEFAULT NULL,
  `poids` float DEFAULT NULL,
  `allergie` text DEFAULT NULL,
  `electrophorese` text DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Structure de la table `hopitaux`
--

CREATE TABLE `hopitaux` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `nom` varchar(100) DEFAULT NULL,
  `localisation` text DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Structure de la table `medecin`
--

CREATE TABLE `medecin` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `nom` varchar(100) DEFAULT NULL,
  `prenom` varchar(100) DEFAULT NULL,
  `datenais` date NOT NULL,
  `email` varchar(100) DEFAULT NULL,
  `contact` varchar(20) DEFAULT NULL,
  `password` varchar(255) NOT NULL,
  `role` varchar(100) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Structure de la table `patient`
--

CREATE TABLE `patient` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `nom` varchar(100) DEFAULT NULL,
  `prenom` varchar(100) DEFAULT NULL,
  `datenais` date DEFAULT NULL,
  `email` varchar(100) DEFAULT NULL,
  `contact` varchar(20) DEFAULT NULL,
  `password` varchar(500) NOT NULL,
  `role` varchar(100) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;


-- Structure de la table `pharmacie`
--

CREATE TABLE `pharmacie` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `nom` varchar(100) DEFAULT NULL,
  `localisation` text DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Structure de la table `prixconsultation`
--

CREATE TABLE `prixconsultation` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `prix` decimal(10,2) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Structure de la table `profilmedecin`
--

CREATE TABLE `profilmedecin` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `adresse` text DEFAULT NULL,
  `profession` varchar(100) DEFAULT NULL,
  `imgdiplome` text DEFAULT NULL,
  `disponibilite` text DEFAULT NULL,
  `idmedecin` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  CONSTRAINT `profilmedecin_ibfk_1` FOREIGN KEY (`idmedecin`) REFERENCES `medecin` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Structure de la table `profilpatient`
--

CREATE TABLE `profilpatient` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `adresse` text DEFAULT NULL,
  `profession` varchar(100) DEFAULT NULL,
  `idpatient` int(11) NOT NULL,
  `idcarnetsante` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  CONSTRAINT `profilpatient_ibfk_1` FOREIGN KEY (`idpatient`) REFERENCES `patient` (`id`),
  CONSTRAINT `profilpatient_ibfk_2` FOREIGN KEY (`idcarnetsante`) REFERENCES `carnetsante` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Structure de la table `rendezvous`
--

CREATE TABLE rendezvous (
  id INT AUTO_INCREMENT PRIMARY KEY,
  dateheure DATETIME,
  statut ENUM('en attente', 'accepté', 'refusé'),
  idmedecin INT NOT NULL,
  idpatient INT NOT NULL,
  FOREIGN KEY (idmedecin) REFERENCES medecin(id),
  FOREIGN KEY (idpatient) REFERENCES patient(id)
);



-- --------------------------------------------------------

--
-- Structure de la table specialite
--

CREATE TABLE specialite (
  id int(11) NOT NULL,
  nomspecialite varchar(100) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--

-- --------------------------------------------------------

--
-- Structure de la table `consultation`
--

CREATE TABLE `consultation` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `dateheure` datetime DEFAULT NULL,
  `type` enum('chat','visio') DEFAULT NULL,
  `compterendu` text DEFAULT NULL,
  `idpatient` int(11) DEFAULT NULL,
  `idmedecin` int(11) DEFAULT NULL,
  `idprixconsultation` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `idPatient` (`idpatient`),
  KEY `idMedecin` (`idmedecin`),
  KEY `idPrixConsultation` (`idprixconsultation`),
  CONSTRAINT `consultation_ibfk_1` FOREIGN KEY (`idPatient`) REFERENCES `patient` (`id`),
  CONSTRAINT `consultation_ibfk_2` FOREIGN KEY (`idMedecin`) REFERENCES `medecin` (`id`),
  CONSTRAINT `consultation_ibfk_3` FOREIGN KEY (`idPrixConsultation`) REFERENCES `prixconsultation` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
