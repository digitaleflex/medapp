-- phpMyAdmin SQL Dump
-- version 5.2.1
-- https://www.phpmyadmin.net/
--
-- Hôte : 127.0.0.1
-- Généré le : mer. 14 mai 2025 à 15:44
-- Version du serveur : 10.4.32-MariaDB
-- Version de PHP : 8.2.12

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Base de données : `medappdb`
--

-- --------------------------------------------------------

--
-- Structure de la table `admin`
--

CREATE TABLE `admin` (
  `id` int(11) NOT NULL,
  `nom` varchar(100) NOT NULL,
  `prenom` varchar(100) NOT NULL,
  `datenais` date NOT NULL,
  `email` varchar(100) NOT NULL,
  `contact` varchar(20) NOT NULL,
  `password` varchar(500) NOT NULL,
  `role` varchar(100) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Structure de la table `carnetsante`
--

CREATE TABLE `carnetsante` (
  `id` int(11) NOT NULL,
  `id_patient` int(11) NOT NULL,
  `groupesanguin` varchar(10) DEFAULT NULL,
  `taille` decimal(5,2) DEFAULT NULL,
  `poids` decimal(5,2) DEFAULT NULL,
  `allergie` text DEFAULT NULL,
  `electrophorese` text DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Déchargement des données de la table `carnetsante`
--

INSERT INTO `carnetsante` (`id`, `id_patient`, `groupesanguin`, `taille`, `poids`, `allergie`, `electrophorese`, `created_at`, `updated_at`) VALUES
(4, 21, '0+', 165.00, 34.00, 'tomate', 'O', '2025-05-09 15:17:37', '2025-05-09 15:30:17'),
(5, 21, '0+', 165.00, 34.00, 'tomate', 'O', '2025-05-09 15:18:23', '2025-05-09 15:30:17'),
(6, 21, '0+', 165.00, 34.00, 'tomate', 'O', '2025-05-09 15:19:59', '2025-05-09 15:20:14'),
(7, 1, '0+', 165.00, 34.00, 'fleur pollen', '+', '2025-05-10 10:57:30', '2025-05-10 11:11:49'),
(12, 26, '0+', 170.00, 65.00, 'Polléne', '+', '2025-05-12 09:41:45', '2025-05-12 09:43:53');

-- --------------------------------------------------------

--
-- Structure de la table `consultation`
--

CREATE TABLE `consultation` (
  `id` int(11) NOT NULL,
  `id_patient` int(11) NOT NULL,
  `id_medecin` int(11) NOT NULL,
  `date_consultation` datetime NOT NULL,
  `motif` text NOT NULL,
  `observations` text DEFAULT NULL,
  `diagnostic` text DEFAULT NULL,
  `traitement` text DEFAULT NULL,
  `recommandations` text DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Structure de la table `dossiers_medicaux`
--

CREATE TABLE `dossiers_medicaux` (
  `id` int(11) NOT NULL,
  `id_patient` int(11) NOT NULL,
  `antecedents` text DEFAULT NULL,
  `allergies` text DEFAULT NULL,
  `traitements` text DEFAULT NULL,
  `derniere_maj` timestamp NOT NULL DEFAULT current_timestamp(),
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Structure de la table `fichemed`
--

CREATE TABLE `fichemed` (
  `id` int(11) NOT NULL,
  `id_patient` int(11) NOT NULL,
  `id_profil` int(11) NOT NULL,
  `id_carnet` int(11) NOT NULL,
  `lieu_naissance` varchar(100) DEFAULT NULL,
  `situation_familiale` varchar(20) DEFAULT NULL,
  `enfants` int(11) DEFAULT NULL,
  `grossesses` int(11) DEFAULT NULL,
  `num_secu` varchar(20) DEFAULT NULL,
  `groupe_sanguin` varchar(10) DEFAULT NULL,
  `medecin_traitant` varchar(100) DEFAULT NULL,
  `Assurance` varchar(100) DEFAULT NULL,
  `antecedents_familiaux` text DEFAULT NULL,
  `maladies_infantiles` text DEFAULT NULL,
  `antecedents_medicaux` text DEFAULT NULL,
  `antecedents_chirurgicaux` text DEFAULT NULL,
  `allergies` text DEFAULT NULL,
  `intolerance_medicament` text DEFAULT NULL,
  `traitement_regulier` text DEFAULT NULL,
  `vaccins` text DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Structure de la table `google_tokens`
--

CREATE TABLE `google_tokens` (
  `id` int(11) NOT NULL,
  `user_id` int(11) NOT NULL,
  `access_token` text NOT NULL,
  `refresh_token` text DEFAULT NULL,
  `expires_at` datetime NOT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Structure de la table `hopitaux`
--

CREATE TABLE `hopitaux` (
  `id` int(11) NOT NULL,
  `nom` varchar(100) DEFAULT NULL,
  `localisation` text DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Structure de la table `login_attempts`
--

CREATE TABLE `login_attempts` (
  `id` int(11) NOT NULL,
  `email` varchar(100) NOT NULL,
  `ip_address` varchar(45) NOT NULL,
  `attempted_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `success` tinyint(1) NOT NULL DEFAULT 0
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Structure de la table `medecin`
--

CREATE TABLE `medecin` (
  `id` int(11) NOT NULL,
  `nom` varchar(100) DEFAULT NULL,
  `prenom` varchar(100) DEFAULT NULL,
  `datenais` date NOT NULL,
  `email` varchar(100) DEFAULT NULL,
  `contact` varchar(20) DEFAULT NULL,
  `num` varchar(20) NOT NULL,
  `password` varchar(255) NOT NULL,
  `role` varchar(100) NOT NULL,
  `idspecialite` int(11) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Déchargement des données de la table `medecin`
--

INSERT INTO `medecin` (`id`, `nom`, `prenom`, `datenais`, `email`, `contact`, `num`, `password`, `role`, `idspecialite`) VALUES
(5, 'Robert', 'Isabelle', '0000-00-00', NULL, NULL, '', '', '', 0),
(6, 'Richard', 'Thomas', '0000-00-00', NULL, NULL, '', '', '', 0),
(7, 'Durand', 'Julie', '0000-00-00', NULL, NULL, '', '', '', 0),
(8, 'Moreau', 'Philippe', '0000-00-00', NULL, NULL, '', '', '', 0),
(9, 'Laurent', 'Catherine', '0000-00-00', NULL, NULL, '', '', '', 0),
(10, 'Simon', 'Michel', '0000-00-00', NULL, NULL, '', '', '', 0),
(11, 'Michel', 'Anne', '0000-00-00', NULL, NULL, '', '', '', 0),
(12, 'Lefebvre', 'François', '0000-00-00', NULL, NULL, '', '', '', 0),
(13, 'Garcia', 'Lucie', '0000-00-00', NULL, NULL, '', '', '', 0),
(14, 'David', 'Antoine', '0000-00-00', NULL, NULL, '', '', '', 0),
(15, 'Bertrand', 'Émilie', '0000-00-00', NULL, NULL, '', '', '', 0),
(16, 'Martin', 'Marc', '2010-04-29', 'test2@gmail.com', '0157866959', '12345', '$2y$10$KGG6i8iZhvTrZJkT1sgcg.Lx.Lyc.lvIqzO6kyufWk4IUnmgjHCC2', 'medecin', 7),
(17, 'FAFA', 'BAKE', '2000-03-03', 'bake@gmail.com', '0157866959', '1234567890', '$2y$10$PXQbkcvvwbuIfb8UvPa97eBHLlx6xG8VGmNdstu4ipEhKrsc/Y0qm', 'medecin', 10),
(18, 'BALAAM', 'CHARLESSE', '2006-05-25', 'chao@gmail.com', '0157866959', '1234567890', '$2y$10$alROKemqZ2.dy13g4yGoVukHXEDpisgCXOC37f.UZPoQNP/jwxN3m', 'medecin', 8);

-- --------------------------------------------------------

--
-- Structure de la table `medecin_specialite`
--

CREATE TABLE `medecin_specialite` (
  `idmedecin` int(11) NOT NULL,
  `idspecialite` int(11) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Déchargement des données de la table `medecin_specialite`
--

INSERT INTO `medecin_specialite` (`idmedecin`, `idspecialite`) VALUES
(10, 10),
(11, 1),
(11, 4),
(12, 5),
(13, 7),
(14, 6),
(15, 4),
(15, 8);

-- --------------------------------------------------------

--
-- Structure de la table `medicament`
--

CREATE TABLE `medicament` (
  `id` int(11) NOT NULL,
  `id_ordonnance` int(11) NOT NULL,
  `nom_medicament` varchar(255) NOT NULL,
  `dosage` varchar(100) NOT NULL,
  `frequence` varchar(100) NOT NULL,
  `date_debut` date NOT NULL,
  `date_fin` date NOT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Structure de la table `message`
--

CREATE TABLE `message` (
  `id` int(11) NOT NULL,
  `id_expediteur` int(11) NOT NULL,
  `id_destinataire` int(11) NOT NULL,
  `sujet` varchar(255) NOT NULL,
  `contenu` text NOT NULL,
  `lu` tinyint(1) DEFAULT 0,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Structure de la table `messages`
--

CREATE TABLE `messages` (
  `id` int(11) NOT NULL,
  `contenu` text NOT NULL,
  `date_envoi` datetime NOT NULL DEFAULT current_timestamp(),
  `sender_id` int(11) NOT NULL,
  `receiver_id` int(11) NOT NULL,
  `sender_type` enum('patient','medecin') NOT NULL,
  `lu` tinyint(1) DEFAULT 0
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Déchargement des données de la table `messages`
--

INSERT INTO `messages` (`id`, `contenu`, `date_envoi`, `sender_id`, `receiver_id`, `sender_type`, `lu`) VALUES
(1, 'CC', '2025-05-14 08:36:46', 18, 26, 'medecin', 1),
(2, 'comment', '2025-05-14 08:37:00', 18, 26, 'medecin', 1),
(3, 'Je vais bien', '2025-05-14 08:38:13', 26, 18, 'patient', 1),
(4, 'Je vais bien', '2025-05-14 08:38:15', 26, 18, 'patient', 1),
(5, 'Je vais bien', '2025-05-14 08:38:17', 26, 18, 'patient', 1),
(6, 'comment', '2025-05-14 08:45:49', 18, 26, 'medecin', 1),
(7, 'comment', '2025-05-14 08:47:05', 18, 26, 'medecin', 1),
(8, 'comment', '2025-05-14 08:47:14', 18, 26, 'medecin', 1),
(9, 'comment', '2025-05-14 08:48:14', 18, 26, 'medecin', 0),
(10, 'comment', '2025-05-14 08:52:24', 18, 26, 'medecin', 0),
(11, 'oui', '2025-05-14 08:57:50', 26, 18, 'patient', 1),
(12, 'comment', '2025-05-14 08:57:58', 18, 26, 'medecin', 0),
(13, 'salut', '2025-05-14 09:01:16', 26, 18, 'patient', 1),
(14, 'oui', '2025-05-14 09:06:25', 26, 18, 'patient', 1),
(15, 'comment', '2025-05-14 09:13:09', 18, 26, 'medecin', 0),
(16, 'salut', '2025-05-14 09:14:04', 26, 18, 'patient', 0),
(17, 'salut', '2025-05-14 09:14:08', 26, 18, 'patient', 0),
(18, 'CC', '2025-05-14 13:20:56', 26, 18, 'patient', 0);

-- --------------------------------------------------------

--
-- Structure de la table `ordonnance`
--

CREATE TABLE `ordonnance` (
  `id` int(11) NOT NULL,
  `idmedecin` int(11) NOT NULL,
  `idpatient` int(11) NOT NULL,
  `date_creation` datetime NOT NULL DEFAULT current_timestamp(),
  `date_validite` date NOT NULL,
  `medicaments` text NOT NULL,
  `posologie` text NOT NULL,
  `quantite` text NOT NULL,
  `duree_medicament` text NOT NULL,
  `duree_traitement` varchar(50) NOT NULL,
  `instructions` text DEFAULT NULL,
  `signature` varchar(255) DEFAULT NULL,
  `renouvellement` tinyint(1) DEFAULT 0,
  `nombre_renouvellements` int(11) DEFAULT 0,
  `statut` enum('active','expiree','annulee') NOT NULL DEFAULT 'active',
  `signature_medecin` varchar(255) DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Déchargement des données de la table `ordonnance`
--

INSERT INTO `ordonnance` (`id`, `idmedecin`, `idpatient`, `date_creation`, `date_validite`, `medicaments`, `posologie`, `quantite`, `duree_medicament`, `duree_traitement`, `instructions`, `signature`, `renouvellement`, `nombre_renouvellements`, `statut`, `signature_medecin`, `created_at`, `updated_at`) VALUES
(6, 18, 26, '2025-05-12 23:30:34', '2025-05-20', 'quinine', '12', '12COMPRIME', '21', '123', '', 'uploads/signatures/signature_6_1747089568.png', 0, 0, 'active', NULL, '2025-05-12 22:30:34', '2025-05-12 22:39:28');

-- --------------------------------------------------------

--
-- Structure de la table `password_reset`
--

CREATE TABLE `password_reset` (
  `id` int(11) NOT NULL,
  `email` varchar(100) NOT NULL,
  `token` varchar(255) NOT NULL,
  `expire_date` datetime NOT NULL,
  `used` tinyint(1) DEFAULT 0
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Structure de la table `patient`
--

CREATE TABLE `patient` (
  `id` int(11) NOT NULL,
  `nom` varchar(100) DEFAULT NULL,
  `prenom` varchar(100) DEFAULT NULL,
  `datenais` date DEFAULT NULL,
  `sexe` enum('M','F','A') NOT NULL,
  `email` varchar(100) DEFAULT NULL,
  `contact` varchar(20) DEFAULT NULL,
  `password` varchar(500) NOT NULL,
  `role` varchar(100) NOT NULL,
  `id_medecin` int(11) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Déchargement des données de la table `patient`
--

INSERT INTO `patient` (`id`, `nom`, `prenom`, `datenais`, `sexe`, `email`, `contact`, `password`, `role`, `id_medecin`) VALUES
(1, 'Elfrida', 'Marc', '2025-04-16', 'F', 'fleuryemadje5@gmail.com', '35679868', '$2y$10$GsXP/yRYADwkRFf82i7fPuj67E6vPUh0IEjS3VSk6N85vFKDvMkQm', 'patient', NULL),
(21, 'YEMADJE Elfrida', 'Melvine', '2005-02-24', 'F', 'test@gmail.com', '57866959', '$2y$10$h4McT0grvwETfKvzDPa.NOYD2dpdSftj5lWdetw5CuaAvBbzERjcm', 'patient', NULL),
(26, 'boko', 'John', '2007-07-12', 'M', 'john@gmail.com', '+2290157866959', '$2y$10$DvxhPp8qxmgsUHTx2YDibu2Etl4BwSW3N0lKBtyvCpv0kRMigSh7K', 'patient', 18);

-- --------------------------------------------------------

--
-- Structure de la table `pharmacie`
--

CREATE TABLE `pharmacie` (
  `id` int(11) NOT NULL,
  `nom` varchar(100) DEFAULT NULL,
  `localisation` text DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Déchargement des données de la table `pharmacie`
--

INSERT INTO `pharmacie` (`id`, `nom`, `localisation`) VALUES
(1, 'Pharmacie Saint Michel', 'Cotonou, Carrefour Zogbo, à côté de l\'église Saint Michel'),
(2, 'Pharmacie de la Paix', 'Abomey-Calavi, Tankpè, en face du supermarché Leader Price'),
(3, 'Pharmacie des Lagunes', 'Porto-Novo, Rue du marché central, quartier Djègan-Kpèvi'),
(4, 'Pharmacie Universitaire', 'Cotonou, Campus UAC, Faculté des Sciences de la Santé'),
(5, 'Pharmacie Etoile du Sud', 'Parakou, Quartier Zongo, à 200m du rond-point Bio Guèra'),
(6, 'Pharmacie Soleil', 'Bohicon, Route de Dassa, à proximité de la station Total'),
(7, 'Pharmacie le Bon Samaritain', 'Djougou, Rue du Lycée, face à la mairie'),
(8, 'Pharmacie Centrale de Natitingou', 'Natitingou, Rue principale, à côté du commissariat'),
(9, 'Pharmacie Médicale', 'Ouidah, Quartier Pahou, près de l\'hôpital Saint Camille'),
(10, 'Pharmacie Renaissance', 'Lokossa, Place de l\'Indépendance, face à l\'ancienne poste');

-- --------------------------------------------------------

--
-- Structure de la table `prixconsultation`
--

CREATE TABLE `prixconsultation` (
  `id` int(11) NOT NULL,
  `prix` decimal(10,2) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Structure de la table `profilmedecin`
--

CREATE TABLE `profilmedecin` (
  `id` int(11) NOT NULL,
  `adresse` text DEFAULT NULL,
  `profession` varchar(100) DEFAULT NULL,
  `imgdiplome` text DEFAULT NULL,
  `disponibilite` text DEFAULT NULL,
  `idmedecin` int(11) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Déchargement des données de la table `profilmedecin`
--

INSERT INTO `profilmedecin` (`id`, `adresse`, `profession`, `imgdiplome`, `disponibilite`, `idmedecin`) VALUES
(1, '', '', 'diplome_8_1746482516.pdf', '', 8),
(2, '', '', 'diplome_8_1746482516.pdf', '', 8),
(3, 'nozresdicx, ', NULL, 'diplome_8_1746482516.pdf', 'rezdsetd', 8),
(4, '', NULL, NULL, '', 8),
(5, '', NULL, NULL, '', 8),
(6, '', NULL, NULL, '', 16);

-- --------------------------------------------------------

--
-- Structure de la table `profilpatient`
--

CREATE TABLE `profilpatient` (
  `id` int(11) NOT NULL,
  `adresse` text DEFAULT NULL,
  `profession` varchar(100) DEFAULT NULL,
  `idpatient` int(11) NOT NULL,
  `idcarnetsante` int(11) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Déchargement des données de la table `profilpatient`
--

INSERT INTO `profilpatient` (`id`, `adresse`, `profession`, `idpatient`, `idcarnetsante`) VALUES
(14, 'cotonou', 'Etudiante', 21, 6),
(23, 'john@gmail.com', 'etudiant', 26, 12);

-- --------------------------------------------------------

--
-- Structure de la table `rendezvous`
--

CREATE TABLE `rendezvous` (
  `id` int(11) NOT NULL,
  `dateheure` datetime DEFAULT NULL,
  `statut` enum('en attente','accepté','refusé') DEFAULT NULL,
  `idmedecin` int(11) NOT NULL,
  `idpatient` int(11) NOT NULL,
  `idspecialite` int(11) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Déchargement des données de la table `rendezvous`
--

INSERT INTO `rendezvous` (`id`, `dateheure`, `statut`, `idmedecin`, `idpatient`, `idspecialite`) VALUES
(16, '2025-05-24 17:30:00', '', 14, 1, 6),
(17, '2025-05-31 16:30:00', '', 5, 1, 5),
(18, '2025-06-08 17:00:00', '', 15, 1, 8),
(19, '2025-05-31 16:30:00', 'en attente', 14, 1, 10),
(20, '2025-05-31 16:30:00', 'en attente', 14, 1, 10),
(21, '2025-05-24 17:30:00', 'en attente', 16, 21, 7),
(22, '2025-05-24 17:00:00', 'en attente', 16, 21, 7),
(23, '2025-05-25 17:30:00', 'en attente', 18, 26, 8);

-- --------------------------------------------------------

--
-- Structure de la table `sessions`
--

CREATE TABLE `sessions` (
  `id` int(11) NOT NULL,
  `session_id` varchar(255) NOT NULL,
  `user_id` int(11) NOT NULL,
  `user_agent` varchar(255) DEFAULT NULL,
  `ip_address` varchar(45) DEFAULT NULL,
  `last_activity` timestamp NOT NULL DEFAULT current_timestamp(),
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Structure de la table `specialite`
--

CREATE TABLE `specialite` (
  `id` int(11) NOT NULL,
  `nomspecialite` varchar(100) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Déchargement des données de la table `specialite`
--

INSERT INTO `specialite` (`id`, `nomspecialite`) VALUES
(1, 'Cardiologie'),
(3, 'Gynécologie'),
(4, 'Neurologie'),
(5, 'Ophtalmologie'),
(6, 'ORL'),
(7, 'Pédiatrie'),
(8, 'Psychiatrie'),
(9, 'Radiologie'),
(10, 'Urologie');

-- --------------------------------------------------------

--
-- Structure de la table `typing_status`
--

CREATE TABLE `typing_status` (
  `id` int(11) NOT NULL,
  `user_id` int(11) NOT NULL,
  `receiver_id` int(11) NOT NULL,
  `sender_type` enum('patient','medecin') NOT NULL,
  `is_typing` tinyint(1) DEFAULT 0,
  `last_updated` datetime NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Déchargement des données de la table `typing_status`
--

INSERT INTO `typing_status` (`id`, `user_id`, `receiver_id`, `sender_type`, `is_typing`, `last_updated`) VALUES
(15, 26, 18, 'patient', 0, '2025-05-14 13:20:59'),
(16, 26, 18, 'patient', 1, '2025-05-14 13:20:59'),
(17, 26, 18, 'patient', 0, '2025-05-14 13:21:06');

-- --------------------------------------------------------

--
-- Structure de la table `users`
--

CREATE TABLE `users` (
  `id` int(11) NOT NULL,
  `nom` varchar(100) NOT NULL,
  `prenom` varchar(100) NOT NULL,
  `email` varchar(100) NOT NULL,
  `password` varchar(255) DEFAULT NULL,
  `google_id` varchar(100) DEFAULT NULL,
  `role` enum('patient','medecin','admin') NOT NULL,
  `auth_method` enum('standard','google') DEFAULT 'standard',
  `date_creation` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Structure de la table `vaccins`
--

CREATE TABLE `vaccins` (
  `id` int(11) NOT NULL,
  `id_patient` int(11) NOT NULL,
  `nom_vaccin` varchar(255) NOT NULL,
  `date_vaccination` date DEFAULT NULL,
  `date_rappel` date DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Index pour les tables déchargées
--

--
-- Index pour la table `admin`
--
ALTER TABLE `admin`
  ADD PRIMARY KEY (`id`);

--
-- Index pour la table `carnetsante`
--
ALTER TABLE `carnetsante`
  ADD PRIMARY KEY (`id`),
  ADD KEY `id_patient` (`id_patient`);

--
-- Index pour la table `consultation`
--
ALTER TABLE `consultation`
  ADD PRIMARY KEY (`id`),
  ADD KEY `id_patient` (`id_patient`),
  ADD KEY `id_medecin` (`id_medecin`);

--
-- Index pour la table `dossiers_medicaux`
--
ALTER TABLE `dossiers_medicaux`
  ADD PRIMARY KEY (`id`),
  ADD KEY `id_patient` (`id_patient`);

--
-- Index pour la table `fichemed`
--
ALTER TABLE `fichemed`
  ADD PRIMARY KEY (`id`),
  ADD KEY `id_patient` (`id_patient`),
  ADD KEY `id_profil` (`id_profil`),
  ADD KEY `id_carnet` (`id_carnet`);

--
-- Index pour la table `google_tokens`
--
ALTER TABLE `google_tokens`
  ADD PRIMARY KEY (`id`),
  ADD KEY `user_id` (`user_id`);

--
-- Index pour la table `hopitaux`
--
ALTER TABLE `hopitaux`
  ADD PRIMARY KEY (`id`);

--
-- Index pour la table `login_attempts`
--
ALTER TABLE `login_attempts`
  ADD PRIMARY KEY (`id`),
  ADD KEY `idx_login_email_ip` (`email`,`ip_address`),
  ADD KEY `idx_login_attempted_at` (`attempted_at`);

--
-- Index pour la table `medecin`
--
ALTER TABLE `medecin`
  ADD PRIMARY KEY (`id`);

--
-- Index pour la table `medecin_specialite`
--
ALTER TABLE `medecin_specialite`
  ADD PRIMARY KEY (`idmedecin`,`idspecialite`),
  ADD KEY `idspecialite` (`idspecialite`);

--
-- Index pour la table `medicament`
--
ALTER TABLE `medicament`
  ADD PRIMARY KEY (`id`),
  ADD KEY `id_ordonnance` (`id_ordonnance`);

--
-- Index pour la table `message`
--
ALTER TABLE `message`
  ADD PRIMARY KEY (`id`),
  ADD KEY `id_expediteur` (`id_expediteur`),
  ADD KEY `id_destinataire` (`id_destinataire`);

--
-- Index pour la table `messages`
--
ALTER TABLE `messages`
  ADD PRIMARY KEY (`id`),
  ADD KEY `idx_sender` (`sender_id`,`sender_type`),
  ADD KEY `idx_receiver` (`receiver_id`),
  ADD KEY `idx_date` (`date_envoi`);

--
-- Index pour la table `ordonnance`
--
ALTER TABLE `ordonnance`
  ADD PRIMARY KEY (`id`),
  ADD KEY `fk_ordonnance_medecin` (`idmedecin`),
  ADD KEY `fk_ordonnance_patient` (`idpatient`);

--
-- Index pour la table `password_reset`
--
ALTER TABLE `password_reset`
  ADD PRIMARY KEY (`id`);

--
-- Index pour la table `patient`
--
ALTER TABLE `patient`
  ADD PRIMARY KEY (`id`),
  ADD KEY `id_medecin` (`id_medecin`);

--
-- Index pour la table `pharmacie`
--
ALTER TABLE `pharmacie`
  ADD PRIMARY KEY (`id`);

--
-- Index pour la table `prixconsultation`
--
ALTER TABLE `prixconsultation`
  ADD PRIMARY KEY (`id`);

--
-- Index pour la table `profilmedecin`
--
ALTER TABLE `profilmedecin`
  ADD PRIMARY KEY (`id`),
  ADD KEY `profilmedecin_ibfk_1` (`idmedecin`);

--
-- Index pour la table `profilpatient`
--
ALTER TABLE `profilpatient`
  ADD PRIMARY KEY (`id`),
  ADD KEY `profilpatient_ibfk_1` (`idpatient`),
  ADD KEY `profilpatient_ibfk_2` (`idcarnetsante`);

--
-- Index pour la table `rendezvous`
--
ALTER TABLE `rendezvous`
  ADD PRIMARY KEY (`id`),
  ADD KEY `idmedecin` (`idmedecin`),
  ADD KEY `idpatient` (`idpatient`),
  ADD KEY `specialite_rendezvous` (`idspecialite`);

--
-- Index pour la table `sessions`
--
ALTER TABLE `sessions`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `session_id` (`session_id`),
  ADD KEY `fk_sessions_users` (`user_id`),
  ADD KEY `idx_sessions_last_activity` (`last_activity`);

--
-- Index pour la table `specialite`
--
ALTER TABLE `specialite`
  ADD PRIMARY KEY (`id`);

--
-- Index pour la table `typing_status`
--
ALTER TABLE `typing_status`
  ADD PRIMARY KEY (`id`),
  ADD KEY `idx_user_receiver` (`user_id`,`receiver_id`,`sender_type`);

--
-- Index pour la table `users`
--
ALTER TABLE `users`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `email` (`email`),
  ADD KEY `idx_users_email` (`email`),
  ADD KEY `idx_users_google_id` (`google_id`);

--
-- Index pour la table `vaccins`
--
ALTER TABLE `vaccins`
  ADD PRIMARY KEY (`id`),
  ADD KEY `id_patient` (`id_patient`);

--
-- AUTO_INCREMENT pour les tables déchargées
--

--
-- AUTO_INCREMENT pour la table `admin`
--
ALTER TABLE `admin`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT pour la table `carnetsante`
--
ALTER TABLE `carnetsante`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=13;

--
-- AUTO_INCREMENT pour la table `consultation`
--
ALTER TABLE `consultation`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT pour la table `dossiers_medicaux`
--
ALTER TABLE `dossiers_medicaux`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT pour la table `fichemed`
--
ALTER TABLE `fichemed`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=13;

--
-- AUTO_INCREMENT pour la table `google_tokens`
--
ALTER TABLE `google_tokens`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT pour la table `hopitaux`
--
ALTER TABLE `hopitaux`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT pour la table `login_attempts`
--
ALTER TABLE `login_attempts`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT pour la table `medecin`
--
ALTER TABLE `medecin`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=19;

--
-- AUTO_INCREMENT pour la table `medicament`
--
ALTER TABLE `medicament`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT pour la table `message`
--
ALTER TABLE `message`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT pour la table `messages`
--
ALTER TABLE `messages`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=19;

--
-- AUTO_INCREMENT pour la table `ordonnance`
--
ALTER TABLE `ordonnance`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=7;

--
-- AUTO_INCREMENT pour la table `password_reset`
--
ALTER TABLE `password_reset`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT pour la table `patient`
--
ALTER TABLE `patient`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=27;

--
-- AUTO_INCREMENT pour la table `pharmacie`
--
ALTER TABLE `pharmacie`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=11;

--
-- AUTO_INCREMENT pour la table `prixconsultation`
--
ALTER TABLE `prixconsultation`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT pour la table `profilmedecin`
--
ALTER TABLE `profilmedecin`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=7;

--
-- AUTO_INCREMENT pour la table `profilpatient`
--
ALTER TABLE `profilpatient`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=24;

--
-- AUTO_INCREMENT pour la table `rendezvous`
--
ALTER TABLE `rendezvous`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=25;

--
-- AUTO_INCREMENT pour la table `sessions`
--
ALTER TABLE `sessions`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT pour la table `specialite`
--
ALTER TABLE `specialite`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=11;

--
-- AUTO_INCREMENT pour la table `typing_status`
--
ALTER TABLE `typing_status`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=18;

--
-- AUTO_INCREMENT pour la table `users`
--
ALTER TABLE `users`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT pour la table `vaccins`
--
ALTER TABLE `vaccins`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- Contraintes pour les tables déchargées
--

--
-- Contraintes pour la table `carnetsante`
--
ALTER TABLE `carnetsante`
  ADD CONSTRAINT `carnetsante_ibfk_1` FOREIGN KEY (`id_patient`) REFERENCES `patient` (`id`) ON DELETE CASCADE;

--
-- Contraintes pour la table `consultation`
--
ALTER TABLE `consultation`
  ADD CONSTRAINT `consultation_ibfk_1` FOREIGN KEY (`id_patient`) REFERENCES `patient` (`id`) ON DELETE CASCADE,
  ADD CONSTRAINT `consultation_ibfk_2` FOREIGN KEY (`id_medecin`) REFERENCES `medecin` (`id`) ON DELETE CASCADE;

--
-- Contraintes pour la table `dossiers_medicaux`
--
ALTER TABLE `dossiers_medicaux`
  ADD CONSTRAINT `dossiers_medicaux_ibfk_1` FOREIGN KEY (`id_patient`) REFERENCES `patient` (`id`);

--
-- Contraintes pour la table `fichemed`
--
ALTER TABLE `fichemed`
  ADD CONSTRAINT `fichemed_ibfk_1` FOREIGN KEY (`id_patient`) REFERENCES `patient` (`id`) ON DELETE CASCADE,
  ADD CONSTRAINT `fichemed_ibfk_2` FOREIGN KEY (`id_profil`) REFERENCES `profilpatient` (`id`) ON DELETE CASCADE,
  ADD CONSTRAINT `fichemed_ibfk_3` FOREIGN KEY (`id_carnet`) REFERENCES `carnetsante_old` (`id`) ON DELETE CASCADE;

--
-- Contraintes pour la table `google_tokens`
--
ALTER TABLE `google_tokens`
  ADD CONSTRAINT `google_tokens_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE;

--
-- Contraintes pour la table `medecin_specialite`
--
ALTER TABLE `medecin_specialite`
  ADD CONSTRAINT `medecin_specialite_ibfk_1` FOREIGN KEY (`idmedecin`) REFERENCES `medecin` (`id`) ON DELETE CASCADE,
  ADD CONSTRAINT `medecin_specialite_ibfk_2` FOREIGN KEY (`idspecialite`) REFERENCES `specialite` (`id`) ON DELETE CASCADE;

--
-- Contraintes pour la table `medicament`
--
ALTER TABLE `medicament`
  ADD CONSTRAINT `medicament_ibfk_1` FOREIGN KEY (`id_ordonnance`) REFERENCES `ordonnance` (`id`) ON DELETE CASCADE;

--
-- Contraintes pour la table `message`
--
ALTER TABLE `message`
  ADD CONSTRAINT `message_ibfk_1` FOREIGN KEY (`id_expediteur`) REFERENCES `medecin` (`id`) ON DELETE CASCADE,
  ADD CONSTRAINT `message_ibfk_2` FOREIGN KEY (`id_destinataire`) REFERENCES `patient` (`id`) ON DELETE CASCADE;

--
-- Contraintes pour la table `ordonnance`
--
ALTER TABLE `ordonnance`
  ADD CONSTRAINT `fk_ordonnance_medecin` FOREIGN KEY (`idmedecin`) REFERENCES `medecin` (`id`) ON DELETE CASCADE,
  ADD CONSTRAINT `fk_ordonnance_patient` FOREIGN KEY (`idpatient`) REFERENCES `patient` (`id`) ON DELETE CASCADE;

--
-- Contraintes pour la table `patient`
--
ALTER TABLE `patient`
  ADD CONSTRAINT `patient_ibfk_1` FOREIGN KEY (`id_medecin`) REFERENCES `medecin` (`id`);

--
-- Contraintes pour la table `profilmedecin`
--
ALTER TABLE `profilmedecin`
  ADD CONSTRAINT `profilmedecin_ibfk_1` FOREIGN KEY (`idmedecin`) REFERENCES `medecin` (`id`);

--
-- Contraintes pour la table `profilpatient`
--
ALTER TABLE `profilpatient`
  ADD CONSTRAINT `profilpatient_ibfk_1` FOREIGN KEY (`idpatient`) REFERENCES `patient` (`id`) ON DELETE CASCADE,
  ADD CONSTRAINT `profilpatient_ibfk_2` FOREIGN KEY (`idcarnetsante`) REFERENCES `carnetsante` (`id`) ON DELETE CASCADE;

--
-- Contraintes pour la table `rendezvous`
--
ALTER TABLE `rendezvous`
  ADD CONSTRAINT `rendezvous_ibfk_1` FOREIGN KEY (`idmedecin`) REFERENCES `medecin` (`id`),
  ADD CONSTRAINT `rendezvous_ibfk_2` FOREIGN KEY (`idpatient`) REFERENCES `patient` (`id`),
  ADD CONSTRAINT `specialite_rendezvous` FOREIGN KEY (`idspecialite`) REFERENCES `specialite` (`id`);

--
-- Contraintes pour la table `sessions`
--
ALTER TABLE `sessions`
  ADD CONSTRAINT `fk_sessions_users` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE;

--
-- Contraintes pour la table `vaccins`
--
ALTER TABLE `vaccins`
  ADD CONSTRAINT `vaccins_ibfk_1` FOREIGN KEY (`id_patient`) REFERENCES `patient` (`id`);
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
