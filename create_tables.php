<?php
require_once 'config/database.php';

try {
    $db = db();

    // Création de la table specialite
    $db->exec("CREATE TABLE IF NOT EXISTS specialite (
        id INT AUTO_INCREMENT PRIMARY KEY,
        nomspecialite VARCHAR(100) NOT NULL
    )");

    // Création de la table medecin
    $db->exec("CREATE TABLE IF NOT EXISTS medecin (
        id INT AUTO_INCREMENT PRIMARY KEY,
        nom VARCHAR(100) NOT NULL,
        prenom VARCHAR(100) NOT NULL
    )");

    // Création de la table medecin_specialite
    $db->exec("CREATE TABLE IF NOT EXISTS medecin_specialite (
        idmedecin INT,
        idspecialite INT,
        PRIMARY KEY (idmedecin, idspecialite),
        FOREIGN KEY (idmedecin) REFERENCES medecin(id) ON DELETE CASCADE,
        FOREIGN KEY (idspecialite) REFERENCES specialite(id) ON DELETE CASCADE
    )");

    echo "Tables créées avec succès !\n";

} catch (Exception $e) {
    echo "Erreur : " . $e->getMessage() . "\n";
} 