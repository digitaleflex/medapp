<?php
require_once 'config/database.php';

try {
    $database = new Database();
    $db = $database->getConnection();
    
    // Vérifier si la table patient existe
    $stmt = $db->query("SHOW TABLES LIKE 'patient'");
    if ($stmt->rowCount() == 0) {
        echo "La table patient n'existe pas. Création en cours...\n";
        
        // Créer la table patient
        $db->exec("CREATE TABLE patient (
            id INT AUTO_INCREMENT PRIMARY KEY,
            nom VARCHAR(100) NOT NULL,
            prenom VARCHAR(100) NOT NULL,
            email VARCHAR(255) NOT NULL UNIQUE,
            password VARCHAR(255) NOT NULL,
            date_naissance DATE NOT NULL,
            sexe ENUM('M', 'F') NOT NULL,
            telephone VARCHAR(20),
            adresse TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )");
        echo "Table patient créée avec succès.\n";
    } else {
        echo "La table patient existe déjà.\n";
    }
    
    // Afficher la structure de la table
    $stmt = $db->query("DESCRIBE patient");
    echo "\nStructure de la table patient :\n";
    while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
        echo "Colonne : " . $row['Field'] . " - Type : " . $row['Type'] . "\n";
    }
    
} catch(PDOException $e) {
    echo "Erreur : " . $e->getMessage() . "\n";
}
?> 