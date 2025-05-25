<?php
require_once 'config/database.php';

try {
    $database = new Database();
    $db = $database->getConnection();
    
    // Vérifier si la table medecin existe
    $stmt = $db->query("SHOW TABLES LIKE 'medecin'");
    if ($stmt->rowCount() == 0) {
        echo "La table medecin n'existe pas. Création en cours...\n";
        
        // Créer la table medecin
        $db->exec("CREATE TABLE medecin (
            id INT AUTO_INCREMENT PRIMARY KEY,
            nom VARCHAR(100) NOT NULL,
            prenom VARCHAR(100) NOT NULL,
            email VARCHAR(255) NOT NULL UNIQUE,
            password VARCHAR(255) NOT NULL,
            num VARCHAR(20) NOT NULL,
            idspecialite INT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )");
        echo "Table medecin créée avec succès.\n";
    } else {
        echo "La table medecin existe déjà.\n";
        
        // Afficher la structure de la table
        $stmt = $db->query("DESCRIBE medecin");
        echo "\nStructure de la table medecin :\n";
        while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
            echo "Colonne : " . $row['Field'] . " - Type : " . $row['Type'] . "\n";
        }
    }
    
} catch(PDOException $e) {
    echo "Erreur : " . $e->getMessage() . "\n";
}
?> 