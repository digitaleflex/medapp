<?php
require_once 'config/database.php';

try {
    $database = new Database();
    $db = $database->getConnection();
    
    // Vérifier si la table profilpatient existe
    $stmt = $db->query("SHOW TABLES LIKE 'profilpatient'");
    if ($stmt->rowCount() > 0) {
        // Afficher la structure actuelle
        echo "Structure actuelle de la table profilpatient :\n";
        $stmt = $db->query("DESCRIBE profilpatient");
        while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
            echo "Colonne : " . $row['Field'] . " - Type : " . $row['Type'] . "\n";
        }
        
        // Supprimer la table existante
        $db->exec("DROP TABLE profilpatient");
        echo "\nTable profilpatient supprimée.\n";
    }
    
    // Créer la table profilpatient avec la bonne structure
    $db->exec("CREATE TABLE profilpatient (
        id INT AUTO_INCREMENT PRIMARY KEY,
        idpatient INT NOT NULL,
        adresse TEXT,
        profession VARCHAR(255),
        FOREIGN KEY (idpatient) REFERENCES patient(id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci");
    echo "Table profilpatient créée avec succès.\n";
    
    // Afficher la nouvelle structure
    echo "\nNouvelle structure de la table profilpatient :\n";
    $stmt = $db->query("DESCRIBE profilpatient");
    while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
        echo "Colonne : " . $row['Field'] . " - Type : " . $row['Type'] . "\n";
    }
    
} catch(PDOException $e) {
    echo "Erreur : " . $e->getMessage() . "\n";
}
?> 