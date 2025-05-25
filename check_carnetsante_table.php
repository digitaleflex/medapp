<?php
require_once 'config/database.php';

try {
    $database = new Database();
    $db = $database->getConnection();
    
    // Vérifier si la table carnetsante existe
    $stmt = $db->query("SHOW TABLES LIKE 'carnetsante'");
    if ($stmt->rowCount() > 0) {
        // Afficher la structure actuelle
        echo "Structure actuelle de la table carnetsante :\n";
        $stmt = $db->query("DESCRIBE carnetsante");
        while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
            echo "Colonne : " . $row['Field'] . " - Type : " . $row['Type'] . "\n";
        }
        
        // Supprimer la table existante
        $db->exec("DROP TABLE carnetsante");
        echo "\nTable carnetsante supprimée.\n";
    }
    
    // Créer la table carnetsante avec la bonne structure
    $db->exec("CREATE TABLE carnetsante (
        id INT AUTO_INCREMENT PRIMARY KEY,
        id_patient INT NOT NULL,
        taille DECIMAL(5,2),
        poids DECIMAL(5,2),
        groupesanguin VARCHAR(10),
        allergie TEXT,
        electrophorese TEXT,
        FOREIGN KEY (id_patient) REFERENCES patient(id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci");
    echo "Table carnetsante créée avec succès.\n";
    
    // Afficher la nouvelle structure
    echo "\nNouvelle structure de la table carnetsante :\n";
    $stmt = $db->query("DESCRIBE carnetsante");
    while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
        echo "Colonne : " . $row['Field'] . " - Type : " . $row['Type'] . "\n";
    }
    
} catch(PDOException $e) {
    echo "Erreur : " . $e->getMessage() . "\n";
}
?> 