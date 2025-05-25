<?php
require_once 'config/database.php';

try {
    $database = new Database();
    $db = $database->getConnection();
    
    // Vérifier si la table messages existe
    $stmt = $db->query("SHOW TABLES LIKE 'messages'");
    if ($stmt->rowCount() > 0) {
        // Afficher la structure actuelle
        echo "Structure actuelle de la table messages :\n";
        $stmt = $db->query("DESCRIBE messages");
        while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
            echo "Colonne : " . $row['Field'] . " - Type : " . $row['Type'] . "\n";
        }
        
        // Supprimer la table existante
        $db->exec("DROP TABLE messages");
        echo "\nTable messages supprimée.\n";
    }
    
    // Créer la table messages avec la bonne structure
    $db->exec("CREATE TABLE messages (
        id INT AUTO_INCREMENT PRIMARY KEY,
        contenu TEXT NOT NULL,
        date_envoi DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        sender_id INT NOT NULL,
        receiver_id INT NOT NULL,
        lu BOOLEAN DEFAULT FALSE,
        FOREIGN KEY (sender_id) REFERENCES patient(id) ON DELETE CASCADE,
        FOREIGN KEY (receiver_id) REFERENCES medecin(id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci");
    echo "Table messages créée avec succès.\n";
    
    // Insérer quelques messages de test
    $db->exec("INSERT INTO messages (contenu, sender_id, receiver_id, date_envoi) VALUES 
        ('Bonjour docteur', 1, 8, NOW()),
        ('Bonjour, comment puis-je vous aider ?', 8, 1, NOW())");
    echo "Messages de test insérés.\n";
    
    // Afficher la nouvelle structure
    echo "\nNouvelle structure de la table messages :\n";
    $stmt = $db->query("DESCRIBE messages");
    while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
        echo "Colonne : " . $row['Field'] . " - Type : " . $row['Type'] . "\n";
    }
    
} catch(PDOException $e) {
    echo "Erreur : " . $e->getMessage() . "\n";
}
?> 