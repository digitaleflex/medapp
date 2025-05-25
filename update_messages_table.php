<?php
require_once 'config/database.php';

try {
    $database = new Database();
    $db = $database->getConnection();
    
    // Vérifier si la table messages existe
    $stmt = $db->query("SHOW TABLES LIKE 'messages'");
    if ($stmt->rowCount() > 0) {
        echo "La table messages existe déjà. Sauvegarde des données existantes...\n";
        
        // Sauvegarder les données existantes
        $stmt = $db->query("SELECT * FROM messages");
        $messages = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
        // Supprimer la table existante
        $db->exec("DROP TABLE messages");
        echo "Table messages supprimée.\n";
    }
    
    // Créer la nouvelle table messages
    $sql = "CREATE TABLE messages (
        id INT AUTO_INCREMENT PRIMARY KEY,
        contenu TEXT NOT NULL,
        date_envoi DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        sender_id INT NOT NULL,
        receiver_id INT NOT NULL,
        sender_type ENUM('patient', 'medecin') NOT NULL,
        lu BOOLEAN DEFAULT FALSE,
        INDEX idx_sender (sender_id, sender_type),
        INDEX idx_receiver (receiver_id),
        INDEX idx_date (date_envoi)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci";
    
    $db->exec($sql);
    echo "Nouvelle table messages créée avec succès.\n";
    
    // Restaurer les données si elles existaient
    if (!empty($messages)) {
        echo "Restauration des données...\n";
        $stmt = $db->prepare("
            INSERT INTO messages (contenu, date_envoi, sender_id, receiver_id, sender_type, lu)
            VALUES (?, ?, ?, ?, ?, ?)
        ");
        
        foreach ($messages as $message) {
            $stmt->execute([
                $message['contenu'],
                $message['date_envoi'],
                $message['sender_id'],
                $message['receiver_id'],
                $message['sender_type'] ?? 'patient', // Valeur par défaut si sender_type n'existait pas
                $message['lu']
            ]);
        }
        echo "Données restaurées avec succès.\n";
    }
    
    echo "Mise à jour terminée avec succès !";
    
} catch (PDOException $e) {
    die("Erreur lors de la mise à jour : " . $e->getMessage());
} 