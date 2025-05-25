<?php
require_once 'config/database.php';

$database = new Database();
$db = $database->getConnection();

try {
    // Désactiver temporairement les clés étrangères
    $db->exec("SET FOREIGN_KEY_CHECKS = 0");
    
    // Supprimer toutes les contraintes existantes
    $db->exec("ALTER TABLE profilpatient DROP FOREIGN KEY IF EXISTS profilpatient_ibfk_1");
    $db->exec("ALTER TABLE profilpatient DROP FOREIGN KEY IF EXISTS profilpatient_ibfk_2");
    
    // Vérifier si la table carnetsante_old existe et la supprimer si nécessaire
    $stmt = $db->query("SHOW TABLES LIKE 'carnetsante_old'");
    if ($stmt->rowCount() > 0) {
        $db->exec("DROP TABLE IF EXISTS carnetsante_old");
        echo "Table carnetsante_old supprimée.\n";
    }
    
    // Recréer les contraintes
    $db->exec("ALTER TABLE profilpatient 
               ADD CONSTRAINT profilpatient_ibfk_1 
               FOREIGN KEY (idpatient) 
               REFERENCES patient(id) 
               ON DELETE CASCADE");
               
    $db->exec("ALTER TABLE profilpatient 
               ADD CONSTRAINT profilpatient_ibfk_2 
               FOREIGN KEY (idcarnetsante) 
               REFERENCES carnetsante(id) 
               ON DELETE CASCADE");
    
    // Réactiver les clés étrangères
    $db->exec("SET FOREIGN_KEY_CHECKS = 1");
    
    echo "La structure de la base de données a été corrigée avec succès.\n";
    
} catch (PDOException $e) {
    echo "Erreur lors de la correction de la base de données : " . $e->getMessage() . "\n";
    
    // Réactiver les clés étrangères en cas d'erreur
    $db->exec("SET FOREIGN_KEY_CHECKS = 1");
} 