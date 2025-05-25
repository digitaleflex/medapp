<?php
require_once 'config/database.php';

$database = new Database();
$db = $database->getConnection();

try {
    // Supprimer la contrainte existante
    $db->exec("ALTER TABLE profilpatient DROP FOREIGN KEY profilpatient_ibfk_2");
    
    // Ajouter la nouvelle contrainte
    $db->exec("ALTER TABLE profilpatient 
               ADD CONSTRAINT profilpatient_ibfk_2 
               FOREIGN KEY (idcarnetsante) 
               REFERENCES carnetsante(id) 
               ON DELETE CASCADE");
    
    echo "Les contraintes de clé étrangère ont été mises à jour avec succès.\n";
} catch (PDOException $e) {
    echo "Erreur lors de la mise à jour des contraintes : " . $e->getMessage() . "\n";
} 