<?php
require_once 'config/config.php';

try {
    // Initialiser la configuration
    Config::init();
    
    // Obtenir la connexion à la base de données
    $pdo = Config::getDbConnection();
    
    // Vérifier la table specialite
    $query = "SELECT * FROM specialite";
    $stmt = $pdo->query($query);
    $specialites = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    echo "Spécialités :\n";
    print_r($specialites);
    
    // Vérifier la table medecin
    $query = "SELECT * FROM medecin";
    $stmt = $pdo->query($query);
    $medecins = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    echo "\nMédecins :\n";
    print_r($medecins);
    
    // Vérifier la table medecin_specialite
    $query = "SELECT ms.*, m.nom, m.prenom, s.nomspecialite 
              FROM medecin_specialite ms 
              JOIN medecin m ON ms.idmedecin = m.id 
              JOIN specialite s ON ms.idspecialite = s.id";
    $stmt = $pdo->query($query);
    $associations = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    echo "\nAssociations Médecin-Spécialité :\n";
    print_r($associations);
    
} catch(Exception $e) {
    echo "Erreur : " . $e->getMessage() . "\n";
    if (Config::get('app.debug', false)) {
        echo "Trace :\n" . $e->getTraceAsString() . "\n";
    }
}
?> 