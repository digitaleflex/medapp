<?php
// Démarrer la capture de sortie
ob_start();

require_once __DIR__ . '/config/config.php';

// Activer l'affichage des erreurs pour le débogage
ini_set('display_errors', 1);
error_reporting(E_ALL);

// Autoriser l'accès depuis le même domaine
header('Access-Control-Allow-Origin: *');
header('Content-Type: application/json');

try {
    error_log("Début de l'exécution de get_medecins.php");
    
    // Initialiser la configuration
    Config::init();
    error_log("Configuration initialisée");
    
    // Obtenir la connexion à la base de données
    $pdo = Config::getDbConnection();
    error_log("Connexion à la base de données établie");
    
    // Vérifier si l'ID de la spécialité est fourni
    if (!isset($_GET['specialite_id'])) {
        throw new Exception('ID de spécialité non fourni');
    }
    
    $specialite_id = intval($_GET['specialite_id']);
    error_log("ID de spécialité reçu : " . $specialite_id);
    
    // Récupérer les médecins pour cette spécialité
    $query = "SELECT m.id, m.nom, m.prenom, s.nomspecialite FROM medecin m JOIN specialite s ON m.idspecialite = s.id WHERE m.idspecialite = :specialite_id";
    
    error_log("Requête SQL : " . $query);
    
    $stmt = $pdo->prepare($query);
    $stmt->execute(['specialite_id' => $specialite_id]);
    $medecins = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    error_log("Nombre de médecins trouvés : " . count($medecins));
    error_log("Médecins trouvés : " . print_r($medecins, true));
    
    // Nettoyer toute sortie précédente
    ob_clean();
    
    // Envoyer la réponse JSON
    echo json_encode($medecins);
    
} catch (Exception $e) {
    error_log("Erreur dans get_medecins.php: " . $e->getMessage());
    error_log("Trace : " . $e->getTraceAsString());
    
    // Nettoyer toute sortie précédente
    ob_clean();
    
    http_response_code(500);
    echo json_encode(['error' => $e->getMessage()]);
}

// Envoyer la sortie et terminer
ob_end_flush();
exit;
?> 