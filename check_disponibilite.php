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
    error_log("Début de l'exécution de check_disponibilite.php");
    
    // Initialiser la configuration
    Config::init();
    error_log("Configuration initialisée");
    
    // Obtenir la connexion à la base de données
    $pdo = Config::getDbConnection();
    error_log("Connexion à la base de données établie");
    
    // Vérifier si les paramètres sont fournis
    if (!isset($_GET['medecin_id']) || !isset($_GET['date'])) {
        throw new Exception('Paramètres manquants');
    }
    
    $medecin_id = intval($_GET['medecin_id']);
    $date = $_GET['date'];
    
    error_log("Médecin ID: " . $medecin_id . ", Date: " . $date);
    
    // Créneaux horaires disponibles (à adapter selon vos besoins)
    $creneaux = [
        '09:00:00', '09:30:00', '10:00:00', '10:30:00',
        '11:00:00', '11:30:00', '14:00:00', '14:30:00',
        '15:00:00', '15:30:00', '16:00:00', '16:30:00',
        '17:00:00', '17:30:00'
    ];
    
    // Récupérer les rendez-vous existants pour cette date et ce médecin
    $query = "SELECT TIME(dateheure) as heure 
              FROM rendezvous 
              WHERE idmedecin = :medecin_id 
              AND DATE(dateheure) = :date 
              AND statut != 'annulé'";
              
    $stmt = $pdo->prepare($query);
    $stmt->execute([
        'medecin_id' => $medecin_id,
        'date' => $date
    ]);
    
    $rdvs_existants = $stmt->fetchAll(PDO::FETCH_COLUMN);
    error_log("Rendez-vous existants : " . print_r($rdvs_existants, true));
    
    // Filtrer les créneaux disponibles
    $creneaux_disponibles = array_filter($creneaux, function($creneau) use ($rdvs_existants) {
        return !in_array($creneau, $rdvs_existants);
    });
    
    error_log("Créneaux disponibles : " . print_r($creneaux_disponibles, true));
    
    // Nettoyer toute sortie précédente
    ob_clean();
    
    // Envoyer la réponse JSON
    echo json_encode(array_values($creneaux_disponibles));
    
} catch (Exception $e) {
    error_log("Erreur dans check_disponibilite.php: " . $e->getMessage());
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