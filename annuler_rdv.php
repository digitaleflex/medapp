<?php
// Activer l'affichage des erreurs pour le débogage
ini_set('display_errors', 1);
error_reporting(E_ALL);

// Démarrer la capture de sortie
ob_start();

// Configurer les en-têtes
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, X-Requested-With');
header('Access-Control-Allow-Credentials: true');

// Gérer les requêtes OPTIONS pour CORS
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit();
}

try {
    error_log("Début de l'exécution de annuler_rdv.php");
    error_log("Méthode de la requête : " . $_SERVER['REQUEST_METHOD']);
    error_log("POST data : " . print_r($_POST, true));
    error_log("GET data : " . print_r($_GET, true));
    error_log("Headers : " . print_r(getallheaders(), true));
    
    // Charger la configuration de session
    require_once __DIR__ . '/includes/session.php';
    require_once __DIR__ . '/config/database.php';

    // Vérifier l'authentification
    requireLogin();
    requireRole('patient');
    
    error_log("Session data : " . print_r($_SESSION, true));
    
    // Vérifier si l'ID du rendez-vous est fourni
    if (!isset($_POST['rdv_id'])) {
        throw new Exception('ID du rendez-vous non fourni');
    }
    
    $rdv_id = intval($_POST['rdv_id']);
    $user_id = $_SESSION['user_id'];
    
    error_log("ID du rendez-vous reçu : " . $rdv_id);
    error_log("ID de l'utilisateur : " . $user_id);
    
    // Vérifier si le rendez-vous existe et appartient au patient
    $query = "SELECT id, statut FROM rendezvous WHERE id = :rdv_id AND idpatient = :patient_id";
    $stmt = db()->prepare($query);
    $stmt->execute([
        'rdv_id' => $rdv_id,
        'patient_id' => $user_id
    ]);
    
    $rdv = $stmt->fetch(PDO::FETCH_ASSOC);
    error_log("Rendez-vous trouvé : " . print_r($rdv, true));
    
    if (!$rdv) {
        throw new Exception('Rendez-vous non trouvé');
    }
    
    if ($rdv['statut'] !== 'en attente') {
        throw new Exception('Ce rendez-vous ne peut pas être annulé');
    }
    
    // Mettre à jour le statut du rendez-vous
    $query = "UPDATE rendezvous SET statut = 'annulé' WHERE id = :rdv_id AND idpatient = :patient_id";
    $stmt = db()->prepare($query);
    $result = $stmt->execute([
        'rdv_id' => $rdv_id,
        'patient_id' => $user_id
    ]);
    
    error_log("Résultat de la mise à jour : " . ($result ? 'succès' : 'échec'));
    
    if (!$result) {
        throw new Exception('Erreur lors de l\'annulation du rendez-vous');
    }
    
    // Nettoyer toute sortie précédente
    ob_clean();
    
    // Envoyer la réponse JSON
    echo json_encode([
        'success' => true, 
        'message' => 'Rendez-vous annulé avec succès',
        'rdv_id' => $rdv_id
    ]);
    
} catch (Exception $e) {
    error_log("Erreur dans annuler_rdv.php: " . $e->getMessage());
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