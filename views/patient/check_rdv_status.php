<?php
// // Configuration du rapport d'erreurs (à désactiver en production)
// ini_set('display_errors', 0);
// error_reporting(E_ALL); // Enregistre toutes les erreurs mais ne les affiche pas

// // Démarrer la temporisation de sortie
// ob_start();

require_once '../../includes/session.php';
require_once '../../config/database.php';

// Initialiser la réponse JSON
$response = ['success' => false, 'message' => 'Erreur inconnue'];

try {
    // Vérifier la méthode HTTP
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        throw new Exception('Méthode non autorisée', 405);
    }

    // Vérifier l'authentification et les autorisations
    if (!isset($_SESSION['user_id'])) {
        throw new Exception('Authentification requise', 401);
    }

    // Vérifier le type de contenu
    if (!isset($_SERVER['CONTENT_TYPE']) || stripos($_SERVER['CONTENT_TYPE'], 'application/json') === false) {
        throw new Exception('Content-Type doit être application/json', 400);
    }

    // Lire et décoder les données JSON
    $input = json_decode(file_get_contents('php://input'), true);
    if (json_last_error() !== JSON_ERROR_NONE) {
        throw new Exception('JSON invalide: ' . json_last_error_msg(), 400);
    }

    // Valider les données d'entrée
    if (!isset($input['rdv_ids']) || !is_array($input['rdv_ids'])) {
        throw new Exception('Le champ rdv_ids est requis et doit être un tableau', 400);
    }

    // Filtrer les IDs des rendez-vous
    $rdvIds = array_filter($input['rdv_ids'], function($id) {
        return is_numeric($id) && $id > 0;
    });

    if (empty($rdvIds)) {
        throw new Exception('Aucun ID de rendez-vous valide fourni', 400);
    }

    // Connexion à la base de données
    $database = new Database();
    $db = $database->getConnection();

    // Préparation de la requête sécurisée
    $placeholders = implode(',', array_fill(0, count($rdvIds), '?'));
    $query = "SELECT id, statut FROM rendezvous 
              WHERE id IN ($placeholders) 
              AND idmedecin = ?"; // Sécurité supplémentaire

    $stmt = $db->prepare($query);
    
    // Combiner les paramètres (IDs + ID médecin)
    $params = array_merge($rdvIds, [$_SESSION['user_id']]);
    
    if (!$stmt->execute($params)) {
        throw new Exception('Erreur lors de la récupération des statuts', 500);
    }

    $rendezvous = $stmt->fetchAll(PDO::FETCH_ASSOC);

    // Préparer la réponse
    $response = [
        'success' => true,
        'data' => [
            'count' => count($rendezvous),
            'rendezvous' => $rendezvous
        ]
    ];

} catch (Exception $e) {
    error_log('[' . date('Y-m-d H:i:s') . '] Erreur check_rdv_status: ' . $e->getMessage());
    $response = [
        'success' => false,
        'error' => [
            'code' => $e->getCode(),
            'message' => $e->getMessage()
        ]
    ];
} finally {
    // Nettoyer le buffer et envoyer la réponse
    ob_clean();
    header('Content-Type: application/json');
    echo json_encode($response, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
    ob_end_flush();
}