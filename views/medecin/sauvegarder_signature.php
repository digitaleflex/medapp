<?php
// Désactiver l'affichage des erreurs pour éviter qu'elles ne polluent la sortie JSON
ini_set('display_errors', 0);
error_reporting(0);

// S'assurer qu'aucune sortie n'est envoyée avant le JSON
ob_start();

require_once '../../includes/session.php';
require_once '../../config/config.php';

// Fonction pour envoyer une réponse JSON
function sendJsonResponse($success, $message = '', $data = []) {
    ob_clean(); // Nettoyer toute sortie précédente
    header('Content-Type: application/json');
    echo json_encode([
        'success' => $success,
        'message' => $message,
        'data' => $data
    ]);
    exit;
}

try {
    requireLogin();
    requireRole('medecin');

    $user_id = $_SESSION['user_id'];

    // Vérifier si les données nécessaires sont présentes
    if (!isset($_POST['signature']) || !isset($_POST['ordonnance_id'])) {
        error_log('Données manquantes: ' . print_r($_POST, true));
        sendJsonResponse(false, 'Données manquantes');
    }

    $ordonnance_id = intval($_POST['ordonnance_id']);
    $signature_data = $_POST['signature'];

    // Vérifier que l'ordonnance appartient au médecin
    $stmt = db()->prepare('SELECT id FROM ordonnance WHERE id = ? AND idmedecin = ?');
    $stmt->execute([$ordonnance_id, $user_id]);
    
    if (!$stmt->fetch()) {
        error_log('Ordonnance non trouvée ou accès non autorisé. ID: ' . $ordonnance_id . ', User ID: ' . $user_id);
        sendJsonResponse(false, 'Ordonnance non trouvée ou accès non autorisé');
    }

    // Créer le dossier signatures s'il n'existe pas
    $signatures_dir = __DIR__ . '/../../uploads/signatures';
    if (!file_exists($signatures_dir)) {
        if (!mkdir($signatures_dir, 0777, true)) {
            error_log('Impossible de créer le dossier signatures: ' . $signatures_dir);
            sendJsonResponse(false, 'Erreur lors de la création du dossier de signatures');
        }
    }

    // Vérifier les permissions du dossier
    if (!is_writable($signatures_dir)) {
        error_log('Le dossier signatures n\'est pas accessible en écriture: ' . $signatures_dir);
        sendJsonResponse(false, 'Le dossier de signatures n\'est pas accessible en écriture');
    }

    // Générer un nom de fichier unique
    $filename = 'signature_' . $ordonnance_id . '_' . time() . '.png';
    $filepath = $signatures_dir . '/' . $filename;

    // Convertir et sauvegarder l'image
    $signature_data = str_replace('data:image/png;base64,', '', $signature_data);
    $signature_data = base64_decode($signature_data);
    
    if ($signature_data === false) {
        error_log('Erreur lors du décodage de la signature');
        sendJsonResponse(false, 'Erreur lors du décodage de la signature');
    }
    
    if (file_put_contents($filepath, $signature_data) === false) {
        error_log('Erreur lors de l\'écriture du fichier: ' . $filepath);
        sendJsonResponse(false, 'Erreur lors de la sauvegarde de la signature');
    }

    // Mettre à jour la base de données avec le chemin de la signature
    $relative_path = 'uploads/signatures/' . $filename;
    $stmt = db()->prepare('UPDATE ordonnance SET signature = ? WHERE id = ?');
    if (!$stmt->execute([$relative_path, $ordonnance_id])) {
        error_log('Erreur lors de la mise à jour de la base de données');
        sendJsonResponse(false, 'Erreur lors de la mise à jour de la base de données');
    }
    
    sendJsonResponse(true, 'Signature sauvegardée avec succès', ['path' => $relative_path]);

} catch (PDOException $e) {
    error_log('Erreur PDO: ' . $e->getMessage());
    sendJsonResponse(false, 'Erreur de base de données');
} catch (Exception $e) {
    error_log('Erreur générale: ' . $e->getMessage());
    sendJsonResponse(false, 'Une erreur est survenue');
} 