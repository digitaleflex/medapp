<?php
require_once '../includes/session.php';
require_once '../config/database.php';

// Vérification de la session
if (!isset($_SESSION['user_id'])) {
    http_response_code(401);
    echo json_encode(['error' => 'Non autorisé']);
    exit;
}

// Vérification de la méthode HTTP
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['error' => 'Méthode non autorisée']);
    exit;
}

// Récupération des données JSON
$data = json_decode(file_get_contents('php://input'), true);

if (!isset($data['receiver_id']) || !isset($data['is_typing'])) {
    http_response_code(400);
    echo json_encode(['error' => 'Données manquantes']);
    exit;
}

$db = (new Database())->getConnection();

try {
    // Détermination du type d'expéditeur (patient ou médecin)
    $user_id = $_SESSION['user_id'];
    $sender_type = isset($_SESSION['role']) && $_SESSION['role'] === 'medecin' ? 'medecin' : 'patient';
    
    // Mise à jour ou insertion du statut de frappe
    $stmt = $db->prepare("
        INSERT INTO typing_status (user_id, receiver_id, sender_type, is_typing, last_updated)
        VALUES (?, ?, ?, ?, NOW())
        ON DUPLICATE KEY UPDATE 
        is_typing = VALUES(is_typing),
        last_updated = VALUES(last_updated)
    ");
    
    $stmt->execute([
        $user_id,
        $data['receiver_id'],
        $sender_type,
        $data['is_typing'] ? 1 : 0
    ]);

    // Nettoyage des anciens statuts (plus de 10 secondes)
    $stmt = $db->prepare("
        DELETE FROM typing_status 
        WHERE last_updated < DATE_SUB(NOW(), INTERVAL 10 SECOND)
    ");
    $stmt->execute();

    echo json_encode(['success' => true]);

} catch (PDOException $e) {
    error_log("Erreur dans typing.php: " . $e->getMessage());
    http_response_code(500);
    echo json_encode(['error' => 'Erreur serveur']);
} 