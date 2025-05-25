<?php
require_once '../includes/session.php';
require_once '../config/database.php';

// Vérification de la session
if (!isset($_SESSION['user_id'])) {
    http_response_code(401);
    echo json_encode(['error' => 'Non autorisé']);
    exit;
}

// Vérification des paramètres
if (!isset($_GET['user_id'])) {
    http_response_code(400);
    echo json_encode(['error' => 'ID utilisateur manquant']);
    exit;
}

$db = (new Database())->getConnection();

try {
    // Détermination du type d'expéditeur (patient ou médecin)
    $receiver_id = $_SESSION['user_id'];
    $sender_type = isset($_SESSION['role']) && $_SESSION['role'] === 'medecin' ? 'medecin' : 'patient';
    $other_type = $sender_type === 'medecin' ? 'patient' : 'medecin';
    
    // Vérification du statut de frappe
    $stmt = $db->prepare("
        SELECT is_typing 
        FROM typing_status 
        WHERE user_id = ? 
        AND receiver_id = ? 
        AND sender_type = ?
        AND last_updated > DATE_SUB(NOW(), INTERVAL 10 SECOND)
    ");
    
    $stmt->execute([
        $_GET['user_id'],
        $receiver_id,
        $other_type
    ]);
    
    $result = $stmt->fetch(PDO::FETCH_ASSOC);
    
    echo json_encode([
        'is_typing' => $result && $result['is_typing'] == 1
    ]);

} catch (PDOException $e) {
    error_log("Erreur dans check_typing.php: " . $e->getMessage());
    http_response_code(500);
    echo json_encode(['error' => 'Erreur serveur']);
} 