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

// Vérification des données POST
if (!isset($_POST['receiver_id']) || !isset($_POST['contenu']) || empty(trim($_POST['contenu']))) {
    http_response_code(400);
    echo json_encode(['error' => 'Données manquantes']);
    exit;
}

$db = (new Database())->getConnection();

try {
    // Détermination du type d'expéditeur (patient ou médecin)
    $user_id = $_SESSION['user_id'];
    $sender_type = isset($_SESSION['role']) && $_SESSION['role'] === 'medecin' ? 'medecin' : 'patient';
    $receiver_id = (int)$_POST['receiver_id'];
    $contenu = trim($_POST['contenu']);

    // Vérification que le sender_type correspond au rôle de l'utilisateur
    if (($sender_type === 'medecin' && $_SESSION['role'] !== 'medecin') ||
        ($sender_type === 'patient' && $_SESSION['role'] !== 'patient')) {
        http_response_code(403);
        echo json_encode(['error' => 'Type d\'expéditeur invalide']);
        exit;
    }

    // Insertion du message
    $stmt = $db->prepare("
        INSERT INTO messages (contenu, date_envoi, sender_id, receiver_id, sender_type, lu) 
        VALUES (?, NOW(), ?, ?, ?, 0)
    ");
    
    $success = $stmt->execute([$contenu, $user_id, $receiver_id, $sender_type]);

    header('Content-Type: application/json');
    echo json_encode(['success' => $success]);

} catch (PDOException $e) {
    error_log("Erreur dans envoyer_message.php: " . $e->getMessage());
    http_response_code(500);
    echo json_encode(['error' => 'Erreur serveur']);
} 