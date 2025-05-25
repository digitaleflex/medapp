<?php
require_once '../../config/database.php';
require_once '../../models/Message.php';
require_once '../../includes/session.php';

// Vérifier si l'utilisateur est connecté et est un patient
if (!isset($_SESSION['user_id']) || $_SESSION['role'] !== 'patient') {
    http_response_code(403);
    echo json_encode(['error' => 'Non autorisé']);
    exit();
}

// Vérifier si un médecin est sélectionné
if (!isset($_GET['medecin_id'])) {
    http_response_code(400);
    echo json_encode(['error' => 'ID du médecin manquant']);
    exit();
}

$database = new Database();
$db = $database->getConnection();
$message = new Message($db);

// Récupérer la conversation
$stmt = $message->getConversation($_SESSION['user_id'], $_GET['medecin_id']);
$conversation = $stmt->fetchAll(PDO::FETCH_ASSOC);

// Marquer les messages comme lus
foreach ($conversation as $msg) {
    if ($msg['receiver_id'] == $_SESSION['user_id'] && $msg['lu'] == 0) {
        $message->marquerCommeLu($msg['id']);
    }
}

// Renvoyer les messages en JSON
header('Content-Type: application/json');
echo json_encode($conversation); 