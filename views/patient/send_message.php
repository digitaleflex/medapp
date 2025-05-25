<?php
require_once '../../config/database.php';
require_once '../../models/Message.php';
require_once '../../includes/session.php';

// Vérifier si l'utilisateur est connecté et est un patient
if (!isset($_SESSION['user_id']) || $_SESSION['role'] !== 'patient') {
    http_response_code(403);
    echo json_encode(['success' => false, 'error' => 'Non autorisé']);
    exit();
}

// Vérifier si les données nécessaires sont présentes
if (!isset($_POST['contenu']) || !isset($_POST['receiver_id'])) {
    http_response_code(400);
    echo json_encode(['success' => false, 'error' => 'Données manquantes']);
    exit();
}

$database = new Database();
$db = $database->getConnection();
$message = new Message($db);

// Préparer et envoyer le message
$message->contenu = $_POST['contenu'];
$message->sender_id = $_SESSION['user_id'];
$message->receiver_id = $_POST['receiver_id'];
$message->sender_type = 'patient';

// Renvoyer la réponse en JSON
header('Content-Type: application/json');
if ($message->envoyer()) {
    echo json_encode(['success' => true]);
} else {
    echo json_encode(['success' => false, 'error' => 'Erreur lors de l\'envoi du message']);
} 