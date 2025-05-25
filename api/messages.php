<?php
require_once '../includes/session.php';
require_once '../config/database.php';

// Vérification de la session
if (!isset($_SESSION['user_id'])) {
    http_response_code(401);
    echo json_encode(['error' => 'Non autorisé']);
    exit;
}

$user_id = $_SESSION['user_id'];
$user_role = $_SESSION['role'];
$db = (new Database())->getConnection();

// Vérification des paramètres
if (!isset($_GET['other_id']) || !is_numeric($_GET['other_id'])) {
    http_response_code(400);
    echo json_encode(['error' => 'ID manquant']);
    exit;
}

$other_id = (int)$_GET['other_id'];

// Récupération des messages selon le rôle
$stmt = $db->prepare("
    SELECT m.*, 
           CASE 
               WHEN m.sender_type = 'patient' THEN CONCAT(p.prenom, ' ', p.nom)
               ELSE CONCAT(med.prenom, ' ', med.nom)
           END as sender_name
    FROM messages m
    LEFT JOIN patient p ON m.sender_id = p.id AND m.sender_type = 'patient'
    LEFT JOIN medecin med ON m.sender_id = med.id AND m.sender_type = 'medecin'
    WHERE (m.sender_id = :user_id AND m.receiver_id = :other_id)
       OR (m.sender_id = :other_id AND m.receiver_id = :user_id)
    ORDER BY m.date_envoi ASC
");

$stmt->execute([
    ':user_id' => $user_id,
    ':other_id' => $other_id
]);

$messages = $stmt->fetchAll(PDO::FETCH_ASSOC);

// Marquer les messages comme lus
$update_stmt = $db->prepare("
    UPDATE messages 
    SET lu = TRUE 
    WHERE receiver_id = :user_id 
    AND sender_id = :other_id 
    AND lu = FALSE
");

$update_stmt->execute([
    ':user_id' => $user_id,
    ':other_id' => $other_id
]);

header('Content-Type: application/json');
echo json_encode($messages); 