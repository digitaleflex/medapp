<?php
require_once '../../config/database.php';
require_once '../../includes/session.php';

// Vérifier que l'utilisateur est connecté
requireLogin();
requireRole('patient');

// Récupérer les paramètres
$rdv_id = $_POST['rdv_id'] ?? null;
$user_id = $_SESSION['user_id'];

if (!$rdv_id) {
    http_response_code(400);
    echo json_encode(['error' => 'ID du rendez-vous manquant']);
    exit;
}

try {
    // Vérifier que le rendez-vous appartient bien au patient
    $stmt = db()->prepare("
        SELECT id 
        FROM rendezvous 
        WHERE id = ? AND idpatient = ? AND statut = 'en attente'
    ");
    $stmt->execute([$rdv_id, $user_id]);
    
    if (!$stmt->fetch()) {
        http_response_code(403);
        echo json_encode(['error' => 'Rendez-vous non trouvé ou non annulable']);
        exit;
    }

    // Annuler le rendez-vous
    $stmt = db()->prepare("
        UPDATE rendezvous 
        SET statut = 'annulé'
        WHERE id = ?
    ");
    $stmt->execute([$rdv_id]);

    // Retourner le succès
    echo json_encode(['success' => true]);
} catch (Exception $e) {
    http_response_code(500);
    echo json_encode(['error' => 'Erreur serveur']);
} 