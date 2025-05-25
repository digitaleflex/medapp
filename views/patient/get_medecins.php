<?php
require_once '../../config/database.php';
require_once '../../includes/session.php';

// Vérifier que l'utilisateur est connecté
requireLogin();
requireRole('patient');

// Récupérer l'ID de la spécialité
$specialite_id = $_GET['specialite_id'] ?? null;

if (!$specialite_id) {
    http_response_code(400);
    echo json_encode(['error' => 'ID de spécialité manquant']);
    exit;
}

try {
    // Récupérer les médecins de la spécialité
    $stmt = db()->prepare("
        SELECT m.id, m.nom, m.prenom
        FROM medecin m
        JOIN medecin_specialite ms ON m.id = ms.idmedecin
        WHERE ms.idspecialite = ?
        ORDER BY m.nom, m.prenom
    ");
    $stmt->execute([$specialite_id]);
    $medecins = $stmt->fetchAll(PDO::FETCH_ASSOC);

    // Retourner les résultats en JSON
    header('Content-Type: application/json');
    echo json_encode($medecins);
} catch (Exception $e) {
    http_response_code(500);
    echo json_encode(['error' => 'Erreur serveur']);
} 