<?php
require_once '../../config/database.php';
require_once '../../includes/session.php';

// Vérifier que l'utilisateur est connecté
requireLogin();
requireRole('patient');

// Récupérer les paramètres
$medecin_id = $_GET['medecin_id'] ?? null;
$date = $_GET['date'] ?? null;

if (!$medecin_id || !$date) {
    http_response_code(400);
    echo json_encode(['error' => 'Paramètres manquants']);
    exit;
}

try {
    // Récupérer les rendez-vous existants pour ce médecin à cette date
    $stmt = db()->prepare("
        SELECT TIME_FORMAT(TIME(dateheure), '%H:%i') as heure
        FROM rendezvous
        WHERE idmedecin = ?
        AND DATE(dateheure) = ?
        AND statut != 'annulé'
    ");
    $stmt->execute([$medecin_id, $date]);
    $rdvs_existants = $stmt->fetchAll(PDO::FETCH_COLUMN);

    // Définir les créneaux disponibles
    $heures_possibles = ['09:00', '09:30', '10:00', '10:30', '11:00', '11:30', 
                        '14:00', '14:30', '15:00', '15:30', '16:00', '16:30'];

    // Filtrer les créneaux disponibles
    $creneaux_disponibles = array_values(array_diff($heures_possibles, $rdvs_existants));

    // Retourner les résultats en JSON
    header('Content-Type: application/json');
    echo json_encode($creneaux_disponibles);
} catch (Exception $e) {
    http_response_code(500);
    echo json_encode(['error' => 'Erreur serveur']);
} 