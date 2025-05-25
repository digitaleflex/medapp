<?php
require_once '../../includes/session.php';
require_once '../../config/database.php';

// Vérifier si l'utilisateur est connecté
requireLogin();

// Vérifier si l'utilisateur a le rôle requis
requireRole('medecin');

// Vérifier si le formulaire a été soumis
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    try {
        // Valider le token CSRF
        if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
            throw new Exception("Erreur de sécurité CSRF");
        }

        $rdv_id = filter_input(INPUT_POST, 'rdv_id', FILTER_VALIDATE_INT);
        $statut = filter_input(INPUT_POST, 'statut', FILTER_SANITIZE_STRING);
        // Correction : forcer une valeur par défaut si vide ou invalide
        $statuts_valides = ['en attente', 'confirmé', 'annulé', 'accepté', 'refusé'];
        if (!$statut || !in_array($statut, $statuts_valides)) {
            $statut = 'en attente';
        }

        // Valider les entrées
        if (!$rdv_id || !$statut) {
            throw new Exception("Données du formulaire invalides");
        }

        // Valider que le statut est parmi les valeurs autorisées
        $statutsAutorises = ['en attente', 'confirmé', 'annulé'];
        if (!in_array($statut, $statutsAutorises)) {
            throw new Exception("Statut invalide");
        }

        // Initialiser la connexion à la base de données
        $database = new Database();
        $db = $database->getConnection();

        // Vérifier que le médecin peut modifier ce rendez-vous
        $queryCheck = "SELECT idmedecin FROM rendezvous WHERE id = :rdv_id";
        $stmtCheck = $db->prepare($queryCheck);
        $stmtCheck->bindParam(':rdv_id', $rdv_id, PDO::PARAM_INT);
        $stmtCheck->execute();
        
        $rdv = $stmtCheck->fetch(PDO::FETCH_ASSOC);
        
        if (!$rdv || $rdv['idmedecin'] != $_SESSION['user_id']) {
            throw new Exception("Vous n'êtes pas autorisé à modifier ce rendez-vous");
        }

        // Mettre à jour le statut du rendez-vous
        $query = "UPDATE rendezvous SET statut = :statut WHERE id = :rdv_id";
        $stmt = $db->prepare($query);
        $stmt->bindParam(':statut', $statut, PDO::PARAM_STR);
        $stmt->bindParam(':rdv_id', $rdv_id, PDO::PARAM_INT);
        
        if (!$stmt->execute()) {
            throw new Exception("Échec de la mise à jour du rendez-vous");
        }

        // Journaliser la modification
        error_log("Mise à jour réussie pour le rendez-vous ID: " . $rdv_id . " par le médecin ID: " . $_SESSION['user_id']);

        // Message de succès
        $_SESSION['flash_message'] = [
            'type' => 'success',
            'message' => 'Le statut du rendez-vous a été mis à jour avec succès'
        ];

    } catch (Exception $e) {
        // Journaliser l'erreur
        error_log("Erreur lors de la mise à jour du rendez-vous: " . $e->getMessage());
        
        // Message d'erreur
        $_SESSION['flash_message'] = [
            'type' => 'error',
            'message' => $e->getMessage()
        ];
    }
}

// Rediriger vers la page de l'agenda
header('Location: rdv.php');
exit;