<?php
/**
 * Page de callback pour l'authentification Google
 * Traite le code d'autorisation retourné par Google
 */

// Démarrer la session (si ce n'est pas déjà fait)
if (session_status() == PHP_SESSION_NONE) {
    session_start();
}

// Charger les dépendances
require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/../includes/session.php';
require_once __DIR__ . '/../config/database.php';
require_once 'GoogleAuth.php';

// Journaliser le début du traitement
Config::logError("Début du traitement du callback Google");

// Vérifier si un code d'autorisation est présent
if (!isset($_GET['code'])) {
    $_SESSION['auth_error'] = "Aucun code d'autorisation reçu de Google";
    Config::logError("Erreur: Aucun code d'autorisation reçu de Google");
    header('Location: ../views/login.php');
    exit;
}

try {
    // Initialiser l'authentification Google
    $googleAuth = new GoogleAuth();
    Config::logError("Instance GoogleAuth créée avec succès");
    
    // Traiter le code d'autorisation
    $user_info = $googleAuth->handleCallback($_GET['code']);
    Config::logError("Informations utilisateur récupérées: " . print_r($user_info, true));
    
    // Connecter ou inscrire l'utilisateur
    $user_id = $googleAuth->loginOrRegisterUser($user_info);
    Config::logError("Utilisateur connecté/inscrit avec succès, ID: " . $user_id);
    
    // Journaliser la connexion réussie
    Config::logError("Connexion réussie via Google pour l'utilisateur {$user_id}");
    
    // Déterminer l'URL de redirection - priorité à post_auth_redirect si défini
    if (isset($_SESSION['post_auth_redirect'])) {
        $redirect = $_SESSION['post_auth_redirect'];
        unset($_SESSION['post_auth_redirect']);
        Config::logError("Redirection vers URL personnalisée: " . $redirect);
    } else {
        // Sinon utiliser la redirection basée sur le rôle définie lors de la connexion
        $redirect = isset($_SESSION['auth_redirect']) ? $_SESSION['auth_redirect'] : '../index.php';
        unset($_SESSION['auth_redirect']); // Nettoyer la session
        Config::logError("Redirection vers URL par défaut: " . $redirect);
    }
    
    header('Location: ' . $redirect);
    exit;
} catch (Exception $e) {
    // En cas d'erreur, rediriger vers la page de connexion avec un message d'erreur
    $_SESSION['auth_error'] = $e->getMessage();
    Config::logError("Erreur lors du callback Google: " . $e->getMessage());
    Config::logError("Trace: " . $e->getTraceAsString());
    header('Location: ../views/login.php');
    exit;
} 