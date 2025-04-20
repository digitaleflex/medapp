<?php
/**
 * Page de callback pour l'authentification Google
 * Traite le code d'autorisation retourné par Google
 */

// Charger les dépendances
require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/../includes/session.php';
require_once 'GoogleAuth.php';

// Vérifier si un code d'autorisation est présent
if (!isset($_GET['code'])) {
    $_SESSION['auth_error'] = "Aucun code d'autorisation reçu de Google";
    header('Location: ../views/login.php');
    exit;
}

try {
    // Initialiser l'authentification Google
    $googleAuth = new GoogleAuth();
    
    // Traiter le code d'autorisation
    $user_info = $googleAuth->handleCallback($_GET['code']);
    
    // Connecter ou inscrire l'utilisateur
    $user_id = $googleAuth->loginOrRegisterUser($user_info);
    
    // Journaliser la connexion réussie
    Config::logError("Connexion réussie via Google pour l'utilisateur {$user_id}");
    
    // Rediriger vers la page appropriée
    $redirect = isset($_SESSION['auth_redirect']) ? $_SESSION['auth_redirect'] : '../index.php';
    unset($_SESSION['auth_redirect']); // Nettoyer la session
    
    header('Location: ' . $redirect);
    exit;
} catch (Exception $e) {
    // En cas d'erreur, rediriger vers la page de connexion avec un message d'erreur
    $_SESSION['auth_error'] = $e->getMessage();
    Config::logError("Erreur lors du callback Google: " . $e->getMessage());
    header('Location: ../views/login.php');
    exit;
} 