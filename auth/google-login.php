<?php
/**
 * Page de redirection pour l'authentification Google
 * Génère l'URL d'authentification et redirige l'utilisateur
 */

// Démarrer la session si nécessaire
if (session_status() == PHP_SESSION_NONE) {
    session_start();
}

// Charger les dépendances
require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/../config/database.php';
require_once 'GoogleAuth.php';

try {
    // Initialiser l'authentification Google
    $googleAuth = new GoogleAuth();
    
    // Stocker l'URL de redirection si fournie
    if (isset($_GET['redirect'])) {
        $_SESSION['post_auth_redirect'] = $_GET['redirect'];
    } else if (isset($_SERVER['HTTP_REFERER'])) {
        // Sinon, stocker la page de référence pour y revenir après
        $_SESSION['post_auth_redirect'] = $_SERVER['HTTP_REFERER'];
    }
    
    // Stocker le type d'utilisateur (médecin ou patient) pour l'inscription
    if (isset($_GET['type']) && in_array($_GET['type'], ['medecin', 'patient'])) {
        $_SESSION['auth_user_type'] = $_GET['type'];
        Config::logError("Type d'utilisateur défini pour l'authentification Google: " . $_GET['type']);
    } else {
        // Par défaut, considérer comme patient
        $_SESSION['auth_user_type'] = 'patient';
    }
    
    // Obtenir l'URL d'authentification
    $authUrl = $googleAuth->getAuthUrl();
    
    // Rediriger vers l'URL d'authentification
    header('Location: ' . $authUrl);
    exit;
} catch (Exception $e) {
    // En cas d'erreur, rediriger vers la page de connexion avec un message d'erreur
    $_SESSION['auth_error'] = "Erreur de connexion Google: " . $e->getMessage();
    Config::logError("Erreur lors de la redirection Google: " . $e->getMessage());
    
    header('Location: ../views/login.php');
    exit;
} 