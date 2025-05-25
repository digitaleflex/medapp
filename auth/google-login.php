<?php
/**
 * Point d'entrée pour l'authentification Google
 * Redirige l'utilisateur vers la page d'authentification Google
 */

// Charger les dépendances
require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/../includes/session.php';
require_once 'GoogleAuth.php';

try {
    // Initialiser l'authentification Google
    $googleAuth = new GoogleAuth();
    
    // Stocker l'URL de retour après connexion si fourni
    if (isset($_GET['redirect'])) {
        $_SESSION['auth_redirect'] = $_GET['redirect'];
    } else {
        $_SESSION['auth_redirect'] = '../index.php';
    }
    
    // Générer l'URL d'authentification et rediriger
    $authUrl = $googleAuth->getAuthUrl();
    header('Location: ' . $authUrl);
    exit;
} catch (Exception $e) {
    // En cas d'erreur, rediriger vers la page de connexion avec un message d'erreur
    $_SESSION['auth_error'] = $e->getMessage();
    header('Location: ../views/login.php');
    exit;
} 