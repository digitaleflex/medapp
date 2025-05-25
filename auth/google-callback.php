<?php
/**
 * Page de callback pour l'authentification Google
 * Traite le code d'autorisation retourné par Google
 */

require_once '../vendor/autoload.php';
require_once '../config/config.php';
require_once '../includes/session.php';
require_once 'GoogleAuth.php';

// Vérifier si l'utilisateur est connecté
requireLogin();
// Supprimer la ligne requireRole('patient') car elle empêche les médecins de se connecter

$user_id = $_SESSION['user_id'];

// Charger la configuration Google
$config = require '../config/google_config.php';

// Créer le client Google
$client = new Google_Client();
$client->setClientId($config['client_id']);
$client->setClientSecret($config['client_secret']);
$client->setRedirectUri($config['redirect_uri']);

try {
    // Vérifier l'état pour éviter les attaques CSRF
    if (!isset($_GET['state']) || $_GET['state'] !== $_SESSION['google_auth_state']) {
        throw new Exception('État invalide');
    }

    $googleAuth = new GoogleAuth();
    $user_info = $googleAuth->handleCallback($_GET['code']);
    $user_id = $googleAuth->loginOrRegisterUser($user_info);

    // La redirection est déjà configurée dans $_SESSION['auth_redirect'] par loginOrRegisterUser
    $redirect_url = isset($_SESSION['auth_redirect']) ? $_SESSION['auth_redirect'] : '../index.php';
    $_SESSION['success'] = "Connexion réussie";
    header('Location: ' . $redirect_url);
    exit;

} catch (Exception $e) {
    $_SESSION['error'] = "Erreur lors de l'authentification : " . $e->getMessage();
    header('Location: ../views/login.php');
    exit;
}

    // Après avoir stocké le token, rediriger selon le rôle
    if (isset($_SESSION['role'])) {
        switch ($_SESSION['role']) {
            case 'medecin':
                $_SESSION['success'] = "Connexion réussie";
                header('Location: ../views/medecin/dashboard.php');
                break;
            case 'patient':
                $_SESSION['success'] = "Connexion réussie";
                header('Location: ../views/patient/dashboard.php');
                break;
            default:
                header('Location: ../index.php');
                break;
        }
        exit;
    } else {
        // Si aucun rôle n'est défini, rediriger vers la page d'accueil
        $_SESSION['error'] = "Erreur : rôle non défini";
        header('Location: ../index.php');
        exit;
    }