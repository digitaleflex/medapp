<?php
/**
 * Gestion sécurisée des sessions
 * Utilise la variable SESSION_SECRET du fichier .env pour renforcer la sécurité
 */

// Charger la configuration si ce n'est pas déjà fait
if (!function_exists('env')) {
    require_once __DIR__ . '/../config/config.php';
}

// Configurer les options de session avant de la démarrer
$session_name = 'MEDSESSID'; // Nom personnalisé pour masquer l'utilisation de PHP
$secure = false; // Définir à true en production avec HTTPS
$httponly = true; // Empêche l'accès au cookie via JavaScript
$samesite = 'Lax'; // Protection contre les attaques CSRF

// En production, forcer HTTPS
if (env('APP_ENV') === 'production') {
    $secure = true;
    ini_set('session.cookie_secure', 1);
}

// Définir les options de cookie
ini_set('session.use_strict_mode', 1);
ini_set('session.use_cookies', 1);
ini_set('session.use_only_cookies', 1);
ini_set('session.cookie_httponly', 1);

// Configurer la durée de vie du cookie (30 minutes = 1800 secondes)
ini_set('session.gc_maxlifetime', 1800);
ini_set('session.cookie_lifetime', 1800);

// Paramétrer le cookie SameSite
session_set_cookie_params([
    'lifetime' => 1800,
    'path' => '/',
    'domain' => '', // Auto
    'secure' => $secure,
    'httponly' => $httponly,
    'samesite' => $samesite
]);

// Définir un nom de session personnalisé uniquement si la session n'est pas déjà active
if (session_status() == PHP_SESSION_NONE) {
    session_name($session_name);
    session_start();
    
    // Régénérer l'ID de session périodiquement pour prévenir la fixation de session
    if (!isset($_SESSION['created'])) {
        $_SESSION['created'] = time();
    } else if (time() - $_SESSION['created'] > 600) { // Régénérer toutes les 10 minutes
        // Régénérer l'ID de session
        session_regenerate_id(true);
        $_SESSION['created'] = time();
    }
}

// Fonction pour vérifier si l'utilisateur est connecté
function isLoggedIn() {
    if (isset($_SESSION['user_id']) && isset($_SESSION['last_activity'])) {
        // Vérifier si la dernière activité date de moins de 30 minutes
        if (time() - $_SESSION['last_activity'] < 1800) {
            // Vérifier l'empreinte du navigateur pour détecter un vol de session
            $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? '';
            $session_hash = hash_hmac('sha256', $user_agent, env('SESSION_SECRET', 'default_secret'));
            
            if (!isset($_SESSION['browser_fingerprint']) || $_SESSION['browser_fingerprint'] !== $session_hash) {
                // Empreinte invalide, déconnecter l'utilisateur
                logout();
                return false;
            }
            
            // Mettre à jour le temps de dernière activité
            $_SESSION['last_activity'] = time();
            return true;
        } else {
            // La session a expiré, déconnecter l'utilisateur
            logout();
        }
    }
    return false;
}

// Fonction pour initialiser une session après connexion
function initSession($user_id, $role, $nom, $prenom, $email, $auth_method = 'standard') {
    // Régénérer l'ID de session pour prévenir la fixation de session
    session_regenerate_id(true);
    
    // Enregistrer les informations de base
    $_SESSION['user_id'] = $user_id;
    $_SESSION['role'] = $role;
    $_SESSION['nom'] = $nom;
    $_SESSION['prenom'] = $prenom;
    $_SESSION['email'] = $email;
    $_SESSION['auth_method'] = $auth_method;
    $_SESSION['last_activity'] = time();
    $_SESSION['created'] = time();
    
    // Stocker l'empreinte du navigateur
    $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? '';
    $_SESSION['browser_fingerprint'] = hash_hmac('sha256', $user_agent, env('SESSION_SECRET', 'default_secret'));
    
    // Journaliser la connexion
    if (function_exists('Config::logError')) {
        Config::logError("Connexion utilisateur {$user_id} ({$role}) via {$auth_method}");
    }
}

// Fonction pour vérifier le rôle de l'utilisateur
function checkRole($required_role) {
    if (isset($_SESSION['role']) && $_SESSION['role'] == $required_role) {
        return true;
    }
    return false;
}

// Fonction pour rediriger vers la page de connexion si l'utilisateur n'est pas connecté
function requireLogin() {
    if (!isLoggedIn()) {
        header("Location: ../login.php");
        exit;
    }
}

// Fonction pour rediriger vers la page appropriée si l'utilisateur n'a pas le rôle requis
function requireRole($required_role) {
    if (!checkRole($required_role)) {
        // Rediriger vers la page d'accueil correspondant au rôle actuel
        $role = $_SESSION['role'];
        switch ($role) {
            case 'admin':
                header("Location: ../admin/dashboard.php");
                break;
            case 'medecin':
                header("Location: ../medecin/dashboard.php");
                break;
            case 'patient':
                header("Location: ../patient/dashboard.php");
                break;
            default:
                header("Location: ../login.php");
                break;
        }
        exit;
    }
}

// Fonction pour déconnecter l'utilisateur
function logout() {
    // Détruire toutes les variables de session
    $_SESSION = array();
    
    // Détruire le cookie de session
    if (ini_get("session.use_cookies")) {
        $params = session_get_cookie_params();
        setcookie(
            session_name(),
            '',
            time() - 42000,
            $params["path"],
            $params["domain"],
            $params["secure"],
            $params["httponly"]
        );
    }
    
    // Détruire la session
    session_destroy();
    
    // Rediriger vers la page de connexion
    header("Location: ../login.php");
    exit;
} 