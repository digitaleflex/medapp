<?php
/**
 * Gestion des sessions et de l'authentification
 * Utilise la variable SESSION_SECRET du fichier .env pour renforcer la sécurité
 */

// Charger la configuration si ce n'est pas déjà fait
if (!function_exists('env')) {
    require_once __DIR__ . '/../config/config.php';
}

// Configurer les options de session avant de la démarrer
$session_name = 'MEDSESSID';
$secure = false; // Désactivé en développement
$httponly = true;
$samesite = 'Lax';

// Définir le chemin de sauvegarde des sessions
$session_path = __DIR__ . '/../storage/sessions';
if (!is_dir($session_path)) {
    mkdir($session_path, 0777, true);
}
ini_set('session.save_path', $session_path);

// Définir les options de cookie
ini_set('session.use_strict_mode', 1);
ini_set('session.use_cookies', 1);
ini_set('session.use_only_cookies', 1);
ini_set('session.cookie_httponly', 1);
ini_set('session.cookie_samesite', $samesite);
ini_set('session.gc_probability', 1);
ini_set('session.gc_divisor', 100);

// Configurer la durée de vie du cookie (2 heures en développement)
$session_lifetime = 7200; // 2 heures
ini_set('session.gc_maxlifetime', $session_lifetime);
ini_set('session.cookie_lifetime', $session_lifetime);

// Paramétrer le cookie
session_set_cookie_params([
    'lifetime' => $session_lifetime,
    'path' => '/medapp/', // Chemin spécifique à l'application
    'domain' => '',
    'secure' => $secure,
    'httponly' => $httponly,
    'samesite' => $samesite
]);

// Démarrer la session si elle n'est pas déjà active
if (session_status() == PHP_SESSION_NONE) {
    session_name($session_name);
    session_start();
}

/**
 * Vérifie si l'utilisateur est connecté
 * 
 * @return bool True si l'utilisateur est connecté
 */
function isLoggedIn() {
    return isset($_SESSION['user_id']) && isset($_SESSION['role']);
}

/**
 * Vérifie si l'utilisateur a le rôle requis
 * 
 * @param string|array $role Le rôle ou les rôles requis (admin, medecin, patient)
 * @return bool True si l'utilisateur a le rôle requis
 */
function hasRole($role) {
    if (!isset($_SESSION['role'])) {
        return false;
    }
    return $_SESSION['role'] === $role;
}

/**
 * Exige que l'utilisateur soit connecté
 * Redirige vers la page de connexion si ce n'est pas le cas
 */
function requireLogin() {
    if (!isLoggedIn()) {
        header('Location: /medapp/views/login.php');
        exit();
    }
}

/**
 * Exige que l'utilisateur ait un rôle spécifique
 * Redirige vers la page d'accueil si ce n'est pas le cas
 * 
 * @param string|array $role Le rôle ou les rôles requis (admin, medecin, patient)
 */
function requireRole($role) {
    requireLogin();
    if (!hasRole($role)) {
        header('Location: /medapp/index.php');
        exit();
    }
}

/**
 * Déconnecte l'utilisateur
 */
function logout() {
    $_SESSION = array();
    if (isset($_COOKIE[session_name()])) {
        setcookie(session_name(), '', time() - 3600, '/medapp/');
    }
    session_destroy();
    header('Location: /medapp/views/login.php');
    exit();
}

/**
 * Initialise la session utilisateur
 */
function initSession($user_id, $role, $nom, $prenom, $email, $auth_method = 'standard') {
    $_SESSION['user_id'] = $user_id;
    $_SESSION['role'] = $role;
    $_SESSION['nom'] = $nom;
    $_SESSION['prenom'] = $prenom;
    $_SESSION['email'] = $email;
    $_SESSION['auth_method'] = $auth_method;
    $_SESSION['last_activity'] = time();
}

/**
 * Génère une empreinte du navigateur pour renforcer la sécurité des sessions
 */
function generateBrowserFingerprint() {
    $user_agent = $_SERVER['HTTP_USER_AGENT'];
    $ip = $_SERVER['REMOTE_ADDR'];
    $fingerprint = hash_hmac('sha256', $user_agent . $ip, env('SESSION_SECRET'));
    $_SESSION['browser_fingerprint'] = $fingerprint;
}

/**
 * Vérifie l'empreinte du navigateur
 * 
 * @return bool True si l'empreinte est valide
 */
function verifyBrowserFingerprint() {
    if (!isset($_SESSION['browser_fingerprint'])) {
        return false;
    }

    $user_agent = $_SERVER['HTTP_USER_AGENT'];
    $ip = $_SERVER['REMOTE_ADDR'];
    $expected = hash_hmac('sha256', $user_agent . $ip, env('SESSION_SECRET'));

    return hash_equals($_SESSION['browser_fingerprint'], $expected);
}

/**
 * Régénère l'ID de session
 * À utiliser après une élévation de privilèges
 */
function regenerateSession() {
    session_regenerate_id(true);
    $_SESSION['created'] = time();
    generateBrowserFingerprint();
} 