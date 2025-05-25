<?php
// Afficher les informations de configuration de la session
echo "=== CONFIGURATION DE LA SESSION ===\n";
echo "session.save_path: " . ini_get('session.save_path') . "\n";
echo "session.use_cookies: " . ini_get('session.use_cookies') . "\n";
echo "session.use_only_cookies: " . ini_get('session.use_only_cookies') . "\n";
echo "session.cookie_lifetime: " . ini_get('session.cookie_lifetime') . "\n";
echo "session.cookie_path: " . ini_get('session.cookie_path') . "\n";
echo "session.cookie_domain: " . ini_get('session.cookie_domain') . "\n";
echo "session.cookie_secure: " . ini_get('session.cookie_secure') . "\n";
echo "session.cookie_httponly: " . ini_get('session.cookie_httponly') . "\n";
echo "session.cookie_samesite: " . ini_get('session.cookie_samesite') . "\n";
echo "session.gc_maxlifetime: " . ini_get('session.gc_maxlifetime') . "\n";

// Démarrer la session
if (session_status() == PHP_SESSION_NONE) {
    session_start();
}

echo "\n=== TEST DE LA SESSION ===\n";
// Tester l'écriture dans la session
$_SESSION['test'] = 'test_value';
echo "Valeur écrite dans la session: " . $_SESSION['test'] . "\n";

// Vérifier si le cookie de session est présent
echo "\n=== COOKIE DE SESSION ===\n";
if (isset($_COOKIE[session_name()])) {
    echo "Cookie de session présent: " . $_COOKIE[session_name()] . "\n";
} else {
    echo "Cookie de session non présent\n";
}

// Afficher toutes les variables de session
echo "\n=== VARIABLES DE SESSION ===\n";
print_r($_SESSION);

// Vérifier le chemin de sauvegarde des sessions
echo "\n=== CHEMIN DE SAUVEGARDE DES SESSIONS ===\n";
$session_path = session_save_path();
echo "Chemin de sauvegarde: " . $session_path . "\n";
echo "Le répertoire existe: " . (is_dir($session_path) ? "Oui" : "Non") . "\n";
echo "Le répertoire est accessible en écriture: " . (is_writable($session_path) ? "Oui" : "Non") . "\n";

// Vérifier les permissions du répertoire de session
if (is_dir($session_path)) {
    echo "Permissions du répertoire: " . substr(sprintf('%o', fileperms($session_path)), -4) . "\n";
} 