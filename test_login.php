<?php
require_once 'controllers/Auth.php';
require_once 'includes/session.php';

// Démarrer la session
if (session_status() == PHP_SESSION_NONE) {
    session_start();
}

// Créer une instance de Auth
$auth = new Auth();

// Test de connexion patient
echo "=== TEST CONNEXION PATIENT ===\n";
$email = "patient@test.com";
$password = "test123";

echo "Tentative de connexion avec :\n";
echo "Email: " . $email . "\n";
echo "Password: " . $password . "\n";

if ($auth->login($email, $password)) {
    echo "Connexion réussie !\n";
    echo "Session data :\n";
    print_r($_SESSION);
} else {
    echo "Échec de la connexion\n";
}

// Vérifier si l'utilisateur est connecté
echo "\nVérification de la connexion :\n";
if ($auth->isLoggedIn()) {
    echo "L'utilisateur est connecté\n";
} else {
    echo "L'utilisateur n'est pas connecté\n";
}

// Vérifier le rôle
echo "\nVérification du rôle :\n";
if (isset($_SESSION['role'])) {
    echo "Rôle : " . $_SESSION['role'] . "\n";
} else {
    echo "Aucun rôle défini\n";
}

// Déconnexion
$auth->logout();
echo "\nDéconnexion effectuée\n"; 