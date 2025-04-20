<?php
/**
 * Script de vérification de la configuration Google OAuth
 * Ce script permet de vérifier si la configuration Google OAuth est correcte
 */

// Charger les dépendances
require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/../includes/session.php';

// Entête HTML
echo '<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vérification de la configuration Google OAuth</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; line-height: 1.6; }
        .container { max-width: 800px; margin: 0 auto; }
        h1 { color: #333; }
        .success { color: green; }
        .error { color: red; }
        .warning { color: orange; }
        .check-item { margin-bottom: 10px; padding: 10px; border: 1px solid #ddd; border-radius: 4px; }
        pre { background: #f5f5f5; padding: 10px; overflow: auto; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Vérification de la configuration Google OAuth</h1>';

// Fonction pour vérifier si une exigence est respectée
function checkRequirement($name, $result, $message) {
    $status = $result ? '<span class="success">✓ OK</span>' : '<span class="error">✗ ERREUR</span>';
    echo '<div class="check-item">';
    echo "<strong>{$name}:</strong> {$status}<br>";
    echo $message;
    echo '</div>';
    
    return $result;
}

// 1. Vérifier si le fichier .env est accessible
$envFileExists = file_exists(__DIR__ . '/../.env');
checkRequirement(
    'Fichier .env', 
    $envFileExists, 
    $envFileExists 
        ? 'Le fichier .env est accessible.' 
        : 'Le fichier .env n\'est pas accessible. Assurez-vous qu\'il existe à la racine du projet.'
);

// 2. Vérifier les variables d'environnement Google OAuth
$clientId = env('GOOGLE_CLIENT_ID');
$clientSecret = env('GOOGLE_CLIENT_SECRET');
$redirectUri = env('GOOGLE_REDIRECT_URI');

$clientIdConfigured = !empty($clientId) && $clientId !== 'votre_client_id_google';
checkRequirement(
    'Client ID Google', 
    $clientIdConfigured, 
    $clientIdConfigured 
        ? 'Le Client ID Google est configuré.' 
        : 'Le Client ID Google n\'est pas configuré correctement dans le fichier .env.'
);

$clientSecretConfigured = !empty($clientSecret) && $clientSecret !== 'votre_client_secret_google';
checkRequirement(
    'Client Secret Google', 
    $clientSecretConfigured, 
    $clientSecretConfigured 
        ? 'Le Client Secret Google est configuré.' 
        : 'Le Client Secret Google n\'est pas configuré correctement dans le fichier .env.'
);

$redirectUriConfigured = !empty($redirectUri);
checkRequirement(
    'URI de redirection Google', 
    $redirectUriConfigured, 
    $redirectUriConfigured 
        ? 'L\'URI de redirection Google est configuré: ' . htmlspecialchars($redirectUri) 
        : 'L\'URI de redirection Google n\'est pas configuré dans le fichier .env.'
);

// 3. Vérifier l'installation des dépendances Composer
$composerAutoloadExists = file_exists(__DIR__ . '/../vendor/autoload.php');
checkRequirement(
    'Installation Composer', 
    $composerAutoloadExists, 
    $composerAutoloadExists 
        ? 'Les dépendances Composer sont installées.' 
        : 'Les dépendances Composer ne sont pas installées. Exécutez "composer install" à la racine du projet.'
);

// 4. Vérifier si Google API Client est installé
$googleApiClientInstalled = false;
if ($composerAutoloadExists) {
    require_once __DIR__ . '/../vendor/autoload.php';
    $googleApiClientInstalled = class_exists('Google_Client');
}
checkRequirement(
    'Google API Client', 
    $googleApiClientInstalled, 
    $googleApiClientInstalled 
        ? 'La bibliothèque Google API Client est installée.' 
        : 'La bibliothèque Google API Client n\'est pas installée. Assurez-vous que "google/apiclient" est dans composer.json et exécutez "composer install".'
);

// 5. Vérifier les tables de la base de données
try {
    $db = db();
    
    // Vérifier si la table users contient la colonne google_id
    $stmt = $db->prepare("SHOW COLUMNS FROM users LIKE 'google_id'");
    $stmt->execute();
    $googleIdColumnExists = $stmt->rowCount() > 0;
    
    checkRequirement(
        'Schéma de base de données', 
        $googleIdColumnExists, 
        $googleIdColumnExists 
            ? 'La colonne "google_id" existe dans la table "users".' 
            : 'La colonne "google_id" n\'existe pas dans la table "users". Ajoutez cette colonne pour permettre l\'authentification Google.'
    );
} catch (Exception $e) {
    checkRequirement(
        'Connexion à la base de données', 
        false, 
        'Impossible de se connecter à la base de données: ' . $e->getMessage()
    );
}

// Conclusion
echo '<h2>Conclusion</h2>';
if ($clientIdConfigured && $clientSecretConfigured && $redirectUriConfigured && $composerAutoloadExists && $googleApiClientInstalled) {
    echo '<p class="success">La configuration Google OAuth semble correcte. Vous pouvez maintenant utiliser l\'authentification Google.</p>';
    echo '<p>Pour tester l\'authentification, visitez <a href="../auth/google-login.php">la page de connexion Google</a>.</p>';
} else {
    echo '<p class="error">La configuration Google OAuth présente des problèmes qui doivent être résolus.</p>';
    echo '<p>Consultez le fichier <a href="README.md">README.md</a> pour obtenir des instructions détaillées sur la configuration.</p>';
}

echo '</div></body></html>'; 