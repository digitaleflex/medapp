<?php
/**
 * Script de diagnostic pour vérifier la configuration du système
 * Affiche les informations sur l'environnement PHP, les extensions requises,
 * les fichiers nécessaires et les dépendances
 */

// Afficher les erreurs en mode développement
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

// Fonction pour vérifier si une extension PHP est chargée
function checkExtension($extension) {
    return extension_loaded($extension) ? 
        "<span style='color: green;'>✓ Installée</span>" : 
        "<span style='color: red;'>✗ Non installée</span>";
}

// Fonction pour vérifier si un fichier existe
function checkFile($file) {
    return file_exists($file) ? 
        "<span style='color: green;'>✓ Présent</span>" : 
        "<span style='color: red;'>✗ Manquant</span>";
}

// Fonction pour vérifier si une dépendance Composer est installée
function checkComposerDependency($package) {
    $composerLock = __DIR__ . '/composer.lock';
    if (!file_exists($composerLock)) {
        return "<span style='color: red;'>✗ Fichier composer.lock manquant</span>";
    }
    
    $content = file_get_contents($composerLock);
    return strpos($content, $package) !== false ? 
        "<span style='color: green;'>✓ Installée</span>" : 
        "<span style='color: red;'>✗ Non installée</span>";
}

// Fonction pour vérifier si une variable d'environnement est définie
function checkEnvVariable($variable) {
    return getenv($variable) !== false ? 
        "<span style='color: green;'>✓ Définie</span>" : 
        "<span style='color: red;'>✗ Non définie</span>";
}

// En-tête HTML
echo "<!DOCTYPE html>
<html lang='fr'>
<head>
    <meta charset='UTF-8'>
    <meta name='viewport' content='width=device-width, initial-scale=1.0'>
    <title>Diagnostic MedConnect</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            margin: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 800px;
            margin: 0 auto;
            background-color: white;
            padding: 20px;
            border-radius: 5px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }
        h1 {
            color: #2c3e50;
            border-bottom: 2px solid #eee;
            padding-bottom: 10px;
        }
        h2 {
            color: #34495e;
            margin-top: 20px;
        }
        .section {
            margin-bottom: 20px;
            padding: 15px;
            background-color: #f9f9f9;
            border-radius: 4px;
        }
        .check-item {
            margin: 5px 0;
        }
        .summary {
            margin-top: 20px;
            padding: 15px;
            background-color: #e8f5e9;
            border-radius: 4px;
        }
        .error {
            color: #c0392b;
        }
        .success {
            color: #27ae60;
        }
    </style>
</head>
<body>
    <div class='container'>
        <h1>Diagnostic MedConnect</h1>";

// Vérification de la version PHP
echo "<div class='section'>
    <h2>Version PHP</h2>
    <div class='check-item'>Version actuelle : " . phpversion() . "</div>
    <div class='check-item'>Version requise : 7.4.0 ou supérieure</div>
</div>";

// Vérification des extensions PHP requises
echo "<div class='section'>
    <h2>Extensions PHP requises</h2>
    <div class='check-item'>PDO : " . checkExtension('pdo') . "</div>
    <div class='check-item'>PDO MySQL : " . checkExtension('pdo_mysql') . "</div>
    <div class='check-item'>OpenSSL : " . checkExtension('openssl') . "</div>
    <div class='check-item'>JSON : " . checkExtension('json') . "</div>
    <div class='check-item'>MBString : " . checkExtension('mbstring') . "</div>
    <div class='check-item'>Fileinfo : " . checkExtension('fileinfo') . "</div>
</div>";

// Vérification des fichiers requis
echo "<div class='section'>
    <h2>Fichiers requis</h2>
    <div class='check-item'>config/config.php : " . checkFile(__DIR__ . '/config/config.php') . "</div>
    <div class='check-item'>.env : " . checkFile(__DIR__ . '/.env') . "</div>
    <div class='check-item'>composer.json : " . checkFile(__DIR__ . '/composer.json') . "</div>
    <div class='check-item'>composer.lock : " . checkFile(__DIR__ . '/composer.lock') . "</div>
</div>";

// Vérification des dépendances Composer
echo "<div class='section'>
    <h2>Dépendances Composer</h2>
    <div class='check-item'>PHPMailer : " . checkComposerDependency('phpmailer/phpmailer') . "</div>
    <div class='check-item'>Monolog : " . checkComposerDependency('monolog/monolog') . "</div>
    <div class='check-item'>Firebase/php-jwt : " . checkComposerDependency('firebase/php-jwt') . "</div>
</div>";

// Vérification des variables d'environnement
echo "<div class='section'>
    <h2>Variables d'environnement</h2>
    <div class='check-item'>DB_HOST : " . checkEnvVariable('DB_HOST') . "</div>
    <div class='check-item'>DB_NAME : " . checkEnvVariable('DB_NAME') . "</div>
    <div class='check-item'>DB_USER : " . checkEnvVariable('DB_USER') . "</div>
    <div class='check-item'>DB_PASS : " . checkEnvVariable('DB_PASS') . "</div>
    <div class='check-item'>APP_URL : " . checkEnvVariable('APP_URL') . "</div>
</div>";

// Résumé et recommandations
echo "<div class='summary'>
    <h2>Résumé</h2>
    <p>Ce diagnostic vérifie les éléments essentiels pour le bon fonctionnement de MedConnect.</p>
    <p>Si des éléments sont marqués en rouge, veuillez les installer ou les configurer avant de continuer.</p>
</div>";

// Pied de page
echo "</div></body></html>";
?> 