<?php
// Mode débogage forcé
ini_set('display_errors', 1);
error_reporting(E_ALL);

// Style pour un affichage lisible
echo '<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Diagnostic MedApp</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; padding: 20px; }
        h1 { color: #333; }
        .success { color: green; }
        .error { color: red; }
        .warning { color: orange; }
        .section { margin-bottom: 20px; padding: 10px; border: 1px solid #ddd; border-radius: 4px; }
        .result { margin-left: 20px; }
        pre { background: #f5f5f5; padding: 10px; overflow: auto; }
    </style>
</head>
<body>
    <h1>Diagnostic MedApp</h1>';

// Fonction pour afficher un résultat
function showResult($test, $result, $message = '') {
    echo '<div class="result">';
    if ($result) {
        echo '<span class="success">✓ ' . $test . ' : OK</span>';
    } else {
        echo '<span class="error">✗ ' . $test . ' : ÉCHEC</span>';
    }
    if (!empty($message)) {
        echo '<br><span class="message">' . $message . '</span>';
    }
    echo '</div>';
    
    return $result;
}

// 1. Vérification de la version PHP
echo '<div class="section">';
echo '<h2>1. Environnement PHP</h2>';
$phpVersion = phpversion();
$requiredVersion = '7.4.0';
$phpVersionOk = version_compare($phpVersion, $requiredVersion, '>=');
showResult('Version PHP', $phpVersionOk, 'Version actuelle: ' . $phpVersion . ', Version requise: >= ' . $requiredVersion);

// Extensions requises
$requiredExtensions = ['pdo', 'pdo_mysql', 'json', 'mbstring', 'openssl'];
echo '<h3>Extensions PHP requises</h3>';
$extensionsOk = true;

foreach ($requiredExtensions as $extension) {
    $loaded = extension_loaded($extension);
    if (!$loaded) {
        $extensionsOk = false;
    }
    showResult('Extension ' . $extension, $loaded);
}
echo '</div>';

// 2. Vérification des chemins et fichiers
echo '<div class="section">';
echo '<h2>2. Chemins et fichiers</h2>';

$rootPath = __DIR__;
echo 'Répertoire racine: ' . $rootPath . '<br>';

$requiredFiles = [
    'config/config.php',
    'config/database.php',
    'includes/session.php',
    'includes/env_loader.php',
    '.env',
    'composer.json'
];

$filesOk = true;
foreach ($requiredFiles as $file) {
    $exists = file_exists($rootPath . '/' . $file);
    if (!$exists) {
        $filesOk = false;
    }
    showResult('Fichier ' . $file, $exists);
}
echo '</div>';

// 3. Vérification de Composer
echo '<div class="section">';
echo '<h2>3. Composer et dépendances</h2>';

$composerAutoload = file_exists($rootPath . '/vendor/autoload.php');
showResult('Fichier vendor/autoload.php', $composerAutoload, 
    $composerAutoload ? 'Les dépendances Composer sont installées.' : 'Les dépendances Composer ne sont PAS installées. Exécutez "composer install" ou "composer update".');

// Si l'autoloader est disponible, vérifier les dépendances spécifiques
if ($composerAutoload) {
    echo '<h3>Dépendances spécifiques</h3>';
    require_once $rootPath . '/vendor/autoload.php';
    
    $dependencies = [
        'Dotenv\\Dotenv' => 'vlucas/phpdotenv',
        'Google_Client' => 'google/apiclient'
    ];
    
    foreach ($dependencies as $class => $package) {
        $exists = class_exists($class);
        showResult('Package ' . $package, $exists);
    }
} else {
    echo '<div class="warning">Impossible de vérifier les dépendances spécifiques sans autoloader.</div>';
}
echo '</div>';

// 4. Vérification des variables d'environnement
echo '<div class="section">';
echo '<h2>4. Variables d\'environnement</h2>';

if (file_exists($rootPath . '/.env')) {
    echo 'Fichier .env trouvé, tentative de chargement...<br>';
    
    // Tenter de charger manuellement le fichier .env pour diagnostic
    try {
        $envContent = file_get_contents($rootPath . '/.env');
        $envLines = explode("\n", $envContent);
        $envVars = [];
        
        foreach ($envLines as $line) {
            $line = trim($line);
            if (empty($line) || strpos($line, '#') === 0) {
                continue;
            }
            
            list($key, $value) = explode('=', $line, 2) + [null, null];
            if (!empty($key)) {
                $envVars[$key] = $value;
            }
        }
        
        echo '<h3>Variables détectées dans .env</h3>';
        echo '<ul>';
        foreach ($envVars as $key => $value) {
            // Masquer les informations sensibles
            if (strpos($key, 'SECRET') !== false || strpos($key, 'PASS') !== false) {
                $value = '******';
            }
            echo '<li>' . htmlspecialchars($key) . ' = ' . htmlspecialchars($value) . '</li>';
        }
        echo '</ul>';
        
        // Vérifier les variables requises
        $requiredEnvVars = ['DB_HOST', 'DB_NAME', 'DB_USER', 'APP_ENV'];
        $envVarsOk = true;
        
        foreach ($requiredEnvVars as $var) {
            $exists = isset($envVars[$var]) && !empty($envVars[$var]);
            if (!$exists) {
                $envVarsOk = false;
            }
            showResult('Variable ' . $var, $exists);
        }
    } catch (Exception $e) {
        echo '<div class="error">Erreur lors de la lecture du fichier .env: ' . $e->getMessage() . '</div>';
    }
} else {
    echo '<div class="error">Fichier .env non trouvé!</div>';
}
echo '</div>';

// 5. Tests d'inclusion
echo '<div class="section">';
echo '<h2>5. Tests d\'inclusion</h2>';

echo '<h3>Test d\'inclusion de config.php</h3>';
try {
    if (file_exists($rootPath . '/config/config.php')) {
        ob_start();
        require_once $rootPath . '/config/config.php';
        ob_end_clean();
        echo '<div class="success">config.php chargé avec succès</div>';
        
        // Vérifier si les fonctions essentielles sont définies
        $configFunctions = [
            'env' => function_exists('env'),
            'config' => function_exists('config'),
            'db' => function_exists('db')
        ];
        
        foreach ($configFunctions as $func => $exists) {
            showResult('Fonction ' . $func . '()', $exists);
        }
    } else {
        echo '<div class="error">config.php non trouvé</div>';
    }
} catch (Exception $e) {
    echo '<div class="error">Erreur lors du chargement de config.php: ' . $e->getMessage() . '</div>';
    echo '<pre>' . $e->getTraceAsString() . '</pre>';
}
echo '</div>';

// Résumé
echo '<div class="section">';
echo '<h2>Résumé du diagnostic</h2>';

$allOk = $phpVersionOk && $extensionsOk && $filesOk && $composerAutoload;
if ($allOk) {
    echo '<div class="success">Toutes les vérifications de base ont réussi.</div>';
} else {
    echo '<div class="error">Certaines vérifications ont échoué. Veuillez résoudre les problèmes indiqués ci-dessus.</div>';
    
    echo '<h3>Recommandations:</h3>';
    echo '<ol>';
    if (!$composerAutoload) {
        echo '<li>Exécutez <code>composer update</code> pour installer les dépendances manquantes.</li>';
    }
    if (!$filesOk) {
        echo '<li>Vérifiez que tous les fichiers requis sont présents dans les bons répertoires.</li>';
    }
    if (!isset($envVarsOk) || !$envVarsOk) {
        echo '<li>Assurez-vous que votre fichier .env contient toutes les variables requises.</li>';
    }
    echo '</ol>';
}
echo '</div>';

echo '</body></html>';
?> 