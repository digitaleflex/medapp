<?php
/**
 * Chargeur de variables d'environnement de secours
 * À utiliser lorsque la bibliothèque vlucas/phpdotenv n'est pas disponible
 */

// Charger manuellement les variables d'environnement depuis le fichier .env
$envFile = __DIR__ . '/../.env';

if (file_exists($envFile)) {
    $lines = file($envFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    
    foreach ($lines as $line) {
        // Ignorer les commentaires
        if (strpos(trim($line), '#') === 0) {
            continue;
        }
        
        // Extraire les paires clé/valeur
        if (strpos($line, '=') !== false) {
            list($key, $value) = explode('=', $line, 2);
            $key = trim($key);
            $value = trim($value);
            
            // Supprimer les guillemets éventuels
            if (strpos($value, '"') === 0 && substr($value, -1) === '"') {
                $value = substr($value, 1, -1);
            } elseif (strpos($value, "'") === 0 && substr($value, -1) === "'") {
                $value = substr($value, 1, -1);
            }
            
            if (!empty($key)) {
                $_ENV[$key] = $value;
                $_SERVER[$key] = $value;
                putenv("$key=$value");
            }
        }
    }
    
    // Vérifier la présence des variables requises
    $requiredVars = ['DB_HOST', 'DB_NAME', 'DB_USER'];
    $missingVars = [];
    
    foreach ($requiredVars as $var) {
        if (!isset($_ENV[$var]) || empty($_ENV[$var])) {
            $missingVars[] = $var;
        }
    }
    
    if (!empty($missingVars)) {
        die('Variables d\'environnement requises manquantes : ' . implode(', ', $missingVars));
    }
    
    // Vérifier que APP_ENV a une valeur valide
    if (isset($_ENV['APP_ENV'])) {
        $validEnvs = ['development', 'production', 'testing'];
        if (!in_array($_ENV['APP_ENV'], $validEnvs)) {
            die('La variable APP_ENV doit avoir une des valeurs suivantes : ' . implode(', ', $validEnvs));
        }
    }
} else {
    die('Le fichier .env est introuvable. Veuillez créer ce fichier à la racine du projet.');
}

/**
 * Fonction pour récupérer une variable d'environnement
 * 
 * @param string $key Nom de la variable
 * @param mixed $default Valeur par défaut si la variable n'existe pas
 * @return mixed Valeur de la variable d'environnement
 */
function env($key, $default = null) {
    return isset($_ENV[$key]) ? $_ENV[$key] : $default;
}

// Afficher un message de debug
if (isset($_ENV['APP_ENV']) && $_ENV['APP_ENV'] === 'development') {
    echo "<!-- Variables d'environnement chargées manuellement -->";
}
?> 