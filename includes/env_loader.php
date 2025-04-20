<?php
/**
 * Chargeur des variables d'environnement
 * Utilise la bibliothèque vlucas/phpdotenv pour charger le fichier .env
 * ou une solution de contournement si la bibliothèque n'est pas disponible
 */

// Vérifier si Composer est installé et autoload est disponible
if (file_exists(__DIR__ . '/../vendor/autoload.php')) {
    require_once __DIR__ . '/../vendor/autoload.php';
    
    // Vérifier si la classe Dotenv existe
    if (class_exists('Dotenv\\Dotenv')) {
        // Charger les variables d'environnement
        $dotenv = Dotenv\Dotenv::createImmutable(__DIR__ . '/..');
        $dotenv->load();
        
        // Définir les variables requises
        $dotenv->required(['DB_HOST', 'DB_NAME', 'DB_USER']);
        
        // Valider certaines variables
        $dotenv->required('APP_ENV')->allowedValues(['development', 'production', 'testing']);
    } else {
        // Si Dotenv n'est pas disponible, utiliser la solution de contournement
        require_once __DIR__ . '/env_loader_bypass.php';
    }
} else {
    // Si Composer n'est pas installé, utiliser la solution de contournement
    if (file_exists(__DIR__ . '/env_loader_bypass.php')) {
        require_once __DIR__ . '/env_loader_bypass.php';
    } else {
        die('Veuillez installer les dépendances via Composer: composer install');
    }
}

/**
 * Fonction pour récupérer une variable d'environnement
 * Ne redéfinir que si elle n'existe pas déjà (peut être définie dans env_loader_bypass.php)
 * 
 * @param string $key Nom de la variable
 * @param mixed $default Valeur par défaut si la variable n'existe pas
 * @return mixed Valeur de la variable d'environnement
 */
if (!function_exists('env')) {
    function env($key, $default = null) {
        return isset($_ENV[$key]) ? $_ENV[$key] : $default;
    }
} 