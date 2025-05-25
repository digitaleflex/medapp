<?php
/**
 * Configuration générale de l'application
 * Inclut les paramètres de base de données et les fonctions de connexion sécurisée
 */

// Définition des constantes de chemins
define('ROOT_PATH', dirname(__DIR__));
define('CONFIG_PATH', __DIR__);
define('INCLUDES_PATH', ROOT_PATH . '/includes');
define('LOGS_PATH', ROOT_PATH . '/logs');
define('UPLOADS_PATH', ROOT_PATH . '/uploads');
define('VIEWS_PATH', ROOT_PATH . '/views');

// Charger les variables d'environnement
require_once INCLUDES_PATH . '/env_loader_bypass.php';

// Activation de la gestion stricte des erreurs
error_reporting(E_ALL);
ini_set('display_errors', env('APP_ENV') === 'development' ? 1 : 0);

// Classe de configuration et gestion de la connexion à la base de données
class Config {
    // Configuration de base de l'application
    private static $config = [
        'database' => [
            'host' => null,
            'dbname' => null,
            'username' => null,
            'password' => null,
            'charset' => 'utf8mb4',
            'options' => [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES => false,
                PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES utf8mb4 COLLATE utf8mb4_unicode_ci"
            ]
        ],
        'app' => [
            'log_errors' => true,
            'error_log_path' => LOGS_PATH . '/error.log',
            'session_timeout' => 1800, // 30 minutes
            'env' => null,
            'debug' => false,
            'allowed_origins' => ['http://localhost', 'https://medapp.com']
        ],
        'auth' => [
            'google' => [
                'client_id' => null,
                'client_secret' => null,
                'redirect_uri' => null,
            ]
        ]
    ];

    /**
     * Initialise la configuration avec les variables d'environnement
     * @throws Exception Si la configuration est invalide
     */
    public static function init() {
        try {
            // Validation des paramètres de base de données
            $required_db_params = ['DB_HOST', 'DB_NAME', 'DB_USER'];
    
            foreach ($required_db_params as $param) {
                if (env($param) === false) {
                    throw new Exception("Paramètre de base de données manquant : {$param}");
                }
            }
    
            // Vérification spéciale pour DB_PASS
            $dbPass = env('DB_PASS');
            if (!isset($dbPass) && !empty($dbPass) && $_ENV['APP_ENV'] !== 'development') {
                throw new Exception("Paramètre de base de données manquant : DB_PASS");
            }
    
            // Charger les paramètres de base de données depuis .env
            self::$config['database']['host'] = env('DB_HOST');
            self::$config['database']['dbname'] = env('DB_NAME');
            self::$config['database']['username'] = env('DB_USER');
            self::$config['database']['password'] = $dbPass; // Utilisation de la valeur DB_PASS
            
            // Charger les paramètres de l'application
            self::$config['app']['env'] = env('APP_ENV', 'development');
            self::$config['app']['debug'] = env('APP_DEBUG', false);
            
            // Charger les paramètres d'authentification Google
            self::$config['auth']['google']['client_id'] = env('GOOGLE_CLIENT_ID');
            self::$config['auth']['google']['client_secret'] = env('GOOGLE_CLIENT_SECRET');
            self::$config['auth']['google']['redirect_uri'] = env('GOOGLE_REDIRECT_URI');

            // Créer les répertoires nécessaires
            self::createRequiredDirectories();
        } catch (Exception $e) {
            self::logError('Erreur d\'initialisation de la configuration : ' . $e->getMessage());
            throw $e;
        }
    }

    /**
     * Crée les répertoires nécessaires s'ils n'existent pas
     */
    private static function createRequiredDirectories() {
        $directories = [
            LOGS_PATH,
            UPLOADS_PATH,
            UPLOADS_PATH . '/temp',
            UPLOADS_PATH . '/documents',
            UPLOADS_PATH . '/images'
        ];

        foreach ($directories as $dir) {
            if (!file_exists($dir)) {
                mkdir($dir, 0755, true);
            }
        }
    }

    /**
     * Récupère une valeur de configuration
     * 
     * @param string $key Clé de configuration (utiliser la notation 'section.paramètre')
     * @param mixed $default Valeur par défaut si la clé n'existe pas
     * @return mixed La valeur de configuration ou la valeur par défaut
     */
    public static function get($key, $default = null) {
        $keys = explode('.', $key);
        $value = self::$config;

        foreach ($keys as $segment) {
            if (!isset($value[$segment])) {
                return $default;
            }
            $value = $value[$segment];
        }

        return $value;
    }

    /**
     * Établit une connexion sécurisée à la base de données
     * 
     * @return PDO Instance de connexion à la base de données
     * @throws PDOException Si la connexion échoue
     */
    public static function getDbConnection() {
        try {
            // Validation des paramètres de configuration
            $host = self::get('database.host');
            $dbname = self::get('database.dbname');
            $username = self::get('database.username');
            $password = self::get('database.password');
            $charset = self::get('database.charset', 'utf8mb4');
            $options = self::get('database.options', []);

            if (empty($host) || empty($dbname)) {
                throw new Exception("Configuration de base de données incomplète");
            }

            // Connexion à la base de données avec timeout
            $dsn = "mysql:host={$host};dbname={$dbname};charset={$charset}";
            $options[PDO::ATTR_TIMEOUT] = 5; // 5 secondes de timeout
            $pdo = new PDO($dsn, $username, $password, $options);

            // Test de la connexion
            $pdo->query("SELECT 1");

            return $pdo;
        } catch (PDOException $e) {
            self::logError('Erreur de connexion à la base de données : ' . $e->getMessage());
            
            // En production, ne pas révéler les détails de l'erreur
            if (self::isProduction()) {
                throw new Exception("Impossible de se connecter à la base de données. Veuillez contacter l'administrateur.");
            } else {
                throw $e; // En développement, propager l'erreur complète
            }
        } catch (Exception $e) {
            self::logError('Erreur de configuration : ' . $e->getMessage());
            throw $e;
        }
    }

    /**
     * Détermine si l'application tourne en mode production
     * 
     * @return bool True si en production
     */
    public static function isProduction() {
        return self::get('app.env') === 'production';
    }

    /**
     * Enregistre une erreur dans le journal
     * 
     * @param string $message Message d'erreur
     * @return void
     */
    public static function logError($message) {
        if (self::get('app.log_errors', true)) {
            $logPath = self::get('app.error_log_path', '../logs/error.log');
            $logDir = dirname($logPath);
            
            // Créer le répertoire de logs s'il n'existe pas
            if (!file_exists($logDir)) {
                mkdir($logDir, 0755, true);
            }
            
            $timestamp = date('Y-m-d H:i:s');
            $logMessage = "[{$timestamp}] {$message}" . PHP_EOL;
            
            error_log($logMessage, 3, $logPath);
        }
    }
}

// Initialiser la configuration
Config::init();

// Fonction raccourci pour récupérer une connexion à la base de données
function db() {
    static $db = null;
    
    if ($db === null) {
        $db = Config::getDbConnection();
    }
    
    return $db;
}

// Fonction raccourci pour récupérer une valeur de configuration
function config($key, $default = null) {
    return Config::get($key, $default);
}


