<?php
/**
 * Classe de gestion de l'authentification Google
 */

// Charger les dépendances
require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/../models/User.php';
require_once __DIR__ . '/../models/Patient.php';
require_once __DIR__ . '/../config/database.php';
require_once __DIR__ . '/../vendor/autoload.php';

use Google\Client as Google_Client;
use Google\Service\Oauth2 as Google_Service_Oauth2;

class GoogleAuth {
    private $client;
    private $db;
    
    /**
     * Constructeur
     * Initialise le client Google
     */
    public function __construct() {
        // Initialiser la connexion à la base de données
        $database = new Database();
        $this->db = $database->getConnection();
        
        // Vérifier que l'autoloader de Composer est disponible
        if (!file_exists(__DIR__ . '/../vendor/autoload.php')) {
            throw new Exception("Les dépendances ne sont pas installées. Exécutez 'composer install'.");
        }
        
        // Initialiser le client Google
        $this->client = new Google_Client();
        
        // Configurer le client Google avec les valeurs depuis le fichier .env
        $this->client->setClientId(config('auth.google.client_id'));
        $this->client->setClientSecret(config('auth.google.client_secret'));
        $this->client->setRedirectUri(config('auth.google.redirect_uri'));
        $this->client->addScope('email');
        $this->client->addScope('profile');
        
        // Journaliser la configuration
        Config::logError("Client Google initialisé avec l'ID client: " . config('auth.google.client_id'));
        Config::logError("URI de redirection: " . config('auth.google.redirect_uri'));
    }
    
    /**
     * Génère l'URL de connexion Google
     * 
     * @return string URL de connexion
     */
    public function getAuthUrl() {
        return $this->client->createAuthUrl();
    }
    
    /**
     * Traite le code d'autorisation retourné par Google
     * 
     * @param string $code Code d'autorisation
     * @return array Informations de l'utilisateur
     */
    public function handleCallback($code) {
        try {
            // Échanger le code contre un token d'accès
            $token = $this->client->fetchAccessTokenWithAuthCode($code);
            $this->client->setAccessToken($token);
            
            // Obtenir les informations de l'utilisateur
            $google_oauth = new Google_Service_Oauth2($this->client);
            $user_info = $google_oauth->userinfo->get();
            
            return [
                'email' => $user_info->getEmail(),
                'name' => $user_info->getName(),
                'given_name' => $user_info->getGivenName(),
                'family_name' => $user_info->getFamilyName(),
                'picture' => $user_info->getPicture(),
                'google_id' => $user_info->getId()
            ];
        } catch (Exception $e) {
            Config::logError("Erreur d'authentification Google: " . $e->getMessage());
            throw new Exception("Échec de l'authentification Google. Veuillez réessayer.");
        }
    }
    
    /**
     * Connexion ou inscription d'un utilisateur via Google
     * 
     * @param array $user_info Informations de l'utilisateur Google
     * @return int ID de l'utilisateur
     */
    public function loginOrRegisterUser($user_info) {
        // Vérifier si l'utilisateur existe déjà
        $stmt = $this->db->prepare("SELECT * FROM users WHERE email = :email");
        $stmt->bindParam(':email', $user_info['email']);
        $stmt->execute();
        
        if ($stmt->rowCount() > 0) {
            // L'utilisateur existe déjà
            $user = $stmt->fetch(PDO::FETCH_ASSOC);
            
            // Mettre à jour l'ID Google si nécessaire
            if (empty($user['google_id'])) {
                $stmt = $this->db->prepare("UPDATE users SET google_id = :google_id WHERE id = :id");
                $stmt->bindParam(':google_id', $user_info['google_id']);
                $stmt->bindParam(':id', $user['id']);
                $stmt->execute();
            }
            
            // Initialiser la session
            if (function_exists('initSession')) {
                initSession($user['id'], $user['role'], $user['nom'], $user['prenom'], $user['email'], 'google');
            } else {
                // Configuration de secours
                $_SESSION['user_id'] = $user['id'];
                $_SESSION['role'] = $user['role'];
                $_SESSION['nom'] = $user['nom'];
                $_SESSION['prenom'] = $user['prenom'];
                $_SESSION['email'] = $user['email'];
                $_SESSION['auth_method'] = 'google';
                $_SESSION['last_activity'] = time();
            }
            
            // Configurer la redirection après authentification en fonction du rôle
            $role = $user['role'];
            switch ($role) {
                case 'admin':
                    $_SESSION['auth_redirect'] = '../views/admin/dashboard.php';
                    break;
                case 'medecin':
                    $_SESSION['auth_redirect'] = '../views/medecin/dashboard.php';
                    break;
                case 'patient':
                    $_SESSION['auth_redirect'] = '../views/patient/dashboard.php';
                    break;
                default:
                    $_SESSION['auth_redirect'] = '../index.php';
                    break;
            }
            
            return $user['id'];
        } else {
            // Créer un nouvel utilisateur
            try {
                // Déterminer le rôle en fonction du type d'utilisateur stocké dans la session
                $role = isset($_SESSION['auth_user_type']) && $_SESSION['auth_user_type'] === 'medecin' 
                      ? 'medecin' : 'patient';
                
                Config::logError("Création d'un nouvel utilisateur Google avec le rôle: " . $role);
                
                // Commencer une transaction
                $this->db->beginTransaction();
                
                // S'assurer que family_name n'est pas vide, utiliser given_name ou "Utilisateur" si vide
                $nom = !empty($user_info['family_name']) ? $user_info['family_name'] : 
                      (!empty($user_info['given_name']) ? $user_info['given_name'] : "Utilisateur");
                
                // Insérer dans la table users
                $stmt = $this->db->prepare("INSERT INTO users (nom, prenom, email, google_id, role, date_creation) VALUES (:nom, :prenom, :email, :google_id, :role, NOW())");
                $stmt->bindParam(':nom', $nom);
                $stmt->bindParam(':prenom', $user_info['given_name']);
                $stmt->bindParam(':email', $user_info['email']);
                $stmt->bindParam(':google_id', $user_info['google_id']);
                $stmt->bindParam(':role', $role);
                $stmt->execute();
                
                $user_id = $this->db->lastInsertId();
                
                // Insérer également dans la table spécifique au rôle
                if ($role === 'medecin') {
                    $stmt = $this->db->prepare("INSERT INTO medecin (id, nom, prenom, email, role) VALUES (:id, :nom, :prenom, :email, :role)");
                } else {
                    $stmt = $this->db->prepare("INSERT INTO patient (id, nom, prenom, email, role) VALUES (:id, :nom, :prenom, :email, :role)");
                }
                
                $stmt->bindParam(':id', $user_id);
                $stmt->bindParam(':nom', $nom);
                $stmt->bindParam(':prenom', $user_info['given_name']);
                $stmt->bindParam(':email', $user_info['email']);
                $stmt->bindParam(':role', $role);
                $stmt->execute();
                
                // Valider la transaction
                $this->db->commit();
                
                // Initialiser la session
                if (function_exists('initSession')) {
                    initSession($user_id, $role, $nom, $user_info['given_name'], $user_info['email'], 'google');
                } else {
                    // Configuration de secours
                    $_SESSION['user_id'] = $user_id;
                    $_SESSION['role'] = $role;
                    $_SESSION['nom'] = $nom;
                    $_SESSION['prenom'] = $user_info['given_name'];
                    $_SESSION['email'] = $user_info['email'];
                    $_SESSION['auth_method'] = 'google';
                    $_SESSION['last_activity'] = time();
                }
                
                // Rediriger l'utilisateur vers le tableau de bord correspondant
                if ($role === 'medecin') {
                    $_SESSION['auth_redirect'] = '../views/medecin/dashboard.php';
                } else {
                    $_SESSION['auth_redirect'] = '../views/patient/dashboard.php';
                }
                
                // Nettoyer la session
                if (isset($_SESSION['auth_user_type'])) {
                    unset($_SESSION['auth_user_type']);
                }
                
                return $user_id;
            } catch (Exception $e) {
                // Annuler la transaction en cas d'erreur
                $this->db->rollBack();
                throw $e;
            }
        }
    }
    
    /**
     * Configure la session utilisateur
     * 
     * @param int $user_id ID de l'utilisateur
     * @param string $role Rôle de l'utilisateur
     * @param array $user_info Informations supplémentaires
     */
    private function setupSession($user_id, $role, $user_info) {
        // S'assurer que family_name n'est pas vide
        $nom = !empty($user_info['family_name']) ? $user_info['family_name'] : 
              (!empty($user_info['given_name']) ? $user_info['given_name'] : "Utilisateur");
              
        // Utiliser la fonction initSession du fichier session.php
        if (function_exists('initSession')) {
            initSession(
                $user_id,
                $role,
                $nom,
                $user_info['given_name'],
                $user_info['email'],
                'google'
            );
        } else {
            // Fallback si la fonction n'existe pas (pour compatibilité)
            $_SESSION['user_id'] = $user_id;
            $_SESSION['role'] = $role;
            $_SESSION['nom'] = $nom;
            $_SESSION['prenom'] = $user_info['given_name'];
            $_SESSION['email'] = $user_info['email'];
            $_SESSION['auth_method'] = 'google';
            $_SESSION['last_activity'] = time();
        }
    }
} 