<?php
/**
 * Classe de gestion de l'authentification Google
 */

// Charger les dépendances
require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/../models/User.php';
require_once __DIR__ . '/../models/Patient.php';

class GoogleAuth {
    private $client;
    
    /**
     * Constructeur
     * Initialise le client Google
     */
    public function __construct() {
        // Vérifier que l'autoloader de Composer est disponible
        if (!file_exists(__DIR__ . '/../vendor/autoload.php')) {
            throw new Exception("Les dépendances ne sont pas installées. Exécutez 'composer install'.");
        }
        
        // Initialiser le client Google
        $this->client = new Google_Client();
        $this->client->setClientId(config('auth.google.client_id'));
        $this->client->setClientSecret(config('auth.google.client_secret'));
        $this->client->setRedirectUri(config('auth.google.redirect_uri'));
        $this->client->addScope('email');
        $this->client->addScope('profile');
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
                $stmt->bindParam(':google_id', $user_info['id']);
                $stmt->bindParam(':id', $user['id']);
                $stmt->execute();
            }
            
            // Initialiser la session
            initSession($user['id'], $user['role'], $user['nom'], $user['prenom'], $user['email'], 'google');
            
            // Configurer la redirection après authentification en fonction du rôle
            if (isset($_SESSION['role'])) {
                switch ($_SESSION['role']) {
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
            }
            
            return $user['id'];
        } else {
            // Créer un nouvel utilisateur
            try {
                // Commencer une transaction
                $this->db->beginTransaction();
                
                // Insérer dans la table users
                $stmt = $this->db->prepare("INSERT INTO users (nom, prenom, email, google_id, role, created_at) VALUES (:nom, :prenom, :email, :google_id, 'patient', NOW())");
                $stmt->bindParam(':nom', $user_info['family_name']);
                $stmt->bindParam(':prenom', $user_info['given_name']);
                $stmt->bindParam(':email', $user_info['email']);
                $stmt->bindParam(':google_id', $user_info['id']);
                $stmt->execute();
                
                $user_id = $this->db->lastInsertId();
                
                // Insérer également dans la table patient
                $stmt = $this->db->prepare("INSERT INTO patient (id, nom, prenom, email, role) VALUES (:id, :nom, :prenom, :email, 'patient')");
                $stmt->bindParam(':id', $user_id);
                $stmt->bindParam(':nom', $user_info['family_name']);
                $stmt->bindParam(':prenom', $user_info['given_name']);
                $stmt->bindParam(':email', $user_info['email']);
                $stmt->execute();
                
                // Valider la transaction
                $this->db->commit();
                
                // Initialiser la session
                initSession($user_id, 'patient', $user_info['family_name'], $user_info['given_name'], $user_info['email'], 'google');
                
                // Rediriger l'utilisateur vers le tableau de bord patient
                $_SESSION['auth_redirect'] = '../views/patient/dashboard.php';
                
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
        // Utiliser la fonction initSession du fichier session.php
        if (function_exists('initSession')) {
            initSession(
                $user_id,
                $role,
                $user_info['family_name'],
                $user_info['given_name'],
                $user_info['email'],
                'google'
            );
        } else {
            // Fallback si la fonction n'existe pas (pour compatibilité)
            $_SESSION['user_id'] = $user_id;
            $_SESSION['role'] = $role;
            $_SESSION['nom'] = $user_info['family_name'];
            $_SESSION['prenom'] = $user_info['given_name'];
            $_SESSION['email'] = $user_info['email'];
            $_SESSION['auth_method'] = 'google';
            $_SESSION['last_activity'] = time();
        }
    }
} 