<?php
require_once '../config/database.php';
require_once '../models/Patient.php';
require_once '../models/Medecin.php';
require_once '../models/Admin.php';
require_once '../includes/session.php';

class Auth {
    private $database;
    private $db;
    
    public function __construct() {
        $this->database = new Database();
        $this->db = $this->database->getConnection();
    }
    
    /**
     * Connexion de l'utilisateur
     *
     * @param string $email Email de l'utilisateur
     * @param string $password Mot de passe de l'utilisateur
     * @return bool Succès ou échec de la connexion
     */
    public function login($email, $password) {
        // Vérifier que les données sont non vides
        if (empty($email) || empty($password)) {
            return false;
        }
        
        try {
            // Rechercher l'utilisateur dans la base de données
            $stmt = $this->db->prepare('SELECT * FROM users WHERE email = :email');
            $stmt->bindParam(':email', $email);
            $stmt->execute();
            
            if ($stmt->rowCount() > 0) {
                $user = $stmt->fetch(PDO::FETCH_ASSOC);
                
                // Vérifier le mot de passe
                if (password_verify($password, $user['password'])) {
                    // Initialiser la session
                    if (function_exists('initSession')) {
                        initSession($user['id'], $user['role'], $user['nom'], $user['prenom'], $user['email'], 'standard');
                    } else {
                        // Configuration de secours
                        $_SESSION['user_id'] = $user['id'];
                        $_SESSION['role'] = $user['role'];
                        $_SESSION['nom'] = $user['nom'];
                        $_SESSION['prenom'] = $user['prenom'];
                        $_SESSION['email'] = $user['email'];
                        $_SESSION['auth_method'] = 'standard';
                        $_SESSION['last_activity'] = time();
                    }
                    
                    // Définir la redirection selon le rôle
                    switch ($user['role']) {
                        case 'admin':
                            $_SESSION['redirect_url'] = 'views/admin/dashboard.php';
                            break;
                        case 'medecin':
                            $_SESSION['redirect_url'] = 'views/medecin/dashboard.php';
                            break;
                        case 'patient':
                            $_SESSION['redirect_url'] = 'views/patient/dashboard.php';
                            break;
                        default:
                            $_SESSION['redirect_url'] = 'index.php';
                            break;
                    }
                    
                    return true;
                }
            }
        } catch (PDOException $e) {
            Config::logError("Erreur de connexion: " . $e->getMessage());
        }
        
        return false;
    }
    
    // Méthode pour vérifier si l'utilisateur est connecté
    public function isLoggedIn() {
        // Ne plus démarrer la session ici car elle est déjà démarrée dans le fichier session.php
        
        // Vérifier si l'ID utilisateur existe dans la session et si la session n'a pas expiré
        if(isset($_SESSION['user_id']) && isset($_SESSION['last_activity'])) {
            // Vérifier si la dernière activité date de moins de 30 minutes
            if(time() - $_SESSION['last_activity'] < 1800) {
                // Mettre à jour le temps de dernière activité
                $_SESSION['last_activity'] = time();
                return true;
            } else {
                // La session a expiré, déconnecter l'utilisateur
                $this->logout();
            }
        }
        
        return false;
    }
    
    // Méthode pour vérifier le rôle de l'utilisateur
    public function checkRole($required_role) {
        // Ne plus démarrer la session ici car elle est déjà démarrée dans le fichier session.php
        
        if(isset($_SESSION['role']) && $_SESSION['role'] == $required_role) {
            return true;
        }
        
        return false;
    }
    
    // Méthode pour déconnecter l'utilisateur
    public function logout() {
        // Ne plus démarrer la session ici car elle est déjà démarrée dans le fichier session.php
        
        // Utiliser la fonction de déconnexion du fichier session.php si disponible
        if (function_exists('logout')) {
            logout();
        } else {
            // Fallback - Détruire toutes les variables de session
            $_SESSION = array();
            
            // Détruire la session
            session_destroy();
        }
    }
    
    // Méthode pour initier la réinitialisation du mot de passe
    public function forgotPassword($email) {
        $patient = new Patient($this->db);
        $patient->email = $email;
        
        $medecin = new Medecin($this->db);
        $medecin->email = $email;
        
        $admin = new Admin($this->db);
        $admin->email = $email;
        
        // Vérifier si l'email existe dans l'une des tables
        if($patient->emailExists()) {
            $token = $patient->generateResetToken();
            $this->sendResetEmail($email, $token);
            return true;
        } elseif($medecin->emailExists()) {
            $token = $medecin->generateResetToken();
            $this->sendResetEmail($email, $token);
            return true;
        } elseif($admin->emailExists()) {
            $token = $admin->generateResetToken();
            $this->sendResetEmail($email, $token);
            return true;
        }
        
        return false;
    }
    
    // Méthode pour envoyer un email de réinitialisation
    private function sendResetEmail($email, $token) {
        $to = $email;
        $subject = "Réinitialisation de mot de passe - MedConnect";
        
        $message = "
        <html>
        <head>
        <title>Réinitialisation de mot de passe</title>
        </head>
        <body>
        <h2>Bonjour,</h2>
        <p>Vous avez demandé la réinitialisation de votre mot de passe. Veuillez cliquer sur le lien ci-dessous pour définir un nouveau mot de passe:</p>
        <p><a href='http://localhost/medapp/views/reset_password.php?token=$token'>Réinitialiser mon mot de passe</a></p>
        <p>Ce lien expirera dans 1 heure.</p>
        <p>Si vous n'avez pas demandé la réinitialisation de votre mot de passe, veuillez ignorer cet email.</p>
        <p>Cordialement,<br>L'équipe MedConnect</p>
        </body>
        </html>
        ";
        
        // Pour envoyer un e-mail HTML, l'en-tête Content-type doit être défini
        $headers = "MIME-Version: 1.0" . "\r\n";
        $headers .= "Content-type:text/html;charset=UTF-8" . "\r\n";
        $headers .= 'From: noreply@medconnect.com' . "\r\n";
        
        // Envoyer l'e-mail
        mail($to, $subject, $message, $headers);
    }
    
    // Méthode pour réinitialiser le mot de passe
    public function resetPassword($token, $new_password) {
        // Vérifier si le token existe et est valide
        $query = "SELECT email, expire_date, used FROM password_reset WHERE token = ? LIMIT 0,1";
        $stmt = $this->db->prepare($query);
        $stmt->bindParam(1, $token);
        $stmt->execute();
        
        if($stmt->rowCount() > 0) {
            $row = $stmt->fetch(PDO::FETCH_ASSOC);
            $email = $row['email'];
            $expire_date = $row['expire_date'];
            $used = $row['used'];
            
            // Vérifier si le token n'a pas expiré et n'a pas déjà été utilisé
            if(strtotime($expire_date) >= time() && $used == 0) {
                // Mettre à jour le mot de passe
                $patient = new Patient($this->db);
                $patient->email = $email;
                
                $medecin = new Medecin($this->db);
                $medecin->email = $email;
                
                $admin = new Admin($this->db);
                $admin->email = $email;
                
                if($patient->emailExists()) {
                    $patient->password = $new_password;
                    if($patient->updatePassword()) {
                        // Marquer le token comme utilisé
                        $this->markTokenAsUsed($token);
                        return true;
                    }
                } elseif($medecin->emailExists()) {
                    $medecin->password = $new_password;
                    if($medecin->updatePassword()) {
                        // Marquer le token comme utilisé
                        $this->markTokenAsUsed($token);
                        return true;
                    }
                } elseif($admin->emailExists()) {
                    $admin->password = $new_password;
                    if($admin->updatePassword()) {
                        // Marquer le token comme utilisé
                        $this->markTokenAsUsed($token);
                        return true;
                    }
                }
            }
        }
        
        return false;
    }
    
    // Méthode pour marquer un token comme utilisé
    private function markTokenAsUsed($token) {
        $query = "UPDATE password_reset SET used = 1 WHERE token = ?";
        $stmt = $this->db->prepare($query);
        $stmt->bindParam(1, $token);
        $stmt->execute();
    }
} 