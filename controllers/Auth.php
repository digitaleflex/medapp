<?php
require_once '../config/database.php';
require_once '../models/Patient.php';
require_once '../models/Medecin.php';
require_once '../models/Admin.php';

class Auth {
    private $database;
    private $db;
    
    public function __construct() {
        $this->database = new Database();
        $this->db = $this->database->getConnection();
    }
    
    // Méthode pour gérer l'authentification
    public function login($email, $password) {
        $patient = new Patient($this->db);
        $patient->email = $email;
        
        $medecin = new Medecin($this->db);
        $medecin->email = $email;
        
        $admin = new Admin($this->db);
        $admin->email = $email;
        
        // Vérifier si l'utilisateur existe dans l'une des tables
        if($patient->emailExists()) {
            // Vérifier le mot de passe
            if(password_verify($password, $patient->password)) {
                // Mot de passe correct, créer la session
                $this->createSession($patient->id, $patient->nom, $patient->prenom, $patient->role);
                return true;
            }
        } elseif($medecin->emailExists()) {
            // Vérifier le mot de passe
            if(password_verify($password, $medecin->password)) {
                // Mot de passe correct, créer la session
                $this->createSession($medecin->id, $medecin->nom, $medecin->prenom, $medecin->role);
                return true;
            }
        } elseif($admin->emailExists()) {
            // Vérifier le mot de passe
            if(password_verify($password, $admin->password)) {
                // Mot de passe correct, créer la session
                $this->createSession($admin->id, $admin->nom, $admin->prenom, $admin->role);
                return true;
            }
        }
        
        return false;
    }
    
    // Méthode pour créer une session
    private function createSession($user_id, $nom, $prenom, $role) {
        // Démarrer la session
        if(session_status() == PHP_SESSION_NONE) {
            session_start();
        }
        
        // Stocker les informations de l'utilisateur dans la session
        $_SESSION['user_id'] = $user_id;
        $_SESSION['nom'] = $nom;
        $_SESSION['prenom'] = $prenom;
        $_SESSION['role'] = $role;
        $_SESSION['last_activity'] = time();
    }
    
    // Méthode pour vérifier si l'utilisateur est connecté
    public function isLoggedIn() {
        if(session_status() == PHP_SESSION_NONE) {
            session_start();
        }
        
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
        if(session_status() == PHP_SESSION_NONE) {
            session_start();
        }
        
        if(isset($_SESSION['role']) && $_SESSION['role'] == $required_role) {
            return true;
        }
        
        return false;
    }
    
    // Méthode pour déconnecter l'utilisateur
    public function logout() {
        if(session_status() == PHP_SESSION_NONE) {
            session_start();
        }
        
        // Détruire toutes les variables de session
        $_SESSION = array();
        
        // Détruire la session
        session_destroy();
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