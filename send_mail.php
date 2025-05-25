<?php
/**
 * Gestion de l'envoi d'emails
 * Utilise PHPMailer pour l'envoi sécurisé des emails
 */

require_once 'config/config.php';
require_once 'vendor/autoload.php';

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;
use PHPMailer\PHPMailer\SMTP;

class Mailer {
    private $mailer;
    private $config;

    public function __construct() {
        $this->mailer = new PHPMailer(true);
        $this->config = [
            'host' => env('MAIL_HOST', 'smtp.gmail.com'),
            'port' => env('MAIL_PORT', 587),
            'username' => env('MAIL_USERNAME'),
            'password' => env('MAIL_PASSWORD'),
            'from_email' => env('MAIL_FROM_ADDRESS'),
            'from_name' => env('MAIL_FROM_NAME', 'MedConnect'),
            'encryption' => env('MAIL_ENCRYPTION', 'tls')
        ];

        $this->initializeMailer();
    }

    private function initializeMailer() {
        try {
            // Configuration du serveur
            $this->mailer->isSMTP();
            $this->mailer->Host = $this->config['host'];
            $this->mailer->SMTPAuth = true;
            $this->mailer->Username = $this->config['username'];
            $this->mailer->Password = $this->config['password'];
            $this->mailer->SMTPSecure = $this->config['encryption'];
            $this->mailer->Port = $this->config['port'];
            $this->mailer->CharSet = 'UTF-8';

            // Configuration de l'expéditeur par défaut
            $this->mailer->setFrom($this->config['from_email'], $this->config['from_name']);

            // Activer le débogage en mode développement
            if (env('APP_ENV') === 'development') {
                $this->mailer->SMTPDebug = SMTP::DEBUG_SERVER;
            }
        } catch (Exception $e) {
            error_log("Erreur d'initialisation du mailer : " . $e->getMessage());
            throw new Exception("Erreur de configuration de l'envoi d'emails");
        }
    }

    /**
     * Envoie un email de confirmation d'inscription
     * 
     * @param string $email Email du destinataire
     * @param string $nom Nom du destinataire
     * @param string $token Token de confirmation
     * @return bool True si l'email a été envoyé avec succès
     */
    public function sendConfirmationEmail($email, $nom, $token) {
        try {
            // Validation des entrées
            if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
                throw new Exception("Adresse email invalide");
            }

            if (empty($nom) || empty($token)) {
                throw new Exception("Données manquantes");
            }

            // Préparation de l'email
            $this->mailer->clearAddresses();
            $this->mailer->addAddress($email, $nom);

            $confirmation_link = env('APP_URL') . "/confirmation.php?token=" . urlencode($token);
            
            // Template HTML de l'email
            $html = $this->getEmailTemplate('confirmation', [
                'nom' => htmlspecialchars($nom),
                'confirmation_link' => $confirmation_link
            ]);

            $this->mailer->isHTML(true);
            $this->mailer->Subject = "Confirmation de votre inscription - MedConnect";
            $this->mailer->Body = $html;
            $this->mailer->AltBody = strip_tags($html);

            // Envoi de l'email
            $this->mailer->send();
            
            // Journalisation du succès
            error_log("Email de confirmation envoyé à : " . $email);
            
            return true;
        } catch (Exception $e) {
            error_log("Erreur lors de l'envoi de l'email de confirmation : " . $e->getMessage());
            throw new Exception("Impossible d'envoyer l'email de confirmation");
        }
    }

    /**
     * Envoie un email de réinitialisation de mot de passe
     * 
     * @param string $email Email du destinataire
     * @param string $nom Nom du destinataire
     * @param string $token Token de réinitialisation
     * @return bool True si l'email a été envoyé avec succès
     */
    public function sendPasswordResetEmail($email, $nom, $token) {
        try {
            // Validation des entrées
            if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
                throw new Exception("Adresse email invalide");
            }

            if (empty($nom) || empty($token)) {
                throw new Exception("Données manquantes");
            }

            // Préparation de l'email
            $this->mailer->clearAddresses();
            $this->mailer->addAddress($email, $nom);

            $reset_link = env('APP_URL') . "/reset-password.php?token=" . urlencode($token);
            
            // Template HTML de l'email
            $html = $this->getEmailTemplate('reset_password', [
                'nom' => htmlspecialchars($nom),
                'reset_link' => $reset_link
            ]);

            $this->mailer->isHTML(true);
            $this->mailer->Subject = "Réinitialisation de votre mot de passe - MedConnect";
            $this->mailer->Body = $html;
            $this->mailer->AltBody = strip_tags($html);

            // Envoi de l'email
            $this->mailer->send();
            
            // Journalisation du succès
            error_log("Email de réinitialisation envoyé à : " . $email);
            
            return true;
        } catch (Exception $e) {
            error_log("Erreur lors de l'envoi de l'email de réinitialisation : " . $e->getMessage());
            throw new Exception("Impossible d'envoyer l'email de réinitialisation");
        }
    }

    /**
     * Génère le template HTML de l'email
     * 
     * @param string $template Nom du template
     * @param array $data Données à injecter dans le template
     * @return string Template HTML
     */
    private function getEmailTemplate($template, $data) {
        $template_path = __DIR__ . "/views/emails/{$template}.php";
        
        if (!file_exists($template_path)) {
            throw new Exception("Template d'email non trouvé : {$template}");
        }

        ob_start();
        extract($data);
        include $template_path;
        return ob_get_clean();
    }
}

// Exemple d'utilisation
try {
    $mailer = new Mailer();
    
    // Pour l'envoi d'un email de confirmation
    $mailer->sendConfirmationEmail(
        'patient@example.com',
        'John Doe',
        'token_de_confirmation'
    );
    
    // Pour l'envoi d'un email de réinitialisation
    $mailer->sendPasswordResetEmail(
        'patient@example.com',
        'John Doe',
        'token_de_reinitialisation'
    );
    
} catch (Exception $e) {
    echo "Erreur : " . $e->getMessage();
}

?>