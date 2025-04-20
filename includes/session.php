<?php
// Démarrer la session si elle n'est pas déjà démarrée
if(session_status() == PHP_SESSION_NONE) {
    session_start();
}

// Fonction pour vérifier si l'utilisateur est connecté
function isLoggedIn() {
    if(isset($_SESSION['user_id']) && isset($_SESSION['last_activity'])) {
        // Vérifier si la dernière activité date de moins de 30 minutes
        if(time() - $_SESSION['last_activity'] < 1800) {
            // Mettre à jour le temps de dernière activité
            $_SESSION['last_activity'] = time();
            return true;
        } else {
            // La session a expiré, déconnecter l'utilisateur
            logout();
        }
    }
    return false;
}

// Fonction pour vérifier le rôle de l'utilisateur
function checkRole($required_role) {
    if(isset($_SESSION['role']) && $_SESSION['role'] == $required_role) {
        return true;
    }
    return false;
}

// Fonction pour rediriger vers la page de connexion si l'utilisateur n'est pas connecté
function requireLogin() {
    if(!isLoggedIn()) {
        header("Location: ../login.php");
        exit;
    }
}

// Fonction pour rediriger vers la page appropriée si l'utilisateur n'a pas le rôle requis
function requireRole($required_role) {
    if(!checkRole($required_role)) {
        // Rediriger vers la page d'accueil correspondant au rôle actuel
        $role = $_SESSION['role'];
        switch($role) {
            case 'admin':
                header("Location: ../admin/dashboard.php");
                break;
            case 'medecin':
                header("Location: ../medecin/dashboard.php");
                break;
            case 'patient':
                header("Location: ../patient/dashboard.php");
                break;
            default:
                header("Location: ../login.php");
                break;
        }
        exit;
    }
}

// Fonction pour déconnecter l'utilisateur
function logout() {
    // Détruire toutes les variables de session
    $_SESSION = array();
    
    // Détruire la session
    session_destroy();
    
    // Rediriger vers la page de connexion
    header("Location: ../login.php");
    exit;
} 