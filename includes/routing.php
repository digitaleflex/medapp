<?php
function redirectIfNotLoggedIn() {
    if (!isset($_SESSION['user_id']) || !isset($_SESSION['role'])) {
        header('Location: ../../index.php');
        exit();
    }
}

function redirectIfNotAuthorized($requiredRole) {
    if (!isset($_SESSION['role']) || $_SESSION['role'] !== $requiredRole) {
        header('Location: ../../index.php');
        exit();
    }
}

function getDashboardUrl() {
    if (!isset($_SESSION['role'])) {
        return '../../index.php';
    }
    
    switch ($_SESSION['role']) {
        case 'admin':
            return '../admin/dashboard.php';
        case 'medecin':
            return '../medecin/dashboard.php';
        case 'patient':
            return '../patient/dashboard.php';
        default:
            return '../../index.php';
    }
}
?> 