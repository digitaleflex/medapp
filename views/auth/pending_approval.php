<?php
require_once '../../includes/session.php';

if (!isset($_SESSION['role']) || $_SESSION['role'] !== 'medecin_pending') {
    header('Location: ../../index.php');
    exit;
}
?>

<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Compte en attente de validation - MedConnect</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
</head>
<body class="bg-gray-100">
    <div class="min-h-screen flex items-center justify-center">
        <div class="bg-white p-8 rounded-lg shadow-md max-w-md w-full">
            <div class="text-center mb-6">
                <i class="fas fa-clock text-4xl text-yellow-500 mb-4"></i>
                <h1 class="text-2xl font-bold text-gray-800">Compte en attente de validation</h1>
            </div>
            
            <div class="text-gray-600 mb-6">
                <p>Votre compte est actuellement en cours de validation par notre équipe administrative. Vous recevrez un email dès que votre compte sera validé.</p>
            </div>
            
            <div class="text-center">
                <a href="../../logout.php" class="inline-block bg-red-500 text-white px-6 py-2 rounded hover:bg-red-600 transition-colors">
                    <i class="fas fa-sign-out-alt mr-2"></i>Déconnexion
                </a>
            </div>
        </div>
    </div>
</body>
</html>