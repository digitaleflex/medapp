<?php
require_once '../../includes/session.php';

// Vérifier si l'utilisateur est connecté
requireLogin();

// Vérifier si l'utilisateur a le rôle requis
requireRole('medecin');

// Accès aux informations de l'utilisateur connecté
$user_id = $_SESSION['user_id'];
$nom = $_SESSION['nom'];
$prenom = $_SESSION['prenom'];
?>

<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Tableau de bord Médecin</title>
    <script src="https://cdn.jsdelivr.net/npm/@tailwindcss/browser@4"></script>
</head>
<body class="bg-gray-100">
    <div class="container mx-auto px-4 py-8">
        <div class="bg-white rounded-lg shadow-md p-6 mb-6">
            <h1 class="text-2xl font-bold text-green-600 mb-4">Bienvenue, Dr. <?php echo htmlspecialchars($prenom . ' ' . $nom); ?></h1>
            <p class="text-gray-600 mb-4">Votre espace médecin personnel</p>
            
            <div class="mt-4">
                <a href="../logout.php" class="bg-red-500 hover:bg-red-600 text-white font-bold py-2 px-4 rounded">
                    Déconnexion
                </a>
            </div>
        </div>
        
        <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div class="bg-white rounded-lg shadow-md p-6">
                <h2 class="text-xl font-semibold text-green-600 mb-4">Mes Patients</h2>
                <p class="text-gray-600">Gérez vos patients et consultez leurs dossiers médicaux.</p>
                <!-- Le contenu sera ajouté dans le sprint suivant -->
            </div>
            
            <div class="bg-white rounded-lg shadow-md p-6">
                <h2 class="text-xl font-semibold text-green-600 mb-4">Mon Agenda</h2>
                <p class="text-gray-600">Gérez vos rendez-vous et votre emploi du temps.</p>
                <!-- Le contenu sera ajouté dans le sprint suivant -->
            </div>
        </div>
    </div>
</body>
</html> 