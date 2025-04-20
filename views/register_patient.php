<?php
require_once '../controllers/Auth.php';
require_once '../config/database.php';
require_once '../models/Patient.php';
require_once '../includes/session.php';

// Définir le chemin racine pour les liens dans header et footer
$root_path = '../';

// Ne pas démarrer la session ici, elle est déjà gérée par session.php

// Traitement du formulaire d'inscription
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $database = new Database();
    $db = $database->getConnection();
    
    $patient = new Patient($db);
    
    // Récupérer les données du formulaire
    $patient->nom = $_POST['nom'];
    $patient->prenom = $_POST['prenom'];
    $patient->datenais = $_POST['datenais'];
    $patient->email = $_POST['email'];
    $patient->contact = $_POST['contact'];
    $patient->password = $_POST['password'];
    
    // Vérifier si l'email existe déjà
    if ($patient->emailExists()) {
        $message = "Cet email est déjà utilisé. Veuillez en choisir un autre.";
    } else {
        // Vérifier que les mots de passe correspondent
        if ($_POST['password'] === $_POST['confirm_password']) {
            // Enregistrer le patient
            if ($patient->register()) {
                // Rediriger vers la page de connexion
                header("Location: login.php?registered=success");
                exit;
            } else {
                $message = "Une erreur s'est produite lors de l'inscription. Veuillez réessayer.";
            }
        } else {
            $message = "Les mots de passe ne correspondent pas. Veuillez réessayer.";
        }
    }
}
?>
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Inscription Patient - MedConnect</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        body {
            font-family: 'Poppins', sans-serif;
        }
    </style>
</head>
<body class="bg-gray-100 flex flex-col min-h-screen">
    <?php include_once 'components/header.php'; ?>

    <main class="flex-grow">
        <div class="container mx-auto px-4 py-12 max-w-md">
            <div class="bg-white rounded-lg shadow-md overflow-hidden">
                <div class="bg-blue-600 text-white px-6 py-4">
                    <h3 class="text-xl font-semibold">Inscription Patient</h3>
                </div>
                <div class="p-6">
                    <?php if (isset($message)): ?>
                        <div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded mb-4">
                            <?php echo $message; ?>
                        </div>
                    <?php endif; ?>
                    
                    <form method="POST" action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>">
                        <div class="mb-4">
                            <label for="nom" class="block text-gray-700 text-sm font-bold mb-2">Nom</label>
                            <input type="text" class="shadow appearance-none border rounded w-full py-2 px-3 text-gray-700 leading-tight focus:outline-none focus:shadow-outline" id="nom" name="nom" required>
                        </div>
                        <div class="mb-4">
                            <label for="prenom" class="block text-gray-700 text-sm font-bold mb-2">Prénom</label>
                            <input type="text" class="shadow appearance-none border rounded w-full py-2 px-3 text-gray-700 leading-tight focus:outline-none focus:shadow-outline" id="prenom" name="prenom" required>
                        </div>
                        <div class="mb-4">
                            <label for="datenais" class="block text-gray-700 text-sm font-bold mb-2">Date de naissance</label>
                            <input type="date" class="shadow appearance-none border rounded w-full py-2 px-3 text-gray-700 leading-tight focus:outline-none focus:shadow-outline" id="datenais" name="datenais" required>
                        </div>
                        <div class="mb-4">
                            <label for="email" class="block text-gray-700 text-sm font-bold mb-2">Email</label>
                            <input type="email" class="shadow appearance-none border rounded w-full py-2 px-3 text-gray-700 leading-tight focus:outline-none focus:shadow-outline" id="email" name="email" required>
                        </div>
                        <div class="mb-4">
                            <label for="contact" class="block text-gray-700 text-sm font-bold mb-2">Contact</label>
                            <input type="text" class="shadow appearance-none border rounded w-full py-2 px-3 text-gray-700 leading-tight focus:outline-none focus:shadow-outline" id="contact" name="contact" required>
                        </div>
                        <div class="mb-4">
                            <label for="password" class="block text-gray-700 text-sm font-bold mb-2">Mot de passe</label>
                            <input type="password" class="shadow appearance-none border rounded w-full py-2 px-3 text-gray-700 leading-tight focus:outline-none focus:shadow-outline" id="password" name="password" required>
                        </div>
                        <div class="mb-6">
                            <label for="confirm_password" class="block text-gray-700 text-sm font-bold mb-2">Confirmer le mot de passe</label>
                            <input type="password" class="shadow appearance-none border rounded w-full py-2 px-3 text-gray-700 leading-tight focus:outline-none focus:shadow-outline" id="confirm_password" name="confirm_password" required>
                        </div>
                        <div class="mb-4">
                            <button type="submit" class="bg-blue-600 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded w-full focus:outline-none focus:shadow-outline">S'inscrire</button>
                        </div>
                    </form>
                    <div class="text-center mt-4">
                        <p class="text-sm text-gray-600 mb-2">Déjà inscrit? <a href="login.php" class="text-blue-600 hover:text-blue-800">Connectez-vous ici</a></p>
                        <p class="text-sm text-gray-600">Vous êtes médecin? <a href="register_medecin.php" class="text-blue-600 hover:text-blue-800">Inscrivez-vous ici</a></p>
                    </div>
                </div>
            </div>
        </div>
    </main>

    <?php include_once 'components/footer.php'; ?>
</body>
</html> 