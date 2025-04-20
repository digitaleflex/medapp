<?php
require_once '../controllers/Auth.php';
require_once '../config/database.php';
require_once '../models/Medecin.php';
require_once '../includes/session.php';

// Définir le chemin racine pour les liens dans header et footer
$root_path = '../';

// Ne pas démarrer la session ici, elle est déjà gérée par session.php

// Traitement du formulaire d'inscription
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $database = new Database();
    $db = $database->getConnection();
    
    $medecin = new Medecin($db);
    
    // Récupérer les données du formulaire
    $medecin->nom = $_POST['nom'];
    $medecin->prenom = $_POST['prenom'];
    $medecin->datenais = $_POST['datenais'];
    $medecin->email = $_POST['email'];
    $medecin->contact = $_POST['contact'];
    $medecin->password = $_POST['password'];
    
    // Vérifier si l'email existe déjà
    if ($medecin->emailExists()) {
        $message = "Cet email est déjà utilisé. Veuillez en choisir un autre.";
    } else {
        // Vérifier que les mots de passe correspondent
        if ($_POST['password'] === $_POST['confirm_password']) {
            // Enregistrer le médecin
            if ($medecin->register()) {
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
    <title>Inscription Médecin - MedConnect</title>
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
                <div class="bg-green-600 text-white px-6 py-4">
                    <h3 class="text-xl font-semibold">Inscription Médecin</h3>
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
                        <div class="mb-4 bg-blue-50 p-4 rounded text-sm text-blue-700 border border-blue-200">
                            <p class="flex items-center"><svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5 mr-2" viewBox="0 0 20 20" fill="currentColor"><path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clip-rule="evenodd" /></svg> Après inscription, vous devrez compléter votre profil professionnel et fournir les pièces justificatives de vos qualifications.</p>
                        </div>
                        <div class="mb-4">
                            <button type="submit" class="bg-green-600 hover:bg-green-700 text-white font-bold py-2 px-4 rounded w-full focus:outline-none focus:shadow-outline">S'inscrire</button>
                        </div>
                    </form>
                    <div class="text-center mt-4">
                        <p class="text-sm text-gray-600 mb-2">Déjà inscrit? <a href="login.php" class="text-green-600 hover:text-green-800">Connectez-vous ici</a></p>
                        <p class="text-sm text-gray-600">Vous êtes patient? <a href="register_patient.php" class="text-green-600 hover:text-green-800">Inscrivez-vous ici</a></p>
                    </div>
                </div>
            </div>
        </div>
    </main>

    <?php include_once 'components/footer.php'; ?>
</body>
</html> 