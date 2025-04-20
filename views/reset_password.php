<?php
require_once '../controllers/Auth.php';

// Vérifier si un token est présent dans l'URL
if (!isset($_GET['token'])) {
    header("Location: login.php");
    exit;
}

$token = $_GET['token'];

// Traitement du formulaire de réinitialisation de mot de passe
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $auth = new Auth();
    
    // Récupérer les données du formulaire
    $password = $_POST['password'];
    $confirm_password = $_POST['confirm_password'];
    
    // Vérifier que les mots de passe correspondent
    if ($password === $confirm_password) {
        // Tenter de réinitialiser le mot de passe
        if ($auth->resetPassword($token, $password)) {
            header("Location: login.php?password_reset=success");
            exit;
        } else {
            $message = "Le lien de réinitialisation est invalide ou a expiré. Veuillez demander un nouveau lien.";
        }
    } else {
        $message = "Les mots de passe ne correspondent pas. Veuillez réessayer.";
    }
}
?>
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Réinitialisation de mot de passe - MedConnect</title>
    <script src="https://cdn.jsdelivr.net/npm/@tailwindcss/browser@4"></script>
</head>
<body class="bg-gray-100">
    <div class="container mx-auto px-4 py-8 max-w-md">
        <div class="bg-white rounded-lg shadow-md overflow-hidden">
            <div class="bg-blue-600 text-white px-6 py-4">
                <h3 class="text-xl font-semibold">Réinitialisation de mot de passe</h3>
            </div>
            <div class="p-6">
                <?php if (isset($message)): ?>
                    <div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded mb-4">
                        <?php echo $message; ?>
                    </div>
                <?php endif; ?>
                
                <p class="mb-4 text-gray-700">Veuillez entrer votre nouveau mot de passe.</p>
                
                <form method="POST" action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]) . "?token=" . $token; ?>">
                    <div class="mb-4">
                        <label for="password" class="block text-gray-700 text-sm font-bold mb-2">Nouveau mot de passe</label>
                        <input type="password" class="shadow appearance-none border rounded w-full py-2 px-3 text-gray-700 leading-tight focus:outline-none focus:shadow-outline" id="password" name="password" required>
                    </div>
                    <div class="mb-6">
                        <label for="confirm_password" class="block text-gray-700 text-sm font-bold mb-2">Confirmer le nouveau mot de passe</label>
                        <input type="password" class="shadow appearance-none border rounded w-full py-2 px-3 text-gray-700 leading-tight focus:outline-none focus:shadow-outline" id="confirm_password" name="confirm_password" required>
                    </div>
                    <div class="mb-4">
                        <button type="submit" class="bg-blue-600 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded w-full focus:outline-none focus:shadow-outline">Réinitialiser le mot de passe</button>
                    </div>
                </form>
                <div class="text-center mt-4">
                    <p class="text-sm text-gray-600"><a href="login.php" class="text-blue-600 hover:text-blue-800">Retour à la page de connexion</a></p>
                </div>
            </div>
        </div>
    </div>
</body>
</html> 