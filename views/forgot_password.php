<?php
require_once '../controllers/Auth.php';

// Traitement du formulaire de demande de réinitialisation
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $auth = new Auth();
    
    // Récupérer l'email du formulaire
    $email = $_POST['email'];
    
    // Tenter d'envoyer un lien de réinitialisation
    if ($auth->forgotPassword($email)) {
        $success = "Un lien de réinitialisation a été envoyé à votre adresse email.";
    } else {
        $message = "Email non trouvé. Veuillez vérifier votre adresse email.";
    }
}
?>
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Mot de passe oublié - MedConnect</title>
    <script src="https://cdn.jsdelivr.net/npm/@tailwindcss/browser@4"></script>
</head>
<body class="bg-gray-100">
    <div class="container mx-auto px-4 py-8 max-w-md">
        <div class="bg-white rounded-lg shadow-md overflow-hidden">
            <div class="bg-blue-600 text-white px-6 py-4">
                <h3 class="text-xl font-semibold">Mot de passe oublié</h3>
            </div>
            <div class="p-6">
                <?php if (isset($message)): ?>
                    <div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded mb-4">
                        <?php echo $message; ?>
                    </div>
                <?php endif; ?>
                
                <?php if (isset($success)): ?>
                    <div class="bg-green-100 border border-green-400 text-green-700 px-4 py-3 rounded mb-4">
                        <?php echo $success; ?>
                    </div>
                <?php endif; ?>
                
                <p class="mb-4 text-gray-700">Veuillez entrer votre adresse email pour recevoir un lien de réinitialisation de mot de passe.</p>
                
                <form method="POST" action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>">
                    <div class="mb-4">
                        <label for="email" class="block text-gray-700 text-sm font-bold mb-2">Email</label>
                        <input type="email" class="shadow appearance-none border rounded w-full py-2 px-3 text-gray-700 leading-tight focus:outline-none focus:shadow-outline" id="email" name="email" required>
                    </div>
                    <div class="mb-4">
                        <button type="submit" class="bg-blue-600 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded w-full focus:outline-none focus:shadow-outline">Envoyer le lien de réinitialisation</button>
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