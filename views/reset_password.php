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
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
</head>
<body>
    <div class="container mt-5">
        <div class="row">
            <div class="col-md-6 mx-auto">
                <div class="card">
                    <div class="card-header bg-primary text-white">
                        <h3 class="card-title">Réinitialisation de mot de passe</h3>
                    </div>
                    <div class="card-body">
                        <?php if (isset($message)): ?>
                            <div class="alert alert-danger">
                                <?php echo $message; ?>
                            </div>
                        <?php endif; ?>
                        
                        <p>Veuillez entrer votre nouveau mot de passe.</p>
                        
                        <form method="POST" action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]) . "?token=" . $token; ?>">
                            <div class="mb-3">
                                <label for="password" class="form-label">Nouveau mot de passe</label>
                                <input type="password" class="form-control" id="password" name="password" required>
                            </div>
                            <div class="mb-3">
                                <label for="confirm_password" class="form-label">Confirmer le nouveau mot de passe</label>
                                <input type="password" class="form-control" id="confirm_password" name="confirm_password" required>
                            </div>
                            <div class="mb-3">
                                <button type="submit" class="btn btn-primary btn-block">Réinitialiser le mot de passe</button>
                            </div>
                        </form>
                        <div class="text-center">
                            <p><a href="login.php">Retour à la page de connexion</a></p>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html> 