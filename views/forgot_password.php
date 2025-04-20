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
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
</head>
<body>
    <div class="container mt-5">
        <div class="row">
            <div class="col-md-6 mx-auto">
                <div class="card">
                    <div class="card-header bg-primary text-white">
                        <h3 class="card-title">Mot de passe oublié</h3>
                    </div>
                    <div class="card-body">
                        <?php if (isset($message)): ?>
                            <div class="alert alert-danger">
                                <?php echo $message; ?>
                            </div>
                        <?php endif; ?>
                        
                        <?php if (isset($success)): ?>
                            <div class="alert alert-success">
                                <?php echo $success; ?>
                            </div>
                        <?php endif; ?>
                        
                        <p>Veuillez entrer votre adresse email pour recevoir un lien de réinitialisation de mot de passe.</p>
                        
                        <form method="POST" action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>">
                            <div class="mb-3">
                                <label for="email" class="form-label">Email</label>
                                <input type="email" class="form-control" id="email" name="email" required>
                            </div>
                            <div class="mb-3">
                                <button type="submit" class="btn btn-primary btn-block">Envoyer le lien de réinitialisation</button>
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