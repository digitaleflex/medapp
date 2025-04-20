<?php
require_once '../controllers/Auth.php';

// Traitement du formulaire de connexion
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $auth = new Auth();
    
    // Récupérer les données du formulaire
    $email = $_POST['email'];
    $password = $_POST['password'];
    
    // Tenter la connexion
    if ($auth->login($email, $password)) {
        // Récupérer le rôle depuis la session
        session_start();
        $role = $_SESSION['role'];
        
        // Rediriger vers la page appropriée selon le rôle
        switch ($role) {
            case 'admin':
                header("Location: admin/dashboard.php");
                break;
            case 'medecin':
                header("Location: medecin/dashboard.php");
                break;
            case 'patient':
                header("Location: patient/dashboard.php");
                break;
            default:
                header("Location: index.php");
                break;
        }
        exit;
    } else {
        $message = "Email ou mot de passe incorrect. Veuillez réessayer.";
    }
}
?>
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Connexion - MedConnect</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
</head>
<body>
    <div class="container mt-5">
        <div class="row">
            <div class="col-md-6 mx-auto">
                <div class="card">
                    <div class="card-header bg-primary text-white">
                        <h3 class="card-title">Connexion</h3>
                    </div>
                    <div class="card-body">
                        <?php if (isset($message)): ?>
                            <div class="alert alert-danger">
                                <?php echo $message; ?>
                            </div>
                        <?php endif; ?>
                        
                        <?php if (isset($_GET['registered']) && $_GET['registered'] == 'success'): ?>
                            <div class="alert alert-success">
                                Inscription réussie ! Vous pouvez maintenant vous connecter.
                            </div>
                        <?php endif; ?>
                        
                        <?php if (isset($_GET['password_reset']) && $_GET['password_reset'] == 'success'): ?>
                            <div class="alert alert-success">
                                Votre mot de passe a été réinitialisé avec succès. Vous pouvez maintenant vous connecter.
                            </div>
                        <?php endif; ?>
                        
                        <form method="POST" action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>">
                            <div class="mb-3">
                                <label for="email" class="form-label">Email</label>
                                <input type="email" class="form-control" id="email" name="email" required>
                            </div>
                            <div class="mb-3">
                                <label for="password" class="form-label">Mot de passe</label>
                                <input type="password" class="form-control" id="password" name="password" required>
                            </div>
                            <div class="mb-3">
                                <button type="submit" class="btn btn-primary btn-block">Se connecter</button>
                            </div>
                        </form>
                        <div class="text-center">
                            <p><a href="forgot_password.php">Mot de passe oublié?</a></p>
                            <p>Vous n'avez pas de compte? <a href="register_patient.php">Inscrivez-vous ici</a></p>
                            <p>Vous êtes médecin? <a href="register_medecin.php">Inscrivez-vous en tant que médecin</a></p>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html> 