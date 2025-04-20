<?php
require_once '../controllers/Auth.php';
require_once '../config/database.php';
require_once '../models/Patient.php';

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
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
</head>
<body>
    <div class="container mt-5">
        <div class="row">
            <div class="col-md-6 mx-auto">
                <div class="card">
                    <div class="card-header bg-primary text-white">
                        <h3 class="card-title">Inscription Patient</h3>
                    </div>
                    <div class="card-body">
                        <?php if (isset($message)): ?>
                            <div class="alert alert-danger">
                                <?php echo $message; ?>
                            </div>
                        <?php endif; ?>
                        
                        <form method="POST" action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>">
                            <div class="mb-3">
                                <label for="nom" class="form-label">Nom</label>
                                <input type="text" class="form-control" id="nom" name="nom" required>
                            </div>
                            <div class="mb-3">
                                <label for="prenom" class="form-label">Prénom</label>
                                <input type="text" class="form-control" id="prenom" name="prenom" required>
                            </div>
                            <div class="mb-3">
                                <label for="datenais" class="form-label">Date de naissance</label>
                                <input type="date" class="form-control" id="datenais" name="datenais" required>
                            </div>
                            <div class="mb-3">
                                <label for="email" class="form-label">Email</label>
                                <input type="email" class="form-control" id="email" name="email" required>
                            </div>
                            <div class="mb-3">
                                <label for="contact" class="form-label">Contact</label>
                                <input type="text" class="form-control" id="contact" name="contact" required>
                            </div>
                            <div class="mb-3">
                                <label for="password" class="form-label">Mot de passe</label>
                                <input type="password" class="form-control" id="password" name="password" required>
                            </div>
                            <div class="mb-3">
                                <label for="confirm_password" class="form-label">Confirmer le mot de passe</label>
                                <input type="password" class="form-control" id="confirm_password" name="confirm_password" required>
                            </div>
                            <div class="mb-3">
                                <button type="submit" class="btn btn-primary btn-block">S'inscrire</button>
                            </div>
                        </form>
                        <div class="text-center">
                            <p>Déjà inscrit? <a href="login.php">Connectez-vous ici</a></p>
                            <p>Vous êtes médecin? <a href="register_medecin.php">Inscrivez-vous ici</a></p>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html> 