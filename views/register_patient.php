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
            background-color: #f0f5ff;
        }
        .form-container {
            max-width: 640px;
            margin: 0 auto;
            padding: 2rem;
            background-color: white;
            border-radius: 1rem;
            box-shadow: 0 8px 24px rgba(149, 157, 165, 0.1);
        }
        .form-header {
            background-color: #3b82f6;
            color: white;
            height: 80px;
            margin: -2rem -2rem 0;
            border-radius: 1rem 1rem 0 0;
            position: relative;
        }
        .form-avatar {
            width: 64px;
            height: 64px;
            background-color: white;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            position: absolute;
            bottom: -32px;
            left: 50%;
            transform: translateX(-50%);
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }
        .form-avatar i {
            color: #3b82f6;
            font-size: 1.75rem;
        }
        .form-input-group {
            display: flex;
            align-items: center;
            border: 1px solid #e5e7eb;
            border-radius: 0.5rem;
            overflow: hidden;
            transition: all 0.2s;
        }
        .form-input-group:focus-within {
            border-color: #3b82f6;
            box-shadow: 0 0 0 2px rgba(59, 130, 246, 0.1);
        }
        .form-input-icon-wrapper {
            display: flex;
            align-items: center;
            justify-content: center;
            width: 48px;
            color: #6B7280;
            background-color: #f9fafb;
            border-right: 1px solid #e5e7eb;
            padding: 0.75rem 0;
        }
        .form-input {
            flex: 1;
            border: none;
            padding: 0.75rem 1rem;
            outline: none;
            background-color: transparent;
            width: 100%;
        }
        .steps-container {
            display: flex;
            justify-content: center;
            align-items: center;
            margin: 2.5rem 0;
        }
        .step-item {
            display: flex;
            flex-direction: column;
            align-items: center;
        }
        .step-circle {
            width: 32px;
            height: 32px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 600;
            font-size: 0.875rem;
            margin-bottom: 0.5rem;
        }
        .step-active {
            background-color: #3b82f6;
            color: white;
        }
        .step-inactive {
            background-color: #dbeafe;
            color: #3b82f6;
        }
        .step-line {
            height: 2px;
            width: 100px;
            background-color: #dbeafe;
            margin: 0 0.5rem;
        }
        .step-label {
            font-size: 0.75rem;
            color: #6B7280;
        }
        .info-box {
            background-color: #f0f7ff;
            border-radius: 0.5rem;
            padding: 1rem;
            margin: 1.5rem 0;
        }
        .info-title {
            font-weight: 600;
            display: flex;
            align-items: center;
            color: #1e40af;
            margin-bottom: 0.75rem;
        }
        .info-item {
            display: flex;
            margin-bottom: 0.5rem;
            font-size: 0.875rem;
            color: #4b5563;
        }
        .info-icon {
            min-width: 20px;
            height: 20px;
            background-color: #3b82f6;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            margin-right: 0.75rem;
        }
        .info-icon i {
            color: white;
            font-size: 0.625rem;
        }
        .submit-btn {
            background-color: #3b82f6;
            color: white;
            border: none;
            border-radius: 0.5rem;
            padding: 0.875rem;
            font-weight: 600;
            width: 100%;
            display: flex;
            align-items: center;
            justify-content: center;
            cursor: pointer;
            transition: background-color 0.2s;
        }
        .submit-btn:hover {
            background-color: #2563eb;
        }
        .google-btn {
            background-color: white;
            color: #4b5563;
            border: 1px solid #e5e7eb;
            border-radius: 0.5rem;
            padding: 0.75rem;
            font-weight: 500;
            width: 100%;
            display: flex;
            align-items: center;
            justify-content: center;
            cursor: pointer;
            transition: background-color 0.2s;
            margin-top: 1rem;
        }
        .google-btn:hover {
            background-color: #f9fafb;
        }
        .google-icon {
            margin-right: 0.75rem;
        }
        .divider {
            display: flex;
            align-items: center;
            margin: 1.5rem 0;
        }
        .divider-line {
            flex: 1;
            height: 1px;
            background-color: #e5e7eb;
        }
        .divider-text {
            padding: 0 1rem;
            color: #6B7280;
            font-size: 0.875rem;
        }
        .helper-text {
            font-size: 0.75rem;
            color: #6B7280;
            margin-top: 0.25rem;
        }
        .link {
            color: #3b82f6;
            text-decoration: none;
            transition: color 0.2s;
        }
        .link:hover {
            color: #2563eb;
            text-decoration: underline;
        }
        .link-secondary {
            color: #10b981;
        }
        .link-secondary:hover {
            color: #059669;
        }
    </style>
</head>
<body class="flex flex-col min-h-screen">
    <?php include_once 'components/header.php'; ?>

    <main class="flex-grow py-12">
        <div class="container mx-auto px-4">
            <!-- Introduction -->
            <div class="text-center mb-10">
                <h1 class="text-3xl font-bold text-blue-800 mb-3">Créez votre compte patient</h1>
                <p class="text-gray-600 max-w-2xl mx-auto">Rejoignez MedConnect pour accéder à nos services médicaux en ligne, prendre rendez-vous avec vos médecins et suivre votre santé dans un environnement sécurisé.</p>
            </div>
            
            <div class="form-container">
                <div class="form-header">
                    <div class="form-avatar">
                        <i class="fas fa-user-plus"></i>
                    </div>
                </div>
                
                <div class="px-6 pt-12 pb-6">
                    <?php if (isset($message)): ?>
                        <div class="bg-red-50 border-l-4 border-red-500 text-red-700 p-4 rounded mb-6 flex items-start">
                            <i class="fas fa-exclamation-circle mr-3 mt-1"></i>
                            <span><?php echo $message; ?></span>
                        </div>
                    <?php endif; ?>
                    
                    <!-- Étapes d'inscription -->
                    <div class="steps-container">
                        <div class="step-item">
                            <div class="step-circle step-active">1</div>
                            <span class="step-label">Informations</span>
                        </div>
                        <div class="step-line"></div>
                        <div class="step-item">
                            <div class="step-circle step-inactive">2</div>
                            <span class="step-label">Confirmation</span>
                        </div>
                        <div class="step-line"></div>
                        <div class="step-item">
                            <div class="step-circle step-inactive">3</div>
                            <span class="step-label">Connexion</span>
                        </div>
                    </div>
                    
                    <form method="POST" action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" class="space-y-6">
                        <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                            <div>
                                <label for="nom" class="block text-gray-700 text-sm font-medium mb-2">Nom</label>
                                <div class="form-input-group">
                                    <div class="form-input-icon-wrapper">
                                        <i class="fas fa-user"></i>
                                    </div>
                                    <input type="text" class="form-input" id="nom" name="nom" placeholder="Votre nom" required>
                                </div>
                            </div>
                            <div>
                                <label for="prenom" class="block text-gray-700 text-sm font-medium mb-2">Prénom</label>
                                <div class="form-input-group">
                                    <div class="form-input-icon-wrapper">
                                        <i class="fas fa-user"></i>
                                    </div>
                                    <input type="text" class="form-input" id="prenom" name="prenom" placeholder="Votre prénom" required>
                                </div>
                            </div>
                        </div>
                        
                        <div>
                            <label for="datenais" class="block text-gray-700 text-sm font-medium mb-2">Date de naissance</label>
                            <div class="form-input-group">
                                <div class="form-input-icon-wrapper">
                                    <i class="fas fa-calendar"></i>
                                </div>
                                <input type="date" class="form-input" id="datenais" name="datenais" placeholder="JJ/MM/AAAA" required>
                            </div>
                        </div>
                        
                        <div>
                            <label for="email" class="block text-gray-700 text-sm font-medium mb-2">Adresse email</label>
                            <div class="form-input-group">
                                <div class="form-input-icon-wrapper">
                                    <i class="fas fa-envelope"></i>
                                </div>
                                <input type="email" class="form-input" id="email" name="email" placeholder="exemple@email.com" required>
                            </div>
                            <p class="helper-text">Nous ne partagerons jamais votre email avec des tiers.</p>
                        </div>
                        
                        <div>
                            <label for="contact" class="block text-gray-700 text-sm font-medium mb-2">Numéro de téléphone</label>
                            <div class="form-input-group">
                                <div class="form-input-icon-wrapper">
                                    <i class="fas fa-phone"></i>
                                </div>
                                <input type="text" class="form-input" id="contact" name="contact" placeholder="+33 6 XX XX XX XX" required>
                            </div>
                        </div>
                        
                        <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                            <div>
                                <label for="password" class="block text-gray-700 text-sm font-medium mb-2">Mot de passe</label>
                                <div class="form-input-group">
                                    <div class="form-input-icon-wrapper">
                                        <i class="fas fa-lock"></i>
                                    </div>
                                    <input type="password" class="form-input" id="password" name="password" placeholder="••••••••" required>
                                </div>
                            </div>
                            
                            <div>
                                <label for="confirm_password" class="block text-gray-700 text-sm font-medium mb-2">Confirmer le mot de passe</label>
                                <div class="form-input-group">
                                    <div class="form-input-icon-wrapper">
                                        <i class="fas fa-lock"></i>
                                    </div>
                                    <input type="password" class="form-input" id="confirm_password" name="confirm_password" placeholder="••••••••" required>
                                </div>
                            </div>
                        </div>
                        
                        <!-- Informations de sécurité -->
                        <div class="info-box">
                            <div class="info-title">
                                <i class="fas fa-shield-alt mr-2"></i>
                                Informations importantes
                            </div>
                            <div class="info-item">
                                <div class="info-icon">
                                    <i class="fas fa-check"></i>
                                </div>
                                <span>Votre compte patient vous permet d'accéder à vos rendez-vous et à votre dossier médical</span>
                            </div>
                            <div class="info-item">
                                <div class="info-icon">
                                    <i class="fas fa-check"></i>
                                </div>
                                <span>Toutes vos informations personnelles sont protégées et sécurisées</span>
                            </div>
                            <div class="info-item">
                                <div class="info-icon">
                                    <i class="fas fa-check"></i>
                                </div>
                                <span>Vous pourrez compléter votre profil médical après l'inscription</span>
                            </div>
                        </div>
                        
                        <div>
                            <button type="submit" class="submit-btn">
                                <i class="fas fa-user-plus mr-2"></i>
                                Créer mon compte patient
                            </button>
                        </div>
                    </form>
                    
                    <div class="divider">
                        <div class="divider-line"></div>
                        <span class="divider-text">ou</span>
                        <div class="divider-line"></div>
                    </div>
                    
                    <a href="../auth/google-login.php" class="google-btn">
                        <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" class="google-icon"><path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/><path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/><path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/><path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/></svg>
                        Continuer avec Google
                    </a>
                    
                    <div class="text-center mt-6 space-y-2">
                        <p class="text-sm text-gray-600">Déjà inscrit ? <a href="login.php" class="link">Connectez-vous ici</a></p>
                        <p class="text-sm text-gray-600">Vous êtes médecin ? <a href="register_medecin.php" class="link link-secondary">Inscrivez-vous en tant que professionnel</a></p>
                    </div>
                </div>
            </div>
            
            <!-- Avantages du compte patient -->
            <div class="mt-16 grid grid-cols-1 md:grid-cols-3 gap-8">
                <div class="bg-white p-6 rounded-xl shadow-md hover:shadow-lg transition duration-300 flex flex-col items-center text-center">
                    <div class="bg-blue-100 rounded-full p-4 w-16 h-16 flex items-center justify-center mb-4">
                        <i class="fas fa-calendar-check text-blue-600 text-xl"></i>
                    </div>
                    <h3 class="font-semibold text-gray-800 mb-3">Rendez-vous en ligne</h3>
                    <p class="text-sm text-gray-600">Trouvez et réservez facilement des rendez-vous avec vos médecins préférés.</p>
                </div>
                
                <div class="bg-white p-6 rounded-xl shadow-md hover:shadow-lg transition duration-300 flex flex-col items-center text-center">
                    <div class="bg-blue-100 rounded-full p-4 w-16 h-16 flex items-center justify-center mb-4">
                        <i class="fas fa-file-medical-alt text-blue-600 text-xl"></i>
                    </div>
                    <h3 class="font-semibold text-gray-800 mb-3">Dossier médical</h3>
                    <p class="text-sm text-gray-600">Accédez à votre historique médical et vos documents à tout moment.</p>
                </div>
                
                <div class="bg-white p-6 rounded-xl shadow-md hover:shadow-lg transition duration-300 flex flex-col items-center text-center">
                    <div class="bg-blue-100 rounded-full p-4 w-16 h-16 flex items-center justify-center mb-4">
                        <i class="fas fa-video text-blue-600 text-xl"></i>
                    </div>
                    <h3 class="font-semibold text-gray-800 mb-3">Téléconsultation</h3>
                    <p class="text-sm text-gray-600">Consultez vos médecins à distance, partout et à tout moment.</p>
                </div>
            </div>
        </div>
    </main>

    <?php include_once 'components/footer.php'; ?>
</body>
</html> 