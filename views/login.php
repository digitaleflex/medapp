<?php
require_once '../controllers/Auth.php';

// Vérifier si la session est déjà démarrée
if (session_status() == PHP_SESSION_NONE) {
    // Cela sera géré par session.php, ne pas démarrer ici
    // session_start();
}

// Inclusion des fichiers nécessaires
require_once '../config/database.php';
require_once '../models/Patient.php';
require_once '../models/Medecin.php';
require_once '../includes/session.php';

// Définir le chemin racine pour les liens dans header et footer
$root_path = '../';

// Vérifier si une erreur d'authentification Google est présente dans la session
if (isset($_SESSION['auth_error'])) {
    $message = $_SESSION['auth_error'];
    unset($_SESSION['auth_error']);
}

// Traitement du formulaire de connexion
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $auth = new Auth();
    
    // Récupérer les données du formulaire
    $email = $_POST['email'];
    $password = $_POST['password'];
    
    // Tenter la connexion
    if ($auth->login($email, $password)) {
        // Récupérer le rôle depuis la session (pas besoin de redémarrer la session)
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
                header("Location:   patient/dashboard.php");
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

// x
?>
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Connexion - MedConnect</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        body {
            font-family: 'Poppins', sans-serif;
            background-color: #f0f9f5;
        }
        .form-container {
            max-width: 480px;
            margin: 0 auto;
            padding: 2rem;
            background-color: white;
            border-radius: 1rem;
            box-shadow: 0 8px 24px rgba(149, 157, 165, 0.1);
        }
        .form-header {
            background-color: #22c55e;
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
            color: #22c55e;
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
            border-color: #22c55e;
            box-shadow: 0 0 0 2px rgba(34, 197, 94, 0.1);
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
        .submit-btn {
            background-color: #22c55e;
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
            background-color: #16a34a;
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
        .link {
            color: #22c55e;
            text-decoration: none;
            transition: color 0.2s;
        }
        .link:hover {
            color: #16a34a;
            text-decoration: underline;
        }
        .link-secondary {
            color: #10b981;
        }
        .link-secondary:hover {
            color: #059669;
        }
        .register-btn {
            background-color: #10b981;
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
            margin-top: 0.5rem;
        }
        .register-btn:hover {
            background-color: #059669;
        }
    </style>
</head>
<body class="flex flex-col min-h-screen">
    <?php include_once 'components/header.php'; ?>

    <main class="flex-grow py-12">
        <div class="container mx-auto px-4">
            <!-- Introduction -->
            <div class="text-center mb-10">
                <h1 class="text-3xl font-bold text-[#166534] mb-3">Bienvenue sur MedConnect</h1>
                <p class="text-[#166534] max-w-2xl mx-auto">Connectez-vous pour accéder à votre espace médical personnel</p>
            </div>
            
            <div class="form-container">
                <div class="form-header">
                    <div class="form-avatar">
                        <i class="fas fa-user-circle"></i>
                    </div>
                </div>

                <div class="px-6 pt-12 pb-6">
                    <?php if (isset($message)): ?>
                        <div class="bg-red-50 border-l-4 border-red-500 text-red-700 p-4 rounded mb-6 flex items-start">
                            <i class="fas fa-exclamation-circle mr-3 mt-1"></i>
                            <span><?php echo $message; ?></span>
                        </div>
                    <?php endif; ?>
                    
                    <form action="" method="POST" class="space-y-6">
                        <input type="hidden" name="action" value="login">
                        
                        <div>
                            <label for="email" class="block text-gray-700 text-sm font-medium mb-2">Adresse email</label>
                            <div class="form-input-group">
                                <div class="form-input-icon-wrapper">
                                    <i class="fas fa-envelope"></i>
                                </div>
                                <input type="email" class="form-input" id="email" name="email" 
                                       placeholder="votre@email.com" required>
                            </div>
                        </div>

                        <div>
                            <label for="password" class="block text-gray-700 text-sm font-medium mb-2">Mot de passe</label>
                            <div class="form-input-group">
                                <div class="form-input-icon-wrapper">
                                    <i class="fas fa-lock"></i>
                                </div>
                                <input type="password" class="form-input" id="password" name="password" 
                                       placeholder="••••••••" required>
                            </div>
                        </div>

                        <div class="flex items-center justify-between">
                            <div class="flex items-center">
                                <input type="checkbox" id="remember" name="remember"
                                    class="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded">
                                <label for="remember" class="ml-2 block text-sm text-gray-700">
                                    Se souvenir de moi
                                </label>
                            </div>
                            <a href="forgot_password.php" class="text-sm text-blue-600 hover:text-blue-700">
                                Mot de passe oublié ?
                            </a>
                        </div>

                        <button type="submit" class="submit-btn">
                            <i class="fas fa-sign-in-alt mr-2"></i>
                            Se connecter
                        </button>
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
                        <p class="text-sm text-gray-600">Vous n'avez pas de compte ?</p>
                        <div class="space-y-3">
                            <a href="register_patient.php" class="register-btn">
                                <i class="fas fa-user-plus mr-2"></i>
                                S'inscrire en tant que patient
                            </a>
                            <a href="register_medecin.php" class="submit-btn">
                                <i class="fas fa-user-md mr-2"></i>
                                S'inscrire en tant que médecin
                            </a>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- Avantages -->
            <div class="mt-16 grid grid-cols-1 md:grid-cols-3 gap-8">
                <div class="bg-white p-6 rounded-xl shadow-md hover:shadow-lg transition duration-300 flex flex-col items-center text-center">
                    <div class="bg-blue-100 rounded-full p-4 w-16 h-16 flex items-center justify-center mb-4">
                        <i class="fas fa-shield-alt text-blue-600 text-xl"></i>
                    </div>
                    <h3 class="font-semibold text-gray-800 mb-3">Sécurité garantie</h3>
                    <p class="text-sm text-gray-600">Vos données sont protégées et cryptées selon les normes les plus strictes.</p>
                </div>
                
                <div class="bg-white p-6 rounded-xl shadow-md hover:shadow-lg transition duration-300 flex flex-col items-center text-center">
                    <div class="bg-blue-100 rounded-full p-4 w-16 h-16 flex items-center justify-center mb-4">
                        <i class="fas fa-clock text-blue-600 text-xl"></i>
                    </div>
                    <h3 class="font-semibold text-gray-800 mb-3">Accès 24/7</h3>
                    <p class="text-sm text-gray-600">Accédez à votre espace médical à tout moment, où que vous soyez.</p>
                </div>
                
                <div class="bg-white p-6 rounded-xl shadow-md hover:shadow-lg transition duration-300 flex flex-col items-center text-center">
                    <div class="bg-blue-100 rounded-full p-4 w-16 h-16 flex items-center justify-center mb-4">
                        <i class="fas fa-headset text-blue-600 text-xl"></i>
                    </div>
                    <h3 class="font-semibold text-gray-800 mb-3">Support réactif</h3>
                    <p class="text-sm text-gray-600">Notre équipe est disponible pour vous aider en cas de besoin.</p>
                </div>
            </div>
        </div>
    </main>

    <?php include_once 'components/footer.php'; ?>

    <script>
        // Animation de chargement du formulaire
        document.addEventListener('DOMContentLoaded', function() {
            const form = document.querySelector('form');
            form.classList.add('fade-in');
        });

        // Gestion des erreurs de formulaire
        const urlParams = new URLSearchParams(window.location.search);
        const error = urlParams.get('error');
        if (error) {
            const notification = document.createElement('div');
            notification.className = 'notification notification-error';
            notification.textContent = decodeURIComponent(error);
            document.body.appendChild(notification);
            setTimeout(() => notification.remove(), 5000);
        }
    </script>
</body>
</html> 