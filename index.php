<?php
// Mode débogage forcé pour identifier l'erreur
ini_set('display_errors', 1);
error_reporting(E_ALL);

// Définir le chemin racine pour les liens dans header et footer
$root_path = '';

// Point d'entrée principal de l'application
// La session sera démarrée dans le fichier session.php, ne pas la démarrer ici

// Afficher un message pour confirmer que le script commence son exécution
echo "<!-- Démarrage du script index.php -->";

try {
    // Inclusion des fichiers nécessaires avec vérification
    if (!file_exists('config/config.php')) {
        throw new Exception("Le fichier config.php est introuvable.");
    }
    require_once 'config/config.php';  
    
    if (!file_exists('includes/session.php')) {
        throw new Exception("Le fichier session.php est introuvable.");
    }
    require_once 'includes/session.php';
    
    echo "<!-- Fichiers chargés avec succès -->";
    
    // Redirection si l'utilisateur est déjà connecté
    if (isset($_SESSION['user_id']) && isset($_SESSION['role'])) {
        // Préparation de la redirection, mais on l'exécutera après l'affichage de la page
        $redirect = true;
        $redirect_url = '';
        
        // Redirection en fonction du rôle de l'utilisateur
        switch ($_SESSION['role']) {
            case 'admin':
                $redirect_url = 'views/admin/dashboard.php';
                break;
            case 'medecin':
                $redirect_url = 'views/medecin/dashboard.php';
                break;
            case 'patient':
                $redirect_url = 'views/patient/dashboard.php';
                break;
            default:
                // En cas de rôle non reconnu, déconnexion et redirection vers la page de connexion
                session_destroy();
                $redirect_url = 'views/login.php';
                break;
        }
    } else {
        $redirect = false;
    }
} catch (Exception $e) {
    // Afficher l'erreur précise pour le débogage
    echo '<div style="background-color: #ffdddd; border: 1px solid #ff0000; padding: 10px; margin: 10px;">';
    echo '<h2>Erreur détectée :</h2>';
    echo '<p>' . htmlspecialchars($e->getMessage()) . '</p>';
    echo '<h3>Trace :</h3>';
    echo '<pre>' . htmlspecialchars($e->getTraceAsString()) . '</pre>';
    
    // Information sur le chemin des fichiers
    echo '<h3>Informations système :</h3>';
    echo '<p>Chemin actuel : ' . getcwd() . '</p>';
    echo '<p>Chemin du fichier : ' . __FILE__ . '</p>';
    echo '<p>PHP version : ' . phpversion() . '</p>';
    
    if (function_exists('env')) {
        echo '<p>APP_ENV : ' . env('APP_ENV', 'non défini') . '</p>';
    } else {
        echo '<p>Fonction env() non disponible</p>';
    }
    
    echo '</div>';
    exit;
}
?>
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MedConnect - Votre santé, notre priorité</title>
    <!-- Intégration de Tailwind via CDN -->
    <script src="https://cdn.tailwindcss.com"></script>
    <!-- Font Awesome pour les icônes -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <!-- Google Fonts -->
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        body {
            font-family: 'Poppins', sans-serif;
        }
        .hero-pattern {
            background-color: #f0f9ff;
            background-image: url("data:image/svg+xml,%3Csvg width='60' height='60' viewBox='0 0 60 60' xmlns='http://www.w3.org/2000/svg'%3E%3Cg fill='none' fill-rule='evenodd'%3E%3Cg fill='%23bae6fd' fill-opacity='0.2'%3E%3Cpath d='M36 34v-4h-2v4h-4v2h4v4h2v-4h4v-2h-4zm0-30V0h-2v4h-4v2h4v4h2V6h4V4h-4zM6 34v-4H4v4H0v2h4v4h2v-4h4v-2H6zM6 4V0H4v4H0v2h4v4h2V6h4V4H6z'/%3E%3C/g%3E%3C/g%3E%3C/svg%3E");
        }
        .service-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 10px 20px rgba(0, 0, 0, 0.1);
        }
    </style>
</head>
<body class="bg-gray-100 flex flex-col min-h-screen">
    <?php include_once 'views/components/header.php'; ?>

    <main class="flex-grow">
        <!-- Section héro -->
        <section class="hero-pattern py-20">
            <div class="container mx-auto px-4 flex flex-col md:flex-row items-center">
                <div class="md:w-1/2 mb-10 md:mb-0">
                    <h1 class="text-4xl md:text-5xl font-bold text-gray-800 leading-tight mb-6">
                        Votre santé, <br><span class="text-blue-600">notre priorité</span>
                    </h1>
                    <p class="text-lg text-gray-600 mb-8">
                        MedConnect vous permet de consulter des médecins qualifiés en ligne, 
                        de prendre rendez-vous facilement et de suivre votre dossier médical en toute sécurité.
                    </p>
                    <div class="flex flex-col sm:flex-row space-y-4 sm:space-y-0 sm:space-x-4">
                        <a href="views/register_patient.php" class="px-6 py-3 bg-blue-600 text-white font-medium rounded-md text-center hover:bg-blue-700 transition duration-300">
                            Créer un compte patient
                        </a>
                        <a href="views/register_medecin.php" class="px-6 py-3 bg-white text-blue-600 font-medium rounded-md text-center hover:bg-gray-100 transition duration-300 border border-blue-600">
                            Vous êtes médecin ?
                        </a>
                    </div>
                </div>
                <div class="md:w-1/2">
                    <img src="https://img.freepik.com/free-vector/online-doctor-consultation-illustration_88138-414.jpg" alt="Illustration MedConnect" class="w-full h-auto">
                </div>
            </div>
        </section>

        <!-- Section services -->
        <section id="services" class="py-16 bg-white">
            <div class="container mx-auto px-4">
                <div class="text-center mb-16">
                    <h2 class="text-3xl font-bold text-gray-800 mb-4">Nos services</h2>
                    <p class="text-gray-600 max-w-2xl mx-auto">
                        Découvrez les services que nous proposons pour améliorer votre expérience de soins de santé.
                    </p>
                </div>
                
                <div class="grid grid-cols-1 md:grid-cols-3 gap-8">
                    <div class="service-card bg-gray-50 p-8 rounded-lg shadow-md transition duration-300">
                        <div class="text-blue-600 text-4xl mb-4">
                            <i class="fas fa-calendar-check"></i>
                        </div>
                        <h3 class="text-xl font-semibold text-gray-800 mb-3">Rendez-vous en ligne</h3>
                        <p class="text-gray-600">
                            Prenez rendez-vous avec votre médecin en quelques clics, sans attente téléphonique.
                        </p>
                    </div>
                    
                    <div class="service-card bg-gray-50 p-8 rounded-lg shadow-md transition duration-300">
                        <div class="text-blue-600 text-4xl mb-4">
                            <i class="fas fa-video"></i>
                        </div>
                        <h3 class="text-xl font-semibold text-gray-800 mb-3">Téléconsultation</h3>
                        <p class="text-gray-600">
                            Consultez un médecin depuis chez vous par vidéoconférence sécurisée.
                        </p>
                    </div>
                    
                    <div class="service-card bg-gray-50 p-8 rounded-lg shadow-md transition duration-300">
                        <div class="text-blue-600 text-4xl mb-4">
                            <i class="fas fa-file-medical"></i>
                        </div>
                        <h3 class="text-xl font-semibold text-gray-800 mb-3">Dossier médical</h3>
                        <p class="text-gray-600">
                            Accédez à votre dossier médical complet et partagez-le en toute sécurité avec vos médecins.
                        </p>
                    </div>
                </div>
            </div>
        </section>

        <!-- Section CTA -->
        <section class="py-16 bg-blue-600">
            <div class="container mx-auto px-4 text-center">
                <h2 class="text-3xl font-bold text-white mb-6">Prêt à prendre soin de votre santé ?</h2>
                <p class="text-blue-100 max-w-2xl mx-auto mb-8">
                    Inscrivez-vous gratuitement et commencez à utiliser MedConnect dès aujourd'hui.
                </p>
                <div class="flex flex-col sm:flex-row justify-center space-y-4 sm:space-y-0 sm:space-x-4">
                    <a href="views/register_patient.php" class="px-8 py-3 bg-white text-blue-600 font-medium rounded-md text-center hover:bg-blue-50 transition duration-300">
                        Créer un compte
                    </a>
                    <a href="views/login.php" class="px-8 py-3 bg-transparent text-white font-medium rounded-md text-center hover:bg-blue-700 transition duration-300 border border-white">
                        Se connecter
                    </a>
                </div>
            </div>
        </section>
    </main>

    <?php include_once 'views/components/footer.php'; ?>

    <!-- Script JS -->
    <script>
        // Menu mobile toggle
        document.addEventListener('DOMContentLoaded', function() {
            const menuButton = document.querySelector('.md\\:hidden');
            const menuItems = document.querySelector('.md\\:flex');
            
            menuButton.addEventListener('click', function() {
                menuItems.classList.toggle('hidden');
            });
            
            <?php if(isset($redirect) && $redirect): ?>
            // Redirection automatique après un délai court pour laisser la page se charger
            setTimeout(function() {
                window.location.href = '<?php echo $redirect_url; ?>';
            }, 100);
            <?php endif; ?>
        });
    </script>
</body>
</html> 