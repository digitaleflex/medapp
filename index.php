<?php
// Ajout des en-têtes de sécurité
header("X-Frame-Options: DENY");
header("X-XSS-Protection: 1; mode=block");
header("X-Content-Type-Options: nosniff");
header("Referrer-Policy: strict-origin-when-cross-origin");
header("Content-Security-Policy: default-src 'self' https: 'unsafe-inline' 'unsafe-eval'; img-src 'self' https: data:;");

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
    
    if (!file_exists('includes/routing.php')) {
        throw new Exception("Le fichier routing.php est introuvable.");
    }
    require_once 'includes/routing.php';
    
    echo "<!-- Fichiers chargés avec succès -->";
    
    // Redirection si l'utilisateur est déjà connecté
    if (isset($_SESSION['user_id']) && isset($_SESSION['role'])) {
        // Redirection vers le dashboard uniquement si on est sur la page d'accueil
        if ($_SERVER['REQUEST_URI'] === '/medapp/' || $_SERVER['REQUEST_URI'] === '/medapp/index.php') {
            header('Location: ' . getDashboardUrl());
            exit();
        }
    }
} catch (Exception $e) {
    // Journalisation de l'erreur
    error_log("Erreur dans index.php : " . $e->getMessage());
    
    // Afficher l'erreur précise pour le débogage
    echo '<div style="background-color: #ffdddd; border: 1px solid #ff0000; padding: 10px; margin: 10px;">';
    echo '<h2>Erreur détectée :</h2>';
    echo '<p>' . htmlspecialchars($e->getMessage()) . '</p>';
    
    // En mode développement, afficher plus de détails
    if (env('APP_ENV') === 'development') {
        echo '<h3>Trace :</h3>';
        echo '<pre>' . htmlspecialchars($e->getTraceAsString()) . '</pre>';
        
        // Information sur le chemin des fichiers
        echo '<h3>Informations système :</h3>';
        echo '<p>Chemin actuel : ' . htmlspecialchars(getcwd()) . '</p>';
        echo '<p>Chemin du fichier : ' . htmlspecialchars(__FILE__) . '</p>';
        echo '<p>PHP version : ' . htmlspecialchars(phpversion()) . '</p>';
        
        if (function_exists('env')) {
            echo '<p>APP_ENV : ' . htmlspecialchars(env('APP_ENV', 'non défini')) . '</p>';
        } else {
            echo '<p>Fonction env() non disponible</p>';
        }
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
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <link href="https://unpkg.com/aos@2.3.1/dist/aos.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        body {
            font-family: 'Inter', sans-serif;
        }
        .hero-pattern {
            background: linear-gradient(135deg, #f0fdf4 0%, #dcfce7 100%);
            position: relative;
            overflow: hidden;
        }
        .hero-pattern::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background-image: url("data:image/svg+xml,%3Csvg width='60' height='60' viewBox='0 0 60 60' xmlns='http://www.w3.org/2000/svg'%3E%3Cg fill='none' fill-rule='evenodd'%3E%3Cg fill='%2322c55e' fill-opacity='0.1'%3E%3Cpath d='M36 34v-4h-2v4h-4v2h4v4h2v-4h4v-2h-4zm0-30V0h-2v4h-4v2h4v4h2V6h4V4h-4zM6 34v-4H4v4H0v2h4v4h2v-4h4v-2H6zM6 4V0H4v4H0v2h4v4h2V6h4V4H6z'/%3E%3C/g%3E%3C/g%3E%3C/svg%3E");
            opacity: 0.5;
        }
        .service-card {
            @apply bg-white p-10 rounded-[2rem] transition-all duration-300 relative overflow-hidden;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
        }
        .service-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04);
        }
        .service-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 4px;
            background: linear-gradient(90deg, #22c55e, #16a34a);
            transform: scaleX(0);
            transition: transform 0.3s ease;
        }
        .service-card:hover::before {
            transform: scaleX(1);
        }
        .gradient-bg {
            background: linear-gradient(135deg, #22c55e 0%, #16a34a 100%);
        }
        .btn-primary {
            @apply text-[#22c55e] hover:text-[#16a34a] transition-all duration-300 flex items-center justify-center gap-3 font-medium text-lg;
        }
        .btn-secondary {
            @apply text-[#22c55e] hover:text-[#16a34a] transition-all duration-300 flex items-center justify-center gap-3 font-medium text-lg;
        }
        .icon {
            @apply w-24 h-24 rounded-[1.5rem] bg-[#dcfce7] flex items-center justify-center mb-8;
        }
        .icon i {
            @apply text-4xl text-[#22c55e];
        }
        .testimonial-card {
            @apply bg-white p-8 rounded-2xl shadow-lg;
        }
        .testimonial-avatar {
            @apply w-16 h-16 rounded-full object-cover border-4 border-[#22c55e];
        }
    </style>
</head>
<body class="bg-gradient-to-br from-[#f0fdf4] to-[#dcfce7] min-h-screen">
    <?php include_once 'views/components/header.php'; ?>

    <main class="flex-grow">
        <!-- Section héro -->
            <section class="hero-pattern py-32 relative z-10">
            <div class="container mx-auto px-6 flex flex-col-reverse lg:flex-row items-center justify-between">
                <!-- Texte -->
                <div class="lg:w-1/2 text-center lg:text-left" data-aos="fade-right">
                    <h1 class="text-5xl md:text-6xl font-extrabold leading-tight text-[#14532d] mb-6">
                        Réinventer la santé,<br>
                        <span class="text-[#22c55e]">simplement et humainement.</span>
                    </h1>
                    <p class="text-xl text-[#166534] mb-8 leading-relaxed max-w-xl">
                        MedConnect, c'est bien plus qu'un site médical. C'est un espace où innovation rime avec accessibilité. 
                        Consultations en ligne, suivi en temps réel et équipe bienveillante à votre écoute.
                    </p>

                    <div class="flex flex-col sm:flex-row sm:space-x-6 space-y-4 sm:space-y-0 justify-center lg:justify-start">
                        <a href="#services" class="bg-[#22c55e] text-white px-8 py-4 rounded-full text-lg font-semibold shadow-md hover:bg-[#16a34a] transition">
                            Découvrir nos services
                        </a>
                        <a href="#contact" class="text-[#22c55e] border border-[#22c55e] px-8 py-4 rounded-full text-lg font-semibold hover:bg-[#dcfce7] transition">
                            Contactez-nous
                        </a>
                    </div>
                </div>

                <!-- Image -->
                <div class="lg:w-1/2 mb-10 lg:mb-0" data-aos="fade-left">
                    <img src="./assets/images/home.jpg" 
                        alt="Équipe médicale illustration" 
                        class="w-full max-w-lg mx-auto h-auto rounded-3xl shadow-2xl transform hover:scale-105 transition-transform duration-500">
                </div>
            </div>
        </section>


        <!-- Section services -->
            <section id="services" class="py-24 bg-gradient-to-b from-white via-[#f0fdf4] to-[#dcfce7]">
                <div class="container mx-auto px-4 max-w-7xl">
                    <div class="text-center mb-20">
                        <h2 class="text-4xl font-bold text-[#166534] mb-6">Une expérience médicale révolutionnaire</h2>
                        <p class="text-xl text-[#166534] max-w-3xl mx-auto">
                            Découvrez comment nous transformons votre parcours de soins avec des solutions innovantes et personnalisées.
                        </p>
                        <hr class="border-t-4 border-[#22c55e] w-24 mx-auto mt-8 rounded-full">
                    </div>

                    <div class="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-12 max-w-6xl mx-auto">
                        
                        <!-- Carte 1 -->
                        <div class="service-card p-8 bg-white rounded-2xl shadow-lg hover:shadow-2xl transition-shadow duration-300">
                            <div class="icon text-4xl text-[#22c55e] mb-6 text-center animate-pulse">
                                <i class="fas fa-calendar-check"></i>
                            </div>
                            <h3 class="text-2xl font-semibold text-[#166534] mb-4 text-center">Consultations intelligentes</h3>
                            <p class="text-[#166534] text-lg leading-relaxed text-center">
                                Planifiez vos rendez-vous en quelques clics avec notre système de prise de rendez-vous intelligent qui s'adapte à vos disponibilités.
                            </p>
                            <ul class="mt-6 space-y-3">
                                <li class="flex items-center text-[#166534]">
                                    <i class="fas fa-check-circle mr-3 text-[#22c55e]"></i>
                                    Disponible 24h/24
                                </li>
                                <li class="flex items-center text-[#166534]">
                                    <i class="fas fa-check-circle mr-3 text-[#22c55e]"></i>
                                    Rappels automatiques
                                </li>
                            </ul>
                        </div>

                        <!-- Carte 2 -->
                        <div class="service-card p-8 bg-white rounded-2xl shadow-lg hover:shadow-2xl transition-shadow duration-300">
                            <div class="icon text-4xl text-[#22c55e] mb-6 text-center animate-pulse">
                                <i class="fas fa-video"></i>
                            </div>
                            <h3 class="text-2xl font-semibold text-[#166534] mb-4 text-center">Téléconsultation premium</h3>
                            <p class="text-[#166534] text-lg leading-relaxed text-center">
                                Consultez des médecins qualifiés depuis chez vous avec une expérience de téléconsultation haute qualité et sécurisée.
                            </p>
                            <ul class="mt-6 space-y-3">
                                <li class="flex items-center text-[#166534]">
                                    <i class="fas fa-check-circle mr-3 text-[#22c55e]"></i>
                                    Vidéo HD sécurisée
                                </li>
                                <li class="flex items-center text-[#166534]">
                                    <i class="fas fa-check-circle mr-3 text-[#22c55e]"></i>
                                    Support technique 24/7
                                </li>
                            </ul>
                        </div>

                        <!-- Carte 3 -->
                        <div class="service-card p-8 bg-white rounded-2xl shadow-lg hover:shadow-2xl transition-shadow duration-300">
                            <div class="icon text-4xl text-[#22c55e] mb-6 text-center animate-pulse">
                                <i class="fas fa-file-medical"></i>
                            </div>
                            <h3 class="text-2xl font-semibold text-[#166534] mb-4 text-center">Dossier médical connecté</h3>
                            <p class="text-[#166534] text-lg leading-relaxed text-center">
                                Accédez à votre dossier médical complet et partagez-le en toute sécurité avec vos praticiens de confiance.
                            </p>
                            <ul class="mt-6 space-y-3">
                                <li class="flex items-center text-[#166534]">
                                    <i class="fas fa-check-circle mr-3 text-[#22c55e]"></i>
                                    Historique complet
                                </li>
                                <li class="flex items-center text-[#166534]">
                                    <i class="fas fa-check-circle mr-3 text-[#22c55e]"></i>
                                    Partage sécurisé
                                </li>
                            </ul>
                        </div>

                    </div>
                </div>
            </section>


        <!-- Section témoignages -->
        <section class="py-24 bg-white">
            <div class="container mx-auto px-4">
                <div class="text-center mb-20">
                    <h2 class="text-4xl font-bold text-[#166534] mb-6">Ce que disent nos utilisateurs</h2>
                    <p class="text-xl text-[#166534] max-w-3xl mx-auto">
                        Découvrez les expériences de nos patients et médecins.
                    </p>
                </div>

                <div class="grid grid-cols-1 md:grid-cols-3 gap-10">
                    <div class="testimonial-card">
                        <div class="flex items-center mb-6">
                            <img src="https://randomuser.me/api/portraits/women/1.jpg" alt="Patient" class="testimonial-avatar">
                            <div class="ml-4">
                                <h4 class="text-lg font-semibold text-[#166534]">Marie Dupont</h4>
                                <p class="text-[#166534]">Patient</p>
                            </div>
                        </div>
                        <p class="text-[#166534] text-lg">"MedConnect a révolutionné ma façon de consulter. Plus besoin de me déplacer, je peux prendre rendez-vous en quelques clics."</p>
                    </div>

                    <div class="testimonial-card">
                        <div class="flex items-center mb-6">
                            <img src="https://randomuser.me/api/portraits/men/1.jpg" alt="Médecin" class="testimonial-avatar">
                            <div class="ml-4">
                                <h4 class="text-lg font-semibold text-[#166534]">Dr. Jean Martin</h4>
                                <p class="text-[#166534]">Médecin généraliste</p>
                            </div>
                        </div>
                        <p class="text-[#166534] text-lg">"Une plateforme intuitive qui me permet de mieux gérer mon cabinet et d'offrir un service de qualité à mes patients."</p>
                    </div>

                    <div class="testimonial-card">
                        <div class="flex items-center mb-6">
                            <img src="https://randomuser.me/api/portraits/women/2.jpg" alt="Patient" class="testimonial-avatar">
                            <div class="ml-4">
                                <h4 class="text-lg font-semibold text-[#166534]">Sophie Bernard</h4>
                                <p class="text-[#166534]">Patient</p>
                            </div>
                        </div>
                        <p class="text-[#166534] text-lg">"Le suivi de mon dossier médical est beaucoup plus simple. Je peux accéder à mes résultats et prescriptions en un clic."</p>
                    </div>
                </div>
            </div>
        </section>

        <!-- Section CTA -->
        <section class="py-24 gradient-bg">
            <div class="container mx-auto px-4 text-center">
                <h2 class="text-4xl font-bold text-white mb-8">Prêt à révolutionner votre accès aux soins ?</h2>
                <p class="text-xl text-white/90 max-w-3xl mx-auto mb-12">
                    Rejoignez MedConnect aujourd'hui et bénéficiez d'une expérience de soins moderne et personnalisée.
                </p>
                <div class="flex flex-col space-y-6">
                    <p class="text-2xl text-white font-medium">
                        <i class="fas fa-heart mr-3"></i>
                        Votre santé mérite le meilleur
                    </p>
                    <p class="text-2xl text-white font-medium">
                        <i class="fas fa-clock mr-3"></i>
                        Des soins accessibles 24h/24 et 7j/7
                    </p>
                </div>
            </div>
        </section>
    </main>

    <?php include_once 'views/components/footer.php'; ?>

    <!-- Script JS -->
    <script>
        document.addEventListener('DOMContentLoaded', function() {
            const menuButton = document.querySelector('.md\\:hidden');
            const menuItems = document.querySelector('.md\\:flex');
            
            menuButton.addEventListener('click', function() {
                menuItems.classList.toggle('hidden');
            });
            
            <?php if(isset($redirect) && $redirect): ?>
            setTimeout(function() {
                window.location.href = '<?php echo $redirect_url; ?>';
            }, 100);
            <?php endif; ?>
        });
    </script>

    <script src="https://unpkg.com/aos@2.3.1/dist/aos.js"></script>
<script>
  AOS.init({
    duration: 1000,
    once: true
  });
</script>

</body>
</html> 