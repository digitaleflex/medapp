<?php
// Point d'entrée de la page d'accueil
require_once '../includes/session.php';
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
        .testimonial {
            background-color: white;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.05);
            padding: 20px;
            margin: 10px;
        }
    </style>
</head>
<body class="bg-gray-50">
    <!-- Barre de navigation -->
    <nav class="bg-white shadow-md p-4">
        <div class="container mx-auto flex justify-between items-center">
            <div class="flex items-center">
                <img src="../assets/images/logo.png" alt="MedConnect Logo" class="h-10 mr-3">
                <span class="text-2xl font-bold text-blue-600">MedConnect</span>
            </div>
            <div class="hidden md:flex space-x-8">
                <a href="#" class="text-gray-800 hover:text-blue-600">Accueil</a>
                <a href="#services" class="text-gray-800 hover:text-blue-600">Services</a>
                <a href="#doctors" class="text-gray-800 hover:text-blue-600">Médecins</a>
                <a href="#testimonials" class="text-gray-800 hover:text-blue-600">Témoignages</a>
                <a href="#contact" class="text-gray-800 hover:text-blue-600">Contact</a>
            </div>
            <div class="flex items-center space-x-4">
                <a href="login.php" class="hidden md:inline-block px-4 py-2 text-blue-600 border border-blue-600 rounded-md hover:bg-blue-50">Se connecter</a>
                <a href="register_patient.php" class="hidden md:inline-block px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700">S'inscrire</a>
                <button class="md:hidden text-gray-800 focus:outline-none">
                    <i class="fas fa-bars text-xl"></i>
                </button>
            </div>
        </div>
    </nav>

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
                    <a href="register_patient.php" class="px-6 py-3 bg-blue-600 text-white font-medium rounded-md text-center hover:bg-blue-700 transition duration-300">
                        Créer un compte patient
                    </a>
                    <a href="register_medecin.php" class="px-6 py-3 bg-white text-blue-600 font-medium rounded-md text-center hover:bg-gray-100 transition duration-300 border border-blue-600">
                        Vous êtes médecin ?
                    </a>
                </div>
            </div>
            <div class="md:w-1/2">
                <img src="https://img.freepik.com/free-vector/online-doctor-consultation-illustration_88138-414.jpg" alt="Illustration MedConnect" class="w-full h-auto">
            </div>
        </div>
    </section>

    <!-- Section statistiques -->
    <section class="py-12 bg-white">
        <div class="container mx-auto px-4">
            <div class="grid grid-cols-1 md:grid-cols-3 gap-8 text-center">
                <div class="p-6">
                    <div class="text-4xl font-bold text-blue-600 mb-2">1500+</div>
                    <div class="text-gray-600">Médecins qualifiés</div>
                </div>
                <div class="p-6">
                    <div class="text-4xl font-bold text-blue-600 mb-2">20 000+</div>
                    <div class="text-gray-600">Patients satisfaits</div>
                </div>
                <div class="p-6">
                    <div class="text-4xl font-bold text-blue-600 mb-2">30+</div>
                    <div class="text-gray-600">Spécialités médicales</div>
                </div>
            </div>
        </div>
    </section>

    <!-- Section services -->
    <section id="services" class="py-16 bg-gray-50">
        <div class="container mx-auto px-4">
            <div class="text-center mb-16">
                <h2 class="text-3xl font-bold text-gray-800 mb-4">Nos services</h2>
                <p class="text-gray-600 max-w-2xl mx-auto">
                    Découvrez les services que nous proposons pour améliorer votre expérience de soins de santé.
                </p>
            </div>
            
            <div class="grid grid-cols-1 md:grid-cols-3 gap-8">
                <div class="service-card bg-white p-8 rounded-lg shadow-md transition duration-300">
                    <div class="text-blue-600 text-4xl mb-4">
                        <i class="fas fa-calendar-check"></i>
                    </div>
                    <h3 class="text-xl font-semibold text-gray-800 mb-3">Rendez-vous en ligne</h3>
                    <p class="text-gray-600">
                        Prenez rendez-vous avec votre médecin en quelques clics, sans attente téléphonique.
                    </p>
                </div>
                
                <div class="service-card bg-white p-8 rounded-lg shadow-md transition duration-300">
                    <div class="text-blue-600 text-4xl mb-4">
                        <i class="fas fa-video"></i>
                    </div>
                    <h3 class="text-xl font-semibold text-gray-800 mb-3">Téléconsultation</h3>
                    <p class="text-gray-600">
                        Consultez un médecin depuis chez vous par vidéoconférence sécurisée.
                    </p>
                </div>
                
                <div class="service-card bg-white p-8 rounded-lg shadow-md transition duration-300">
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

    <!-- Section médecins -->
    <section id="doctors" class="py-16 bg-white">
        <div class="container mx-auto px-4">
            <div class="text-center mb-16">
                <h2 class="text-3xl font-bold text-gray-800 mb-4">Nos médecins</h2>
                <p class="text-gray-600 max-w-2xl mx-auto">
                    Une équipe de médecins experts dans différentes spécialités, prêts à vous accompagner.
                </p>
            </div>
            
            <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-8">
                <!-- Médecin 1 -->
                <div class="bg-gray-50 rounded-lg overflow-hidden shadow-md">
                    <img src="https://randomuser.me/api/portraits/women/44.jpg" alt="Dr. Emilie Laurent" class="w-full h-64 object-cover">
                    <div class="p-6">
                        <h3 class="text-xl font-semibold text-gray-800 mb-1">Dr. Emilie Laurent</h3>
                        <p class="text-blue-600 mb-3">Cardiologue</p>
                        <div class="flex items-center mb-3">
                            <div class="text-yellow-400 flex">
                                <i class="fas fa-star"></i>
                                <i class="fas fa-star"></i>
                                <i class="fas fa-star"></i>
                                <i class="fas fa-star"></i>
                                <i class="fas fa-star-half-alt"></i>
                            </div>
                            <span class="text-gray-600 ml-2">4.8/5</span>
                        </div>
                        <button class="w-full py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 transition duration-300">
                            Voir le profil
                        </button>
                    </div>
                </div>
                
                <!-- Médecin 2 -->
                <div class="bg-gray-50 rounded-lg overflow-hidden shadow-md">
                    <img src="https://randomuser.me/api/portraits/men/32.jpg" alt="Dr. Thomas Petit" class="w-full h-64 object-cover">
                    <div class="p-6">
                        <h3 class="text-xl font-semibold text-gray-800 mb-1">Dr. Thomas Petit</h3>
                        <p class="text-blue-600 mb-3">Dermatologue</p>
                        <div class="flex items-center mb-3">
                            <div class="text-yellow-400 flex">
                                <i class="fas fa-star"></i>
                                <i class="fas fa-star"></i>
                                <i class="fas fa-star"></i>
                                <i class="fas fa-star"></i>
                                <i class="fas fa-star"></i>
                            </div>
                            <span class="text-gray-600 ml-2">5.0/5</span>
                        </div>
                        <button class="w-full py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 transition duration-300">
                            Voir le profil
                        </button>
                    </div>
                </div>
                
                <!-- Médecin 3 -->
                <div class="bg-gray-50 rounded-lg overflow-hidden shadow-md">
                    <img src="https://randomuser.me/api/portraits/women/68.jpg" alt="Dr. Sophie Martin" class="w-full h-64 object-cover">
                    <div class="p-6">
                        <h3 class="text-xl font-semibold text-gray-800 mb-1">Dr. Sophie Martin</h3>
                        <p class="text-blue-600 mb-3">Pédiatre</p>
                        <div class="flex items-center mb-3">
                            <div class="text-yellow-400 flex">
                                <i class="fas fa-star"></i>
                                <i class="fas fa-star"></i>
                                <i class="fas fa-star"></i>
                                <i class="fas fa-star"></i>
                                <i class="far fa-star"></i>
                            </div>
                            <span class="text-gray-600 ml-2">4.1/5</span>
                        </div>
                        <button class="w-full py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 transition duration-300">
                            Voir le profil
                        </button>
                    </div>
                </div>
                
                <!-- Médecin 4 -->
                <div class="bg-gray-50 rounded-lg overflow-hidden shadow-md">
                    <img src="https://randomuser.me/api/portraits/men/86.jpg" alt="Dr. Nicolas Dubois" class="w-full h-64 object-cover">
                    <div class="p-6">
                        <h3 class="text-xl font-semibold text-gray-800 mb-1">Dr. Nicolas Dubois</h3>
                        <p class="text-blue-600 mb-3">Généraliste</p>
                        <div class="flex items-center mb-3">
                            <div class="text-yellow-400 flex">
                                <i class="fas fa-star"></i>
                                <i class="fas fa-star"></i>
                                <i class="fas fa-star"></i>
                                <i class="fas fa-star"></i>
                                <i class="fas fa-star-half-alt"></i>
                            </div>
                            <span class="text-gray-600 ml-2">4.7/5</span>
                        </div>
                        <button class="w-full py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 transition duration-300">
                            Voir le profil
                        </button>
                    </div>
                </div>
            </div>
            
            <div class="text-center mt-12">
                <a href="#" class="inline-block px-6 py-3 bg-white text-blue-600 font-medium rounded-md border border-blue-600 hover:bg-blue-50 transition duration-300">
                    Voir tous les médecins
                </a>
            </div>
        </div>
    </section>

    <!-- Section témoignages -->
    <section id="testimonials" class="py-16 bg-gray-50">
        <div class="container mx-auto px-4">
            <div class="text-center mb-16">
                <h2 class="text-3xl font-bold text-gray-800 mb-4">Ce que disent nos patients</h2>
                <p class="text-gray-600 max-w-2xl mx-auto">
                    Découvrez les expériences vécues par nos patients grâce à MedConnect.
                </p>
            </div>
            
            <div class="grid grid-cols-1 md:grid-cols-3 gap-8">
                <div class="testimonial">
                    <div class="flex items-center mb-4">
                        <img src="https://randomuser.me/api/portraits/women/33.jpg" alt="Marie Durand" class="w-12 h-12 rounded-full mr-4">
                        <div>
                            <h4 class="font-semibold text-gray-800">Marie Durand</h4>
                            <div class="text-yellow-400 flex text-sm">
                                <i class="fas fa-star"></i>
                                <i class="fas fa-star"></i>
                                <i class="fas fa-star"></i>
                                <i class="fas fa-star"></i>
                                <i class="fas fa-star"></i>
                            </div>
                        </div>
                    </div>
                    <p class="text-gray-600 italic">
                        "MedConnect a changé ma façon de consulter. Plus besoin d'attendre des heures en salle d'attente, j'obtiens un rendez-vous rapidement et je peux même consulter en visio quand je ne peux pas me déplacer !"
                    </p>
                </div>
                
                <div class="testimonial">
                    <div class="flex items-center mb-4">
                        <img src="https://randomuser.me/api/portraits/men/45.jpg" alt="Pierre Moreau" class="w-12 h-12 rounded-full mr-4">
                        <div>
                            <h4 class="font-semibold text-gray-800">Pierre Moreau</h4>
                            <div class="text-yellow-400 flex text-sm">
                                <i class="fas fa-star"></i>
                                <i class="fas fa-star"></i>
                                <i class="fas fa-star"></i>
                                <i class="fas fa-star"></i>
                                <i class="fas fa-star-half-alt"></i>
                            </div>
                        </div>
                    </div>
                    <p class="text-gray-600 italic">
                        "Le suivi de mon dossier médical est devenu tellement plus simple ! Tous mes documents sont accessibles en un clic et je peux facilement les partager avec mes différents médecins."
                    </p>
                </div>
                
                <div class="testimonial">
                    <div class="flex items-center mb-4">
                        <img src="https://randomuser.me/api/portraits/women/56.jpg" alt="Lucie Bernard" class="w-12 h-12 rounded-full mr-4">
                        <div>
                            <h4 class="font-semibold text-gray-800">Lucie Bernard</h4>
                            <div class="text-yellow-400 flex text-sm">
                                <i class="fas fa-star"></i>
                                <i class="fas fa-star"></i>
                                <i class="fas fa-star"></i>
                                <i class="fas fa-star"></i>
                                <i class="far fa-star"></i>
                            </div>
                        </div>
                    </div>
                    <p class="text-gray-600 italic">
                        "En tant que maman de trois enfants, MedConnect me facilite énormément la vie. Je peux gérer les rendez-vous médicaux de toute la famille depuis une seule application !"
                    </p>
                </div>
            </div>
        </div>
    </section>

    <!-- Section FAQ -->
    <section class="py-16 bg-white">
        <div class="container mx-auto px-4">
            <div class="text-center mb-16">
                <h2 class="text-3xl font-bold text-gray-800 mb-4">Questions fréquentes</h2>
                <p class="text-gray-600 max-w-2xl mx-auto">
                    Nous avons répondu aux questions les plus fréquemment posées par nos utilisateurs.
                </p>
            </div>
            
            <div class="max-w-3xl mx-auto">
                <div class="mb-6 border-b border-gray-200 pb-6">
                    <h3 class="text-xl font-semibold text-gray-800 mb-2">Comment prendre rendez-vous avec un médecin ?</h3>
                    <p class="text-gray-600">
                        Après vous être connecté à votre compte, vous pouvez rechercher un médecin par spécialité ou par nom, 
                        consulter ses disponibilités et réserver un créneau qui vous convient en quelques clics.
                    </p>
                </div>
                
                <div class="mb-6 border-b border-gray-200 pb-6">
                    <h3 class="text-xl font-semibold text-gray-800 mb-2">Comment fonctionne la téléconsultation ?</h3>
                    <p class="text-gray-600">
                        Lors de votre prise de rendez-vous, vous pouvez choisir l'option "téléconsultation". Au moment du rendez-vous, 
                        connectez-vous à votre compte et cliquez sur le bouton "Rejoindre la consultation" pour lancer la vidéoconférence sécurisée avec votre médecin.
                    </p>
                </div>
                
                <div class="mb-6 border-b border-gray-200 pb-6">
                    <h3 class="text-xl font-semibold text-gray-800 mb-2">Comment sont protégées mes données médicales ?</h3>
                    <p class="text-gray-600">
                        MedConnect utilise des protocoles de chiffrement avancés pour protéger vos données. Seuls vous et les médecins 
                        que vous autorisez peuvent accéder à votre dossier médical. Nous respectons strictement le RGPD et toutes les réglementations en vigueur.
                    </p>
                </div>
                
                <div class="mb-6">
                    <h3 class="text-xl font-semibold text-gray-800 mb-2">Comment devenir médecin partenaire ?</h3>
                    <p class="text-gray-600">
                        Si vous êtes médecin et souhaitez rejoindre notre plateforme, créez un compte médecin en fournissant vos diplômes 
                        et numéro RPPS. Notre équipe vérifiera votre profil et vous accompagnera dans la prise en main de la plateforme.
                    </p>
                </div>
            </div>
        </div>
    </section>

    <!-- Section CTA -->
    <section class="py-20 bg-blue-600">
        <div class="container mx-auto px-4 text-center">
            <h2 class="text-3xl font-bold text-white mb-6">Prêt à prendre soin de votre santé ?</h2>
            <p class="text-blue-100 max-w-2xl mx-auto mb-8">
                Inscrivez-vous gratuitement et commencez à utiliser MedConnect dès aujourd'hui pour simplifier votre parcours de soins.
            </p>
            <div class="flex flex-col sm:flex-row justify-center space-y-4 sm:space-y-0 sm:space-x-4">
                <a href="register_patient.php" class="px-8 py-3 bg-white text-blue-600 font-medium rounded-md text-center hover:bg-blue-50 transition duration-300">
                    Créer un compte
                </a>
                <a href="login.php" class="px-8 py-3 bg-transparent text-white font-medium rounded-md text-center hover:bg-blue-700 transition duration-300 border border-white">
                    Se connecter
                </a>
            </div>
        </div>
    </section>

    <!-- Footer -->
    <footer class="bg-gray-800 text-white py-16">
        <div class="container mx-auto px-4">
            <div class="grid grid-cols-1 md:grid-cols-4 gap-8">
                <div>
                    <h3 class="text-xl font-semibold mb-4">MedConnect</h3>
                    <p class="text-gray-400 mb-4">
                        Votre plateforme de santé connectée pour faciliter l'accès aux soins et améliorer le suivi médical.
                    </p>
                    <div class="flex space-x-4">
                        <a href="#" class="text-gray-400 hover:text-white"><i class="fab fa-facebook-f"></i></a>
                        <a href="#" class="text-gray-400 hover:text-white"><i class="fab fa-twitter"></i></a>
                        <a href="#" class="text-gray-400 hover:text-white"><i class="fab fa-instagram"></i></a>
                        <a href="#" class="text-gray-400 hover:text-white"><i class="fab fa-linkedin-in"></i></a>
                    </div>
                </div>
                
                <div>
                    <h3 class="text-xl font-semibold mb-4">Liens rapides</h3>
                    <ul class="space-y-2">
                        <li><a href="#" class="text-gray-400 hover:text-white">Accueil</a></li>
                        <li><a href="#services" class="text-gray-400 hover:text-white">Services</a></li>
                        <li><a href="#doctors" class="text-gray-400 hover:text-white">Médecins</a></li>
                        <li><a href="#testimonials" class="text-gray-400 hover:text-white">Témoignages</a></li>
                        <li><a href="#contact" class="text-gray-400 hover:text-white">Contact</a></li>
                    </ul>
                </div>
                
                <div>
                    <h3 class="text-xl font-semibold mb-4">Services</h3>
                    <ul class="space-y-2">
                        <li><a href="#" class="text-gray-400 hover:text-white">Téléconsultation</a></li>
                        <li><a href="#" class="text-gray-400 hover:text-white">Rendez-vous en ligne</a></li>
                        <li><a href="#" class="text-gray-400 hover:text-white">Dossier médical</a></li>
                        <li><a href="#" class="text-gray-400 hover:text-white">Suivi de santé</a></li>
                        <li><a href="#" class="text-gray-400 hover:text-white">Conseil médical</a></li>
                    </ul>
                </div>
                
                <div>
                    <h3 class="text-xl font-semibold mb-4" id="contact">Contact</h3>
                    <ul class="space-y-2">
                        <li class="flex items-start">
                            <i class="fas fa-map-marker-alt mt-1 mr-2 text-gray-400"></i>
                            <span class="text-gray-400">123 Avenue de la Santé, 75001 Paris</span>
                        </li>
                        <li class="flex items-center">
                            <i class="fas fa-phone-alt mr-2 text-gray-400"></i>
                            <span class="text-gray-400">+33 1 23 45 67 89</span>
                        </li>
                        <li class="flex items-center">
                            <i class="fas fa-envelope mr-2 text-gray-400"></i>
                            <span class="text-gray-400">contact@medconnect.fr</span>
                        </li>
                    </ul>
                </div>
            </div>
            
            <div class="border-t border-gray-700 mt-12 pt-8 text-center text-gray-400">
                <p>&copy; 2024 MedConnect. Tous droits réservés.</p>
            </div>
        </div>
    </footer>

    <!-- Script JS -->
    <script>
        // Menu mobile toggle
        document.addEventListener('DOMContentLoaded', function() {
            const menuButton = document.querySelector('.md\\:hidden');
            const menuItems = document.querySelector('.md\\:flex');
            
            menuButton.addEventListener('click', function() {
                menuItems.classList.toggle('hidden');
            });
        });
    </script>
</body>
</html> 