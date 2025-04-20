<!-- Footer -->
<footer class="bg-gray-800 text-white py-12">
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
                    <li><a href="../../index.php" class="text-gray-400 hover:text-white">Accueil</a></li>
                    <li><a href="../../index.php#services" class="text-gray-400 hover:text-white">Services</a></li>
                    <li><a href="../../index.php#contact" class="text-gray-400 hover:text-white">Contact</a></li>
                    <?php if (isset($_SESSION['user_id'])): ?>
                    <li><a href="../views/logout.php" class="text-gray-400 hover:text-white">Déconnexion</a></li>
                    <?php else: ?>
                    <li><a href="../views/login.php" class="text-gray-400 hover:text-white">Connexion</a></li>
                    <?php endif; ?>
                </ul>
            </div>
            
            <div>
                <h3 class="text-xl font-semibold mb-4">Services</h3>
                <ul class="space-y-2">
                    <li><a href="#" class="text-gray-400 hover:text-white">Téléconsultation</a></li>
                    <li><a href="#" class="text-gray-400 hover:text-white">Rendez-vous en ligne</a></li>
                    <li><a href="#" class="text-gray-400 hover:text-white">Dossier médical</a></li>
                    <li><a href="#" class="text-gray-400 hover:text-white">Suivi de santé</a></li>
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
        
        <div class="border-t border-gray-700 mt-8 pt-8 text-center text-gray-400">
            <p>&copy; <?php echo date('Y'); ?> MedConnect. Tous droits réservés.</p>
        </div>
    </div>
</footer> 