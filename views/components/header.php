<?php
// Vérifier si l'utilisateur est connecté
$isLoggedIn = isset($_SESSION['user_id']);
$userRole = $_SESSION['role'] ?? '';
?>

<style>
    /* Style du bouton primaire */
.btn-primary {
    display: inline-flex;
    align-items: center;
    background: linear-gradient(135deg, #2E7D32, #81C784); /* Dégradé vert moderne */
    color: white;
    font-weight: 600;
    padding: 12px 24px;
    border-radius: 50px; /* Bouton avec bords arrondis */
    font-size: 1rem;
    text-transform: uppercase;
    letter-spacing: 1px;
    transition: all 0.3s ease-in-out; /* Transition fluide */
    box-shadow: 0 4px 10px rgba(0, 0, 0, 0.1); /* Ombre légère */
}

.btn-primary:hover {
    background: linear-gradient(135deg, #4CAF50, #388E3C); /* Dégradé plus foncé au survol */
    box-shadow: 0 6px 15px rgba(0, 0, 0, 0.15); /* Ombre plus marquée au survol */
    transform: translateY(-4px); /* Effet de surélévation */
}

.btn-primary i {
    font-size: 1.2rem; /* L'icône est légèrement agrandie pour plus d'impact */
    transition: transform 0.3s ease; /* Transition pour l'icône */
}

.btn-primary:hover i {
    transform: translateX(5px); /* L'icône bouge légèrement lors du survol */
}

</style>

<header class="bg-white bg-opacity-20 backdrop-blur-lg sticky top-0 z-50">
    <nav class="container mx-auto px-4 py-4">
        <div class="flex justify-between items-center">
            <!-- Logo -->
            <a href="/medapp" class="flex items-center space-x-2">
                <div class="w-10 h-10 rounded-full bg-gradient-to-br from-[#2E7D32] to-[#81C784] flex items-center justify-center">
                    <i class="fas fa-heartbeat text-white text-xl"></i>
                </div>
                <span class="text-2xl font-semibold text-[#1B5E20]">MedConnect</span>
            </a>

            <!-- Navigation principale -->
            <div class="hidden md:flex items-center space-x-8">
                <a href="/medapp" class="nav-link text-[#1B5E20] hover:text-[#2E7D32] transition-colors duration-300">
                    Accueil
                </a>
                <a href="#services" class="nav-link text-[#1B5E20] hover:text-[#2E7D32] transition-colors duration-300">
                    Services
                </a>
                <a href="#about" class="nav-link text-[#1B5E20] hover:text-[#2E7D32] transition-colors duration-300">
                    À propos
                </a>
                <a href="#contact" class="nav-link text-[#1B5E20] hover:text-[#2E7D32] transition-colors duration-300">
                    Contact
                </a>
            </div>

            <!-- Boutons de connexion -->
            <div class="hidden md:flex items-center space-x-4">
                <?php if ($isLoggedIn): ?>
                    <div class="relative group">
                        <button class="flex items-center space-x-2 text-[#1B5E20] hover:text-[#2E7D32] transition-colors duration-300">
                            <div class="w-8 h-8 rounded-full bg-gradient-to-br from-[#2E7D32] to-[#81C784] flex items-center justify-center">
                                <i class="fas fa-user text-white"></i>
                            </div>
                            <span>Mon compte</span>
                            <i class="fas fa-chevron-down text-sm"></i>
                        </button>
                        <div class="absolute right-0 mt-2 w-48 bg-white rounded-lg shadow-lg py-2 hidden group-hover:block transition-all duration-300">
                            <?php if ($userRole === 'medecin'): ?>
                                <a href="/medapp/views/medecin/dashboard.php" class="block px-4 py-2 text-[#1B5E20] hover:bg-[#4CAF50]/10">
                                    <i class="fas fa-tachometer-alt mr-2"></i>Tableau de bord
                                </a>
                                <a href="/medapp/views/medecin/profile_medecin.php" class="block px-4 py-2 text-[#1B5E20] hover:bg-[#4CAF50]/10">
                                    <i class="fas fa-user-md mr-2"></i>Mon profil
                                </a>
                            <?php elseif ($userRole === 'patient'): ?>
                                <a href="/medapp/views/patient/dashboard.php" class="block px-4 py-2 text-[#1B5E20] hover:bg-[#4CAF50]/10">
                                    <i class="fas fa-tachometer-alt mr-2"></i>Tableau de bord
                                </a>
                                <a href="/medapp/views/patient/profile_patient.php" class="block px-4 py-2 text-[#1B5E20] hover:bg-[#4CAF50]/10">
                                    <i class="fas fa-user mr-2"></i>Mon profil
                                </a>
                            <?php endif; ?>
                            <div class="border-t border-gray-200 my-2"></div>
                            <a href="/medapp/views/logout.php" class="block px-4 py-2 text-red-600 hover:bg-red-50">
                                <i class="fas fa-sign-out-alt mr-2"></i>Déconnexion
                            </a>
                        </div>
                    </div>
                <?php else: ?>
                <a href="/medapp/views/login.php" class="btn-primary">
                    <i class="fas fa-sign-in-alt mr-2"></i>Connexion
                </a>

                <?php endif; ?>
            </div>

            <!-- Menu mobile -->
            <button class="md:hidden text-[#1B5E20] hover:text-[#2E7D32] transition-colors duration-300" id="mobile-menu-button">
                <i class="fas fa-bars text-2xl"></i>
            </button>
        </div>

        <!-- Menu mobile déroulant -->
        <div class="md:hidden hidden" id="mobile-menu">
            <div class="px-2 pt-2 pb-3 space-y-1">
                <a href="/medapp" class="block px-3 py-2 rounded-md text-[#1B5E20] hover:bg-[#4CAF50]/10">
                    Accueil
                </a>
                <a href="#services" class="block px-3 py-2 rounded-md text-[#1B5E20] hover:bg-[#4CAF50]/10">
                    Services
                </a>
                <a href="#about" class="block px-3 py-2 rounded-md text-[#1B5E20] hover:bg-[#4CAF50]/10">
                    À propos
                </a>
                <a href="#contact" class="block px-3 py-2 rounded-md text-[#1B5E20] hover:bg-[#4CAF50]/10">
                    Contact
                </a>
                <?php if (!$isLoggedIn): ?>
                    <div class="pt-4 space-y-2">
                        <a href="/medapp/views/login.php" class="block w-full text-center px-3 py-2 rounded-md bg-[#2E7D32] text-white hover:bg-[#1B5E20]">
                            <i class="fas fa-sign-in-alt mr-2"></i>Connexion
                        </a>
                    </div>
                <?php endif; ?>
            </div>
        </div>
    </nav>
</header>

<script>
    // Menu mobile toggle
    document.getElementById('mobile-menu-button').addEventListener('click', function() {
        const mobileMenu = document.getElementById('mobile-menu');
        mobileMenu.classList.toggle('hidden');
        mobileMenu.classList.toggle('transform'); // Ajout d'une transition
    });
</script>

