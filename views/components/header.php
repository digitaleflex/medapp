<!-- Barre de navigation -->
<nav class="bg-white shadow-md p-4">
    <div class="container mx-auto flex justify-between items-center">
        <div class="flex items-center">
            <a href="<?php echo isset($root_path) ? $root_path : ''; ?>index.php" class="flex items-center">
                <img src="<?php echo isset($root_path) ? $root_path : ''; ?>assets/images/logo.png" alt="MedConnect Logo" class="h-10 mr-3">
                <span class="text-2xl font-bold text-blue-600">MedConnect</span>
            </a>
        </div>
        <div class="hidden md:flex space-x-8">
            <a href="<?php echo isset($root_path) ? $root_path : ''; ?>index.php" class="text-gray-800 hover:text-blue-600">Accueil</a>
            <a href="<?php echo isset($root_path) ? $root_path : ''; ?>index.php#services" class="text-gray-800 hover:text-blue-600">Services</a>
            <a href="<?php echo isset($root_path) ? $root_path : ''; ?>index.php#contact" class="text-gray-800 hover:text-blue-600">Contact</a>
            
            <?php if (isset($_SESSION['user_id']) && isset($_SESSION['role'])): ?>
                <?php switch($_SESSION['role']): 
                    case 'admin': ?>
                        <a href="<?php echo isset($root_path) ? $root_path : ''; ?>views/admin/dashboard.php" class="text-gray-800 hover:text-blue-600">Tableau de bord</a>
                    <?php break; ?>
                    <?php case 'medecin': ?>
                        <a href="<?php echo isset($root_path) ? $root_path : ''; ?>views/medecin/dashboard.php" class="text-gray-800 hover:text-blue-600">Tableau de bord</a>
                    <?php break; ?>
                    <?php case 'patient': ?>
                        <a href="<?php echo isset($root_path) ? $root_path : ''; ?>views/patient/dashboard.php" class="text-gray-800 hover:text-blue-600">Tableau de bord</a>
                    <?php break; ?>
                <?php endswitch; ?>
            <?php endif; ?>
        </div>
        <div class="flex items-center space-x-4">
            <?php if (isset($_SESSION['user_id'])): ?>
                <div class="hidden md:flex items-center">
                    <span class="text-gray-800 mr-2">Bonjour, <?php echo isset($_SESSION['prenom']) ? htmlspecialchars($_SESSION['prenom']) : 'Utilisateur'; ?></span>
                    <a href="<?php echo isset($root_path) ? $root_path : ''; ?>views/logout.php" class="px-4 py-2 text-blue-600 border border-blue-600 rounded-md hover:bg-blue-50 font-medium">Déconnexion</a>
                </div>
            <?php else: ?>
                <a href="<?php echo isset($root_path) ? $root_path : ''; ?>views/login.php" class="hidden md:inline-block px-4 py-2 text-blue-600 border border-blue-600 rounded-md hover:bg-blue-50 font-medium">Se connecter</a>
                <a href="<?php echo isset($root_path) ? $root_path : ''; ?>views/register_patient.php" class="hidden md:inline-block px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 font-medium">S'inscrire</a>
            <?php endif; ?>
            <button class="md:hidden text-gray-800 focus:outline-none" id="mobile-menu-button">
                <i class="fas fa-bars text-xl"></i>
            </button>
        </div>
    </div>
    <!-- Menu mobile -->
    <div id="mobile-menu" class="hidden md:hidden bg-white pt-4 pb-2 px-4">
        <a href="<?php echo isset($root_path) ? $root_path : ''; ?>index.php" class="block py-2 text-gray-800 hover:text-blue-600">Accueil</a>
        <a href="<?php echo isset($root_path) ? $root_path : ''; ?>index.php#services" class="block py-2 text-gray-800 hover:text-blue-600">Services</a>
        <a href="<?php echo isset($root_path) ? $root_path : ''; ?>index.php#contact" class="block py-2 text-gray-800 hover:text-blue-600">Contact</a>
        
        <?php if (isset($_SESSION['user_id']) && isset($_SESSION['role'])): ?>
            <?php switch($_SESSION['role']): 
                case 'admin': ?>
                    <a href="<?php echo isset($root_path) ? $root_path : ''; ?>views/admin/dashboard.php" class="block py-2 text-gray-800 hover:text-blue-600">Tableau de bord</a>
                <?php break; ?>
                <?php case 'medecin': ?>
                    <a href="<?php echo isset($root_path) ? $root_path : ''; ?>views/medecin/dashboard.php" class="block py-2 text-gray-800 hover:text-blue-600">Tableau de bord</a>
                <?php break; ?>
                <?php case 'patient': ?>
                    <a href="<?php echo isset($root_path) ? $root_path : ''; ?>views/patient/dashboard.php" class="block py-2 text-gray-800 hover:text-blue-600">Tableau de bord</a>
                <?php break; ?>
            <?php endswitch; ?>
            
            <a href="<?php echo isset($root_path) ? $root_path : ''; ?>views/logout.php" class="block py-2 text-gray-800 hover:text-blue-600">Déconnexion</a>
        <?php else: ?>
            <a href="<?php echo isset($root_path) ? $root_path : ''; ?>views/login.php" class="block py-2 text-gray-800 hover:text-blue-600">Se connecter</a>
            <a href="<?php echo isset($root_path) ? $root_path : ''; ?>views/register_patient.php" class="block py-2 text-gray-800 hover:text-blue-600">S'inscrire</a>
        <?php endif; ?>
    </div>
</nav>

<script>
    // Menu mobile toggle
    document.addEventListener('DOMContentLoaded', function() {
        const menuButton = document.getElementById('mobile-menu-button');
        const mobileMenu = document.getElementById('mobile-menu');
        
        menuButton.addEventListener('click', function() {
            mobileMenu.classList.toggle('hidden');
        });
    });
</script> 