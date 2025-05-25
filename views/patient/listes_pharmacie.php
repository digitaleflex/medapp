<?php
require_once '../../config/config.php';
require_once '../../includes/session.php';
requireLogin();
requireRole('patient');

// Récupération du mot-clé de recherche
$search = $_GET['search'] ?? '';

if (!empty($search)) {
    $sql = "SELECT * FROM pharmacie WHERE nom LIKE :search1 OR localisation LIKE :search2 ORDER BY nom ASC";
    $stmt = db()->prepare($sql);
    $stmt->execute([':search1' => "%$search%", ':search2' => "%$search%"]);
} else {
    $sql = "SELECT * FROM pharmacie ORDER BY nom ASC";
    $stmt = db()->prepare($sql);
    $stmt->execute();
}

$pharmacies = $stmt->fetchAll();
?>

<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Pharmacies - MedConnect</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        body {
            font-family: 'Poppins', sans-serif;
            background-color: #f0f9f5;
        }
        .nav-link {
            transition: all 0.3s ease;
        }
        .nav-link:hover {
            background-color: rgba(59, 130, 246, 0.1);
            transform: translateX(5px);
        }
        .nav-link.active {
            background-color: rgba(59, 130, 246, 0.2);
            border-left: 4px solid #3b82f6;
        }
        .glass-effect {
            background: rgba(255, 255, 255, 0.9);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.2);
        }
        .pharmacy-card {
            transition: all 0.3s ease;
        }
        .pharmacy-card:hover {
            transform: translateY(-5px);
        }
        .search-input {
            transition: all 0.3s ease;
        }
        .search-input:focus {
            border-color: #3b82f6;
            box-shadow: 0 0 0 2px rgba(59, 130, 246, 0.1);
        }
    </style>
</head>
<body class="bg-gradient-to-br from-[#EFF6FF] to-[#DBEAFE] min-h-screen">
    <div class="min-h-screen flex">
        <!-- Barre latérale -->
        <aside class="w-64 bg-white shadow-lg flex flex-col py-6 px-4">
            <div class="flex items-center justify-center mb-10">
                <div class="w-12 h-12 rounded-full bg-gradient-to-br from-[#3b82f6] to-[#60a5fa] flex items-center justify-center">
                    <i class="fas fa-heartbeat text-white text-xl"></i>
                </div>
                <h1 class="text-2xl font-bold text-[#1e40af] ml-3">MedConnect</h1>
            </div>
            <nav class="flex-1 space-y-2">
                <a href="dashboard.php" class="nav-link block px-4 py-3 rounded-lg text-[#1e40af]">
                    <i class="fas fa-home mr-3"></i>Tableau de bord
                </a>
                <a href="carnet.php" class="nav-link block px-4 py-3 rounded-lg text-[#1e40af]">
                    <i class="fas fa-book-medical mr-3"></i>Mon Carnet de Santé
                </a>
                <a href="rdv.php" class="nav-link block px-4 py-3 rounded-lg text-[#1e40af]">
                    <i class="fas fa-calendar-alt mr-3"></i>Mes Rendez-vous
                </a>
                <a href="ordonnace.php" class="nav-link block px-4 py-3 rounded-lg text-[#1e40af]">
                    <i class="fas fa-prescription mr-3"></i>Mes Ordonnances
                </a>
                <a href="listes_pharmacie.php" class="nav-link active block px-4 py-3 rounded-lg text-[#1e40af]">
                    <i class="fas fa-pills mr-3"></i>Ma Pharmacie
                </a>
                <a href="messages.php" class="nav-link block px-4 py-3 rounded-lg text-[#1e40af]">
                    <i class="fas fa-envelope mr-3"></i>Messages
                </a>
                <a href="profile_patient.php" class="nav-link block px-4 py-3 rounded-lg text-[#1e40af]">
                    <i class="fas fa-user mr-3"></i>Mon Profil
                </a>
            </nav>
            <div class="mt-6">
                <a href="../../logout.php" class="block bg-[#FF5252] hover:bg-[#D32F2F] text-white text-center px-4 py-3 rounded-lg transition-colors duration-300">
                    <i class="fas fa-sign-out-alt mr-2"></i>Déconnexion
                </a>
            </div>
        </aside>

        <!-- Contenu principal -->
        <div class="flex-1">
            <!-- En-tête -->
            <header class="bg-white shadow-sm">
                <div class="container mx-auto px-4 py-4 flex justify-between items-center">
                    <div class="flex items-center space-x-4">
                        <div class="w-12 h-12 rounded-full bg-gradient-to-br from-[#3b82f6] to-[#60a5fa] flex items-center justify-center">
                            <i class="fas fa-pills text-white text-xl"></i>
                        </div>
                        <h1 class="text-2xl font-bold text-[#1e40af]">Pharmacies</h1>
                    </div>
                    <div class="text-sm text-[#3b82f6]">
                        <i class="fas fa-calendar-alt mr-2"></i><?php echo date('d/m/Y'); ?>
                    </div>
                </div>
            </header>

            <!-- Contenu principal -->
            <main class="container mx-auto px-4 py-8">
                <!-- Formulaire de recherche -->
                <div class="bg-white rounded-xl shadow-lg p-6 mb-8 glass-effect">
                    <form method="get" class="flex items-center gap-4">
                        <div class="flex-1 relative">
                            <input type="text" 
                                   name="search" 
                                   placeholder="Rechercher une pharmacie..." 
                                   value="<?= htmlspecialchars($search) ?>"
                                   class="search-input w-full border border-gray-200 rounded-lg px-4 py-3 pl-10 focus:outline-none">
                            <i class="fas fa-search absolute left-3 top-1/2 transform -translate-y-1/2 text-[#3b82f6]"></i>
                        </div>
                        <button type="submit" 
                                class="bg-[#3b82f6] hover:bg-[#2563eb] text-white px-6 py-3 rounded-lg transition-colors duration-300 flex items-center gap-2">
                            <i class="fas fa-search"></i>
                            Rechercher
                        </button>
                    </form>
                </div>

                <!-- Liste des pharmacies -->
                <?php if (count($pharmacies) > 0): ?>
                    <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                        <?php foreach ($pharmacies as $pharmacie): ?>
                            <div class="pharmacy-card bg-white rounded-xl shadow-lg p-6 glass-effect">
                                <div class="flex items-start justify-between">
                                    <div class="flex items-center space-x-4">
                                        <div class="w-12 h-12 rounded-full bg-gradient-to-br from-[#3b82f6] to-[#60a5fa] flex items-center justify-center">
                                            <i class="fas fa-pills text-white text-xl"></i>
                                        </div>
                                        <div>
                                            <h3 class="text-xl font-semibold text-[#1e40af]"><?= htmlspecialchars($pharmacie['nom']) ?></h3>
                                            <p class="text-[#3b82f6] mt-1">
                                                <i class="fas fa-map-marker-alt mr-2"></i>
                                                <?= nl2br(htmlspecialchars($pharmacie['localisation'])) ?>
                                            </p>
                                        </div>
                                    </div>
                                </div>
                                <div class="mt-4">
                                    <a href="https://www.google.com/maps/search/?api=1&query=<?= urlencode($pharmacie['localisation']) ?>"
                                       target="_blank" 
                                       class="inline-flex items-center gap-2 text-[#3b82f6] hover:text-[#2563eb] transition-colors duration-300">
                                        <i class="fas fa-map-marked-alt"></i>
                                        Voir sur Google Maps
                                    </a>
                                </div>
                            </div>
                        <?php endforeach; ?>
                    </div>
                <?php else: ?>
                    <div class="bg-white rounded-xl shadow-lg p-8 text-center glass-effect">
                        <div class="w-16 h-16 rounded-full bg-[#FEE2E2] flex items-center justify-center mx-auto mb-4">
                            <i class="fas fa-exclamation-circle text-[#991B1B] text-2xl"></i>
                        </div>
                        <h3 class="text-xl font-semibold text-[#1e40af] mb-2">Aucune pharmacie trouvée</h3>
                        <p class="text-[#3b82f6]">Essayez de modifier vos critères de recherche</p>
                    </div>
                <?php endif; ?>
            </main>
        </div>
    </div>
</body>
</html>
