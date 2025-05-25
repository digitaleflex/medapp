<?php
require_once '../../includes/session.php';
require_once '../../config/config.php';

// Vérifier si l'utilisateur est connecté et est un médecin
requireLogin();
requireRole('medecin');

$user_id = $_SESSION['user_id'];

try {
    // Récupérer la liste des patients du médecin
    $stmt = db()->prepare("
        SELECT DISTINCT 
            p.*
        FROM patient p
        WHERE p.id_medecin = ?
        ORDER BY p.nom, p.prenom
    ");
    
    if (!$stmt->execute([$user_id])) {
        throw new PDOException("Erreur lors de l'exécution de la requête");
    }
    
    $patients = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    if (empty($patients)) {
        $message = "Vous n'avez pas encore de patients.";
    }
} catch (PDOException $e) {
    error_log("Erreur de base de données : " . $e->getMessage());
    $message = "Une erreur est survenue lors de la récupération des patients.";
}
?>

<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Mes Patients - MedConnect</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <?php include_once '../../views/components/styles.php'; ?>
    <style>
        .patient-card {
            transition: all 0.3s ease;
        }
        .patient-card:hover {
            transform: translateX(5px);
        }
        .nav-link {
            transition: all 0.3s ease;
        }
        .nav-link:hover {
            background-color: rgba(46, 125, 50, 0.1);
            transform: translateX(5px);
        }
        .nav-link.active {
            background-color: rgba(46, 125, 50, 0.2);
            border-left: 4px solid #2E7D32;
        }
    </style>
</head>
<body class="bg-gradient-to-br from-[#F1F8E9] to-[#E8F5E9] min-h-screen">
    <div class="min-h-screen flex">
        <!-- Barre latérale -->
        <aside class="w-64 bg-white shadow-lg flex flex-col py-6 px-4">
            <div class="flex items-center justify-center mb-10">
                <div class="w-12 h-12 rounded-full bg-gradient-to-br from-[#2E7D32] to-[#81C784] flex items-center justify-center">
                    <i class="fas fa-heartbeat text-white text-xl"></i>
                </div>
                <h1 class="text-2xl font-bold text-[#1B5E20] ml-3">MedConnect</h1>
            </div>
            <nav class="flex-1 space-y-2">
                <a href="dashboard.php" class="nav-link block px-4 py-3 rounded-lg text-[#1B5E20]">
                    <i class="fas fa-home mr-3"></i>Tableau de bord
                </a>
                <a href="patients.php" class="nav-link active block px-4 py-3 rounded-lg text-[#1B5E20]">
                    <i class="fas fa-users mr-3"></i>Mes Patients
                </a>
                <a href="rdv.php" class="nav-link block px-4 py-3 rounded-lg text-[#1B5E20]">
                    <i class="fas fa-calendar-alt mr-3"></i>Agenda
                </a>
                <a href="consultations.php" class="nav-link block px-4 py-3 rounded-lg text-[#1B5E20]">
                    <i class="fas fa-stethoscope mr-3"></i>Consultations
                </a>
                <a href="ordonnances.php" class="nav-link block px-4 py-3 rounded-lg text-[#1B5E20]">
                    <i class="fas fa-prescription mr-3"></i>Ordonnances
                </a>
                <a href="messages.php" class="nav-link block px-4 py-3 rounded-lg text-[#1B5E20]">
                    <i class="fas fa-envelope mr-3"></i>Messages
                </a>
                <a href="profile_medecin.php" class="nav-link block px-4 py-3 rounded-lg text-[#1B5E20]">
                    <i class="fas fa-user-md mr-3"></i>Mon Profil
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
                        <div class="w-12 h-12 rounded-full bg-gradient-to-br from-[#2E7D32] to-[#81C784] flex items-center justify-center">
                            <i class="fas fa-user-md text-white text-xl"></i>
                        </div>
                        <h1 class="text-2xl font-bold text-[#1B5E20]">Mes Patients</h1>
                    </div>
                    <div class="flex items-center space-x-4">
                        <div class="relative">
                            <input type="text" placeholder="Rechercher un patient..." class="pl-10 pr-4 py-2 rounded-lg border border-gray-300 focus:outline-none focus:ring-2 focus:ring-green-500 focus:border-transparent">
                            <i class="fas fa-search absolute left-3 top-3 text-gray-400"></i>
                        </div>
                    </div>
                </div>
            </header>

            <!-- Contenu principal -->
            <main class="container mx-auto px-4 py-8">
                <?php if (isset($_SESSION['success'])): ?>
                    <div class="bg-[#EFF6FF] border-l-4 border-[#3b82f6] text-[#1e40af] p-4 mb-4 rounded-lg" role="alert">
                        <div class="flex items-center">
                            <div class="flex-shrink-0">
                                <i class="fas fa-check-circle text-[#3b82f6]"></i>
                            </div>
                            <div class="ml-3">
                                <p class="text-sm font-medium"><?php echo $_SESSION['success']; ?></p>
                            </div>
                        </div>
                    </div>
                    <?php unset($_SESSION['success']); ?>
                <?php endif; ?>

                <?php if (isset($message)): ?>
                    <div class="bg-yellow-100 border-l-4 border-yellow-500 text-yellow-700 p-4 mb-4 rounded-lg" role="alert">
                        <p><?php echo htmlspecialchars($message); ?></p>
                    </div>
                <?php endif; ?>

                <!-- Liste des patients -->
                <div class="bg-white rounded-xl shadow-lg p-6 glass-effect">
                    <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                        <?php foreach ($patients as $patient): ?>
                            <div class="patient-card bg-[#F1F8E9] rounded-lg p-4 hover:bg-[#E8F5E9]">
                                <div class="flex items-center justify-between">
                                    <div class="flex items-center space-x-4">
                                        <div class="w-12 h-12 rounded-full bg-gradient-to-br from-[#2E7D32] to-[#81C784] flex items-center justify-center">
                                            <i class="fas fa-user text-white"></i>
                                        </div>
                                        <div>
                                            <h3 class="text-lg font-semibold text-[#1B5E20]">
                                                <?php echo htmlspecialchars($patient['prenom'] . ' ' . $patient['nom']); ?>
                                            </h3>
                                            <p class="text-sm text-[#558B2F]">
                                                <?php echo htmlspecialchars($patient['email'] ?? 'Email non renseigné'); ?>
                                            </p>
                                        </div>
                                    </div>
                                    <div class="flex space-x-2">
                                        <a href="patient_details.php?id=<?php echo $patient['id']; ?>" 
                                           class="text-[#2E7D32] hover:text-[#1B5E20]">
                                            <i class="fas fa-eye"></i>
                                        </a>
                                        <a href="nouvelle_consultation.php?patient_id=<?php echo $patient['id']; ?>" 
                                           class="text-[#2E7D32] hover:text-[#1B5E20]">
                                            <i class="fas fa-plus-circle"></i>
                                        </a>
                                    </div>
                                </div>
                                <div class="mt-4">
                                    <p class="text-sm text-[#558B2F]">
                                        <i class="fas fa-phone mr-2"></i>
                                        <?php echo htmlspecialchars($patient['contact'] ?? 'Contact non renseigné'); ?>
                                    </p>
                                </div>
                            </div>
                        <?php endforeach; ?>
                    </div>
                </div>
            </main>
        </div>
    </div>
</body>
</html> 