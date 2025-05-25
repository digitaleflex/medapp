<?php
require_once '../../includes/session.php';
require_once '../../config/config.php';

// Vérifier si l'utilisateur est connecté et est un médecin
requireLogin();
requireRole('medecin');

$user_id = $_SESSION['user_id'];
$ordonnances = []; // Initialiser le tableau des ordonnances

try {
    // Récupérer la liste des ordonnances du médecin
    $stmt = db()->prepare("
        SELECT o.*, p.nom as patient_nom, p.prenom as patient_prenom
        FROM ordonnance o
        JOIN patient p ON o.idpatient = p.id
        WHERE o.idmedecin = ?
        ORDER BY o.date_creation DESC
    ");
    
    if (!$stmt->execute([$user_id])) {
        throw new PDOException("Erreur lors de l'exécution de la requête");
    }
    
    $ordonnances = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    if (empty($ordonnances)) {
        $message = "Vous n'avez pas encore créé d'ordonnances.";
    }
} catch (PDOException $e) {
    error_log("Erreur de base de données : " . $e->getMessage());
    $message = "Une erreur est survenue lors de la récupération des ordonnances.";
    $ordonnances = []; // S'assurer que $ordonnances est un tableau vide en cas d'erreur
}
?>

<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Ordonnances - MedConnect</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <?php include_once '../../views/components/styles.php'; ?>
    <style>
        .ordonnance-card {
            transition: all 0.3s ease;
        }
        .ordonnance-card:hover {
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
                <a href="patients.php" class="nav-link block px-4 py-3 rounded-lg text-[#1B5E20]">
                    <i class="fas fa-users mr-3"></i>Mes Patients
                </a>
                <a href="rdv.php" class="nav-link block px-4 py-3 rounded-lg text-[#1B5E20]">
                    <i class="fas fa-calendar-alt mr-3"></i>Agenda
                </a>
                <a href="consultations.php" class="nav-link block px-4 py-3 rounded-lg text-[#1B5E20]">
                    <i class="fas fa-stethoscope mr-3"></i>Consultations
                </a>
                <a href="ordonnances.php" class="nav-link active block px-4 py-3 rounded-lg text-[#1B5E20]">
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
                            <i class="fas fa-prescription text-white text-xl"></i>
                        </div>
                        <h1 class="text-2xl font-bold text-[#1B5E20]">Ordonnances</h1>
                    </div>
                    <div class="flex items-center space-x-4">
                        <div class="relative">
                            <input type="text" placeholder="Rechercher une ordonnance..." class="pl-10 pr-4 py-2 rounded-lg border border-gray-300 focus:outline-none focus:ring-2 focus:ring-green-500 focus:border-transparent">
                            <i class="fas fa-search absolute left-3 top-3 text-gray-400"></i>
                        </div>
                        <a href="nouvelle_ordonnance.php" class="btn-primary">
                            <i class="fas fa-plus-circle mr-2"></i>Nouvelle ordonnance
                        </a>
                    </div>
                </div>
            </header>

            <!-- Contenu principal -->
            <main class="container mx-auto px-4 py-8">
                <?php if (isset($message)): ?>
                    <div class="bg-yellow-100 border-l-4 border-yellow-500 text-yellow-700 p-4 mb-4 rounded-lg" role="alert">
                        <p><?php echo htmlspecialchars($message); ?></p>
                    </div>
                <?php endif; ?>

                <!-- Liste des ordonnances -->
                <div class="bg-white rounded-xl shadow-lg p-6 glass-effect">
                    <div class="grid grid-cols-1 gap-6">
                        <?php foreach ($ordonnances as $ordonnance): ?>
                            <div class="ordonnance-card bg-[#F1F8E9] rounded-lg p-6 hover:bg-[#E8F5E9]">
                                <div class="flex items-center justify-between mb-4">
                                    <div class="flex items-center space-x-4">
                                        <div class="w-12 h-12 rounded-full bg-gradient-to-br from-[#2E7D32] to-[#81C784] flex items-center justify-center">
                                            <i class="fas fa-user text-white"></i>
                                        </div>
                                        <div>
                                            <h3 class="text-lg font-semibold text-[#1B5E20]">
                                                <?php echo htmlspecialchars($ordonnance['patient_prenom'] . ' ' . $ordonnance['patient_nom']); ?>
                                            </h3>
                                            <p class="text-sm text-[#558B2F]">
                                                Date: <?php echo date('d/m/Y', strtotime($ordonnance['date_creation'])); ?>
                                            </p>
                                        </div>
                                    </div>
                                    <div class="flex space-x-3">
                                        <a href="voir_ordonnance.php?id=<?php echo $ordonnance['id']; ?>" 
                                           class="text-[#2E7D32] hover:text-[#1B5E20]">
                                            <i class="fas fa-eye"></i>
                                        </a>
                                        <a href="modifier_ordonnance.php?id=<?php echo $ordonnance['id']; ?>" 
                                           class="text-[#2E7D32] hover:text-[#1B5E20]">
                                            <i class="fas fa-edit"></i>
                                        </a>
                                        <a href="imprimer_ordonnance.php?id=<?php echo $ordonnance['id']; ?>" 
                                           class="text-[#2E7D32] hover:text-[#1B5E20]">
                                            <i class="fas fa-print"></i>
                                        </a>
                                    </div>
                                </div>
                                <div class="mt-4">
                                    <p class="text-sm text-[#558B2F]">
                                        <i class="fas fa-pills mr-2"></i>
                                        <?php echo htmlspecialchars($ordonnance['medicaments'] ?? 'Aucun médicament prescrit'); ?>
                                    </p>
                                    <p class="text-sm text-[#558B2F] mt-2">
                                        <i class="fas fa-clipboard-list mr-2"></i>
                                        <?php echo htmlspecialchars($ordonnance['instructions'] ?? 'Aucune instruction spécifique'); ?>
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