<?php
require_once '../../includes/session.php';
require_once '../../config/config.php';

// Vérifier si l'utilisateur est connecté et est un médecin
requireLogin();
requireRole('medecin');

$user_id = $_SESSION['user_id'];
$nom = $_SESSION['nom'];
$prenom = $_SESSION['prenom'];

// Récupérer la liste des patients du médecin
try {
    $stmt = db()->prepare("
        SELECT DISTINCT p.id, p.nom, p.prenom
        FROM patient p
        WHERE p.id_medecin = ?
        ORDER BY p.nom, p.prenom
    ");
    $stmt->execute([$user_id]);
    $patients = $stmt->fetchAll(PDO::FETCH_ASSOC);
} catch (PDOException $e) {
    $error = "Erreur lors de la récupération des patients.";
    error_log($e->getMessage());
    $patients = [];
}

// Récupérer les consultations
try {
    $query = "
        SELECT c.*, p.nom as patient_nom, p.prenom as patient_prenom
        FROM consultation c
        JOIN patient p ON c.id_patient = p.id
        WHERE c.id_medecin = ?
    ";
    $params = [$user_id];

    // Si un patient est sélectionné, ajouter le filtre
    if (isset($_GET['patient_id']) && !empty($_GET['patient_id'])) {
        $query .= " AND c.id_patient = ?";
        $params[] = $_GET['patient_id'];
    }

    $query .= " ORDER BY c.date_consultation DESC";
    
    $stmt = db()->prepare($query);
    $stmt->execute($params);
    $consultations = $stmt->fetchAll(PDO::FETCH_ASSOC);
} catch (PDOException $e) {
    $error = "Erreur lors de la récupération des consultations.";
    error_log($e->getMessage());
    $consultations = [];
}
?>

<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Consultations - MedConnect</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <?php include_once '../../views/components/styles.php'; ?>
    <style>
        .consultation-card {
            transition: all 0.3s ease;
        }
        
        .consultation-card:hover {
            transform: translateY(-5px);
        }
        
        .status-badge {
            padding: 0.5rem 1rem;
            border-radius: 9999px;
            font-size: 0.875rem;
            font-weight: 500;
        }
        
        .status-scheduled {
            background-color: #E8F5E9;
            color: #2E7D32;
        }
        
        .status-completed {
            background-color: #C8E6C9;
            color: #1B5E20;
        }
        
        .status-cancelled {
            background-color: #FFEBEE;
            color: #C62828;
        }
        
        .filter-btn {
            transition: all 0.3s ease;
        }
        
        .filter-btn:hover {
            transform: translateY(-2px);
        }
        
        .filter-btn.active {
            background-color: #2E7D32;
            color: white;
        }
        
        .consultation-row:hover {
            background-color: #f8fafc;
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
                <a href="consultations.php" class="nav-link active block px-4 py-3 rounded-lg text-[#1B5E20]">
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
                <a href="../logout.php" class="block bg-[#FF5252] hover:bg-[#D32F2F] text-white text-center px-4 py-3 rounded-lg transition-colors duration-300">
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
                        <h1 class="text-2xl font-bold text-[#1B5E20]">Dr. <?php echo htmlspecialchars($prenom . ' ' . $nom); ?></h1>
                    </div>
                    <div class="text-sm text-[#558B2F]">
                        <i class="fas fa-calendar-alt mr-2"></i><?php echo date('d/m/Y'); ?>
                    </div>
                </div>
            </header>

            <!-- Contenu principal -->
            <main class="container mx-auto px-4 py-8">
                <!-- En-tête de la page -->
                <div class="flex justify-between items-center mb-8">
                    <div>
                        <h2 class="text-2xl font-bold text-[#1B5E20]">Consultations</h2>
                        <p class="text-[#558B2F]">Gérez vos consultations et suivez vos patients</p>
                    </div>
                    <a href="nouvelle_consultation.php" class="bg-blue-500 hover:bg-blue-600 text-white px-4 py-2 rounded-lg transition-colors duration-300">
                        <i class="fas fa-plus mr-2"></i>Nouvelle Consultation
                    </a>
                </div>

                <?php if (isset($error)): ?>
                    <div class="bg-red-100 border-l-4 border-red-500 text-red-700 p-4 mb-6">
                        <i class="fas fa-exclamation-circle mr-2"></i><?php echo $error; ?>
                    </div>
                <?php endif; ?>

                <!-- Filtre par patient -->
                <div class="bg-white rounded-lg shadow-md p-4 mb-6">
                    <form method="GET" class="flex items-center space-x-4">
                        <div class="flex-1">
                            <label for="patient_id" class="block text-sm font-medium text-gray-700 mb-2">Filtrer par patient</label>
                            <select name="patient_id" id="patient_id" class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-[#2E7D32] focus:border-transparent">
                                <option value="">Tous les patients</option>
                                <?php foreach ($patients as $patient): ?>
                                    <option value="<?php echo $patient['id']; ?>" <?php echo (isset($_GET['patient_id']) && $_GET['patient_id'] == $patient['id']) ? 'selected' : ''; ?>>
                                        <?php echo htmlspecialchars($patient['prenom'] . ' ' . $patient['nom']); ?>
                                    </option>
                                <?php endforeach; ?>
                            </select>
                        </div>
                        <div class="flex items-end">
                            <button type="submit" class="bg-[#2E7D32] hover:bg-[#1B5E20] text-white px-4 py-2 rounded-lg transition-colors duration-300">
                                <i class="fas fa-filter mr-2"></i>Filtrer
                            </button>
                            <?php if (isset($_GET['patient_id']) && !empty($_GET['patient_id'])): ?>
                                <a href="consultations.php" class="ml-2 bg-gray-500 hover:bg-gray-600 text-white px-4 py-2 rounded-lg transition-colors duration-300">
                                    <i class="fas fa-times mr-2"></i>Effacer
                                </a>
                            <?php endif; ?>
                        </div>
                    </form>
                </div>

                <div class="overflow-x-auto">
                    <table class="min-w-full bg-white">
                        <thead class="bg-gray-50">
                            <tr>
                                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Date</th>
                                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Patient</th>
                                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Motif</th>
                                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Diagnostic</th>
                                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Traitement</th>
                                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
                            </tr>
                        </thead>
                        <tbody class="divide-y divide-gray-200">
                            <?php if (empty($consultations)): ?>
                                <tr>
                                    <td colspan="6" class="px-6 py-4 text-center text-gray-500">
                                        Aucune consultation enregistrée
                                    </td>
                                </tr>
                            <?php else: ?>
                                <?php foreach ($consultations as $consultation): ?>
                                    <tr class="consultation-row">
                                        <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                                            <?php echo date('d/m/Y H:i', strtotime($consultation['date_consultation'])); ?>
                                        </td>
                                        <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                                            <?php echo htmlspecialchars($consultation['patient_prenom'] . ' ' . $consultation['patient_nom']); ?>
                                        </td>
                                        <td class="px-6 py-4 text-sm text-gray-900">
                                            <?php echo htmlspecialchars($consultation['motif']); ?>
                                        </td>
                                        <td class="px-6 py-4 text-sm text-gray-900">
                                            <?php echo htmlspecialchars($consultation['diagnostic'] ?? 'Non spécifié'); ?>
                                        </td>
                                        <td class="px-6 py-4 text-sm text-gray-900">
                                            <?php echo htmlspecialchars($consultation['traitement'] ?? 'Non spécifié'); ?>
                                        </td>
                                        <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                                            <a href="voir_consultation.php?id=<?php echo $consultation['id']; ?>" 
                                               class="text-blue-500 hover:text-blue-700 mr-3">
                                                <i class="fas fa-eye"></i>
                                            </a>
                                            <a href="modifier_consultation.php?id=<?php echo $consultation['id']; ?>" 
                                               class="text-yellow-500 hover:text-yellow-700 mr-3">
                                                <i class="fas fa-edit"></i>
                                            </a>
                                            <a href="imprimer_consultation.php?id=<?php echo $consultation['id']; ?>" 
                                               class="text-green-500 hover:text-green-700">
                                                <i class="fas fa-print"></i>
                                            </a>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                            <?php endif; ?>
                        </tbody>
                    </table>
                </div>
            </main>
        </div>
    </div>

    <script>
        // Gestion des filtres
        document.querySelectorAll('.filter-btn').forEach(button => {
            button.addEventListener('click', () => {
                document.querySelectorAll('.filter-btn').forEach(btn => {
                    btn.classList.remove('active');
                });
                button.classList.add('active');
            });
        });

        // Auto-submit du formulaire de filtre quand un patient est sélectionné
        document.getElementById('patient_id').addEventListener('change', function() {
            this.form.submit();
        });
    </script>
</body>
</html> 