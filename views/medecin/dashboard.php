<?php
require_once '../../includes/session.php';
require_once '../../config/database.php';
require_once '../../models/Dashboard.php';

// Vérifier si l'utilisateur est connecté
requireLogin();

// Vérifier si l'utilisateur a le rôle requis
requireRole('medecin');

// Accès aux informations de l'utilisateur connecté
$user_id = $_SESSION['user_id'];
$nom = $_SESSION['nom'];
$prenom = $_SESSION['prenom'];

// Initialiser la connexion à la base de données
$database = new Database();
$db = $database->getConnection();

// Initialiser le dashboard
$dashboard = new Dashboard($db, $user_id);

// Récupérer les données du dashboard
$rdv_aujourdhui = $dashboard->getRendezVousAujourdhui();
$patients_actifs = $dashboard->getPatientsActifs();
$consultations_jour = $dashboard->getConsultationsDuJour();
$messages_non_lus = $dashboard->getMessagesNonLus();
$derniers_patients = $dashboard->getDerniersPatients();
$rdv_du_jour = $dashboard->getRendezVousDuJour();
$rappels = $dashboard->getRappelsImportants();

// Nombre de consultations par jour pour le mois en cours (optimisé)
$days_in_month = date('t');
$current_month = date('m');
$current_year = date('Y');
$stmt = $db->prepare("
    SELECT DATE(date_consultation) as jour, COUNT(*) as total
    FROM consultation
    WHERE id_medecin = ? AND MONTH(date_consultation) = ? AND YEAR(date_consultation) = ?
    GROUP BY jour
    ORDER BY jour
");
$stmt->execute([$user_id, $current_month, $current_year]);
$rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

// Préparer les données pour tous les jours du mois
$consultations_par_jour = [];
$labels = [];
for ($i = 1; $i <= $days_in_month; $i++) {
    $date = sprintf('%04d-%02d-%02d', $current_year, $current_month, $i);
    $labels[] = date('d/m', strtotime($date));
    $consultations_par_jour[$date] = 0;
}
foreach ($rows as $row) {
    $consultations_par_jour[$row['jour']] = (int)$row['total'];
}
$consultations_par_jour = array_values($consultations_par_jour);

// Nombre total de patients suivis (tous les patients affectés à ce médecin)
$stmt = $db->prepare("SELECT COUNT(*) FROM patient WHERE id_medecin = ?");
$stmt->execute([$user_id]);
$total_patients = (int)$stmt->fetchColumn();
?>

<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Tableau de bord Médecin</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <?php include_once '../../views/components/styles.php'; ?>
    <style>
        .stat-card {
            transition: all 0.3s ease;
        }
        .stat-card:hover {
            transform: translateY(-5px);
        }
        .patient-card {
            transition: all 0.3s ease;
        }
        .patient-card:hover {
            transform: translateX(5px);
        }
        .reminder-card {
            transition: all 0.3s ease;
        }
        .reminder-card:hover {
            transform: scale(1.02);
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
                <a href="dashboard.php" class="nav-link active block px-4 py-3 rounded-lg text-[#1B5E20]">
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
                <a href="../../views/logout.php" class="block bg-[#FF5252] hover:bg-[#D32F2F] text-white text-center px-4 py-3 rounded-lg transition-colors duration-300">
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
                <!-- Statistiques rapides -->
                <div class="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
                    <div class="stat-card bg-white rounded-xl shadow-lg p-6 border-l-4 border-[#2E7D32] glass-effect">
                        <div class="flex items-center justify-between">
                            <div>
                                <p class="text-sm text-[#558B2F]">Rendez-vous aujourd'hui</p>
                                <h3 class="text-2xl font-bold text-[#1B5E20]"><?php echo $rdv_aujourdhui; ?></h3>
                            </div>
                            <div class="w-12 h-12 rounded-full bg-[#E8F5E9] flex items-center justify-center">
                                <i class="fas fa-calendar-check text-xl text-[#2E7D32]"></i>
                            </div>
                        </div>
                    </div>
                    <div class="stat-card bg-white rounded-xl shadow-lg p-6 border-l-4 border-[#4CAF50] glass-effect">
                        <div class="flex items-center justify-between">
                            <div>
                                <p class="text-sm text-[#558B2F]">Patients actifs</p>
                                <h3 class="text-2xl font-bold text-[#1B5E20]"><?php echo $patients_actifs; ?></h3>
                            </div>
                            <div class="w-12 h-12 rounded-full bg-[#E8F5E9] flex items-center justify-center">
                                <i class="fas fa-users text-xl text-[#4CAF50]"></i>
                            </div>
                        </div>
                    </div>
                    <div class="stat-card bg-white rounded-xl shadow-lg p-6 border-l-4 border-[#81C784] glass-effect">
                        <div class="flex items-center justify-between">
                            <div>
                                <p class="text-sm text-[#558B2F]">Consultations du jour</p>
                                <h3 class="text-2xl font-bold text-[#1B5E20]"><?php echo $consultations_jour; ?></h3>
                            </div>
                            <div class="w-12 h-12 rounded-full bg-[#E8F5E9] flex items-center justify-center">
                                <i class="fas fa-stethoscope text-xl text-[#81C784]"></i>
                            </div>
                        </div>
                    </div>
                    <div class="stat-card bg-white rounded-xl shadow-lg p-6 border-l-4 border-[#A5D6A7] glass-effect">
                        <div class="flex items-center justify-between">
                            <div>
                                <p class="text-sm text-[#558B2F]">Messages non lus</p>
                                <h3 class="text-2xl font-bold text-[#1B5E20]"><?php echo $messages_non_lus; ?></h3>
                            </div>
                            <div class="w-12 h-12 rounded-full bg-[#E8F5E9] flex items-center justify-center">
                                <i class="fas fa-envelope text-xl text-[#A5D6A7]"></i>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Après les statistiques rapides, ajouter le graphique et l'indicateur -->
                <div class="bg-white rounded-xl shadow-lg p-6 glass-effect my-8">
                    <h2 class="text-xl font-semibold text-[#1B5E20] mb-4">
                        <i class="fas fa-chart-bar mr-2"></i>Consultations du mois en cours
                    </h2>
                    <canvas id="consultationsChart" height="100"></canvas>
                    <div class="mt-6 text-lg">
                        <span class="font-semibold text-[#1B5E20]">Nombre total de patients suivis : </span>
                        <span class="text-[#2E7D32] font-bold"><?php echo $total_patients; ?></span>
                    </div>
                </div>

                <!-- Sections principales -->
                <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                  

                  
                </div>

                <!-- Section Rappels -->
                <div class="mt-8 bg-white rounded-xl shadow-lg p-6 glass-effect">
                    <h2 class="text-xl font-semibold text-[#1B5E20] mb-6">
                        <i class="fas fa-bell mr-2"></i>Rappels importants
                    </h2>
                    <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
                        <div class="reminder-card p-4 bg-[#FFF3E0] rounded-lg border border-[#FFE0B2]">
                            <div class="flex items-center space-x-3">
                                <div class="w-10 h-10 rounded-full bg-[#FFE0B2] flex items-center justify-center">
                                    <i class="fas fa-exclamation-circle text-[#E65100]"></i>
                                </div>
                                <p class="text-sm text-[#E65100]"><?php echo $rappels['vaccins']; ?> rappels de vaccins à effectuer</p>
                            </div>
                        </div>
                        <div class="reminder-card p-4 bg-[#E3F2FD] rounded-lg border border-[#BBDEFB]">
                            <div class="flex items-center space-x-3">
                                <div class="w-10 h-10 rounded-full bg-[#BBDEFB] flex items-center justify-center">
                                    <i class="fas fa-file-medical text-[#1565C0]"></i>
                                </div>
                                <p class="text-sm text-[#1565C0]"><?php echo $rappels['dossiers']; ?> dossiers à mettre à jour</p>
                            </div>
                        </div>
                        <div class="reminder-card p-4 bg-[#FFEBEE] rounded-lg border border-[#FFCDD2]">
                            <div class="flex items-center space-x-3">
                                <div class="w-10 h-10 rounded-full bg-[#FFCDD2] flex items-center justify-center">
                                    <i class="fas fa-clock text-[#C62828]"></i>
                                </div>
                                <p class="text-sm text-[#C62828]"><?php echo $rappels['rdv_confirmation']; ?> rendez-vous en attente de confirmation</p>
                            </div>
                        </div>
                    </div>
                </div>
            </main>
        </div>
    </div>

    <!-- Avant </body>, ajouter Chart.js et le script du graphique -->
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script>
    const ctx = document.getElementById('consultationsChart').getContext('2d');
    const consultationsData = <?php echo json_encode($consultations_par_jour); ?>;
    const labels = <?php echo json_encode($labels); ?>;

    new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                label: 'Consultations',
                data: consultationsData,
                backgroundColor: 'rgba(30, 64, 175, 0.7)'
            }]
        },
        options: {
            responsive: true,
            scales: {
                y: { beginAtZero: true }
            }
        }
    });
    </script>
</body>
</html> 