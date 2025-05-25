<?php
// Charger la configuration de session
require_once __DIR__ . '/../../includes/session.php';

// Vérifier l'authentification et l'autorisation
requireLogin();
requireRole('patient');

// Initialisation des messages
$success = "";
$error = "";

$user_id = $_SESSION['user_id'];

// Définir le chemin racine
$root_path = __DIR__ . '/../../';

require_once $root_path . 'config/database.php';

// Requête pour récupérer les ordonnances du patient avec infos médecin
$sql = "SELECT o.*, m.nom AS nom_medecin, m.prenom AS prenom_medecin
        FROM ordonnance o
        JOIN medecin m ON o.idmedecin = m.id
        WHERE o.idpatient = :idpatient
        ORDER BY o.date_creation DESC";

$stmt = db()->prepare($sql);
$stmt->execute(['idpatient' => $user_id]);
$ordonnances = $stmt->fetchAll(PDO::FETCH_ASSOC);

// Calculer les statistiques des ordonnances
$ordonnances_actives = array_filter($ordonnances, function($ord) {
    return $ord['statut'] === 'active';
});

$ordonnances_a_renouveler = 0;

foreach ($ordonnances as $ord) {
    if ($ord['statut'] === 'à renouveler') {
        $ordonnances_a_renouveler++;
    }
}

// Pour l'affichage, on définit un nombre de médicaments par défaut
foreach ($ordonnances as &$ord) {
    $medicaments = explode("\n", $ord['medicaments']);
    $ord['nombre_medicaments'] = count($medicaments);
}
unset($ord); // Important pour éviter des effets de bord
?>
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Ordonnances - MedConnect</title>
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
        .prescription-card {
            transition: all 0.3s ease;
        }
        .prescription-card:hover {
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
                <a href="ordonnace.php" class="nav-link active block px-4 py-3 rounded-lg text-[#1e40af]">
                    <i class="fas fa-prescription mr-3"></i>Mes Ordonnances
                </a>
                <a href="listes_pharmacie.php" class="nav-link block px-4 py-3 rounded-lg text-[#1e40af]">
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
                <a href="./../logout.php" class="block bg-[#FF5252] hover:bg-[#D32F2F] text-white text-center px-4 py-3 rounded-lg transition-colors duration-300">
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
                            <i class="fas fa-prescription text-white text-xl"></i>
                        </div>
                        <h1 class="text-2xl font-bold text-[#1e40af]">Mes Ordonnances</h1>
                    </div>
                    <div class="text-sm text-[#3b82f6]">
                        <i class="fas fa-calendar-alt mr-2"></i><?php echo date('d/m/Y'); ?>
                    </div>
                </div>
            </header>

            <!-- Contenu principal -->
            <main class="container mx-auto px-4 py-8">
                <!-- Statistiques -->
                <div class="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
                    <div class="bg-white rounded-xl shadow-lg p-6 glass-effect">
                        <div class="flex items-center justify-between">
                            <div>
                                <p class="text-sm text-[#3b82f6]">Ordonnances actives</p>
                                <h3 class="text-2xl font-bold text-[#1e40af]"><?php echo count($ordonnances_actives); ?></h3>
                            </div>
                            <div class="w-12 h-12 rounded-full bg-[#EFF6FF] flex items-center justify-center">
                                <i class="fas fa-prescription text-xl text-[#3b82f6]"></i>
                            </div>
                        </div>
                    </div>
                    <div class="bg-white rounded-xl shadow-lg p-6 glass-effect">
                        <div class="flex items-center justify-between">
                            <div>
                                <p class="text-sm text-[#10b981]">Médicaments en cours</p>
                                <h3 class="text-2xl font-bold text-[#1e40af]"><?php echo count($ordonnances); ?></h3>
                            </div>
                            <div class="w-12 h-12 rounded-full bg-[#ECFDF5] flex items-center justify-center">
                                <i class="fas fa-pills text-xl text-[#10b981]"></i>
                            </div>
                        </div>
                    </div>
                    <div class="bg-white rounded-xl shadow-lg p-6 glass-effect">
                        <div class="flex items-center justify-between">
                            <div>
                                <p class="text-sm text-[#f59e0b]">À renouveler</p>
                                <h3 class="text-2xl font-bold text-[#1e40af]"><?php echo $ordonnances_a_renouveler; ?></h3>
                            </div>
                            <div class="w-12 h-12 rounded-full bg-[#FFFBEB] flex items-center justify-center">
                                <i class="fas fa-clock text-xl text-[#f59e0b]"></i>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Liste des ordonnances -->
                <div class="bg-white rounded-xl shadow-lg p-6 glass-effect">
                    <div class="flex justify-between items-center mb-6">
                        <h2 class="text-xl font-semibold text-[#1e40af] flex items-center">
                            <i class="fas fa-prescription mr-2"></i>
                            Mes dernières ordonnances
                        </h2>
                    </div>

                    <?php foreach ($ordonnances as $ordonnance): ?>
                        <div class="prescription-card bg-white rounded-lg shadow-md p-6 mb-6 border border-gray-100">
                            <div class="flex justify-between items-start mb-4">
                                <div>
                                    <h3 class="text-lg font-semibold text-[#1e40af]">
                                        Ordonnance du <?php echo date('d/m/Y', strtotime($ordonnance['date_creation'])); ?>
                                    </h3>
                                    <p class="text-sm text-gray-600">
                                        Dr. <?php echo htmlspecialchars($ordonnance['prenom_medecin'] . ' ' . $ordonnance['nom_medecin']); ?>
                                    </p>
                                </div>
                                <div class="flex items-center space-x-2">
                                    <span class="px-3 py-1 rounded-full text-sm <?php echo $ordonnance['statut'] === 'active' ? 'bg-green-100 text-green-800' : 'bg-yellow-100 text-yellow-800'; ?>">
                                        <?php echo ucfirst($ordonnance['statut']); ?>
                                    </span>
                                    <a href="telecharger_ordonnance.php?id=<?php echo $ordonnance['id']; ?>" class="btn-primary text-sm">
                                        <i class="fas fa-download mr-2"></i>Télécharger
                                    </a>
                                </div>
                            </div>

                            <div class="mt-4">
                                <h4 class="text-md font-semibold text-[#1e40af] mb-2">Médicaments prescrits</h4>
                                <div class="overflow-x-auto">
                                    <table class="min-w-full bg-white rounded-lg overflow-hidden">
                                        <thead class="bg-[#EFF6FF]">
                                            <tr>
                                                <th class="px-4 py-2 text-left text-sm font-medium text-[#1e40af]">Médicament</th>
                                                <th class="px-4 py-2 text-left text-sm font-medium text-[#1e40af]">Posologie</th>
                                                <th class="px-4 py-2 text-left text-sm font-medium text-[#1e40af]">Quantité</th>
                                                <th class="px-4 py-2 text-left text-sm font-medium text-[#1e40af]">Durée</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            <?php
                                            $medicaments = explode("\n", $ordonnance['medicaments']);
                                            $posologies = explode("\n", $ordonnance['posologie']);
                                            $quantites = explode("\n", $ordonnance['quantite']);
                                            $durees = explode("\n", $ordonnance['duree_medicament']);
                                            $max = max(count($medicaments), count($posologies), count($quantites), count($durees));
                                            for ($i = 0; $i < $max; $i++): ?>
                                                <tr class="border-b border-gray-100">
                                                    <td class="px-4 py-2"><?php echo isset($medicaments[$i]) ? htmlspecialchars($medicaments[$i]) : ''; ?></td>
                                                    <td class="px-4 py-2"><?php echo isset($posologies[$i]) ? htmlspecialchars($posologies[$i]) : ''; ?></td>
                                                    <td class="px-4 py-2"><?php echo isset($quantites[$i]) ? htmlspecialchars($quantites[$i]) : ''; ?></td>
                                                    <td class="px-4 py-2"><?php echo isset($durees[$i]) ? htmlspecialchars($durees[$i]) : ''; ?></td>
                                                </tr>
                                            <?php endfor; ?>
                                        </tbody>
                                    </table>
                                </div>
                            </div>

                            <?php if (!empty($ordonnance['instructions'])): ?>
                                <div class="mt-4">
                                    <h4 class="text-md font-semibold text-[#1e40af] mb-2">Instructions supplémentaires</h4>
                                    <p class="text-gray-700"><?php echo nl2br(htmlspecialchars($ordonnance['instructions'])); ?></p>
                                </div>
                            <?php endif; ?>

                            <div class="mt-4 text-sm text-gray-600">
                                <p>Date de validité : <?php echo date('d/m/Y', strtotime($ordonnance['date_validite'])); ?></p>
                                <?php if ($ordonnance['renouvellement']): ?>
                                    <p>Renouvellement possible : <?php echo $ordonnance['nombre_renouvellements']; ?> fois</p>
                                <?php endif; ?>
                            </div>
                        </div>
                    <?php endforeach; ?>
                </div>
            </main>
        </div>
    </div>
</body>
</html>
