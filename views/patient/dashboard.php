<?php
require_once '../../includes/session.php';
require_once '../../config/database.php';

requireLogin();
requireRole('patient');

$user_id = $_SESSION['user_id'];
$nom = $_SESSION['nom'];
$prenom = $_SESSION['prenom'];

// Récupérer le prochain rendez-vous
$stmt = db()->prepare("
    SELECT r.dateheure, m.nom as medecin_nom, m.prenom as medecin_prenom, r.statut
    FROM rendezvous r
    JOIN medecin m ON r.idmedecin = m.id
    WHERE r.idpatient = ? AND DATE(r.dateheure) >= CURDATE()
    ORDER BY r.dateheure ASC
    LIMIT 1
");
$stmt->execute([$user_id]);
$prochain_rdv = $stmt->fetch(PDO::FETCH_ASSOC);

// Récupérer le médecin traitant
$stmt = db()->prepare("
    SELECT m.nom, m.prenom
    FROM medecin m
    JOIN patient p ON p.id_medecin = m.id
    WHERE p.id = ?
");
$stmt->execute([$user_id]);
$medecin = $stmt->fetch(PDO::FETCH_ASSOC);

// Compter les ordonnances
$stmt = db()->prepare("
    SELECT COUNT(*) as total
    FROM ordonnance
    WHERE idpatient = ?
");
$stmt->execute([$user_id]);
$ordonnances = $stmt->fetch(PDO::FETCH_ASSOC);

// Compter les messages non lus
$stmt = db()->prepare("
    SELECT COUNT(*) as total
    FROM message
    WHERE id_destinataire = ? AND lu = 0
");
$stmt->execute([$user_id]);
$messages = $stmt->fetch(PDO::FETCH_ASSOC);

// Récupérer les rendez-vous récents
$stmt = db()->prepare("
    SELECT r.dateheure, m.nom as medecin_nom, m.prenom as medecin_prenom, r.statut
    FROM rendezvous r
    JOIN medecin m ON r.idmedecin = m.id
    WHERE r.idpatient = ? AND DATE(r.dateheure) >= CURDATE()
    ORDER BY r.dateheure ASC
    LIMIT 3
");
$stmt->execute([$user_id]);
$rdvs = $stmt->fetchAll(PDO::FETCH_ASSOC);

// Récupérer les rappels de médicaments
$stmt = db()->prepare("
    SELECT o.medicaments, o.posologie, o.date_validite
    FROM ordonnance o
    WHERE o.idpatient = ? AND o.date_validite >= CURDATE()
    ORDER BY o.date_validite ASC
    LIMIT 3
");
$stmt->execute([$user_id]);
$medicaments = $stmt->fetchAll(PDO::FETCH_ASSOC);

// Récupérer les documents médicaux
$stmt = db()->prepare("
    SELECT o.id, o.date_creation, o.medicaments, m.nom as medecin_nom, m.prenom as medecin_prenom
    FROM ordonnance o
    JOIN medecin m ON o.idmedecin = m.id
    WHERE o.idpatient = ?
    ORDER BY o.date_creation DESC
    LIMIT 2
");
$stmt->execute([$user_id]);
$documents = $stmt->fetchAll(PDO::FETCH_ASSOC);

// Récupérer les rappels importants
$stmt = db()->prepare("
    SELECT o.id, o.date_validite, o.renouvellement, o.nombre_renouvellements
    FROM ordonnance o
    WHERE o.idpatient = ? 
    AND o.date_validite >= CURDATE()
    AND (o.renouvellement = 1 OR o.date_validite <= DATE_ADD(CURDATE(), INTERVAL 7 DAY))
    ORDER BY o.date_validite ASC
    LIMIT 3
");
$stmt->execute([$user_id]);
$rappels = $stmt->fetchAll(PDO::FETCH_ASSOC);

// Récupérer les derniers messages
$stmt = db()->prepare("
    SELECT m.id, m.sujet, m.contenu, m.created_at, med.nom as medecin_nom, med.prenom as medecin_prenom
    FROM message m
    JOIN medecin med ON m.id_expediteur = med.id
    WHERE m.id_destinataire = ?
    ORDER BY m.created_at DESC
    LIMIT 1
");
$stmt->execute([$user_id]);
$dernier_message = $stmt->fetch(PDO::FETCH_ASSOC);
?>

<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Tableau de bord Patient - MedConnect</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        body {
            font-family: 'Poppins', sans-serif;
            background-color: #f0f9f5;
        }
        .stat-card {
            transition: all 0.3s ease;
        }
        .stat-card:hover {
            transform: translateY(-5px);
        }
        .rdv-card {
            transition: all 0.3s ease;
        }
        .rdv-card:hover {
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
                <a href="dashboard.php" class="nav-link active block px-4 py-3 rounded-lg text-[#1e40af]">
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
                            <i class="fas fa-user text-white text-xl"></i>
                        </div>
                        <h1 class="text-2xl font-bold text-[#1e40af]"><?php echo htmlspecialchars($prenom . ' ' . $nom); ?></h1>
                    </div>
                    <div class="text-sm text-[#3b82f6]">
                        <i class="fas fa-calendar-alt mr-2"></i><?php echo date('d/m/Y'); ?>
                    </div>
                </div>
            </header>

            <!-- Contenu principal -->
            <main class="container mx-auto px-4 py-8">
                <!-- Statistiques rapides -->
                <div class="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
                    <div class="stat-card bg-white rounded-xl shadow-lg p-6 border-l-4 border-[#3b82f6] glass-effect">
                        <div class="flex items-center justify-between">
                            <div>
                                <p class="text-sm text-[#3b82f6]">Prochain RDV</p>
                                <h3 class="text-2xl font-bold text-[#1e40af]">
                                    <?php 
                                    if ($prochain_rdv) {
                                        echo date('d M', strtotime($prochain_rdv['dateheure']));
                                    } else {
                                        echo "Aucun";
                                    }
                                    ?>
                                </h3>
                            </div>
                            <div class="w-12 h-12 rounded-full bg-[#EFF6FF] flex items-center justify-center">
                                <i class="fas fa-calendar-check text-xl text-[#3b82f6]"></i>
                            </div>
                        </div>
                    </div>
                    <div class="stat-card bg-white rounded-xl shadow-lg p-6 border-l-4 border-[#10b981] glass-effect">
                        <div class="flex items-center justify-between">
                            <div>
                                <p class="text-sm text-[#10b981]">Médecin traitant</p>
                                <h3 class="text-2xl font-bold text-[#1e40af]">
                                    <?php 
                                    if ($medecin) {
                                        echo "Dr. " . htmlspecialchars($medecin['prenom'] . ' ' . $medecin['nom']);
                                    } else {
                                        echo "Non assigné";
                                    }
                                    ?>
                                </h3>
                            </div>
                            <div class="w-12 h-12 rounded-full bg-[#ECFDF5] flex items-center justify-center">
                                <i class="fas fa-user-md text-xl text-[#10b981]"></i>
                            </div>
                        </div>
                    </div>
                    <div class="stat-card bg-white rounded-xl shadow-lg p-6 border-l-4 border-[#f59e0b] glass-effect">
                        <div class="flex items-center justify-between">
                            <div>
                                <p class="text-sm text-[#f59e0b]">Ordonnances</p>
                                <h3 class="text-2xl font-bold text-[#1e40af]"><?php echo $ordonnances['total']; ?></h3>
                            </div>
                            <div class="w-12 h-12 rounded-full bg-[#FFFBEB] flex items-center justify-center">
                                <i class="fas fa-prescription text-xl text-[#f59e0b]"></i>
                            </div>
                        </div>
                    </div>
                    <div class="stat-card bg-white rounded-xl shadow-lg p-6 border-l-4 border-[#8b5cf6] glass-effect">
                        <div class="flex items-center justify-between">
                            <div>
                                <p class="text-sm text-[#8b5cf6]">Messages non lus</p>
                                <h3 class="text-2xl font-bold text-[#1e40af]"><?php echo $messages['total']; ?></h3>
                            </div>
                            <div class="w-12 h-12 rounded-full bg-[#F5F3FF] flex items-center justify-center">
                                <i class="fas fa-envelope text-xl text-[#8b5cf6]"></i>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Sections principales -->
                <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <!-- Section Rendez-vous -->
                    <div class="bg-white rounded-xl shadow-lg p-6 glass-effect">
                        <div class="flex justify-between items-center mb-6">
                            <h2 class="text-xl font-semibold text-[#1e40af]">
                                <i class="fas fa-calendar-alt mr-2"></i>Mes Rendez-vous
                            </h2>
                            <a href="/medapp/views/patient/rdv.php" class="bg-[#3b82f6] hover:bg-[#2563eb] text-white px-4 py-2 rounded-lg transition-colors duration-300">
                                <i class="fas fa-plus-circle mr-2"></i>Nouveau RDV
                            </a>
                        </div>
                        <div class="space-y-4">
                            <?php if (empty($rdvs)): ?>
                                <p class="text-gray-500 text-center py-4">Aucun rendez-vous à venir</p>
                            <?php else: ?>
                                <?php foreach ($rdvs as $rdv): ?>
                                    <div class="rdv-card p-4 bg-[#EFF6FF] rounded-lg hover:bg-[#DBEAFE]">
                                        <div class="flex justify-between items-center">
                                            <div>
                                                <p class="font-medium text-[#1e40af]">Dr. <?php echo htmlspecialchars($rdv['medecin_prenom'] . ' ' . $rdv['medecin_nom']); ?></p>
                                                <p class="text-sm text-[#3b82f6]">
                                                    <?php echo date('d M Y H:i', strtotime($rdv['dateheure'])); ?>
                                                </p>
                                            </div>
                                            <span class="px-3 py-1 <?php 
                                                echo $rdv['statut'] === 'confirmé' ? 'bg-[#DCFCE7] text-[#10b981]' : 
                                                    ($rdv['statut'] === 'en attente' ? 'bg-[#FEF3C7] text-[#f59e0b]' : 
                                                    'bg-[#FEE2E2] text-[#ef4444]'); 
                                            ?> rounded-full text-sm">
                                                <?php echo ucfirst($rdv['statut']); ?>
                                            </span>
                                        </div>
                                    </div>
                                <?php endforeach; ?>
                            <?php endif; ?>
                        </div>
                    </div>

                    <!-- Section Rappels -->
                    <div class="bg-white rounded-xl shadow-lg p-6 glass-effect">
                        <div class="flex justify-between items-center mb-6">
                            <h2 class="text-xl font-semibold text-[#1e40af]">
                                <i class="fas fa-bell mr-2"></i>Rappels de médicaments
                            </h2>
                        </div>
                        <div class="space-y-4">
                            <?php if (empty($medicaments)): ?>
                                <p class="text-gray-500 text-center py-4">Aucun rappel de médicament</p>
                            <?php else: ?>
                                <?php foreach ($medicaments as $med): ?>
                                    <div class="reminder-card p-4 bg-[#EFF6FF] rounded-lg">
                                        <div class="flex justify-between items-start">
                                            <div>
                                                <p class="font-medium text-[#1e40af]"><?php echo htmlspecialchars($med['medicaments']); ?></p>
                                                <p class="text-sm text-[#3b82f6]">
                                                    <?php echo htmlspecialchars($med['posologie']); ?>
                                                </p>
                                                <p class="text-xs text-gray-500 mt-1">
                                                    Jusqu'au <?php echo date('d/m/Y', strtotime($med['date_validite'])); ?>
                                                </p>
                                            </div>
                                            <div class="w-8 h-8 rounded-full bg-[#DBEAFE] flex items-center justify-center">
                                                <i class="fas fa-pills text-sm text-[#3b82f6]"></i>
                                            </div>
                                        </div>
                                    </div>
                                <?php endforeach; ?>
                            <?php endif; ?>
                        </div>
                    </div>
                </div>

                <!-- Section Documents -->
                <div class="mt-8 bg-white rounded-xl shadow-lg p-6 glass-effect">
                    <div class="flex justify-between items-center mb-6">
                        <h2 class="text-xl font-semibold text-[#1e40af]">
                            <i class="fas fa-file-medical mr-2"></i>Mes Documents
                        </h2>
                        <a href="carnet.php" class="bg-[#3b82f6] hover:bg-[#2563eb] text-white px-4 py-2 rounded-lg transition-colors duration-300">
                            <i class="fas fa-upload mr-2"></i>Ajouter
                        </a>
                    </div>
                    <div class="space-y-4">
                        <?php if (empty($documents)): ?>
                            <p class="text-gray-500 text-center py-4">Aucun document disponible</p>
                        <?php else: ?>
                            <?php foreach ($documents as $doc): ?>
                                <div class="flex items-center justify-between p-4 bg-[#EFF6FF] rounded-lg hover:bg-[#DBEAFE]">
                                    <div class="flex items-center space-x-4">
                                        <div class="w-12 h-12 rounded-full bg-[#DBEAFE] flex items-center justify-center">
                                            <i class="fas fa-file-medical text-[#3b82f6] text-xl"></i>
                                        </div>
                                        <div>
                                            <p class="font-medium text-[#1e40af]">Ordonnance - <?php echo date('d/m/Y', strtotime($doc['date_creation'])); ?></p>
                                            <p class="text-sm text-[#3b82f6]">Dr. <?php echo htmlspecialchars($doc['medecin_prenom'] . ' ' . $doc['medecin_nom']); ?></p>
                                        </div>
                                    </div>
                                    <a href="ordonnance.php?id=<?php echo $doc['id']; ?>" class="text-[#3b82f6] hover:text-[#2563eb]">
                                        <i class="fas fa-download"></i>
                                    </a>
                                </div>
                            <?php endforeach; ?>
                        <?php endif; ?>
                    </div>
                </div>

                <!-- Section Rappels et Alertes -->
                <div class="mt-8 bg-white rounded-xl shadow-lg p-6 glass-effect">
                    <h2 class="text-xl font-semibold text-[#1e40af] mb-6">
                        <i class="fas fa-bell mr-2"></i>Rappels et Alertes
                    </h2>
                    <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
                        <?php if (empty($rappels)): ?>
                            <p class="text-gray-500 text-center py-4 col-span-3">Aucun rappel pour le moment</p>
                        <?php else: ?>
                            <?php foreach ($rappels as $rappel): ?>
                                <?php if ($rappel['renouvellement'] == 1): ?>
                                    <div class="reminder-card p-4 bg-[#FFFBEB] rounded-lg border border-[#FEF3C7]">
                                        <div class="flex items-center space-x-3">
                                            <div class="w-10 h-10 rounded-full bg-[#FEF3C7] flex items-center justify-center">
                                                <i class="fas fa-pills text-[#f59e0b]"></i>
                                            </div>
                                            <p class="text-sm text-[#92400e]">
                                                Renouvellement d'ordonnance dans <?php echo date_diff(new DateTime(), new DateTime($rappel['date_validite']))->days; ?> jours
                                                <?php if ($rappel['nombre_renouvellements'] > 0): ?>
                                                    (<?php echo $rappel['nombre_renouvellements']; ?> renouvellement(s) restant(s))
                                                <?php endif; ?>
                                            </p>
                                        </div>
                                    </div>
                                <?php else: ?>
                                    <div class="reminder-card p-4 bg-[#EFF6FF] rounded-lg border border-[#DBEAFE]">
                                        <div class="flex items-center space-x-3">
                                            <div class="w-10 h-10 rounded-full bg-[#DBEAFE] flex items-center justify-center">
                                                <i class="fas fa-calendar-alt text-[#3b82f6]"></i>
                                            </div>
                                            <p class="text-sm text-[#1e40af]">
                                                Ordonnance expirant dans <?php echo date_diff(new DateTime(), new DateTime($rappel['date_validite']))->days; ?> jours
                                            </p>
                                        </div>
                                    </div>
                                <?php endif; ?>
                            <?php endforeach; ?>
                        <?php endif; ?>
                    </div>
                </div>

                <!-- Section Messagerie -->
                <div class="mt-8 bg-white rounded-xl shadow-lg p-6 glass-effect">
                    <div class="flex justify-between items-center mb-6">
                        <h2 class="text-xl font-semibold text-[#1e40af]">
                            <i class="fas fa-envelope mr-2"></i>Messagerie
                            <?php if ($messages['total'] > 0): ?>
                                <span class="ml-2 px-2 py-1 bg-[#3b82f6] text-white text-sm rounded-full">
                                    <?php echo $messages['total']; ?> non lu(s)
                                </span>
                            <?php endif; ?>
                        </h2>
                        <a href="messages.php" class="bg-[#3b82f6] hover:bg-[#2563eb] text-white px-4 py-2 rounded-lg transition-colors duration-300">
                            Voir tous les messages
                        </a>
                    </div>
                    <div class="space-y-4">
                        <?php if (empty($dernier_message)): ?>
                            <p class="text-gray-500 text-center py-4">Aucun message</p>
                        <?php else: ?>
                            <div class="flex items-center justify-between p-4 bg-[#EFF6FF] rounded-lg hover:bg-[#DBEAFE]">
                                <div class="flex items-center space-x-4">
                                    <div class="w-12 h-12 rounded-full bg-[#DBEAFE] flex items-center justify-center">
                                        <i class="fas fa-user-md text-[#3b82f6] text-xl"></i>
                                    </div>
                                    <div>
                                        <p class="font-medium text-[#1e40af]">Dr. <?php echo htmlspecialchars($dernier_message['medecin_prenom'] . ' ' . $dernier_message['medecin_nom']); ?></p>
                                        <p class="text-sm text-[#3b82f6]"><?php echo htmlspecialchars($dernier_message['sujet']); ?></p>
                                    </div>
                                </div>
                                <span class="text-xs text-[#3b82f6]">
                                    <?php 
                                    $date = new DateTime($dernier_message['created_at']);
                                    $now = new DateTime();
                                    $diff = $date->diff($now);
                                    
                                    if ($diff->d == 0) {
                                        if ($diff->h == 0) {
                                            echo "Il y a " . $diff->i . " min";
                                        } else {
                                            echo "Il y a " . $diff->h . "h";
                                        }
                                    } else if ($diff->d == 1) {
                                        echo "Hier";
                                    } else {
                                        echo $date->format('d/m/Y');
                                    }
                                    ?>
                                </span>
                            </div>
                        <?php endif; ?>
                    </div>
                </div>
            </main>
        </div>
    </div>
</body>
</html>
