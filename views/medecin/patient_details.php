<?php
require_once '../../includes/session.php';
require_once '../../config/config.php';

// Vérifier si l'utilisateur est connecté et est un médecin
requireLogin();
requireRole('medecin');

$user_id = $_SESSION['user_id'];
$patient_id = isset($_GET['id']) ? (int)$_GET['id'] : 0;

if (!$patient_id) {
    header('Location: /medapp/views/medecin/dashboard.php');
    exit;
}

// Récupérer les informations du patient
$stmt = db()->prepare("
    SELECT 
        p.*,
        pp.adresse,
        pp.profession,
        cs.groupesanguin,
        cs.taille,
        cs.poids,
        cs.allergie,
        cs.electrophorese
    FROM patient p
    LEFT JOIN profilpatient pp ON p.id = pp.idpatient
    LEFT JOIN carnetsante cs ON p.id = cs.id_patient
    WHERE p.id = ?
");
$stmt->execute([$patient_id]);
$patient = $stmt->fetch(PDO::FETCH_ASSOC);

if (!$patient) {
    header('Location: patients.php');
    exit;
}

// Récupérer l'historique des consultations
$stmt = db()->prepare("
    SELECT c.*, m.nom as medecin_nom, m.prenom as medecin_prenom
    FROM consultation c
    JOIN medecin m ON c.id_medecin = m.id
    WHERE c.id_patient = ?
    ORDER BY c.date_consultation DESC
");
$stmt->execute([$patient_id]);
$consultations = $stmt->fetchAll(PDO::FETCH_ASSOC);

// Récupérer les derniers rendez-vous
$stmt = db()->prepare("
    SELECT r.*, m.nom as medecin_nom, m.prenom as medecin_prenom
    FROM rendez_vous r
    JOIN medecin m ON r.id_medecin = m.id
    WHERE r.id_patient = ?
    ORDER BY r.date_rdv DESC, r.heure_rdv DESC
    LIMIT 5
");
$stmt->execute([$patient_id]);
$rendezvous = $stmt->fetchAll(PDO::FETCH_ASSOC);

// Récupérer les dernières ordonnances
$stmt = db()->prepare("
    SELECT o.*, m.nom as medecin_nom, m.prenom as medecin_prenom
    FROM ordonnance o
    JOIN medecin m ON o.idmedecin = m.id
    WHERE o.idpatient = ?
    ORDER BY o.date_creation DESC
    LIMIT 5
");
$stmt->execute([$patient_id]);
$ordonnances = $stmt->fetchAll(PDO::FETCH_ASSOC);
?>

<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Détails Patient - MedConnect</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <?php include_once '../../views/components/styles.php'; ?>
</head>
<body class="bg-gradient-to-br from-[#F1F8E9] to-[#E8F5E9] min-h-screen">
    <div class="min-h-screen flex">
        <!-- Barre latérale -->
        <?php include_once 'components/sidebar.php'; ?>

        <!-- Contenu principal -->
        <div class="flex-1">
            <!-- En-tête -->
            <header class="bg-white shadow-sm">
                <div class="container mx-auto px-4 py-4 flex justify-between items-center">
                    <div class="flex items-center space-x-4">
                        <div class="w-12 h-12 rounded-full bg-gradient-to-br from-[#2E7D32] to-[#81C784] flex items-center justify-center">
                            <i class="fas fa-user text-white text-xl"></i>
                        </div>
                        <h1 class="text-2xl font-bold text-[#1B5E20]">
                            <?php echo htmlspecialchars($patient['prenom'] . ' ' . $patient['nom']); ?>
                        </h1>
                    </div>
                    <div class="flex space-x-4">
                        <a href="nouvelle_consultation.php?patient_id=<?php echo $patient_id; ?>" class="btn-primary">
                            <i class="fas fa-plus mr-2"></i>Nouvelle Consultation
                        </a>
                        <a href="patients.php" class="btn-secondary">
                            <i class="fas fa-arrow-left mr-2"></i>Retour
                        </a>
                    </div>
                </div>
            </header>

            <!-- Contenu principal -->
            <main class="container mx-auto px-4 py-8">
                <div class="grid grid-cols-1 md:grid-cols-2 gap-8">
                    <!-- Informations personnelles -->
                    <div class="bg-white rounded-xl shadow-lg p-6 glass-effect">
                        <h2 class="text-xl font-semibold text-[#1B5E20] mb-4">Informations personnelles</h2>
                        <div class="space-y-4">
                            <div>
                                <label class="block text-sm font-medium text-gray-600">Date de naissance</label>
                                <p class="mt-1"><?php echo date('d/m/Y', strtotime($patient['datenais'])); ?></p>
                            </div>
                            <div>
                                <label class="block text-sm font-medium text-gray-600">Sexe</label>
                                <p class="mt-1">
                                    <?php
                                    switch($patient['sexe']) {
                                        case 'M':
                                            echo 'Masculin';
                                            break;
                                        case 'F':
                                            echo 'Féminin';
                                            break;
                                        case 'A':
                                            echo 'Autre';
                                            break;
                                        default:
                                            echo 'Non renseigné';
                                    }
                                    ?>
                                </p>
                            </div>
                            <div>
                                <label class="block text-sm font-medium text-gray-600">Email</label>
                                <p class="mt-1"><?php echo htmlspecialchars($patient['email']); ?></p>
                            </div>
                            <div>
                                <label class="block text-sm font-medium text-gray-600">Téléphone</label>
                                <p class="mt-1"><?php echo htmlspecialchars($patient['contact']); ?></p>
                            </div>
                            <div>
                                <label class="block text-sm font-medium text-gray-600">Adresse</label>
                                <p class="mt-1"><?php echo htmlspecialchars($patient['adresse'] ?? 'Non renseignée'); ?></p>
                            </div>
                            <div>
                                <label class="block text-sm font-medium text-gray-600">Profession</label>
                                <p class="mt-1"><?php echo htmlspecialchars($patient['profession'] ?? 'Non renseignée'); ?></p>
                            </div>
                        </div>
                    </div>

                    <!-- Informations médicales -->
                    <div class="bg-white rounded-xl shadow-lg p-6 glass-effect">
                        <h2 class="text-xl font-semibold text-[#1B5E20] mb-4">Informations médicales</h2>
                        <div class="space-y-4">
                            <div>
                                <label class="block text-sm font-medium text-gray-600">Groupe sanguin</label>
                                <p class="mt-1"><?php echo htmlspecialchars($patient['groupesanguin'] ?? 'Non renseigné'); ?></p>
                            </div>
                            <div>
                                <label class="block text-sm font-medium text-gray-600">Taille</label>
                                <p class="mt-1"><?php echo $patient['taille'] ? $patient['taille'] . ' cm' : 'Non renseignée'; ?></p>
                            </div>
                            <div>
                                <label class="block text-sm font-medium text-gray-600">Poids</label>
                                <p class="mt-1"><?php echo $patient['poids'] ? $patient['poids'] . ' kg' : 'Non renseigné'; ?></p>
                            </div>
                            <div>
                                <label class="block text-sm font-medium text-gray-600">Allergies</label>
                                <p class="mt-1"><?php echo htmlspecialchars($patient['allergie'] ?? 'Aucune allergie connue'); ?></p>
                            </div>
                            <div>
                                <label class="block text-sm font-medium text-gray-600">Électrophorèse</label>
                                <p class="mt-1"><?php echo htmlspecialchars($patient['electrophorese'] ?? 'Non renseignée'); ?></p>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Historique des consultations -->
                <div class="mt-8 bg-white rounded-xl shadow-lg p-6 glass-effect">
                    <h2 class="text-xl font-semibold text-[#1B5E20] mb-4">Historique des consultations</h2>
                    <?php if (empty($consultations)): ?>
                        <p class="text-gray-500">Aucune consultation enregistrée.</p>
                    <?php else: ?>
                        <div class="space-y-4">
                            <?php foreach ($consultations as $consultation): ?>
                                <div class="border-b border-gray-200 pb-4">
                                    <div class="flex justify-between items-start">
                                        <div>
                                            <h3 class="font-medium text-[#1B5E20]">
                                                Dr. <?php echo htmlspecialchars($consultation['medecin_prenom'] . ' ' . $consultation['medecin_nom']); ?>
                                            </h3>
                                            <p class="text-sm text-gray-600">
                                                <?php echo date('d/m/Y H:i', strtotime($consultation['date_consultation'])); ?>
                                            </p>
                                        </div>
                                        <a href="consultation_details.php?id=<?php echo $consultation['id']; ?>" class="text-[#2E7D32] hover:text-[#1B5E20]">
                                            <i class="fas fa-eye"></i>
                                        </a>
                                    </div>
                                    <p class="mt-2 text-gray-700">
                                        <?php echo htmlspecialchars($consultation['motif']); ?>
                                    </p>
                                </div>
                            <?php endforeach; ?>
                        </div>
                    <?php endif; ?>
                </div>

                <!-- Derniers rendez-vous -->
                <div class="mt-8 bg-white rounded-xl shadow-lg p-6 glass-effect">
                    <div class="flex justify-between items-center mb-4">
                        <h2 class="text-xl font-semibold text-[#1B5E20]">Derniers rendez-vous</h2>
                        <a href="rdv.php?patient_id=<?php echo $patient_id; ?>" class="text-[#2E7D32] hover:text-[#1B5E20]">
                            Voir tout
                        </a>
                    </div>
                    <div class="space-y-4">
                        <?php foreach ($rendezvous as $rdv): ?>
                            <div class="border-b border-gray-200 pb-4">
                                <div class="flex justify-between items-start">
                                    <div>
                                        <h3 class="font-medium text-[#1B5E20]">
                                            Dr. <?php echo htmlspecialchars($rdv['medecin_prenom'] . ' ' . $rdv['medecin_nom']); ?>
                                        </h3>
                                        <p class="text-sm text-gray-600">
                                            <?php echo date('d/m/Y H:i', strtotime($rdv['date_rdv'])); ?>
                                        </p>
                                    </div>
                                    <span class="px-3 py-1 rounded-full text-sm <?php 
                                        $statusClass = '';
                                        switch($rdv['statut']) {
                                            case 'confirmé':
                                                $statusClass = 'bg-green-100 text-green-800';
                                                break;
                                            case 'annulé':
                                                $statusClass = 'bg-red-100 text-red-800';
                                                break;
                                            default:
                                                $statusClass = 'bg-yellow-100 text-yellow-800';
                                        }
                                        echo $statusClass;
                                    ?>">
                                        <?php echo ucfirst($rdv['statut']); ?>
                                    </span>
                                </div>
                            </div>
                        <?php endforeach; ?>
                    </div>
                </div>

                <!-- Dernières ordonnances -->
                <div class="mt-8 bg-white rounded-xl shadow-lg p-6 glass-effect">
                    <div class="flex justify-between items-center mb-4">
                        <h2 class="text-xl font-semibold text-[#1B5E20]">Dernières ordonnances</h2>
                        <a href="ordonnances.php?patient_id=<?php echo $patient_id; ?>" class="text-[#2E7D32] hover:text-[#1B5E20]">
                            Voir tout
                        </a>
                    </div>
                    <div class="space-y-4">
                        <?php foreach ($ordonnances as $ordonnance): ?>
                            <div class="border-b border-gray-200 pb-4">
                                <div class="flex justify-between items-start">
                                    <div>
                                        <h3 class="font-medium text-[#1B5E20]">
                                            Dr. <?php echo htmlspecialchars($ordonnance['medecin_prenom'] . ' ' . $ordonnance['medecin_nom']); ?>
                                        </h3>
                                        <p class="text-sm text-gray-600">
                                            <?php echo date('d/m/Y', strtotime($ordonnance['date_creation'])); ?>
                                        </p>
                                    </div>
                                    <a href="voir_ordonnance.php?id=<?php echo $ordonnance['id']; ?>" class="text-[#2E7D32] hover:text-[#1B5E20]">
                                        <i class="fas fa-eye"></i>
                                    </a>
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