<?php
// Connexion à la base de données
require_once '../../config/config.php';
require_once '../../includes/session.php';
requireLogin();
requireRole('patient');

// Récupération des données du patient connecté
$id_patient = $_SESSION['user_id'];
$nom = $_SESSION['nom'];
$prenom = $_SESSION['prenom'];

// Vérifier si le carnet de santé existe
$stmt = db()->prepare("SELECT id FROM carnetsante WHERE id_patient = ?");
$stmt->execute([$id_patient]);
$carnet_exists = $stmt->fetch();

if (!$carnet_exists) {
    // Insérer un nouveau carnet de santé
    $stmt = db()->prepare("
        INSERT INTO carnetsante (id_patient, taille, poids, groupesanguin, allergie, electrophorese)
        VALUES (?, NULL, NULL, '', '', '')
    ");
    $stmt->execute([$id_patient]);
    $id_carnet = db()->lastInsertId();
} else {
    $id_carnet = $carnet_exists['id'];
}

// Vérifier si le profil patient existe
$stmt = db()->prepare("SELECT id FROM profilpatient WHERE idpatient = ?");
$stmt->execute([$id_patient]);
$profil_exists = $stmt->fetch();

if (!$profil_exists) {
    // Insérer un nouveau profil patient avec l'id du carnet de santé
    $stmt = db()->prepare("
        INSERT INTO profilpatient (idpatient, idcarnetsante, adresse, profession)
        VALUES (?, ?, '', '')
    ");
    $stmt->execute([$id_patient, $id_carnet]);
}

// Initialiser le tableau carnet avec des valeurs par défaut
$carnet = [
    'adresse' => '',
    'profession' => '',
    'taille' => '',
    'poids' => '',
    'groupesanguin' => '',
    'allergie' => '',
    'electrophorese' => ''
];

// Récupérer les données du profil patient
$stmt = db()->prepare("
    SELECT adresse, profession
    FROM profilpatient
    WHERE idpatient = ?
");
$stmt->execute([$id_patient]);
$profil = $stmt->fetch(PDO::FETCH_ASSOC);

if ($profil) {
    $carnet['adresse'] = $profil['adresse'] ?? '';
    $carnet['profession'] = $profil['profession'] ?? '';
}

// Récupérer les données du carnet de santé
$stmt = db()->prepare("
    SELECT taille, poids, groupesanguin, allergie, electrophorese
    FROM carnetsante
    WHERE id_patient = ?
");
$stmt->execute([$id_patient]);
$carnet_data = $stmt->fetch(PDO::FETCH_ASSOC);

if ($carnet_data) {
    $carnet = array_merge($carnet, $carnet_data);
}

// Récupérer l'historique des ordonnances
$stmt = db()->prepare("
    SELECT o.*, m.nom as medecin_nom, m.prenom as medecin_prenom
    FROM ordonnance o
    JOIN medecin m ON o.idmedecin = m.id
    WHERE o.idpatient = ?
    ORDER BY o.date_creation DESC
");
$stmt->execute([$id_patient]);
$ordonnances = $stmt->fetchAll(PDO::FETCH_ASSOC);

// Traitement du formulaire de mise à jour
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    try {
        $db = db();
        $db->beginTransaction();

        // Mise à jour du carnet de santé
        $stmt = $db->prepare("
            UPDATE carnetsante 
            SET groupesanguin = ?, taille = ?, poids = ?, allergie = ?, electrophorese = ?
            WHERE id_patient = ?
        ");
        $stmt->execute([
            $_POST['groupesanguin'] ?? '',
            $_POST['taille'] ?? '',
            $_POST['poids'] ?? '',
            $_POST['allergie'] ?? '',
            $_POST['electrophorese'] ?? '',
            $id_patient
        ]);

        // Mise à jour du profil patient
        $stmt = $db->prepare("
            UPDATE profilpatient 
            SET adresse = ?, profession = ?
            WHERE idpatient = ?
        ");
        $stmt->execute([
            $_POST['adresse'] ?? '',
            $_POST['profession'] ?? '',
            $id_patient
        ]);

        $db->commit();
        $success = "Votre carnet de santé a été mis à jour avec succès.";

        // Mettre à jour le tableau $carnet avec les nouvelles valeurs
        $carnet['adresse'] = $_POST['adresse'] ?? '';
        $carnet['profession'] = $_POST['profession'] ?? '';
        $carnet['groupesanguin'] = $_POST['groupesanguin'] ?? '';
        $carnet['taille'] = $_POST['taille'] ?? '';
        $carnet['poids'] = $_POST['poids'] ?? '';
        $carnet['allergie'] = $_POST['allergie'] ?? '';
        $carnet['electrophorese'] = $_POST['electrophorese'] ?? '';

    } catch (PDOException $e) {
        $db->rollBack();
        $error = "Une erreur est survenue lors de la mise à jour : " . $e->getMessage();
    }
}

// Fonction de raccourci pour affichage sécurisé
function val($key) {
    global $carnet;
    return htmlspecialchars($carnet[$key] ?? '');
}
?>

<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Mon Carnet de Santé - MedConnect</title>
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
        .health-card {
            transition: all 0.3s ease;
        }
        .health-card:hover {
            transform: translateY(-5px);
        }
        .fade-in {
            animation: fadeIn 0.6s ease-out;
        }
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
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
                <a href="carnet.php" class="nav-link active block px-4 py-3 rounded-lg text-[#1e40af]">
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
                <?php if (isset($success)): ?>
                    <div class="bg-[#EFF6FF] border border-[#3b82f6] text-[#1e40af] px-4 py-3 rounded-lg mb-6 flex items-center" role="alert">
                        <div class="w-8 h-8 rounded-full bg-[#3b82f6] flex items-center justify-center mr-3">
                            <i class="fas fa-check text-white"></i>
                        </div>
                        <span class="block sm:inline"><?php echo $success; ?></span>
                    </div>
                <?php endif; ?>

                <?php if (isset($error)): ?>
                    <div class="bg-[#FEF2F2] border border-[#EF4444] text-[#991B1B] px-4 py-3 rounded-lg mb-6 flex items-center" role="alert">
                        <div class="w-8 h-8 rounded-full bg-[#EF4444] flex items-center justify-center mr-3">
                            <i class="fas fa-exclamation-circle text-white"></i>
                        </div>
                        <span class="block sm:inline"><?php echo $error; ?></span>
                    </div>
                <?php endif; ?>

                <!-- Statistiques -->
                <div class="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
                    <div class="health-card bg-white rounded-xl shadow-lg p-6 glass-effect">
                        <div class="flex items-center justify-between">
                            <div>
                                <p class="text-sm text-[#3b82f6]">IMC</p>
                                <h3 class="text-2xl font-bold text-[#1e40af]">
                                    <?php 
                                    if (!empty($carnet['taille']) && !empty($carnet['poids'])) {
                                        $taille_m = $carnet['taille'] / 100;
                                        $imc = round($carnet['poids'] / ($taille_m * $taille_m), 1);
                                        echo $imc;
                                    } else {
                                        echo "N/A";
                                    }
                                    ?>
                                </h3>
                            </div>
                            <div class="w-12 h-12 rounded-full bg-[#EFF6FF] flex items-center justify-center">
                                <i class="fas fa-weight text-xl text-[#3b82f6]"></i>
                            </div>
                        </div>
                    </div>
                    <div class="health-card bg-white rounded-xl shadow-lg p-6 glass-effect">
                        <div class="flex items-center justify-between">
                            <div>
                                <p class="text-sm text-[#10b981]">Groupe Sanguin</p>
                                <h3 class="text-2xl font-bold text-[#1e40af]">
                                    <?php echo !empty($carnet['groupesanguin']) ? htmlspecialchars($carnet['groupesanguin']) : 'Non renseigné'; ?>
                                </h3>
                            </div>
                            <div class="w-12 h-12 rounded-full bg-[#ECFDF5] flex items-center justify-center">
                                <i class="fas fa-tint text-xl text-[#10b981]"></i>
                            </div>
                        </div>
                    </div>
                    <div class="health-card bg-white rounded-xl shadow-lg p-6 glass-effect">
                        <div class="flex items-center justify-between">
                            <div>
                                <p class="text-sm text-[#f59e0b]">Ordonnances Actives</p>
                                <h3 class="text-2xl font-bold text-[#1e40af]">
                                    <?php 
                                    $active_count = 0;
                                    foreach ($ordonnances as $ordonnance) {
                                        if (strtotime($ordonnance['date_validite']) >= time()) {
                                            $active_count++;
                                        }
                                    }
                                    echo $active_count;
                                    ?>
                                </h3>
                            </div>
                            <div class="w-12 h-12 rounded-full bg-[#FFFBEB] flex items-center justify-center">
                                <i class="fas fa-prescription text-xl text-[#f59e0b]"></i>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Informations médicales -->
                <div class="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
                    <!-- Formulaire du carnet de santé -->
                    <div class="bg-white rounded-xl shadow-lg p-6 glass-effect">
                        <h2 class="text-xl font-semibold text-[#1e40af] mb-6 flex items-center">
                            <i class="fas fa-book-medical mr-2"></i>Informations Médicales
                        </h2>
                        <form method="POST" class="space-y-6">
                            <div class="grid grid-cols-1 gap-6">
                                <div class="grid grid-cols-2 gap-4">
                                    <div>
                                        <label class="block text-sm font-medium text-gray-700 mb-2">Groupe Sanguin</label>
                                        <input type="text" name="groupesanguin" value="<?php echo htmlspecialchars($carnet['groupesanguin'] ?? ''); ?>" 
                                            class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-[#3b82f6] focus:border-transparent">
                                    </div>
                                    <div>
                                        <label class="block text-sm font-medium text-gray-700 mb-2">Taille (cm)</label>
                                        <input type="number" step="0.01" name="taille" value="<?php echo htmlspecialchars($carnet['taille'] ?? ''); ?>" 
                                            class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-[#3b82f6] focus:border-transparent">
                                    </div>
                                </div>
                                <div>
                                    <label class="block text-sm font-medium text-gray-700 mb-2">Poids (kg)</label>
                                    <input type="number" step="0.01" name="poids" value="<?php echo htmlspecialchars($carnet['poids'] ?? ''); ?>" 
                                        class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-[#3b82f6] focus:border-transparent">
                                </div>
                                <div>
                                    <label class="block text-sm font-medium text-gray-700 mb-2">Allergies</label>
                                    <textarea name="allergie" rows="3" placeholder="Listez vos allergies ici..."
                                        class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-[#3b82f6] focus:border-transparent"><?php echo htmlspecialchars($carnet['allergie'] ?? ''); ?></textarea>
                                </div>
                                <div>
                                    <label class="block text-sm font-medium text-gray-700 mb-2">Électrophorèse</label>
                                    <textarea name="electrophorese" rows="3" placeholder="Résultats de l'électrophorèse..."
                                        class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-[#3b82f6] focus:border-transparent"><?php echo htmlspecialchars($carnet['electrophorese'] ?? ''); ?></textarea>
                                </div>
                            </div>
                    </div>

                    <!-- Informations personnelles -->
                    <div class="bg-white rounded-xl shadow-lg p-6 glass-effect">
                        <h2 class="text-xl font-semibold text-[#1e40af] mb-6 flex items-center">
                            <i class="fas fa-user mr-2"></i>Informations Personnelles
                        </h2>
                        <div class="space-y-6">
                            <div>
                                <label class="block text-sm font-medium text-gray-700 mb-2">Adresse</label>
                                <input type="text" name="adresse" value="<?= val('adresse') ?>" 
                                    placeholder="Votre adresse complète..."
                                    class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-[#3b82f6] focus:border-transparent">
                            </div>
                            <div>
                                <label class="block text-sm font-medium text-gray-700 mb-2">Profession</label>
                                <input type="text" name="profession" value="<?= val('profession') ?>" 
                                    placeholder="Votre profession..."
                                    class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-[#3b82f6] focus:border-transparent">
                            </div>
                        </div>
                    </div>
                </div>
                <div class="flex justify-end mb-8">
                    <button type="submit" class="bg-[#3b82f6] hover:bg-[#2563eb] text-white px-6 py-2 rounded-lg transition-colors duration-300">
                        <i class="fas fa-save mr-2"></i>Enregistrer les modifications
                    </button>
                </div>
                </form>

                <!-- Historique des ordonnances -->
                <div class="bg-white rounded-xl shadow-lg p-6 glass-effect">
                    <div class="flex justify-between items-center mb-6">
                        <h2 class="text-xl font-semibold text-[#1e40af] flex items-center">
                            <i class="fas fa-prescription mr-2"></i>Historique des Ordonnances
                        </h2>
                        <div class="flex space-x-2">
                            <button class="px-4 py-2 text-sm bg-[#EFF6FF] text-[#3b82f6] rounded-lg hover:bg-[#DBEAFE] transition-colors duration-300">
                                <i class="fas fa-filter mr-2"></i>Filtrer
                            </button>
                            <button class="px-4 py-2 text-sm bg-[#EFF6FF] text-[#3b82f6] rounded-lg hover:bg-[#DBEAFE] transition-colors duration-300">
                                <i class="fas fa-download mr-2"></i>Exporter
                            </button>
                        </div>
                    </div>
                    <div class="space-y-4">
                        <?php if (empty($ordonnances)): ?>
                            <div class="text-center py-8">
                                <div class="w-16 h-16 mx-auto mb-4 rounded-full bg-[#EFF6FF] flex items-center justify-center">
                                    <i class="fas fa-prescription text-2xl text-[#3b82f6]"></i>
                                </div>
                                <p class="text-gray-500">Aucune ordonnance disponible</p>
                            </div>
                        <?php else: ?>
                            <?php foreach ($ordonnances as $ordonnance): ?>
                                <div class="p-4 bg-[#EFF6FF] rounded-lg hover:bg-[#DBEAFE] transition-colors duration-300">
                                    <div class="flex justify-between items-start">
                                        <div class="flex-1">
                                            <div class="flex items-center mb-2">
                                                <div class="w-10 h-10 rounded-full bg-[#DBEAFE] flex items-center justify-center mr-3">
                                                    <i class="fas fa-user-md text-[#3b82f6]"></i>
                                                </div>
                                                <div>
                                                    <p class="font-medium text-[#1e40af]">
                                                        Dr. <?php echo htmlspecialchars($ordonnance['medecin_prenom'] . ' ' . $ordonnance['medecin_nom']); ?>
                                                    </p>
                                                    <p class="text-sm text-[#3b82f6]">
                                                        <?php echo date('d/m/Y', strtotime($ordonnance['date_creation'])); ?>
                                                    </p>
                                                </div>
                                            </div>
                                            <div class="ml-13 space-y-3">
                                                <div>
                                                    <p class="text-sm font-medium text-gray-700">Médicaments :</p>
                                                    <p class="text-sm text-gray-600"><?php echo nl2br(htmlspecialchars($ordonnance['medicaments'])); ?></p>
                                                </div>
                                                <div>
                                                    <p class="text-sm font-medium text-gray-700">Posologie :</p>
                                                    <p class="text-sm text-gray-600"><?php echo nl2br(htmlspecialchars($ordonnance['posologie'])); ?></p>
                                                </div>
                                                <?php if ($ordonnance['instructions']): ?>
                                                    <div>
                                                        <p class="text-sm font-medium text-gray-700">Instructions :</p>
                                                        <p class="text-sm text-gray-600"><?php echo nl2br(htmlspecialchars($ordonnance['instructions'])); ?></p>
                                                    </div>
                                                <?php endif; ?>
                                            </div>
                                        </div>
                                        <div class="text-right ml-4">
                                            <p class="text-sm text-gray-500">
                                                Valide jusqu'au : <?php echo date('d/m/Y', strtotime($ordonnance['date_validite'])); ?>
                                            </p>
                                            <?php if ($ordonnance['renouvellement']): ?>
                                                <span class="inline-block mt-2 px-3 py-1 bg-[#FEF3C7] text-[#92400e] rounded-full text-sm">
                                                    Renouvelable (<?php echo $ordonnance['nombre_renouvellements']; ?> fois)
                                                </span>
                                            <?php endif; ?>
                                            <div class="mt-4">
                                                <button class="text-[#3b82f6] hover:text-[#2563eb]">
                                                    <i class="fas fa-download"></i>
                                                </button>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            <?php endforeach; ?>
                        <?php endif; ?>
                    </div>
                </div>
            </main>
        </div>
    </div>

    <!-- Bouton de chat flottant -->
    <button class="fixed bottom-4 right-4 bg-[#3b82f6] hover:bg-[#2563eb] text-white rounded-full w-14 h-14 text-2xl shadow-lg transition-colors duration-300 flex items-center justify-center">
        <i class="fas fa-comments"></i>
    </button>
</body>
</html>
