<?php
require_once '../../config/config.php';
require_once '../../includes/session.php';
requireLogin();
requireRole('patient');

$user_id = $_SESSION['user_id'];
$success = "";
$error = "";

// Pré-remplissage des données
$stmt =  db()->prepare("
    SELECT 
        p.nom, p.prenom, p.datenais, p.email, p.contact, p.sexe,
        pr.adresse, pr.profession,
        cs.groupesanguin, cs.taille, cs.poids, cs.allergie, cs.electrophorese,
        pr.id AS profil_id, cs.id AS carnet_id
    FROM patient p  
    LEFT JOIN profilpatient pr ON p.id = pr.idpatient
    LEFT JOIN carnetsante cs ON pr.idcarnetsante = cs.id
    WHERE p.id = ?
");
$stmt->execute([$user_id]);
$data = $stmt->fetch();

// Pré-remplissage
$nom = $data['nom'] ?? '';
$prenom = $data['prenom'] ?? '';
$email = $data['email'] ?? '';
$contact = $data['contact'] ?? '';
$datenais = $data['datenais'] ?? '';
$sexe = $data['sexe'] ?? '';
$adresse = $data['adresse'] ?? '';
$profession = $data['profession'] ?? '';
$groupesanguin = $data['groupesanguin'] ?? '';
$taille = $data['taille'] ?? '';
$poids = $data['poids'] ?? '';
$allergie = $data['allergie'] ?? '';
$electrophorese = $data['electrophorese'] ?? '';
$profil_id = $data['profil_id'] ?? null;
$carnet_id = $data['carnet_id'] ?? null;

// Traitement du formulaire
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $nom = $_POST['nom'];
    $prenom = $_POST['prenom'];
    $datenais = $_POST['datenais'];
    $email = $_POST['email'];
    $contact = $_POST['telephone'];
    $sexe = $_POST['sexe'];
    $adresse = $_POST['adresse'];
    $profession = $_POST['profession'];

    $groupesanguin = $_POST['groupesanguin'];
    $taille = $_POST['taille'];
    $poids = $_POST['poids'];
    $allergie = $_POST['allergie'];
    $electrophorese = $_POST['electrophorese'];

    // MAJ patient
    $stmt =  db()->prepare("UPDATE patient SET nom = ?, prenom = ?, datenais = ?, email = ?, contact = ?, sexe = ? WHERE id = ?");
    $stmt->execute([$nom, $prenom, $datenais, $email, $contact, $sexe, $user_id]);

    // MAJ ou insertion profilpatient
    if ($profil_id) {
        $stmt =  db()->prepare("UPDATE profilpatient SET adresse = ?, profession = ? WHERE id = ?");
        $stmt->execute([$adresse, $profession, $profil_id]);
    } else {
        // D'abord insérer dans carnetsante avec l'id_patient
        $stmt = db()->prepare("INSERT INTO carnetsante (id_patient, groupesanguin, taille, poids, allergie, electrophorese) VALUES (?, '', '', '', '', '')");
        $stmt->execute([$user_id]);
        $new_carnet_id = db()->lastInsertId();
        
        // Ensuite insérer dans profilpatient
        $stmt = db()->prepare("INSERT INTO profilpatient (adresse, profession, idpatient, idcarnetsante) VALUES (?, ?, ?, ?)");
        $stmt->execute([$adresse, $profession, $user_id, $new_carnet_id]);
    }

    // MAJ carnet de santé
    if ($carnet_id) {
        $stmt =  db()->prepare("UPDATE carnetsante SET groupesanguin = ?, taille = ?, poids = ?, allergie = ?, electrophorese = ? WHERE id = ?");
        $stmt->execute([$groupesanguin, $taille, $poids, $allergie, $electrophorese, $carnet_id]);
    }

    $success = "Profil mis à jour avec succès.";
}
?>
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Profil du Patient - MedConnect</title>
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
        .form-input {
            transition: all 0.3s ease;
        }
        .form-input:focus {
            border-color: #3b82f6;
            box-shadow: 0 0 0 2px rgba(59, 130, 246, 0.1);
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
                <a href="profile_patient.php" class="nav-link active block px-4 py-3 rounded-lg text-[#1e40af]">
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
                <div class="bg-white rounded-xl shadow-lg p-8 max-w-3xl mx-auto glass-effect fade-in">
                    <div class="flex items-center space-x-4 mb-8">
                        <div class="w-20 h-20 rounded-full bg-gradient-to-br from-[#3b82f6] to-[#60a5fa] flex items-center justify-center">
                            <i class="fas fa-user text-white text-3xl"></i>
                        </div>
                        <div>
                            <h2 class="text-2xl font-semibold text-[#1e40af]"><?= htmlspecialchars($prenom . ' ' . $nom) ?></h2>
                            <p class="text-[#3b82f6]"><?= htmlspecialchars($email) ?></p>
                        </div>
                    </div>

                    <?php if (!empty($success)) : ?>
                        <div class="bg-[#DCFCE7] text-[#065f46] px-4 py-3 rounded-lg mb-6 flex items-center">
                            <i class="fas fa-check-circle mr-2"></i>
                            <?= htmlspecialchars($success) ?>
                        </div>
                    <?php endif; ?>

                    <form action="profile_patient.php" method="post" class="grid grid-cols-1 md:grid-cols-2 gap-6">
                        <!-- Infos personnelles -->
                        <div class="col-span-2">
                            <h3 class="text-lg font-semibold text-[#1e40af] mb-4 flex items-center">
                                <i class="fas fa-user-circle mr-2"></i>
                                Informations personnelles
                            </h3>
                        </div>

                        <div class="space-y-2">
                            <label class="block text-sm font-medium text-[#1e40af]">Nom</label>
                            <input type="text" name="nom" value="<?= htmlspecialchars($nom) ?>" 
                                   class="form-input w-full border border-gray-200 rounded-lg px-4 py-2 focus:outline-none">
                        </div>

                        <div class="space-y-2">
                            <label class="block text-sm font-medium text-[#1e40af]">Prénom</label>
                            <input type="text" name="prenom" value="<?= htmlspecialchars($prenom) ?>" 
                                   class="form-input w-full border border-gray-200 rounded-lg px-4 py-2 focus:outline-none">
                        </div>

                        <div class="space-y-2">
                            <label class="block text-sm font-medium text-[#1e40af]">Email</label>
                            <input type="email" name="email" value="<?= htmlspecialchars($email) ?>" 
                                   class="form-input w-full border border-gray-200 rounded-lg px-4 py-2 focus:outline-none">
                        </div>

                        <div class="space-y-2">
                            <label class="block text-sm font-medium text-[#1e40af]">Téléphone</label>
                            <input type="text" name="telephone" value="<?= htmlspecialchars($contact) ?>" 
                                   class="form-input w-full border border-gray-200 rounded-lg px-4 py-2 focus:outline-none">
                        </div>

                        <div class="space-y-2">
                            <label class="block text-sm font-medium text-[#1e40af]">Profession</label>
                            <input type="text" name="profession" value="<?= htmlspecialchars($profession) ?>" 
                                   class="form-input w-full border border-gray-200 rounded-lg px-4 py-2 focus:outline-none">
                        </div>

                        <div class="space-y-2">
                            <label class="block text-sm font-medium text-[#1e40af]">Date de naissance</label>
                            <input type="date" name="datenais" value="<?= htmlspecialchars($datenais) ?>" 
                                   class="form-input w-full border border-gray-200 rounded-lg px-4 py-2 focus:outline-none">
                        </div>

                        <div class="space-y-2">
                            <label class="block text-sm font-medium text-[#1e40af]">Sexe</label>
                            <select name="sexe" class="form-input w-full border border-gray-200 rounded-lg px-4 py-2 focus:outline-none">
                                <option value="">Sélectionnez</option>
                                <option value="M" <?= $sexe === 'M' ? 'selected' : '' ?>>Masculin</option>
                                <option value="F" <?= $sexe === 'F' ? 'selected' : '' ?>>Féminin</option>
                                <option value="A" <?= $sexe === 'A' ? 'selected' : '' ?>>Autre</option>
                            </select>
                        </div>

                        <div class="col-span-2 space-y-2">
                            <label class="block text-sm font-medium text-[#1e40af]">Adresse</label>
                            <input type="text" name="adresse" value="<?= htmlspecialchars($adresse) ?>" 
                                   class="form-input w-full border border-gray-200 rounded-lg px-4 py-2 focus:outline-none">
                        </div>

                        <!-- Informations médicales -->
                        <div class="col-span-2 mt-8">
                            <h3 class="text-lg font-semibold text-[#1e40af] mb-4 flex items-center">
                                <i class="fas fa-heartbeat mr-2"></i>
                                Informations médicales
                            </h3>
                        </div>

                        <div class="space-y-2">
                            <label class="block text-sm font-medium text-[#1e40af]">Groupe sanguin</label>
                            <input type="text" name="groupesanguin" value="<?= htmlspecialchars($groupesanguin) ?>" 
                                   class="form-input w-full border border-gray-200 rounded-lg px-4 py-2 focus:outline-none">
                        </div>

                        <div class="space-y-2">
                            <label class="block text-sm font-medium text-[#1e40af]">Taille (cm)</label>
                            <input type="text" name="taille" value="<?= htmlspecialchars($taille) ?>" 
                                   class="form-input w-full border border-gray-200 rounded-lg px-4 py-2 focus:outline-none">
                        </div>

                        <div class="space-y-2">
                            <label class="block text-sm font-medium text-[#1e40af]">Poids (kg)</label>
                            <input type="text" name="poids" value="<?= htmlspecialchars($poids) ?>" 
                                   class="form-input w-full border border-gray-200 rounded-lg px-4 py-2 focus:outline-none">
                        </div>

                        <div class="space-y-2">
                            <label class="block text-sm font-medium text-[#1e40af]">Allergies</label>
                            <input type="text" name="allergie" value="<?= htmlspecialchars($allergie) ?>" 
                                   class="form-input w-full border border-gray-200 rounded-lg px-4 py-2 focus:outline-none">
                        </div>

                        <div class="space-y-2">
                            <label class="block text-sm font-medium text-[#1e40af]">Électrophorèse</label>
                            <input type="text" name="electrophorese" value="<?= htmlspecialchars($electrophorese) ?>" 
                                   class="form-input w-full border border-gray-200 rounded-lg px-4 py-2 focus:outline-none">
                        </div>

                        <div class="col-span-2 mt-8">
                            <button type="submit" class="bg-[#3b82f6] hover:bg-[#2563eb] text-white px-6 py-3 rounded-lg transition-colors duration-300 flex items-center justify-center gap-2 w-full">
                                <i class="fas fa-save"></i>
                                Enregistrer les modifications
                            </button>
                        </div>
                    </form>
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
