<?php
// Charger la configuration de session
require_once '../../includes/session.php';

// Vérifier l'authentification et l'autorisation
requireLogin();
requireRole('patient');

// Initialisation des messages
$success = "";
$error = "";

$user_id = $_SESSION['user_id'];

// Définir le chemin racine
$root_path = '../../';

require_once $root_path . 'config/database.php';
require_once $root_path . 'includes/routing.php';
require_once $root_path . 'includes/google_calendar.php';

// Vérifier si l'utilisateur est connecté à Google Calendar
$stmt = db()->prepare("SELECT id FROM google_tokens WHERE user_id = ?");
$stmt->execute([$user_id]);
$is_google_connected = $stmt->fetch() !== false;

// Requête pour récupérer les rendez-vous du patient avec infos médecin
$sql = "SELECT r.id, r.dateheure, r.statut, m.nom AS nom_medecin, m.prenom AS prenom_medecin, s.nomspecialite
        FROM rendezvous r
        JOIN medecin m ON r.idmedecin = m.id
        LEFT JOIN specialite s ON r.idspecialite = s.id
        WHERE r.idpatient = :idpatient
        ORDER BY r.dateheure DESC
        ";

$stmt = db()->prepare($sql);
$stmt->execute(['idpatient' => $user_id]);
$rendezvous = $stmt->fetchAll(PDO::FETCH_ASSOC);

// Calculer les statistiques des rendez-vous
$rdvs_a_venir = array_filter($rendezvous, function($rdv) {
    return strtotime($rdv['dateheure']) >= strtotime('today');
});

$rdvs_confirmes = array_filter($rdvs_a_venir, function($rdv) {
    return $rdv['statut'] === 'confirmé';
});

$rdvs_en_attente = array_filter($rdvs_a_venir, function($rdv) {
    return $rdv['statut'] === 'en attente';
});

// prendre rendez vous

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    try {
        $idpatient = $_SESSION['user_id'];
        $idmedecin = $_POST['medecin'] ?? null;
        $idspecialite = $_POST['specialite'] ?? null;
        $date = $_POST['date'] ?? null;
        $heure = $_POST['heure'] ?? null;

        if ($idmedecin && $idspecialite && $date && $heure) {
            $dateheure = $date . ' ' . $heure;
            
        $sql = "INSERT INTO rendezvous (dateheure, statut, idmedecin, idpatient, idspecialite)
                VALUES (:dateheure, 'en attente', :idmedecin, :idpatient, :idspecialite)";
        $stmt = db()->prepare($sql);
        $result = $stmt->execute([
            'dateheure' => $dateheure,
            'idmedecin' => $idmedecin,
            'idpatient' => $idpatient,
            'idspecialite' => $idspecialite
        ]);

        if ($result) {
                $_SESSION['success'] = "Votre rendez-vous a été pris avec succès.";
                header('Location: rdv.php');
            exit();
            } else {
                $_SESSION['error'] = "Une erreur est survenue lors de la prise de rendez-vous.";
            }
        } else {
            $_SESSION['error'] = "Veuillez remplir tous les champs requis.";
        }
    } catch (Exception $e) {
        $_SESSION['error'] = "Une erreur est survenue : " . $e->getMessage();
    }
    
    header('Location: rdv.php');
    exit();
}

// Traiter l'ajout d'un rendez-vous
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'])) {
    try {
        if ($_POST['action'] === 'add') {
            // Vérification anti-conflit de créneau
            $stmt = db()->prepare("SELECT COUNT(*) FROM rendezvous WHERE idmedecin = ? AND dateheure = ? AND statut != 'annulé'");
            $stmt->execute([$_POST['id_medecin'], $_POST['date_rdv'] . ' ' . $_POST['heure_rdv']]);
            if ($stmt->fetchColumn() > 0) {
                throw new Exception("Ce créneau est déjà réservé.");
            }
            
            $stmt = db()->prepare("
                INSERT INTO rendezvous (idpatient, idmedecin, dateheure, statut, idspecialite)
                VALUES (?, ?, ?, 'en attente', ?)
            ");
            
            $stmt->execute([
                $user_id,
                $_POST['id_medecin'],
                $_POST['date_rdv'] . ' ' . $_POST['heure_rdv'],
                $_POST['specialite']
            ]);

            $rdv_id = db()->lastInsertId();

            // Si connecté à Google Calendar, ajouter l'événement
            if ($is_google_connected) {
                $calendar = new GoogleCalendar($user_id);
                $event = [
                    'title' => 'Rendez-vous médical',
                    'description' => $_POST['motif'],
                    'start' => $_POST['date_rdv'] . ' ' . $_POST['heure_rdv'],
                    'end' => date('Y-m-d H:i:s', strtotime($_POST['date_rdv'] . ' ' . $_POST['heure_rdv'] . ' +1 hour'))
                ];
                $google_event_id = $calendar->addEvent($event);

                // Stocker l'ID de l'événement Google
                $stmt = db()->prepare("UPDATE rendezvous SET google_event_id = ? WHERE id = ?");
                $stmt->execute([$google_event_id, $rdv_id]);
            }

            $_SESSION['success'] = "Rendez-vous ajouté avec succès.";
        }
    } catch (Exception $e) {
        $_SESSION['error'] = "Erreur lors de l'ajout du rendez-vous : " . $e->getMessage();
    }
    
    header('Location: rdv.php');
    exit;
}

?>

<!DOCTYPE html>
<html lang="fr">
<head>    
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Mes Rendez-vous - MedConnect</title>
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
        .appointment-card {
            transition: all 0.3s ease;
        }
        .appointment-card:hover {
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
                <a href="rdv.php" class="nav-link active block px-4 py-3 rounded-lg text-[#1e40af]">
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
                            <i class="fas fa-calendar-alt text-white text-xl"></i>
                        </div>
                        <h1 class="text-2xl font-bold text-[#1e40af]">Mes Rendez-vous</h1>
                    </div>
                    <div class="text-sm text-[#3b82f6]">
                        <i class="fas fa-calendar-alt mr-2"></i><?php echo date('d/m/Y'); ?>
                    </div>
                </div>
            </header>

            <!-- Contenu principal -->
            <main class="container mx-auto px-4 py-8">
                <?php if (isset($_SESSION['success'])): ?>
                    <div class="bg-green-100 border border-green-400 text-green-700 px-4 py-3 rounded relative mb-4" role="alert">
                        <span class="block sm:inline"><?php echo $_SESSION['success']; ?></span>
                        <button type="button" class="absolute top-0 bottom-0 right-0 px-4 py-3" onclick="this.parentElement.remove()">
                            <i class="fas fa-times"></i>
                        </button>
                    </div>
                    <?php unset($_SESSION['success']); ?>
                <?php endif; ?>

                <?php if (isset($_SESSION['error'])): ?>
                    <div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded relative mb-4" role="alert">
                        <span class="block sm:inline"><?php echo $_SESSION['error']; ?></span>
                        <button type="button" class="absolute top-0 bottom-0 right-0 px-4 py-3" onclick="this.parentElement.remove()">
                            <i class="fas fa-times"></i>
                        </button>
                    </div>
                    <?php unset($_SESSION['error']); ?>
                <?php endif; ?>

                <!-- Statistiques -->
                <div class="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
                    <div class="bg-white rounded-xl shadow-lg p-6 glass-effect">
                        <div class="flex items-center justify-between">
                            <div>
                                <p class="text-sm text-[#3b82f6]">Rendez-vous à venir</p>
                                <h3 class="text-2xl font-bold text-[#1e40af]"><?= count($rdvs_a_venir) ?></h3>
                            </div>
                            <div class="w-12 h-12 rounded-full bg-[#EFF6FF] flex items-center justify-center">
                                <i class="fas fa-calendar-check text-xl text-[#3b82f6]"></i>
                            </div>
                        </div>
                    </div>
                    <div class="bg-white rounded-xl shadow-lg p-6 glass-effect">
                        <div class="flex items-center justify-between">
                            <div>
                                <p class="text-sm text-[#10b981]">Rendez-vous confirmés</p>
                                <h3 class="text-2xl font-bold text-[#1e40af]"><?= count($rdvs_confirmes) ?></h3>
                            </div>
                            <div class="w-12 h-12 rounded-full bg-[#ECFDF5] flex items-center justify-center">
                                <i class="fas fa-check-circle text-xl text-[#10b981]"></i>
                            </div>
                        </div>
                    </div>
                    <div class="bg-white rounded-xl shadow-lg p-6 glass-effect">
                        <div class="flex items-center justify-between">
                            <div>
                                <p class="text-sm text-[#f59e0b]">En attente</p>
                                <h3 class="text-2xl font-bold text-[#1e40af]"><?= count($rdvs_en_attente) ?></h3>
                            </div>
                            <div class="w-12 h-12 rounded-full bg-[#FFFBEB] flex items-center justify-center">
                                <i class="fas fa-clock text-xl text-[#f59e0b]"></i>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Bouton pour afficher/masquer le formulaire -->
                <button onclick="toggleForm()" class="mb-6 bg-[#3b82f6] hover:bg-[#2563eb] text-white px-6 py-3 rounded-lg transition-colors duration-300 flex items-center gap-2">
                    <i class="fas fa-plus"></i>
                    Prendre un rendez-vous
                </button>

                <!-- Formulaire caché par défaut -->
                <div id="formRdv" class="bg-white rounded-xl shadow-lg p-6 mb-8 glass-effect hidden">
                    <form action="" method="POST" class="space-y-6">
                        <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                            <div>
                                <label for="specialite" class="block text-sm font-medium text-[#1e40af] mb-2">Spécialité :</label>
                                <select name="specialite" id="specialite" required class="w-full border border-gray-200 rounded-lg px-4 py-3 focus:outline-none focus:border-[#3b82f6]">
                                    <option value="">-- Choisir une spécialité --</option>
                                    <?php
                                    $specialites = db()->query("SELECT id, nomspecialite FROM specialite")->fetchAll(PDO::FETCH_ASSOC);
                                    foreach ($specialites as $s) {
                                        echo "<option value='{$s['id']}'>{$s['nomspecialite']}</option>";
                                    }
                                    ?>
                                </select>
                            </div>

                            <div>
                                <label for="medecin" class="block text-sm font-medium text-[#1e40af] mb-2">Médecin :</label>
                                <select name="medecin" id="medecin" required class="w-full border border-gray-200 rounded-lg px-4 py-3 focus:outline-none focus:border-[#3b82f6]">
                                    <option value="">-- Sélectionner une spécialité d'abord --</option>
                                </select>
                            </div>

                            <div>
                                <label for="date" class="block text-sm font-medium text-[#1e40af] mb-2">Date :</label>
                                <input type="date" name="date" id="date" required min="<?= date('Y-m-d') ?>" class="w-full border border-gray-200 rounded-lg px-4 py-3 focus:outline-none focus:border-[#3b82f6]">
                            </div>

                            <div>
                                <label for="heure" class="block text-sm font-medium text-[#1e40af] mb-2">Heure :</label>
                                <select name="heure" id="heure" required class="w-full border border-gray-200 rounded-lg px-4 py-3 focus:outline-none focus:border-[#3b82f6]">
                                    <option value="">-- Sélectionner une date d'abord --</option>
                                </select>
                            </div>
                        </div>

                        <div class="flex justify-end">
                            <button type="submit" class="bg-[#10b981] hover:bg-[#059669] text-white px-6 py-3 rounded-lg transition-colors duration-300 flex items-center gap-2">
                                <i class="fas fa-check"></i>
                                Confirmer
                            </button>
                        </div>
                    </form>
                </div>

                <!-- Liste des rendez-vous -->
                <div class="bg-white rounded-xl shadow-lg p-6 glass-effect">
                    <div class="flex justify-between items-center mb-6">
                        <h2 class="text-xl font-semibold text-[#1e40af] flex items-center">
                            <i class="fas fa-calendar-alt mr-2"></i>
                            Mes rendez-vous
                        </h2>
                        <div class="flex gap-4">
                            <div class="relative">
                                <input type="text" 
                                       placeholder="Rechercher..." 
                                       class="search-input border border-gray-200 rounded-lg px-4 py-2 pl-10 focus:outline-none">
                                <i class="fas fa-search absolute left-3 top-1/2 transform -translate-y-1/2 text-[#3b82f6]"></i>
                            </div>
                            <button class="bg-[#3b82f6] hover:bg-[#2563eb] text-white px-4 py-2 rounded-lg transition-colors duration-300 flex items-center gap-2">
                                <i class="fas fa-filter"></i>
                                Filtrer
                            </button>
                        </div>
                    </div>

                    <?php if (count($rendezvous) > 0): ?>
                        <div class="space-y-4">
                            <?php foreach ($rendezvous as $rdv): ?>
                                <div class="p-4 bg-[#F1F8E9] rounded-lg hover:bg-[#E8F5E9]" data-rdv-id="<?= $rdv['id'] ?>">
                                    <div class="flex justify-between items-center">
                                        <div>
                                            <p class="font-medium text-[#1B5E20]">
                                                Dr. <?= htmlspecialchars($rdv['nom_medecin'] . ' ' . $rdv['prenom_medecin']) ?>
                                            </p>
                                            <p class="text-sm text-[#558B2F]">
                                                <?= date('d/m/Y H:i', strtotime($rdv['dateheure'])) ?>
                                            </p>
                                            <?php if ($rdv['nomspecialite']): ?>
                                                <p class="text-sm text-[#558B2F]">
                                                    Spécialité : <?= htmlspecialchars($rdv['nomspecialite']) ?>
                                                </p>
                                            <?php endif; ?>
                                        </div>
                                        <span class="px-3 py-1 rounded-full text-sm status-badge
                                            <?php 
                                            if ($rdv['statut'] === 'confirmé' || $rdv['statut'] === 'accepté') {
                                                echo 'bg-green-200 text-green-800';
                                            } elseif ($rdv['statut'] === 'annulé' || $rdv['statut'] === 'refusé') {
                                                echo 'bg-red-200 text-red-800';
                                            } else {
                                                echo 'bg-yellow-200 text-yellow-800';
                                            }
                                            ?>">
                                            <?= ucfirst($rdv['statut']) ?>
                                        </span>
                                    </div>
                                </div>
                            <?php endforeach; ?>
                        </div>
                    <?php else: ?>
                        <div class="text-center py-8">
                            <div class="w-16 h-16 rounded-full bg-[#FEE2E2] flex items-center justify-center mx-auto mb-4">
                                <i class="fas fa-calendar-times text-[#991B1B] text-2xl"></i>
                            </div>
                            <h3 class="text-xl font-semibold text-[#1e40af] mb-2">Aucun rendez-vous</h3>
                            <p class="text-[#3b82f6]">Prenez votre premier rendez-vous en cliquant sur le bouton ci-dessus</p>
                        </div>
                    <?php endif; ?>
                </div>
            </main>
        </div>
    </div>

    <!-- Script pour la gestion des médecins par spécialité, des créneaux et des annulations -->
    <script>
        // Fonction pour afficher/masquer le formulaire
        function toggleForm() {
            const form = document.getElementById('formRdv');
            form.classList.toggle('hidden');
            
            // Si le formulaire est visible, réinitialiser les champs
            if (!form.classList.contains('hidden')) {
                document.querySelector('select[name="specialite"]').value = '';
                document.querySelector('select[name="medecin"]').innerHTML = '<option value="">Sélectionnez d\'abord une spécialité</option>';
                document.querySelector('select[name="medecin"]').disabled = true;
                document.querySelector('input[name="date"]').value = '';
                document.querySelector('select[name="heure"]').innerHTML = '<option value="">Sélectionnez d\'abord une date</option>';
                document.querySelector('select[name="heure"]').disabled = true;
            }
        }

        document.addEventListener('DOMContentLoaded', function() {
            // Gestion du changement de spécialité
            document.querySelector('select[name="specialite"]').addEventListener('change', function() {
                const specialiteId = this.value;
                const medecinSelect = document.querySelector('select[name="medecin"]');

                if (specialiteId) {
                    medecinSelect.innerHTML = '<option value="">Chargement...</option>';
                    medecinSelect.disabled = true;
                    
                    // Appel AJAX pour récupérer les médecins
                    fetch(`../../get_medecins.php?specialite_id=${specialiteId}`, {
                        headers: {
                            'Accept': 'application/json'
                        }
                    })
                        .then(response => {
                            if (!response.ok) {
                                throw new Error(`HTTP error! status: ${response.status}`);
                            }
                            // Afficher la réponse brute pour le débogage
                            return response.text().then(text => {
                                console.log('Réponse brute:', text);
                                try {
                                    return JSON.parse(text);
                                } catch (e) {
                                    console.error('Erreur de parsing JSON:', e);
                                    throw new Error('Réponse invalide du serveur');
                                }
                            });
                        })
                        .then(medecins => {
                            console.log('Médecins reçus:', medecins);
                            medecinSelect.disabled = false;
                            
                            if (Array.isArray(medecins) && medecins.length > 0) {
                                let options = '<option value="">Sélectionnez un médecin</option>';
                                medecins.forEach(medecin => {
                                    options += `<option value="${medecin.id}">Dr. ${medecin.prenom} ${medecin.nom} - ${medecin.nomspecialite}</option>`;
                                });
                                medecinSelect.innerHTML = options;
                            } else {
                                medecinSelect.innerHTML = '<option value="">Aucun médecin disponible</option>';
                            }
                        })
                        .catch(error => {
                            console.error('Erreur:', error);
                            medecinSelect.disabled = false;
                            medecinSelect.innerHTML = '<option value="">Erreur lors du chargement</option>';
                            // Afficher un message d'erreur à l'utilisateur
                            alert('Une erreur est survenue lors du chargement des médecins. Veuillez réessayer.');
                        });
                } else {
                    medecinSelect.innerHTML = '<option value="">Sélectionnez d\'abord une spécialité</option>';
                    medecinSelect.disabled = true;
                }
            });
        });

        // Gestion du changement de date
        function checkDisponibilites() {
            const medecinId = document.querySelector('select[name="medecin"]').value;
            const date = document.querySelector('input[name="date"]').value;
            const heureSelect = document.querySelector('select[name="heure"]');

            if (medecinId && date) {
                heureSelect.innerHTML = '<option value="">Chargement...</option>';
                heureSelect.disabled = true;
                
                // Appel AJAX pour récupérer les créneaux disponibles
                fetch(`../../check_disponibilite.php?medecin_id=${medecinId}&date=${date}`, {
                    headers: {
                        'Accept': 'application/json'
                    }
                })
                    .then(response => {
                        if (!response.ok) {
                            throw new Error(`HTTP error! status: ${response.status}`);
                        }
                        // Afficher la réponse brute pour le débogage
                        return response.text().then(text => {
                            console.log('Réponse brute des créneaux:', text);
                            try {
                                return JSON.parse(text);
                            } catch (e) {
                                console.error('Erreur de parsing JSON:', e);
                                throw new Error('Réponse invalide du serveur');
                            }
                        });
                    })
                    .then(creneaux => {
                        heureSelect.disabled = false;
                        if (Array.isArray(creneaux) && creneaux.length > 0) {
                            let options = '<option value="">Sélectionnez une heure</option>';
                            creneaux.forEach(creneau => {
                                options += `<option value="${creneau}">${creneau}</option>`;
                            });
                            heureSelect.innerHTML = options;
                        } else {
                            heureSelect.innerHTML = '<option value="">Aucun créneau disponible</option>';
                        }
                    })
                    .catch(error => {
                        console.error('Erreur:', error);
                        heureSelect.disabled = false;
                        heureSelect.innerHTML = '<option value="">Erreur lors du chargement</option>';
                        alert('Une erreur est survenue lors du chargement des créneaux. Veuillez réessayer.');
                    });
            } else {
                heureSelect.innerHTML = '<option value="">Sélectionnez d\'abord un médecin et une date</option>';
                heureSelect.disabled = true;
            }
        }

        // Écouter les changements de médecin et de date
        document.querySelector('select[name="medecin"]').addEventListener('change', checkDisponibilites);
        document.querySelector('input[name="date"]').addEventListener('change', checkDisponibilites);

        // Fonction pour vérifier les mises à jour des statuts
        function checkStatusUpdates() {
            const rdvCards = document.querySelectorAll('[data-rdv-id]');
            const rdvIds = Array.from(rdvCards).map(card => card.dataset.rdvId);

            if (rdvIds.length > 0) {
                fetch('check_rdv_status.php', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Accept': 'application/json'
                    },
                    body: JSON.stringify({ rdv_ids: rdvIds })
                })
                .then(response => {
                    if (!response.ok) {
                        throw new Error(`HTTP error! status: ${response.status}`);
                    }
                    return response.text().then(text => {
                        try {
                            return JSON.parse(text);
                        } catch (e) {
                            console.error('Réponse invalide:', text);
                            throw new Error('Réponse invalide du serveur');
                        }
                    });
                })
                .then(data => {
                    if (data.success && data.rendezvous) {
                        data.rendezvous.forEach(rdv => {
                            const card = document.querySelector(`[data-rdv-id="${rdv.id}"]`);
                            if (card) {
                                const statusBadge = card.querySelector('.status-badge');
                                if (statusBadge) {
                                    // Normaliser le statut pour la comparaison
                                    const normalize = s => (s || '').toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '').trim();
                                    const newStatus = normalize(rdv.statut);
                                    let displayStatus = '';
                                    if (["confirme", "confirmé", "accepte", "accepté"].includes(newStatus)) {
                                        displayStatus = 'Confirmé';
                                    } else if (["annule", "annulé", "refuse", "refusé"].includes(newStatus)) {
                                        displayStatus = 'Annulé';
                                    } else if (["en attente", "enattente"].includes(newStatus.replace(/ /g, ''))) {
                                        displayStatus = 'En attente';
                                    } else {
                                        displayStatus = 'Statut inconnu';
                                    }
                                    console.log('Statut reçu:', rdv.statut, '->', displayStatus);
                                    statusBadge.textContent = displayStatus;
                                    if (["confirme", "confirmé", "accepte", "accepté"].includes(newStatus)) {
                                        statusBadge.className = 'px-3 py-1 rounded-full text-sm status-badge bg-green-200 text-green-800';
                                    } else if (["annule", "annulé", "refuse", "refusé"].includes(newStatus)) {
                                        statusBadge.className = 'px-3 py-1 rounded-full text-sm status-badge bg-red-200 text-red-800';
                                    } else {
                                        statusBadge.className = 'px-3 py-1 rounded-full text-sm status-badge bg-yellow-200 text-yellow-800';
                                    }
                                }
                            }
                        });
                    }
                })
                .catch(error => {
                    console.error('Erreur lors de la vérification des statuts:', error);
                });
            }
        }

        // Vérifier les mises à jour toutes les 3 secondes
        setInterval(checkStatusUpdates, 3000);

        // Vérifier les mises à jour au chargement de la page
        document.addEventListener('DOMContentLoaded', checkStatusUpdates);
    </script>
</body>
</html>
