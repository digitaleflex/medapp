<?php
require_once '../../includes/session.php';
require_once '../../config/database.php';

// Vérifier si l'utilisateur est connecté
requireLogin();

// Vérifier si l'utilisateur a le rôle requis
requireRole('medecin');

// Initialiser les messages flash
if (!isset($_SESSION['flash_message'])) {
    $_SESSION['flash_message'] = [];
}

// Initialiser la connexion à la base de données
$database = new Database();
$db = $database->getConnection();

// Récupérer les informations du médecin
$query = "SELECT prenom, nom FROM medecin WHERE id = :medecin_id";
$stmt = $db->prepare($query);
$stmt->bindParam(':medecin_id', $_SESSION['user_id']);
$stmt->execute();
$medecin = $stmt->fetch(PDO::FETCH_ASSOC);
$prenom = $medecin['prenom'];
$nom = $medecin['nom'];

// Gestion de la mise à jour du statut
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['update_status'])) {
    try {
        // Vérification CSRF
        if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
            throw new Exception("Erreur de sécurité: Token CSRF invalide");
        }

        // Validation des entrées
        $rdv_id = filter_input(INPUT_POST, 'rdv_id', FILTER_VALIDATE_INT);
        error_log('Statut reçu en POST : ' . var_export($_POST['statut'], true));
        $statut = filter_input(INPUT_POST, 'statut', FILTER_SANITIZE_STRING);
        error_log('Statut après filter_input : ' . var_export($statut, true));
        $statuts_valides = ['en attente', 'confirmé', 'annulé', 'accepté', 'refusé'];
        if (!$statut || !in_array($statut, $statuts_valides)) {
            error_log('Statut vide ou invalide, mise à jour annulée.');
            if (!empty($_SERVER['HTTP_X_REQUESTED_WITH']) && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) == 'xmlhttprequest') {
                header('Content-Type: application/json');
                echo json_encode([
                    'success' => false,
                    'message' => 'Statut de rendez-vous invalide ou vide.'
                ]);
                exit;
            } else {
                $_SESSION['flash_message'] = [
                    'type' => 'error',
                    'message' => 'Statut de rendez-vous invalide ou vide.'
                ];
                header('Location: rdv.php');
                exit;
            }
        }

        if (!$rdv_id || !$statut) {
            throw new Exception("Données du formulaire invalides");
        }

        // Vérifier que le statut est valide
        $allowed_statuses = ['en attente', 'confirmé'];
        if (!in_array($statut, $allowed_statuses)) {
            throw new Exception("Statut invalide");
        }

        // Démarrer une transaction
        $db->beginTransaction();

        // Vérifier que le médecin peut modifier ce rendez-vous
        $query = "SELECT id, idpatient FROM rendezvous WHERE id = :id AND idmedecin = :medecin_id";
        $stmt = $db->prepare($query);
        $stmt->bindParam(':id', $rdv_id, PDO::PARAM_INT);
        $stmt->bindParam(':medecin_id', $_SESSION['user_id'], PDO::PARAM_INT);
        $stmt->execute();
        $rendezvous = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$rendezvous) {
            throw new Exception("Vous n'êtes pas autorisé à modifier ce rendez-vous");
        }

        // Mettre à jour le statut
        $updateQuery = "UPDATE rendezvous SET statut = :statut WHERE id = :id";
        $updateStmt = $db->prepare($updateQuery);
        $updateStmt->bindParam(':statut', $statut, PDO::PARAM_STR);
        $updateStmt->bindParam(':id', $rdv_id, PDO::PARAM_INT);

        if (!$updateStmt->execute()) {
            throw new Exception("Échec de la mise à jour du rendez-vous");
        }

        // Si le rendez-vous est confirmé, mettre à jour le médecin du patient
        if ($statut === 'confirmé') {
            $updatePatientQuery = "UPDATE patient SET id_medecin = :medecin_id WHERE id = :patient_id";
            $updatePatientStmt = $db->prepare($updatePatientQuery);
            $updatePatientStmt->bindParam(':medecin_id', $_SESSION['user_id'], PDO::PARAM_INT);
            $updatePatientStmt->bindParam(':patient_id', $rendezvous['idpatient'], PDO::PARAM_INT);
            
            if (!$updatePatientStmt->execute()) {
                throw new Exception("Échec de la mise à jour du médecin du patient");
            }
        }

        // Valider la transaction
        $db->commit();

        // Vérifier si la requête est AJAX
        if (!empty($_SERVER['HTTP_X_REQUESTED_WITH']) && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) == 'xmlhttprequest') {
            header('Content-Type: application/json');
            echo json_encode(['success' => true, 'message' => 'Le statut du rendez-vous a été mis à jour avec succès']);
            exit;
        }

        $_SESSION['flash_message'] = [
            'type' => 'success',
            'message' => 'Le statut du rendez-vous a été mis à jour avec succès'
        ];

    } catch (Exception $e) {
        // Annuler la transaction en cas d'erreur
        if ($db->inTransaction()) {
            $db->rollBack();
        }

        // Vérifier si la requête est AJAX
        if (!empty($_SERVER['HTTP_X_REQUESTED_WITH']) && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) == 'xmlhttprequest') {
            header('Content-Type: application/json');
            echo json_encode(['success' => false, 'message' => $e->getMessage()]);
            exit;
        }

        $_SESSION['flash_message'] = [
            'type' => 'error',
            'message' => $e->getMessage()
        ];
        error_log("Erreur rdv.php: " . $e->getMessage());
    }

    if (empty($_SERVER['HTTP_X_REQUESTED_WITH']) || strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) != 'xmlhttprequest') {
        header('Location: rdv.php');
        exit;
    }
}

// Récupérer les rendez-vous du médecin
$query = "SELECT r.*, p.nom as patient_nom, p.prenom as patient_prenom 
          FROM rendezvous r 
          JOIN patient p ON r.idpatient = p.id 
          WHERE r.idmedecin = :medecin_id 
          ORDER BY r.dateheure ASC";
$stmt = $db->prepare($query);
$stmt->bindParam(':medecin_id', $_SESSION['user_id']);
$stmt->execute();
$rendezvous = $stmt->fetchAll(PDO::FETCH_ASSOC);

// Générer un token CSRF s'il n'existe pas
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Gestion globale des erreurs et des accès refusés pour AJAX
function send_json_error($message) {
    header('Content-Type: application/json');
    echo json_encode([
        'success' => false,
        'message' => $message
    ]);
    exit;
}

// Vérifier l'authentification et le rôle
if (!isset($_SESSION['user_id']) || $_SESSION['role'] !== 'medecin') {
    if (!empty($_SERVER['HTTP_X_REQUESTED_WITH']) && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) == 'xmlhttprequest') {
        send_json_error('Accès refusé ou session expirée.');
    } else {
        header('Location: ../../login.php');
        exit;
    }
}
?>

<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Agenda Médecin</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <?php include_once '../../views/components/styles.php'; ?>
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
                <a href="rdv.php" class="nav-link active block px-4 py-3 rounded-lg text-[#1B5E20]">
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

            <main class="container mx-auto px-4 py-8">
                <!-- Afficher les messages flash -->
                <?php if (!empty($_SESSION['flash_message'])): ?>
                    <div class="mb-4 p-4 rounded <?= $_SESSION['flash_message']['type'] === 'success' ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800' ?>">
                        <?= htmlspecialchars($_SESSION['flash_message']['message']) ?>
                    </div>
                    <?php unset($_SESSION['flash_message']); ?>
                <?php endif; ?>

                <div class="bg-white rounded-xl shadow-lg p-6">
                    <h2 class="text-xl font-semibold text-[#1B5E20] mb-6">
                        <i class="fas fa-calendar-alt mr-2"></i>Mon Agenda
                    </h2>

                    <?php if (empty($rendezvous)): ?>
                        <p class="text-[#558B2F]">Aucun rendez-vous pour le moment.</p>
                    <?php else: ?>
                        <div class="space-y-4">
                            <?php foreach ($rendezvous as $rdv): ?>
                                <div class="p-4 bg-[#F1F8E9] rounded-lg hover:bg-[#E8F5E9]">
                                    <div class="flex justify-between items-center">
                                        <div>
                                            <p class="font-medium text-[#1B5E20]">
                                                <?= htmlspecialchars($rdv['patient_nom'] . ' ' . $rdv['patient_prenom']) ?>
                                            </p>
                                            <p class="text-sm text-[#558B2F]">
                                                <?= date('d/m/Y H:i', strtotime($rdv['dateheure'])) ?>
                                            </p>
                                        </div>
                                        <span class="px-3 py-1 rounded-full text-sm status-badge <?= 
                                            $rdv['statut'] === 'confirmé' ? 'bg-green-200 text-green-800' : 'bg-yellow-200 text-yellow-800'
                                        ?>">
                                            <?= ucfirst($rdv['statut']) ?>
                                        </span>
                                    </div>
                                    
                                    <form method="post" action="rdv.php" class="mt-4" id="form-<?= $rdv['id'] ?>">
                                        <input type="hidden" name="csrf_token" value="<?= $_SESSION['csrf_token'] ?>">
                                        <input type="hidden" name="rdv_id" value="<?= $rdv['id'] ?>">
                                        <input type="hidden" name="update_status" value="1">
                                        
                                        <div class="flex items-center space-x-2">
                                            <select name="statut" class="p-2 border rounded">
                                                <option value="en attente" <?= $rdv['statut'] === 'en attente' ? 'selected' : '' ?>>En attente</option>
                                                <option value="confirmé" <?= $rdv['statut'] === 'confirmé' ? 'selected' : '' ?>>Confirmé</option>
                                                <option value="annulé" <?= $rdv['statut'] === 'annulé' ? 'selected' : '' ?>>Annulé</option>
                                            </select>
                                            
                                            <button type="button" onclick="updateStatus(<?= $rdv['id'] ?>)" class="bg-[#2E7D32] text-white px-4 py-2 rounded hover:bg-[#1B5E20] transition-colors duration-300">
                                                Mettre à jour
                                            </button>
                                        </div>
                                    </form>
                                </div>
                            <?php endforeach; ?>
                        </div>
                    <?php endif; ?>
                </div>
            </main>
        </div>
    </div>
</body>
<script>
function updateStatus(rdvId) {
    const form = document.getElementById(`form-${rdvId}`);
    const formData = new FormData(form);
    const select = form.querySelector('select[name="statut"]');
    const newStatus = select.value;

    // Mettre à jour visuellement le statut immédiatement
    const statusSpan = form.closest('.p-4').querySelector('.status-badge');
    statusSpan.className = `px-3 py-1 rounded-full text-sm status-badge ${
        newStatus === 'confirmé' ? 'bg-green-200 text-green-800' : 'bg-yellow-200 text-yellow-800'
    }`;
    statusSpan.textContent = newStatus.charAt(0).toUpperCase() + newStatus.slice(1);

    // Désactiver le bouton pendant la mise à jour
    const button = form.querySelector('button');
    const originalText = button.textContent;
    button.disabled = true;
    button.textContent = 'Mise à jour...';

    // Envoyer la requête AJAX
    fetch('rdv.php', {
        method: 'POST',
        body: formData
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            // Afficher un message de succès temporaire
            const successMessage = document.createElement('div');
            successMessage.className = 'fixed top-4 right-4 bg-green-100 text-green-800 px-4 py-2 rounded shadow-lg';
            successMessage.textContent = 'Statut mis à jour avec succès';
            document.body.appendChild(successMessage);
            
            // Supprimer le message après 3 secondes
            setTimeout(() => {
                successMessage.remove();
            }, 3000);
        } else {
            // En cas d'erreur, restaurer l'ancien statut
            const select = form.querySelector('select');
            select.value = select.getAttribute('data-old-value');
            
            // Afficher un message d'erreur
            const errorMessage = document.createElement('div');
            errorMessage.className = 'fixed top-4 right-4 bg-red-100 text-red-800 px-4 py-2 rounded shadow-lg';
            errorMessage.textContent = data.message || 'Erreur lors de la mise à jour du statut';
            document.body.appendChild(errorMessage);
            
            // Supprimer le message après 3 secondes
            setTimeout(() => {
                errorMessage.remove();
            }, 3000);
        }
    })
    .catch(error => {
        console.error('Erreur:', error);
        // Restaurer l'ancien statut en cas d'erreur
        const select = form.querySelector('select');
        select.value = select.getAttribute('data-old-value');
    })
    .finally(() => {
        // Réactiver le bouton
        button.disabled = false;
        button.textContent = originalText;
    });
}

// Stocker l'ancienne valeur du select avant le changement
document.querySelectorAll('select[name="statut"]').forEach(select => {
    select.addEventListener('focus', function() {
        this.setAttribute('data-old-value', this.value);
    });
});
</script>
</html> 