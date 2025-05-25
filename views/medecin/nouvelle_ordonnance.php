<?php
require_once '../../includes/session.php';
require_once '../../config/config.php';

// Vérifier si l'utilisateur est connecté et est un médecin
requireLogin();
requireRole('medecin');

$user_id = $_SESSION['user_id'];

// Traitement du formulaire
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    try {
        // Validation des données requises
        if (empty($_POST['idpatient'])) {
            throw new Exception("Veuillez sélectionner un patient.");
        }
        if (empty($_POST['date_validite'])) {
            throw new Exception("La date de validité est requise.");
        }
        if (empty($_POST['medicaments_data'])) {
            throw new Exception("Veuillez ajouter au moins un médicament.");
        }
        if (empty($_POST['duree_traitement'])) {
            throw new Exception("La durée du traitement est requise.");
        }

        // Validation de la date de validité
        $date_validite = new DateTime($_POST['date_validite']);
        $today = new DateTime();
        if ($date_validite < $today) {
            throw new Exception("La date de validité ne peut pas être dans le passé.");
        }

        // Récupérer et valider les données des médicaments
        $medicaments_data = json_decode($_POST['medicaments_data'], true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new Exception("Format de données des médicaments invalide.");
        }

        if (empty($medicaments_data)) {
            throw new Exception("Veuillez ajouter au moins un médicament.");
        }

        $medicaments = [];
        $posologie = [];
        $quantites = [];
        $durees = [];

        foreach ($medicaments_data as $med) {
            if (empty($med['medicament']) || empty($med['posologie'])) {
                throw new Exception("Tous les champs des médicaments doivent être remplis.");
            }
            $medicaments[] = trim($med['medicament']);
            $posologie[] = trim($med['posologie']);
            $quantites[] = trim($med['quantite'] ?? '');
            $durees[] = trim($med['duree'] ?? '');
        }

        $stmt = db()->prepare("
            INSERT INTO ordonnance (
                idmedecin, idpatient, date_validite, medicaments, 
                posologie, quantite, duree_medicament, duree_traitement, 
                instructions, renouvellement, nombre_renouvellements
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ");

        $renouvellement = isset($_POST['renouvellement']) ? 1 : 0;
        $nombre_renouvellements = isset($_POST['renouvellement']) ? intval($_POST['nombre_renouvellements']) : 0;

        $stmt->execute([
            $user_id,
            $_POST['idpatient'],
            $_POST['date_validite'],
            implode("\n", $medicaments),
            implode("\n", $posologie),
            implode("\n", $quantites),
            implode("\n", $durees),
            trim($_POST['duree_traitement']),
            trim($_POST['instructions'] ?? ''),
            $renouvellement,
            $nombre_renouvellements
        ]);

        $success = "L'ordonnance a été créée avec succès.";
    } catch (Exception $e) {
        $error = $e->getMessage();
        error_log("Erreur lors de la création de l'ordonnance : " . $e->getMessage());
    } catch (PDOException $e) {
        $error = "Une erreur est survenue lors de la création de l'ordonnance.";
        error_log("Erreur PDO lors de la création de l'ordonnance : " . $e->getMessage());
    }
}

// Récupérer la liste des patients
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
?>

<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Nouvelle Ordonnance - MedConnect</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <?php include_once '../../views/components/styles.php'; ?>
    <style>
        .form-input {
            transition: all 0.3s ease;
        }
        .form-input:focus {
            box-shadow: 0 0 0 2px rgba(46, 125, 50, 0.2);
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
                        <h1 class="text-2xl font-bold text-[#1B5E20]">Nouvelle Ordonnance</h1>
                    </div>
                    <a href="ordonnances.php" class="btn-secondary">
                        <i class="fas fa-arrow-left mr-2"></i>Retour aux ordonnances
                    </a>
                </div>
            </header>

            <!-- Contenu principal -->
            <main class="container mx-auto px-4 py-8">
                <?php if (isset($success)): ?>
                    <div class="bg-green-100 border-l-4 border-[#2E7D32] text-[#1B5E20] p-4 mb-4 rounded-r-lg">
                        <i class="fas fa-check-circle mr-2"></i><?php echo $success; ?>
                    </div>
                <?php endif; ?>

                <?php if (isset($error)): ?>
                    <div class="bg-red-100 border-l-4 border-red-500 text-red-700 p-4 mb-4 rounded-r-lg">
                        <i class="fas fa-exclamation-circle mr-2"></i><?php echo $error; ?>
                    </div>
                <?php endif; ?>

                <div class="bg-white rounded-xl shadow-lg p-6 glass-effect">
                    <form method="POST" class="space-y-6">
                        <!-- Sélection du patient -->
                        <div>
                            <label for="idpatient" class="block text-sm font-medium text-[#1B5E20] mb-2">
                                Patient
                            </label>
                            <div class="relative">
                                <input type="text" 
                                       id="searchPatient" 
                                       class="form-input w-full px-4 py-2 rounded-lg border border-gray-300 focus:outline-none focus:border-[#2E7D32]"
                                       placeholder="Rechercher un patient..."
                                       autocomplete="off">
                                <div id="patientResults" class="absolute z-10 w-full mt-1 bg-white rounded-lg shadow-lg hidden">
                                    <!-- Les résultats de recherche seront affichés ici -->
                                </div>
                            </div>
                            <input type="hidden" name="idpatient" id="idpatient" required>
                            <div id="selectedPatient" class="mt-2 p-3 bg-[#E8F5E9] rounded-lg hidden">
                                <div class="flex items-center justify-between">
                                    <div class="flex items-center">
                                        <div class="w-10 h-10 rounded-full bg-gradient-to-br from-[#2E7D32] to-[#81C784] flex items-center justify-center">
                                            <i class="fas fa-user text-white"></i>
                                        </div>
                                        <div class="ml-3">
                                            <p class="text-sm font-medium text-[#1B5E20]" id="selectedPatientName"></p>
                                        </div>
                                    </div>
                                    <button type="button" onclick="clearPatientSelection()" class="text-[#2E7D32] hover:text-[#1B5E20]">
                                        <i class="fas fa-times"></i>
                                    </button>
                                </div>
                            </div>
                        </div>

                        <!-- Date de validité -->
                        <div>
                            <label for="date_validite" class="block text-sm font-medium text-[#1B5E20] mb-2">
                                Date de validité
                            </label>
                            <input type="date" name="date_validite" id="date_validite" required
                                   min="<?php echo date('Y-m-d'); ?>"
                                   class="form-input w-full px-4 py-2 rounded-lg border border-gray-300 focus:outline-none focus:border-[#2E7D32]">
                        </div>

                        <!-- Médicaments et Posologie -->
                        <div>
                            <div class="flex justify-between items-center mb-4">
                                <label class="block text-sm font-medium text-[#1B5E20]">
                                    Médicaments et Posologie
                                </label>
                                <button type="button" id="ajouterMedicament" class="btn-secondary text-sm">
                                    <i class="fas fa-plus mr-2"></i>Ajouter un médicament
                                </button>
                            </div>
                            <div class="overflow-x-auto">
                                <table class="min-w-full bg-white rounded-lg overflow-hidden">
                                    <thead class="bg-[#E8F5E9]">
                                        <tr>
                                            <th class="px-4 py-2 text-left text-sm font-medium text-[#1B5E20]">Médicament</th>
                                            <th class="px-4 py-2 text-left text-sm font-medium text-[#1B5E20]">Posologie</th>
                                            <th class="px-4 py-2 text-left text-sm font-medium text-[#1B5E20]">Quantité</th>
                                            <th class="px-4 py-2 text-left text-sm font-medium text-[#1B5E20]">Durée</th>
                                            <th class="px-4 py-2 text-center text-sm font-medium text-[#1B5E20]">Actions</th>
                                        </tr>
                                    </thead>
                                    <tbody id="medicamentsTableBody">
                                        <!-- Les lignes seront ajoutées dynamiquement ici -->
                                    </tbody>
                                </table>
                            </div>
                            <input type="hidden" name="medicaments_data" id="medicamentsData">
                        </div>

                        <!-- Durée du traitement -->
                        <div>
                            <label for="duree_traitement" class="block text-sm font-medium text-[#1B5E20] mb-2">
                                Durée du traitement
                            </label>
                            <input type="text" name="duree_traitement" id="duree_traitement" required
                                   class="form-input w-full px-4 py-2 rounded-lg border border-gray-300 focus:outline-none focus:border-[#2E7D32]"
                                   placeholder="Ex: 7 jours, 1 mois, etc.">
                        </div>

                        <!-- Instructions supplémentaires -->
                        <div>
                            <label for="instructions" class="block text-sm font-medium text-[#1B5E20] mb-2">
                                Instructions supplémentaires
                            </label>
                            <textarea name="instructions" id="instructions" rows="3"
                                      class="form-input w-full px-4 py-2 rounded-lg border border-gray-300 focus:outline-none focus:border-[#2E7D32]"
                                      placeholder="Instructions particulières ou recommandations"></textarea>
                        </div>

                        <!-- Renouvellement -->
                        <div class="flex items-center space-x-4">
                            <div class="flex items-center">
                                <input type="checkbox" name="renouvellement" id="renouvellement"
                                       class="form-checkbox h-5 w-5 text-[#2E7D32] rounded border-gray-300 focus:ring-[#2E7D32]">
                                <label for="renouvellement" class="ml-2 text-sm font-medium text-[#1B5E20]">
                                    Renouvellement possible
                                </label>
                            </div>
                            <div class="flex-1">
                                <label for="nombre_renouvellements" class="block text-sm font-medium text-[#1B5E20] mb-2">
                                    Nombre de renouvellements
                                </label>
                                <input type="number" name="nombre_renouvellements" id="nombre_renouvellements"
                                       min="0" max="12" value="0"
                                       class="form-input w-full px-4 py-2 rounded-lg border border-gray-300 focus:outline-none focus:border-[#2E7D32]">
                            </div>
                        </div>

                        <!-- Boutons d'action -->
                        <div class="flex justify-end space-x-4">
                            <a href="ordonnances.php" class="btn-secondary">
                                <i class="fas fa-times mr-2"></i>Annuler
                            </a>
                            <button type="submit" class="btn-primary">
                                <i class="fas fa-save mr-2"></i>Enregistrer l'ordonnance
                            </button>
                        </div>
                    </form>
                </div>
            </main>
        </div>
    </div>

    <script>
        // Gestion de la recherche de patients
        const searchPatientInput = document.getElementById('searchPatient');
        const patientResults = document.getElementById('patientResults');
        const selectedPatient = document.getElementById('selectedPatient');
        const selectedPatientName = document.getElementById('selectedPatientName');
        const idpatientInput = document.getElementById('idpatient');

        // Liste des patients (sera remplie par PHP)
        const patients = <?php echo json_encode($patients); ?>;

        searchPatientInput.addEventListener('input', function() {
            const searchTerm = this.value.toLowerCase();
            if (searchTerm.length < 2) {
                patientResults.classList.add('hidden');
                return;
            }

            const filteredPatients = patients.filter(patient => 
                patient.nom.toLowerCase().includes(searchTerm) || 
                patient.prenom.toLowerCase().includes(searchTerm)
            );

            if (filteredPatients.length > 0) {
                patientResults.innerHTML = filteredPatients.map(patient => `
                    <div class="p-2 hover:bg-[#E8F5E9] cursor-pointer" 
                         onclick="selectPatient(${patient.id}, '${patient.prenom} ${patient.nom}')">
                        ${patient.prenom} ${patient.nom}
                    </div>
                `).join('');
                patientResults.classList.remove('hidden');
            } else {
                patientResults.classList.add('hidden');
            }
        });

        function selectPatient(id, name) {
            idpatientInput.value = id;
            selectedPatientName.textContent = name;
            selectedPatient.classList.remove('hidden');
            searchPatientInput.value = '';
            patientResults.classList.add('hidden');
        }

        function clearPatientSelection() {
            idpatientInput.value = '';
            selectedPatientName.textContent = '';
            selectedPatient.classList.add('hidden');
        }

        // Fermer les résultats si on clique en dehors
        document.addEventListener('click', function(e) {
            if (!searchPatientInput.contains(e.target) && !patientResults.contains(e.target)) {
                patientResults.classList.add('hidden');
            }
        });

        // Gestion du renouvellement
        const renouvellementCheckbox = document.getElementById('renouvellement');
        const nombreRenouvellementsInput = document.getElementById('nombre_renouvellements');

        renouvellementCheckbox.addEventListener('change', function() {
            nombreRenouvellementsInput.disabled = !this.checked;
            if (!this.checked) {
                nombreRenouvellementsInput.value = '0';
            }
        });

        // Désactiver le champ nombre de renouvellements par défaut
        nombreRenouvellementsInput.disabled = !renouvellementCheckbox.checked;

        // Gestion du tableau des médicaments
        const medicamentsTableBody = document.getElementById('medicamentsTableBody');
        const ajouterMedicamentBtn = document.getElementById('ajouterMedicament');
        const medicamentsData = document.getElementById('medicamentsData');
        let medicaments = [];

        function ajouterLigneMedicament() {
            const ligne = document.createElement('tr');
            ligne.className = 'border-b border-gray-200 hover:bg-[#F1F8E9]';
            
            const medicamentCell = document.createElement('td');
            medicamentCell.className = 'px-4 py-2';
            medicamentCell.innerHTML = `
                <input type="text" class="form-input w-full px-2 py-1 rounded border border-gray-300 focus:outline-none focus:border-[#2E7D32]" 
                       placeholder="Nom du médicament" required>
            `;

            const posologieCell = document.createElement('td');
            posologieCell.className = 'px-4 py-2';
            posologieCell.innerHTML = `
                <input type="text" class="form-input w-full px-2 py-1 rounded border border-gray-300 focus:outline-none focus:border-[#2E7D32]" 
                       placeholder="Ex: 1 comprimé matin et soir" required>
            `;

            const quantiteCell = document.createElement('td');
            quantiteCell.className = 'px-4 py-2';
            quantiteCell.innerHTML = `
                <input type="text" class="form-input w-full px-2 py-1 rounded border border-gray-300 focus:outline-none focus:border-[#2E7D32]" 
                       placeholder="Ex: 30 comprimés" required>
            `;

            const dureeCell = document.createElement('td');
            dureeCell.className = 'px-4 py-2';
            dureeCell.innerHTML = `
                <input type="text" class="form-input w-full px-2 py-1 rounded border border-gray-300 focus:outline-none focus:border-[#2E7D32]" 
                       placeholder="Ex: 15 jours" required>
            `;

            const actionsCell = document.createElement('td');
            actionsCell.className = 'px-4 py-2 text-center';
            actionsCell.innerHTML = `
                <button type="button" class="text-red-500 hover:text-red-700" onclick="supprimerLigne(this)">
                    <i class="fas fa-trash"></i>
                </button>
            `;

            ligne.appendChild(medicamentCell);
            ligne.appendChild(posologieCell);
            ligne.appendChild(quantiteCell);
            ligne.appendChild(dureeCell);
            ligne.appendChild(actionsCell);

            medicamentsTableBody.appendChild(ligne);
            mettreAJourMedicamentsData();
        }

        function supprimerLigne(button) {
            const ligne = button.closest('tr');
            ligne.remove();
            mettreAJourMedicamentsData();
        }

        function mettreAJourMedicamentsData() {
            const lignes = medicamentsTableBody.getElementsByTagName('tr');
            medicaments = [];

            for (let ligne of lignes) {
                const inputs = ligne.getElementsByTagName('input');
                if (inputs.length >= 4) {  // Vérifier qu'il y a bien 4 inputs
                    medicaments.push({
                        medicament: inputs[0].value.trim(),
                        posologie: inputs[1].value.trim(),
                        quantite: inputs[2].value.trim(),
                        duree: inputs[3].value.trim()
                    });
                }
            }

            medicamentsData.value = JSON.stringify(medicaments);
            console.log('Médicaments mis à jour:', medicaments); // Pour le débogage
        }

        // Ajouter un événement pour mettre à jour les données à chaque modification
        medicamentsTableBody.addEventListener('input', mettreAJourMedicamentsData);

        // Ajouter une ligne initiale
        ajouterMedicamentBtn.addEventListener('click', ajouterLigneMedicament);
        ajouterLigneMedicament(); // Ajouter une première ligne par défaut

        // Validation du formulaire
        document.querySelector('form').addEventListener('submit', function(e) {
            e.preventDefault(); // Empêcher la soumission par défaut

            if (medicaments.length === 0) {
                alert('Veuillez ajouter au moins un médicament.');
                return;
            }

            // Vérifier que tous les champs sont remplis
            const inputs = medicamentsTableBody.getElementsByTagName('input');
            for (let input of inputs) {
                if (!input.value.trim()) {
                    alert('Veuillez remplir tous les champs des médicaments.');
                    return;
                }
            }

            // Si tout est valide, soumettre le formulaire
            mettreAJourMedicamentsData(); // Mettre à jour une dernière fois
            this.submit();
        });
    </script>
</body>
</html> 