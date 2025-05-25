<?php
require_once '../../includes/session.php';
require_once '../../config/config.php';

requireLogin();
requireRole('medecin');

$user_id = $_SESSION['user_id'];

// Vérifier la présence de l'ID de l'ordonnance
if (!isset($_GET['id']) || !is_numeric($_GET['id'])) {
    header('Location: ordonnances.php');
    exit;
}
$ordonnance_id = intval($_GET['id']);

// Charger l'ordonnance
try {
    $stmt = db()->prepare('
        SELECT o.*, p.nom as patient_nom, p.prenom as patient_prenom, p.email as patient_email, p.contact as patient_contact
        FROM ordonnance o
        JOIN patient p ON o.idpatient = p.id
        WHERE o.id = ? AND o.idmedecin = ?
    ');
    $stmt->execute([$ordonnance_id, $user_id]);
    $ordonnance = $stmt->fetch(PDO::FETCH_ASSOC);
    if (!$ordonnance) {
        $error = "Ordonnance introuvable ou accès non autorisé.";
    }
} catch (PDOException $e) {
    $error = "Erreur lors de la récupération de l'ordonnance.";
    error_log($e->getMessage());
}
?>
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Voir l'ordonnance - MedConnect</title>
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
            <header class="bg-white shadow-sm">
                <div class="container mx-auto px-4 py-4 flex justify-between items-center">
                    <div class="flex items-center space-x-4">
                        <div class="w-12 h-12 rounded-full bg-gradient-to-br from-[#2E7D32] to-[#81C784] flex items-center justify-center">
                            <i class="fas fa-prescription text-white text-xl"></i>
                        </div>
                        <h1 class="text-2xl font-bold text-[#1B5E20]">Détail de l'ordonnance</h1>
                    </div>
                    <div class="flex items-center space-x-4">
                        <a href="ordonnances.php" class="btn-secondary">
                            <i class="fas fa-arrow-left mr-2"></i>Retour à la liste
                        </a>
                        <button onclick="window.print()" class="btn-primary">
                            <i class="fas fa-print mr-2"></i>Imprimer
                        </button>
                        <a href="telecharger_ordonnance.php?id=<?php echo $ordonnance_id; ?>" class="btn-primary">
                            <i class="fas fa-download mr-2"></i>Télécharger PDF
                        </a>
                        <button onclick="openSignatureModal()" class="btn-primary">
                            <i class="fas fa-signature mr-2"></i>Signer
                        </button>
                    </div>
                </div>
            </header>
            <main class="container mx-auto px-4 py-8">
                <?php if (isset($error)): ?>
                    <div class="bg-red-100 border-l-4 border-red-500 text-red-700 p-4 mb-4 rounded-lg">
                        <i class="fas fa-exclamation-circle mr-2"></i><?php echo $error; ?>
                    </div>
                <?php elseif (isset($ordonnance)): ?>
                    <div class="bg-white rounded-xl shadow-lg p-8 glass-effect max-w-2xl mx-auto">
                        <h2 class="text-xl font-bold text-[#1B5E20] mb-4">Informations du patient</h2>
                        <div class="mb-6">
                            <p><span class="font-semibold">Nom :</span> <?php echo htmlspecialchars($ordonnance['patient_prenom'] . ' ' . $ordonnance['patient_nom']); ?></p>
                            <?php if (!empty($ordonnance['patient_email'])): ?>
                                <p><span class="font-semibold">Email :</span> <?php echo htmlspecialchars($ordonnance['patient_email']); ?></p>
                            <?php endif; ?>
                            <?php if (!empty($ordonnance['patient_contact'])): ?>
                                <p><span class="font-semibold">Contact :</span> <?php echo htmlspecialchars($ordonnance['patient_contact']); ?></p>
                            <?php endif; ?>
                        </div>
                        <h2 class="text-xl font-bold text-[#1B5E20] mb-4">Détails de l'ordonnance</h2>
                        <p><span class="font-semibold">Date de création :</span> <?php echo date('d/m/Y', strtotime($ordonnance['date_creation'])); ?></p>
                        <p><span class="font-semibold">Date de validité :</span> <?php echo date('d/m/Y', strtotime($ordonnance['date_validite'])); ?></p>
                        <p><span class="font-semibold">Durée du traitement :</span> <?php echo htmlspecialchars($ordonnance['duree_traitement']); ?></p>
                        <p><span class="font-semibold">Renouvellement :</span> <?php echo $ordonnance['renouvellement'] ? 'Oui' : 'Non'; ?></p>
                        <?php if ($ordonnance['renouvellement']): ?>
                            <p><span class="font-semibold">Nombre de renouvellements :</span> <?php echo (int)$ordonnance['nombre_renouvellements']; ?></p>
                        <?php endif; ?>
                        <div class="mt-6">
                            <h3 class="text-lg font-semibold text-[#1B5E20] mb-2">Médicaments et Posologie</h3>
                            <div class="overflow-x-auto">
                                <table class="min-w-full bg-white rounded-lg overflow-hidden border border-gray-200">
                                    <thead class="bg-[#E8F5E9]">
                                        <tr>
                                            <th class="px-4 py-2 text-left text-sm font-medium text-[#1B5E20]">Médicament</th>
                                            <th class="px-4 py-2 text-left text-sm font-medium text-[#1B5E20]">Posologie</th>
                                            <th class="px-4 py-2 text-left text-sm font-medium text-[#1B5E20]">Quantité</th>
                                            <th class="px-4 py-2 text-left text-sm font-medium text-[#1B5E20]">Durée</th>
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
                        <div class="mt-4">
                            <h3 class="text-lg font-semibold text-[#1B5E20] mb-2">Instructions supplémentaires</h3>
                            <p><?php echo nl2br(htmlspecialchars($ordonnance['instructions'])); ?></p>
                        </div>

                        <?php if (!empty($ordonnance['signature'])): ?>
                        <div class="mt-6">
                            <h3 class="text-lg font-semibold text-[#1B5E20] mb-2">Signature du médecin</h3>
                            <img src="<?php echo htmlspecialchars($ordonnance['signature']); ?>" alt="Signature du médecin" class="max-w-xs">
                        </div>
                        <?php endif; ?>
                    </div>
                <?php endif; ?>
            </main>
        </div>
    </div>

    <!-- Modal de signature -->
    <div id="signatureModal" class="fixed inset-0 bg-black bg-opacity-50 hidden items-center justify-center">
        <div class="bg-white p-6 rounded-lg shadow-xl max-w-md w-full">
            <h2 class="text-xl font-bold text-[#1B5E20] mb-4">Signer l'ordonnance</h2>
            <div class="mb-4">
                <canvas id="signatureCanvas" class="border border-gray-300 rounded w-full" height="200"></canvas>
            </div>
            <div class="flex justify-end space-x-4">
                <button onclick="clearSignature()" class="btn-secondary">
                    <i class="fas fa-eraser mr-2"></i>Effacer
                </button>
                <button onclick="saveSignature()" class="btn-primary">
                    <i class="fas fa-save mr-2"></i>Enregistrer
                </button>
                <button onclick="closeSignatureModal()" class="btn-secondary">
                    <i class="fas fa-times mr-2"></i>Annuler
                </button>
            </div>
        </div>
    </div>

    <script>
    let canvas = document.getElementById('signatureCanvas');
    let ctx = canvas.getContext('2d');
    let isDrawing = false;
    let lastX = 0;
    let lastY = 0;

    // Ajuster la taille du canvas
    function resizeCanvas() {
        const container = canvas.parentElement;
        const rect = container.getBoundingClientRect();
        
        // Sauvegarder les données actuelles si le canvas n'est pas vide
        let imageData = null;
        if (canvas.width > 0 && canvas.height > 0) {
            try {
                imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
            } catch (e) {
                console.log('Canvas vide ou non initialisé');
            }
        }

        // Définir les nouvelles dimensions
        canvas.width = rect.width;
        canvas.height = 200;

        // Restaurer les paramètres de dessin
        ctx.strokeStyle = '#1B5E20';
        ctx.lineWidth = 2;
        ctx.lineCap = 'round';

        // Restaurer les données si elles existaient
        if (imageData) {
            ctx.putImageData(imageData, 0, 0);
        }
    }

    // Initialiser le canvas
    window.addEventListener('load', function() {
        resizeCanvas();
        window.addEventListener('resize', resizeCanvas);
    });

    // Gestionnaire d'événements pour le dessin
    canvas.addEventListener('mousedown', startDrawing);
    canvas.addEventListener('mousemove', draw);
    canvas.addEventListener('mouseup', stopDrawing);
    canvas.addEventListener('mouseout', stopDrawing);

    // Gestionnaire d'événements tactiles
    canvas.addEventListener('touchstart', handleTouch);
    canvas.addEventListener('touchmove', handleTouch);
    canvas.addEventListener('touchend', stopDrawing);

    function handleTouch(e) {
        e.preventDefault();
        const touch = e.touches[0];
        const rect = canvas.getBoundingClientRect();
        const mouseEvent = new MouseEvent(e.type === 'touchstart' ? 'mousedown' : 'mousemove', {
            clientX: touch.clientX,
            clientY: touch.clientY
        });
        canvas.dispatchEvent(mouseEvent);
    }

    function startDrawing(e) {
        isDrawing = true;
        const rect = canvas.getBoundingClientRect();
        lastX = e.clientX - rect.left;
        lastY = e.clientY - rect.top;
    }

    function draw(e) {
        if (!isDrawing) return;
        
        const rect = canvas.getBoundingClientRect();
        const x = e.clientX - rect.left;
        const y = e.clientY - rect.top;
        
        ctx.beginPath();
        ctx.moveTo(lastX, lastY);
        ctx.lineTo(x, y);
        ctx.stroke();
        
        [lastX, lastY] = [x, y];
    }

    function stopDrawing() {
        isDrawing = false;
    }

    function clearSignature() {
        ctx.clearRect(0, 0, canvas.width, canvas.height);
    }

    function openSignatureModal() {
        document.getElementById('signatureModal').classList.remove('hidden');
        document.getElementById('signatureModal').classList.add('flex');
        // Réinitialiser le canvas quand on ouvre le modal
        resizeCanvas();
    }

    function closeSignatureModal() {
        document.getElementById('signatureModal').classList.add('hidden');
        document.getElementById('signatureModal').classList.remove('flex');
        clearSignature();
    }

    function saveSignature() {
        // Vérifier si le canvas est vide
        let hasSignature = false;
        try {
            const pixelData = ctx.getImageData(0, 0, canvas.width, canvas.height).data;
            hasSignature = pixelData.some(pixel => pixel !== 0);
        } catch (e) {
            console.error('Erreur lors de la vérification de la signature:', e);
        }
        
        if (!hasSignature) {
            alert('Veuillez dessiner une signature avant de sauvegarder');
            return;
        }

        const signatureData = canvas.toDataURL('image/png');
        
        // Afficher un indicateur de chargement
        const saveButton = document.querySelector('button[onclick="saveSignature()"]');
        const originalText = saveButton.innerHTML;
        saveButton.innerHTML = '<i class="fas fa-spinner fa-spin mr-2"></i>Enregistrement...';
        saveButton.disabled = true;
        
        // Envoyer la signature au serveur
        fetch('sauvegarder_signature.php', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: `signature=${encodeURIComponent(signatureData)}&ordonnance_id=<?php echo $ordonnance_id; ?>`
        })
        .then(response => {
            if (!response.ok) {
                throw new Error('Erreur réseau');
            }
            return response.json();
        })
        .then(data => {
            if (data.success) {
                // Fermer le modal
                closeSignatureModal();
                // Recharger la page pour afficher la signature
                window.location.reload();
            } else {
                throw new Error(data.message || 'Erreur lors de la sauvegarde de la signature');
            }
        })
        .catch(error => {
            console.error('Erreur:', error);
            alert(error.message || 'Erreur lors de la sauvegarde de la signature');
        })
        .finally(() => {
            // Restaurer le bouton
            saveButton.innerHTML = originalText;
            saveButton.disabled = false;
        });
    }
    </script>
</body>
</html> 