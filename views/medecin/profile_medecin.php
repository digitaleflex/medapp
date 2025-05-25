<?php
require_once '../../includes/session.php';
require_once '../../config/config.php';

// Vérifier si l'utilisateur est connecté
requireLogin();

// Vérifier si l'utilisateur a le rôle requis
requireRole('medecin');

$user_id = $_SESSION['user_id'];
$success = "";
$error = "";

// Récupérer les informations du médecin
$stmt = db()->prepare("
    SELECT 
        m.*,
        pm.adresse,
        pm.profession,
        pm.imgdiplome,
        pm.disponibilite,
        s.nomspecialite
    FROM medecin m
    LEFT JOIN profilmedecin pm ON m.id = pm.idmedecin
    LEFT JOIN specialite s ON m.idspecialite = s.id
    WHERE m.id = ?
");
$stmt->execute([$user_id]);
$medecin = $stmt->fetch(PDO::FETCH_ASSOC);

// Traitement du formulaire
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    try {
        db()->beginTransaction();

        // Mise à jour des informations de base
        $stmt = db()->prepare("
            UPDATE medecin 
            SET nom = ?, prenom = ?, email = ?, contact = ?
            WHERE id = ?
        ");
        $stmt->execute([
            $_POST['nom'],
            $_POST['prenom'],
            $_POST['email'],
            $_POST['contact'],
            $user_id
        ]);

        // Mise à jour ou insertion du profil
        $stmt = db()->prepare("
            INSERT INTO profilmedecin (idmedecin, adresse, disponibilite)
            VALUES (?, ?, ?)
            ON DUPLICATE KEY UPDATE
            adresse = VALUES(adresse),
            disponibilite = VALUES(disponibilite)
        ");
        $stmt->execute([
            $user_id,
            $_POST['adresse'],
            $_POST['disponibilite']
        ]);

        // Gestion de l'upload de l'image du diplôme
        if (isset($_FILES['imgdiplome']) && $_FILES['imgdiplome']['error'] === UPLOAD_ERR_OK) {
            $upload_dir = '../../uploads/diplomes/';
            if (!file_exists($upload_dir)) {
                mkdir($upload_dir, 0777, true);
            }

            $file_extension = strtolower(pathinfo($_FILES['imgdiplome']['name'], PATHINFO_EXTENSION));
            $new_filename = 'diplome_' . $user_id . '_' . time() . '.' . $file_extension;
            $upload_path = $upload_dir . $new_filename;

            if (move_uploaded_file($_FILES['imgdiplome']['tmp_name'], $upload_path)) {
                $stmt = db()->prepare("
                    UPDATE profilmedecin 
                    SET imgdiplome = ?
                    WHERE idmedecin = ?
                ");
                $stmt->execute([$new_filename, $user_id]);
            }
        }

        db()->commit();
        $success = "Profil mis à jour avec succès !";
        
        // Rafraîchir les données
        $stmt = db()->prepare("
            SELECT 
                m.*,
                pm.adresse,
                pm.profession,
                pm.imgdiplome,
                pm.disponibilite,
                s.nomspecialite
            FROM medecin m
            LEFT JOIN profilmedecin pm ON m.id = pm.idmedecin
            LEFT JOIN specialite s ON m.idspecialite = s.id
            WHERE m.id = ?
        ");
        $stmt->execute([$user_id]);
        $medecin = $stmt->fetch(PDO::FETCH_ASSOC);

    } catch (Exception $e) {
        db()->rollBack();
        $error = "Une erreur est survenue lors de la mise à jour du profil.";
    }
}
?>

<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Profil Médecin - MedConnect</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <?php include_once '../../views/components/styles.php'; ?>
    <style>
        .profile-section {
            transition: all 0.3s ease;
        }
        
        .profile-section:hover {
            transform: translateY(-2px);
        }
        
        .input-field {
            transition: all 0.3s ease;
        }
        
        .input-field:focus {
            box-shadow: 0 0 0 2px rgba(46, 125, 50, 0.2);
        }
        
        .file-upload {
            position: relative;
            overflow: hidden;
        }
        
        .file-upload input[type="file"] {
            position: absolute;
            top: 0;
            right: 0;
            min-width: 100%;
            min-height: 100%;
            font-size: 100px;
            text-align: right;
            filter: alpha(opacity=0);
            opacity: 0;
            outline: none;
            cursor: pointer;
            display: block;
        }
    </style>
</head>
<body class="bg-gradient-to-br from-[#F1F8E9] to-[#E8F5E9] min-h-screen">
    <?php include_once '../../views/components/header.php'; ?>

    <div class="container mx-auto px-4 py-8">
        <div class="max-w-4xl mx-auto">
            <div class="flex items-center justify-between mb-8">
                <h1 class="text-3xl font-bold text-[#1B5E20]">
                    <i class="fas fa-user-md mr-3"></i>Mon Profil
                </h1>
                <a href="dashboard.php" class="btn-secondary">
                    <i class="fas fa-arrow-left mr-2"></i>Retour au tableau de bord
                </a>
            </div>

            <?php if ($success): ?>
                <div class="bg-green-100 border-l-4 border-[#2E7D32] text-[#1B5E20] p-4 mb-6 rounded-r-lg">
                    <i class="fas fa-check-circle mr-2"></i><?php echo $success; ?>
                </div>
            <?php endif; ?>

            <?php if ($error): ?>
                <div class="bg-red-100 border-l-4 border-red-500 text-red-700 p-4 mb-6 rounded-r-lg">
                    <i class="fas fa-exclamation-circle mr-2"></i><?php echo $error; ?>
                </div>
            <?php endif; ?>

            <div class="bg-white rounded-xl shadow-lg overflow-hidden glass-effect">
                <form method="POST" enctype="multipart/form-data" class="p-6 space-y-8">
                    <!-- Informations personnelles -->
                    <div class="profile-section bg-[#F1F8E9] p-6 rounded-lg">
                        <h2 class="text-xl font-semibold text-[#1B5E20] mb-4">
                            <i class="fas fa-user mr-2"></i>Informations personnelles
                        </h2>
                        
                        <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                            <div>
                                <label class="block text-sm font-medium text-[#1B5E20] mb-2">Nom</label>
                                <input type="text" name="nom" value="<?php echo htmlspecialchars($medecin['nom']); ?>" 
                                       class="input-field w-full px-4 py-2 border border-[#81C784] rounded-lg focus:outline-none focus:border-[#2E7D32]" required>
                            </div>
                            <div>
                                <label class="block text-sm font-medium text-[#1B5E20] mb-2">Prénom</label>
                                <input type="text" name="prenom" value="<?php echo htmlspecialchars($medecin['prenom']); ?>" 
                                       class="input-field w-full px-4 py-2 border border-[#81C784] rounded-lg focus:outline-none focus:border-[#2E7D32]" required>
                            </div>
                        </div>

                        <div class="grid grid-cols-1 md:grid-cols-2 gap-6 mt-6">
                            <div>
                                <label class="block text-sm font-medium text-[#1B5E20] mb-2">Email</label>
                                <input type="email" name="email" value="<?php echo htmlspecialchars($medecin['email']); ?>" 
                                       class="input-field w-full px-4 py-2 border border-[#81C784] rounded-lg focus:outline-none focus:border-[#2E7D32]" required>
                            </div>
                            <div>
                                <label class="block text-sm font-medium text-[#1B5E20] mb-2">Téléphone</label>
                                <input type="tel" name="contact" value="<?php echo htmlspecialchars($medecin['contact']); ?>" 
                                       class="input-field w-full px-4 py-2 border border-[#81C784] rounded-lg focus:outline-none focus:border-[#2E7D32]" required>
                            </div>
                        </div>
                    </div>

                    <!-- Informations professionnelles -->
                    <div class="profile-section bg-[#F1F8E9] p-6 rounded-lg">
                        <h2 class="text-xl font-semibold text-[#1B5E20] mb-4">
                            <i class="fas fa-briefcase-medical mr-2"></i>Informations professionnelles
                        </h2>
                        
                        <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                            <div>
                                <label class="block text-sm font-medium text-[#1B5E20] mb-2">Spécialité</label>
                                <input type="text" value="<?php echo htmlspecialchars($medecin['nomspecialite'] ?? ''); ?>" 
                                       class="w-full px-4 py-2 border border-[#81C784] rounded-lg bg-[#E8F5E9] text-[#1B5E20]" readonly>
                            </div>
                        </div>

                        <div class="mt-6">
                            <label class="block text-sm font-medium text-[#1B5E20] mb-2">Adresse professionnelle</label>
                            <textarea name="adresse" rows="3" 
                                      class="input-field w-full px-4 py-2 border border-[#81C784] rounded-lg focus:outline-none focus:border-[#2E7D32]"><?php echo htmlspecialchars($medecin['adresse'] ?? ''); ?></textarea>
                        </div>

                        <div class="mt-6">
                            <label class="block text-sm font-medium text-[#1B5E20] mb-2">Disponibilités</label>
                            <textarea name="disponibilite" rows="3" 
                                      class="input-field w-full px-4 py-2 border border-[#81C784] rounded-lg focus:outline-none focus:border-[#2E7D32]"><?php echo htmlspecialchars($medecin['disponibilite'] ?? ''); ?></textarea>
                        </div>

                        <div class="mt-6">
                            <label class="block text-sm font-medium text-[#1B5E20] mb-2">Diplôme</label>
                            <?php if (!empty($medecin['imgdiplome'])): ?>
                                <div class="mb-2">
                                    <a href="../../uploads/diplomes/<?php echo htmlspecialchars($medecin['imgdiplome']); ?>" 
                                       target="_blank" class="text-[#2E7D32] hover:text-[#1B5E20]">
                                        <i class="fas fa-file-pdf mr-2"></i>Voir le diplôme actuel
                                    </a>
                                </div>
                            <?php endif; ?>
                            <div class="file-upload">
                                <label class="btn-secondary inline-block cursor-pointer">
                                    <i class="fas fa-upload mr-2"></i>Choisir un fichier
                                </label>
                                <input type="file" name="imgdiplome" accept=".pdf,.jpg,.jpeg,.png" 
                                       class="input-field w-full px-4 py-2 border border-[#81C784] rounded-lg focus:outline-none focus:border-[#2E7D32]">
                            </div>
                            <p class="mt-1 text-sm text-[#558B2F]">Formats acceptés : PDF, JPG, PNG</p>
                        </div>
                    </div>

                    <div class="flex justify-end">
                        <button type="submit" class="btn-primary">
                            <i class="fas fa-save mr-2"></i>Enregistrer les modifications
                        </button>
                    </div>
                </form>
            </div>
        </div>
    </div>

    <script>
        // Mise à jour du nom du fichier sélectionné
        document.querySelector('input[type="file"]').addEventListener('change', function(e) {
            const fileName = e.target.files[0]?.name;
            if (fileName) {
                this.previousElementSibling.innerHTML = `<i class="fas fa-file mr-2"></i>${fileName}`;
            }
        });
    </script>
</body>
</html> 