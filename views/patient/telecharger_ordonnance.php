<?php
// Désactiver l'affichage des erreurs
error_reporting(0);
ini_set('display_errors', 0);

// Démarrer la mise en tampon de sortie
ob_start();

require_once '../../includes/session.php';
require_once '../../config/config.php';
require_once '../../vendor/autoload.php';

requireLogin();
requireRole('patient');

$user_id = $_SESSION['user_id'];

// Vérifier la présence de l'ID de l'ordonnance
if (!isset($_GET['id']) || !is_numeric($_GET['id'])) {
    header('Location: ordonnace.php');
    exit;
}
$ordonnance_id = intval($_GET['id']);

// Charger l'ordonnance
try {
    $stmt = db()->prepare('
        SELECT o.*, p.nom as patient_nom, p.prenom as patient_prenom, p.email as patient_email, p.contact as patient_contact,
               m.nom as medecin_nom, m.prenom as medecin_prenom
        FROM ordonnance o
        JOIN patient p ON o.idpatient = p.id
        JOIN medecin m ON o.idmedecin = m.id
        WHERE o.id = ? AND o.idpatient = ?
    ');
    $stmt->execute([$ordonnance_id, $user_id]);
    $ordonnance = $stmt->fetch(PDO::FETCH_ASSOC);
    
    if (!$ordonnance) {
        header('Location: ordonnace.php');
        exit;
    }
} catch (PDOException $e) {
    error_log($e->getMessage());
    header('Location: ordonnace.php');
    exit;
}

// Vider le tampon de sortie
ob_end_clean();

// Créer le PDF
class MYPDF extends TCPDF {
    public function Header() {
        $this->SetFont('helvetica', 'B', 20);
        $this->Cell(0, 15, 'ORDONNANCE MÉDICALE', 0, true, 'C', 0);
        $this->Ln(10);
    }
}

// Créer une nouvelle instance de PDF
$pdf = new MYPDF(PDF_PAGE_ORIENTATION, PDF_UNIT, PDF_PAGE_FORMAT, true, 'UTF-8', false);

// Définir les informations du document
$pdf->SetCreator(PDF_CREATOR);
$pdf->SetAuthor('MedConnect');
$pdf->SetTitle('Ordonnance - ' . $ordonnance['patient_prenom'] . ' ' . $ordonnance['patient_nom']);

// Définir les marges
$pdf->SetMargins(15, 40, 15);
$pdf->SetHeaderMargin(5);
$pdf->SetFooterMargin(10);

// Ajouter une page
$pdf->AddPage();

// Définir la police
$pdf->SetFont('helvetica', '', 12);

// Informations du patient
$pdf->SetFont('helvetica', 'B', 14);
$pdf->Cell(0, 10, 'Informations du patient', 0, 1, 'L');
$pdf->SetFont('helvetica', '', 12);
$pdf->Cell(40, 7, 'Nom :', 0, 0);
$pdf->Cell(0, 7, $ordonnance['patient_prenom'] . ' ' . $ordonnance['patient_nom'], 0, 1);
if (!empty($ordonnance['patient_email'])) {
    $pdf->Cell(40, 7, 'Email :', 0, 0);
    $pdf->Cell(0, 7, $ordonnance['patient_email'], 0, 1);
}
if (!empty($ordonnance['patient_contact'])) {
    $pdf->Cell(40, 7, 'Contact :', 0, 0);
    $pdf->Cell(0, 7, $ordonnance['patient_contact'], 0, 1);
}

$pdf->Ln(5);

// Détails de l'ordonnance
$pdf->SetFont('helvetica', 'B', 14);
$pdf->Cell(0, 10, 'Détails de l\'ordonnance', 0, 1, 'L');
$pdf->SetFont('helvetica', '', 12);
$pdf->Cell(60, 7, 'Date de création :', 0, 0);
$pdf->Cell(0, 7, date('d/m/Y', strtotime($ordonnance['date_creation'])), 0, 1);
$pdf->Cell(60, 7, 'Date de validité :', 0, 0);
$pdf->Cell(0, 7, date('d/m/Y', strtotime($ordonnance['date_validite'])), 0, 1);
$pdf->Cell(60, 7, 'Durée du traitement :', 0, 0);
$pdf->Cell(0, 7, $ordonnance['duree_traitement'], 0, 1);
$pdf->Cell(60, 7, 'Renouvellement :', 0, 0);
$pdf->Cell(0, 7, $ordonnance['renouvellement'] ? 'Oui' : 'Non', 0, 1);
if ($ordonnance['renouvellement']) {
    $pdf->Cell(60, 7, 'Nombre de renouvellements :', 0, 0);
    $pdf->Cell(0, 7, $ordonnance['nombre_renouvellements'], 0, 1);
}

$pdf->Ln(5);

// Médicaments et posologie
$pdf->SetFont('helvetica', 'B', 14);
$pdf->Cell(0, 10, 'Médicaments et Posologie', 0, 1, 'L');
$pdf->SetFont('helvetica', '', 12);

// En-tête du tableau
$pdf->SetFillColor(232, 245, 233);
$pdf->SetFont('helvetica', 'B', 12);
$pdf->Cell(90, 7, 'Médicament', 1, 0, 'C', true);
$pdf->Cell(90, 7, 'Posologie', 1, 1, 'C', true);

// Contenu du tableau
$pdf->SetFont('helvetica', '', 12);
$medicaments = explode("\n", $ordonnance['medicaments']);
$posologies = explode("\n", $ordonnance['posologie']);
$max = max(count($medicaments), count($posologies));

for ($i = 0; $i < $max; $i++) {
    $pdf->Cell(90, 7, isset($medicaments[$i]) ? $medicaments[$i] : '', 1, 0);
    $pdf->Cell(90, 7, isset($posologies[$i]) ? $posologies[$i] : '', 1, 1);
}

$pdf->Ln(5);

// Instructions supplémentaires
if (!empty($ordonnance['instructions'])) {
    $pdf->SetFont('helvetica', 'B', 14);
    $pdf->Cell(0, 10, 'Instructions supplémentaires', 0, 1, 'L');
    $pdf->SetFont('helvetica', '', 12);
    $pdf->MultiCell(0, 7, $ordonnance['instructions'], 0, 'L');
}

$pdf->Ln(20);

// Signature
$pdf->SetFont('helvetica', 'B', 12);
$pdf->Cell(0, 7, 'Signature du médecin', 0, 1, 'R');
$pdf->SetFont('helvetica', '', 12);
$pdf->Cell(0, 7, $ordonnance['medecin_prenom'] . ' ' . $ordonnance['medecin_nom'], 0, 1, 'R');

// Ajouter l'image de la signature si elle existe
$temp_path = null;
if (!empty($ordonnance['signature'])) {
    $signature_path = __DIR__ . '/../../' . $ordonnance['signature'];
    if (file_exists($signature_path)) {
        $pdf->Ln(5);

        $temp_image = imagecreatetruecolor(500, 200);
        $white = imagecolorallocate($temp_image, 255, 255, 255);
        imagefill($temp_image, 0, 0, $white);

        $original_image = imagecreatefrompng($signature_path);
        if ($original_image) {
            imagecopy($temp_image, $original_image, 0, 0, 0, 0, 500, 200);

            // Sauvegarder le chemin pour suppression après Output
            $temp_path = __DIR__ . '/../../uploads/signatures/temp_' . time() . '.jpg';
            imagejpeg($temp_image, $temp_path, 100);

            $page_width = $pdf->GetPageWidth();
            $image_width = 50;
            $x = $page_width - $image_width - 15;

            $pdf->Image($temp_path, $x, $pdf->GetY(), $image_width);

            imagedestroy($original_image);
            imagedestroy($temp_image);
        } else {
            error_log('Impossible de charger l\'image PNG: ' . $signature_path);
        }
    } else {
        error_log('Le fichier de signature n\'existe pas à l\'emplacement: ' . $signature_path);
    }
} else {
    error_log('Aucune signature trouvée dans l\'ordonnance');
}

// Générer le PDF
$pdf->Output('Ordonnance_' . $ordonnance['patient_prenom'] . '_' . $ordonnance['patient_nom'] . '.pdf', 'D');

// Supprimer le fichier temporaire APRÈS l'envoi du PDF
if ($temp_path && file_exists($temp_path)) {
    unlink($temp_path);
} 