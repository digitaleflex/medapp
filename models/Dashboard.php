<?php
class Dashboard {
    private $db;
    private $medecin_id;

    public function __construct($db, $medecin_id) {
        $this->db = $db;
        $this->medecin_id = $medecin_id;
    }

    // Obtenir le nombre de rendez-vous du jour
    public function getRendezVousAujourdhui() {
        $query = "SELECT COUNT(*) as total FROM rendezvous 
                 WHERE idmedecin = ? AND DATE(dateheure) = CURDATE()";
        $stmt = $this->db->prepare($query);
        $stmt->execute([$this->medecin_id]);
        $result = $stmt->fetch(PDO::FETCH_ASSOC);
        return $result['total'];
    }

    // Obtenir le nombre de patients actifs
    public function getPatientsActifs() {
        $query = "SELECT COUNT(DISTINCT idpatient) as total 
                 FROM rendezvous 
                 WHERE idmedecin = ? 
                 AND dateheure >= DATE_SUB(CURDATE(), INTERVAL 6 MONTH)";
        $stmt = $this->db->prepare($query);
        $stmt->execute([$this->medecin_id]);
        $result = $stmt->fetch(PDO::FETCH_ASSOC);
        return $result['total'];
    }

    // Obtenir le nombre de consultations du jour
    public function getConsultationsDuJour() {
        $today = date('Y-m-d');
        $stmt = $this->db->prepare("
            SELECT COUNT(*) as total
            FROM consultation
            WHERE id_medecin = ? 
            AND DATE(date_consultation) = ?
        ");
        $stmt->execute([$this->medecin_id, $today]);
        return $stmt->fetch(PDO::FETCH_ASSOC)['total'];
    }

    // Obtenir le nombre de messages non lus
    public function getMessagesNonLus() {
        $query = "SELECT COUNT(*) as total FROM messages m
                 INNER JOIN patient p ON m.sender_id = p.id
                 WHERE m.receiver_id = :user_id 
                 AND m.lu = 0";
        $stmt = $this->db->prepare($query);
        $stmt->bindParam(":user_id", $this->medecin_id);
        $stmt->execute();
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        return $row['total'];
    }

    // Obtenir les derniers patients
    public function getDerniersPatients($limit = 5) {
        $query = "SELECT p.id, p.nom, p.prenom, p.datenais, p.sexe, p.email, p.contact, MAX(r.dateheure) as derniere_visite 
                 FROM patient p 
                 INNER JOIN rendezvous r ON p.id = r.idpatient 
                 WHERE r.idmedecin = ? 
                 GROUP BY p.id 
                 ORDER BY derniere_visite DESC 
                 LIMIT ?";
        $stmt = $this->db->prepare($query);
        $stmt->execute([$this->medecin_id, $limit]);
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    // Obtenir les rendez-vous du jour
    public function getRendezVousDuJour() {
        $query = "SELECT r.*, p.nom, p.prenom 
                 FROM rendezvous r 
                 INNER JOIN patient p ON r.idpatient = p.id 
                 WHERE r.idmedecin = ? 
                 AND DATE(r.dateheure) = CURDATE() 
                 ORDER BY r.dateheure ASC";
        $stmt = $this->db->prepare($query);
        $stmt->execute([$this->medecin_id]);
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    // Obtenir les rappels importants
    public function getRappelsImportants() {
        $rappels = [
            'vaccins' => $this->getRappelsVaccins(),
            'dossiers' => $this->getDossiersAMettreAJour(),
            'rdv_confirmation' => $this->getRendezVousEnAttente()
        ];
        return $rappels;
    }

    private function getRappelsVaccins() {
        $query = "SELECT COUNT(*) as total 
                 FROM vaccins 
                 WHERE id_patient IN (
                     SELECT idpatient FROM rendezvous WHERE idmedecin = ?
                 ) 
                 AND date_rappel <= DATE_ADD(CURDATE(), INTERVAL 7 DAY)";
        $stmt = $this->db->prepare($query);
        $stmt->execute([$this->medecin_id]);
        $result = $stmt->fetch(PDO::FETCH_ASSOC);
        return $result['total'];
    }

    private function getDossiersAMettreAJour() {
        $query = "SELECT COUNT(*) as total 
                 FROM dossiers_medicaux 
                 WHERE id_patient IN (
                     SELECT idpatient FROM rendezvous WHERE idmedecin = ?
                 ) 
                 AND derniere_maj <= DATE_SUB(CURDATE(), INTERVAL 3 MONTH)";
        $stmt = $this->db->prepare($query);
        $stmt->execute([$this->medecin_id]);
        $result = $stmt->fetch(PDO::FETCH_ASSOC);
        return $result['total'];
    }

    private function getRendezVousEnAttente() {
        $query = "SELECT COUNT(*) as total 
                 FROM rendezvous 
                 WHERE idmedecin = ? 
                 AND statut = 'en attente' 
                 AND dateheure >= CURDATE()";
        $stmt = $this->db->prepare($query);
        $stmt->execute([$this->medecin_id]);
        $result = $stmt->fetch(PDO::FETCH_ASSOC);
        return $result['total'];
    }
}
?> 