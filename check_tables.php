<?php
require_once 'config/database.php';

try {
    $database = new Database();
    $db = $database->getConnection();
    
    // Vérifier et créer la table rendez_vous
    $db->exec("CREATE TABLE IF NOT EXISTS rendez_vous (
        id INT AUTO_INCREMENT PRIMARY KEY,
        id_medecin INT NOT NULL,
        id_patient INT NOT NULL,
        date_rdv DATETIME NOT NULL,
        statut ENUM('en attente', 'confirmé', 'annulé') DEFAULT 'en attente',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (id_medecin) REFERENCES medecin(id),
        FOREIGN KEY (id_patient) REFERENCES patient(id)
    )");
    echo "Table rendez_vous vérifiée/créée\n";

    // Vérifier et créer la table consultations
    $db->exec("CREATE TABLE IF NOT EXISTS consultations (
        id INT AUTO_INCREMENT PRIMARY KEY,
        id_medecin INT NOT NULL,
        id_patient INT NOT NULL,
        date_consultation DATETIME NOT NULL,
        motif TEXT,
        observations TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (id_medecin) REFERENCES medecin(id),
        FOREIGN KEY (id_patient) REFERENCES patient(id)
    )");
    echo "Table consultations vérifiée/créée\n";

    // Vérifier et créer la table messages
    $db->exec("CREATE TABLE IF NOT EXISTS messages (
        id INT AUTO_INCREMENT PRIMARY KEY,
        expediteur_id INT NOT NULL,
        destinataire_id INT NOT NULL,
        sujet VARCHAR(255),
        message TEXT,
        lu BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (expediteur_id) REFERENCES medecin(id),
        FOREIGN KEY (destinataire_id) REFERENCES medecin(id)
    )");
    echo "Table messages vérifiée/créée\n";

    // Vérifier et créer la table vaccins
    $db->exec("CREATE TABLE IF NOT EXISTS vaccins (
        id INT AUTO_INCREMENT PRIMARY KEY,
        id_patient INT NOT NULL,
        nom_vaccin VARCHAR(255) NOT NULL,
        date_vaccination DATE,
        date_rappel DATE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (id_patient) REFERENCES patient(id)
    )");
    echo "Table vaccins vérifiée/créée\n";

    // Vérifier et créer la table dossiers_medicaux
    $db->exec("CREATE TABLE IF NOT EXISTS dossiers_medicaux (
        id INT AUTO_INCREMENT PRIMARY KEY,
        id_patient INT NOT NULL,
        antecedents TEXT,
        allergies TEXT,
        traitements TEXT,
        derniere_maj TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (id_patient) REFERENCES patient(id)
    )");
    echo "Table dossiers_medicaux vérifiée/créée\n";

    echo "Toutes les tables ont été vérifiées et créées si nécessaire.\n";

} catch(PDOException $e) {
    echo "Erreur : " . $e->getMessage() . "\n";
}
?> 