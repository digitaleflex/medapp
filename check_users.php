<?php
require_once 'config/database.php';

$database = new Database();
$db = $database->getConnection();

// Vérifier les patients
echo "=== PATIENTS ===\n";
$query = "SELECT id, nom, prenom, email, password, role FROM patient";
$stmt = $db->prepare($query);
$stmt->execute();

while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
    echo "ID: " . $row['id'] . "\n";
    echo "Nom: " . $row['nom'] . "\n";
    echo "Prénom: " . $row['prenom'] . "\n";
    echo "Email: " . $row['email'] . "\n";
    echo "Password Hash: " . $row['password'] . "\n";
    echo "Role: " . $row['role'] . "\n";
    echo "-------------------\n";
}

// Vérifier les médecins
echo "\n=== MEDECINS ===\n";
$query = "SELECT id, nom, prenom, email, password, role FROM medecin";
$stmt = $db->prepare($query);
$stmt->execute();

while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
    echo "ID: " . $row['id'] . "\n";
    echo "Nom: " . $row['nom'] . "\n";
    echo "Prénom: " . $row['prenom'] . "\n";
    echo "Email: " . $row['email'] . "\n";
    echo "Password Hash: " . $row['password'] . "\n";
    echo "Role: " . $row['role'] . "\n";
    echo "-------------------\n";
} 