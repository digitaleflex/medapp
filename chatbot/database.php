<?php
define('DB_HOST', 'localhost');
define('DB_USER', 'root');
define('DB_PASS', '');
define('DB_NAME', 'chatbot');

$conn = new mysqli(DB_HOST, DB_USER, DB_PASS);

if ($conn->connect_error) {
    die("Erreur de connexion: " . $conn->connect_error);
}

// Créer la base de données si elle n'existe pas
if (!$conn->query("CREATE DATABASE IF NOT EXISTS " . DB_NAME)) {
    die("Erreur lors de la création de la base de données: " . $conn->error);
}

// Sélectionner la base de données
if (!$conn->select_db(DB_NAME)) {
    die("Erreur lors de la sélection de la base de données: " . $conn->error);
}

// Définir l'encodage UTF-8
$conn->set_charset("utf8mb4");
?>
