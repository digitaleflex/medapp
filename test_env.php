<?php
$envFile = __DIR__ . '/.env';

echo "Test de lecture du fichier .env\n";
echo "Chemin du fichier : " . $envFile . "\n";
echo "Le fichier existe : " . (file_exists($envFile) ? "Oui" : "Non") . "\n";

if (file_exists($envFile)) {
    echo "Contenu du fichier :\n";
    echo file_get_contents($envFile);
    
    echo "\n\nPermissions du fichier :\n";
    echo "Lisible : " . (is_readable($envFile) ? "Oui" : "Non") . "\n";
    echo "Taille : " . filesize($envFile) . " octets\n";
} 