<?php
require_once 'config/database.php';

try {
    $db = db();

    // Désactiver temporairement les vérifications de clés étrangères
    $db->exec("SET FOREIGN_KEY_CHECKS = 0");

    // Supprimer les données existantes et réinitialiser les auto-incréments
    $db->exec("TRUNCATE TABLE medecin_specialite");
    $db->exec("TRUNCATE TABLE medecin");
    $db->exec("TRUNCATE TABLE specialite");

    // Insérer les spécialités
    $specialites = [
        ['nomspecialite' => 'Cardiologie'],
        ['nomspecialite' => 'Dermatologie'],
        ['nomspecialite' => 'Gynécologie'],
        ['nomspecialite' => 'Neurologie'],
        ['nomspecialite' => 'Ophtalmologie'],
        ['nomspecialite' => 'ORL'],
        ['nomspecialite' => 'Pédiatrie'],
        ['nomspecialite' => 'Psychiatrie'],
        ['nomspecialite' => 'Radiologie'],
        ['nomspecialite' => 'Urologie']
    ];

    $stmt = $db->prepare("INSERT INTO specialite (nomspecialite) VALUES (?)");
    foreach ($specialites as $specialite) {
        $stmt->execute([$specialite['nomspecialite']]);
    }

    // Insérer les médecins
    $medecins = [
        [
            'nom' => 'Dubois',
            'prenom' => 'Marie',
            'specialites' => ['Cardiologie']
        ],
        [
            'nom' => 'Martin',
            'prenom' => 'Jean',
            'specialites' => ['Dermatologie']
        ],
        [
            'nom' => 'Bernard',
            'prenom' => 'Sophie',
            'specialites' => ['Gynécologie']
        ],
        [
            'nom' => 'Petit',
            'prenom' => 'Pierre',
            'specialites' => ['Neurologie']
        ],
        [
            'nom' => 'Robert',
            'prenom' => 'Isabelle',
            'specialites' => ['Ophtalmologie']
        ],
        [
            'nom' => 'Richard',
            'prenom' => 'Thomas',
            'specialites' => ['ORL']
        ],
        [
            'nom' => 'Durand',
            'prenom' => 'Julie',
            'specialites' => ['Pédiatrie']
        ],
        [
            'nom' => 'Moreau',
            'prenom' => 'Philippe',
            'specialites' => ['Psychiatrie']
        ],
        [
            'nom' => 'Laurent',
            'prenom' => 'Catherine',
            'specialites' => ['Radiologie']
        ],
        [
            'nom' => 'Simon',
            'prenom' => 'Michel',
            'specialites' => ['Urologie']
        ],
        // Médecins avec plusieurs spécialités
        [
            'nom' => 'Michel',
            'prenom' => 'Anne',
            'specialites' => ['Cardiologie', 'Neurologie']
        ],
        [
            'nom' => 'Lefebvre',
            'prenom' => 'François',
            'specialites' => ['Dermatologie', 'Ophtalmologie']
        ],
        [
            'nom' => 'Garcia',
            'prenom' => 'Lucie',
            'specialites' => ['Gynécologie', 'Pédiatrie']
        ],
        [
            'nom' => 'David',
            'prenom' => 'Antoine',
            'specialites' => ['ORL', 'Urologie']
        ],
        [
            'nom' => 'Bertrand',
            'prenom' => 'Émilie',
            'specialites' => ['Psychiatrie', 'Neurologie']
        ]
    ];

    $stmt = $db->prepare("INSERT INTO medecin (nom, prenom) VALUES (?, ?)");
    $stmt_specialite = $db->prepare("INSERT INTO medecin_specialite (idmedecin, idspecialite) VALUES (?, ?)");
    
    foreach ($medecins as $medecin) {
        $stmt->execute([$medecin['nom'], $medecin['prenom']]);
        $id_medecin = $db->lastInsertId();
        
        foreach ($medecin['specialites'] as $specialite) {
            $stmt_specialite_id = $db->prepare("SELECT id FROM specialite WHERE nomspecialite = ?");
            $stmt_specialite_id->execute([$specialite]);
            $id_specialite = $stmt_specialite_id->fetchColumn();
            
            if ($id_specialite) {
                $stmt_specialite->execute([$id_medecin, $id_specialite]);
            }
        }
    }

    // Réactiver les vérifications de clés étrangères
    $db->exec("SET FOREIGN_KEY_CHECKS = 1");

    echo "Données de test créées avec succès !\n";
    echo "15 médecins et 10 spécialités ont été ajoutés.\n";

} catch (Exception $e) {
    // Réactiver les vérifications de clés étrangères en cas d'erreur
    $db->exec("SET FOREIGN_KEY_CHECKS = 1");
    echo "Erreur : " . $e->getMessage() . "\n";
} 