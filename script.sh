#!/bin/bash

# Définir le nom du projet
project_name="medapp"

# Créer les dossiers principaux
mkdir -p $project_name/{app/{Controllers,Models,Views},public,config,storage/{logs,cache},vendor}

# Créer les fichiers de base dans chaque dossier
# App - Controllers
touch $project_name/app/Controllers/HomeController.php
echo "<?php

namespace App\Controllers;

class HomeController {
    public function index() {
        echo 'Hello, World!';
    }
}" > $project_name/app/Controllers/HomeController.php

# App - Models
touch $project_name/app/Models/User.php
echo "<?php

namespace App\Models;

class User {
    private \$id;
    private \$name;

    public function __construct(\$id, \$name) {
        \$this->id = \$id;
        \$this->name = \$name;
    }

    public function getId() {
        return \$this->id;
    }

    public function getName() {
        return \$this->name;
    }
}" > $project_name/app/Models/User.php

# App - Views (exemple avec un fichier HTML basique)
mkdir -p $project_name/app/Views
touch $project_name/app/Views/home.php
echo "<!DOCTYPE html>
<html lang='en'>
<head>
    <meta charset='UTF-8'>
    <meta name='viewport' content='width=device-width, initial-scale=1.0'>
    <title>Home</title>
</head>
<body>
    <h1>Welcome to Home Page</h1>
</body>
</html>" > $project_name/app/Views/home.php

# Config
mkdir -p $project_name/config
touch $project_name/config/config.php
echo "<?php

// Configuration générale
return [
    'database' => [
        'host' => 'localhost',
        'dbname' => 'mon_projet_db',
        'username' => 'root',
        'password' => '',
    ]
];" > $project_name/config/config.php

# Public
mkdir -p $project_name/public
touch $project_name/public/index.php
echo "<?php

require_once '../vendor/autoload.php';

use App\Controllers\HomeController;

\$controller = new HomeController();
\$controller->index();" > $project_name/public/index.php

# Storage - logs
mkdir -p $project_name/storage/logs
touch $project_name/storage/logs/app.log

# Storage - cache
mkdir -p $project_name/storage/cache
touch $project_name/storage/cache/app.cache

# Vendor (généré avec Composer)
echo "Assurez-vous d'avoir exécuté Composer pour générer le dossier vendor."

# Script terminé
echo "L'architecture POO a été créée dans le dossier '$project_name'."
