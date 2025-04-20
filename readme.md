# MedConnect

Application de gestion de consultations médicales en ligne.

## Installation et configuration

### Prérequis
- PHP 7.4 ou supérieur
- MySQL/MariaDB
- Composer

### Installation de Composer

#### Sur Linux/MacOS
```bash
curl -sS https://getcomposer.org/installer | php
sudo mv composer.phar /usr/local/bin/composer
chmod +x /usr/local/bin/composer
```

#### Sur Windows
Téléchargez et exécutez [l'installateur de Composer](https://getcomposer.org/Composer-Setup.exe).

### Installation du projet

1. Clonez le dépôt
```bash
git clone [URL_DU_DEPOT]
cd medapp
```

2. Installez les dépendances via Composer
```bash
composer install
```

3. Créez la base de données
```sql
CREATE DATABASE medconnectdb;
```

4. Importez le schéma de base de données
```bash
mysql -u [username] -p medconnectdb < config/database.sql
mysql -u [username] -p medconnectdb < config/password_reset.sql
```

5. Configurez la connexion à la base de données
   - Ouvrez `config/database.php`
   - Modifiez les informations de connexion selon votre environnement

## Structure du projet

- **`config/`** - Configuration de la base de données et SQL
- **`models/`** - Classes de modèles d'utilisateurs
- **`controllers/`** - Contrôleurs d'authentification
- **`views/`** - Formulaires et pages d'authentification
- **`includes/`** - Fonctions utilitaires et gestion de session

## Fonctionnalités

- Authentification des utilisateurs (patients, médecins, admin)
- Gestion des profils
- Prise de rendez-vous
- Consultations en ligne
- Gestion du carnet de santé 