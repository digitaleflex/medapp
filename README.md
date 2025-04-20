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

3. Configurez les variables d'environnement
   - Copiez le fichier `.env.example` vers `.env`
   - Modifiez les paramètres dans `.env` selon votre environnement

4. Créez la base de données
```sql
CREATE DATABASE medconnectdb;
```

5. Importez le schéma de base de données
```bash
mysql -u [username] -p medconnectdb < config/database.sql
mysql -u [username] -p medconnectdb < config/password_reset.sql
```

### Configuration de l'authentification Google OAuth

1. Créez un projet dans la [Google Cloud Console](https://console.cloud.google.com)
2. Configurez les identifiants OAuth2 comme décrit dans le fichier `auth/README.md`
3. Ajoutez les paramètres suivants dans votre fichier `.env` :
```
GOOGLE_CLIENT_ID=votre_client_id
GOOGLE_CLIENT_SECRET=votre_client_secret
GOOGLE_REDIRECT_URI=http://localhost/medapp-master/auth/google-callback.php
```

4. Vérifiez la configuration en accédant à :
```
http://localhost/medapp-master/auth/check-google-config.php
```

### Diagnostics

En cas de problème, utilisez l'outil de diagnostic disponible à :
```
http://localhost/medapp-master/diagnostic.php
```

## Structure du projet

- **`config/`** - Configuration de la base de données et SQL
- **`models/`** - Classes de modèles d'utilisateurs
- **`controllers/`** - Contrôleurs d'authentification
- **`views/`** - Formulaires et pages d'authentification
- **`includes/`** - Fonctions utilitaires et gestion de session
- **`auth/`** - Système d'authentification Google
- **`vendor/`** - Dépendances Composer

## Fonctionnalités

- Authentification des utilisateurs (patients, médecins, admin)
  - Connexion traditionnelle par email/mot de passe
  - Connexion via Google OAuth 2.0
- Gestion des profils
- Prise de rendez-vous
- Consultations en ligne
- Gestion du carnet de santé 

## Fonctionnement sans Composer

Si vous rencontrez des problèmes avec l'installation des dépendances Composer, l'application inclut un chargeur de variables d'environnement de secours qui permet de fonctionner sans la bibliothèque Dotenv.

Cependant, nous recommandons fortement d'installer les dépendances via Composer pour profiter de toutes les fonctionnalités, particulièrement l'authentification Google. 