# MedConnect

Application de gestion de consultations médicales en ligne.

## Installation et configuration

### Prérequis
- PHP 7.4 ou supérieur
- MySQL/MariaDB
- Composer

### Installation

1. Clonez le dépôt
```bash
git clone https://github.com/fri25/medapp.git
cd medapp
```

2. Installez les dépendances via Composer
```bash
composer install
```

3. Configurez l'environnement
```bash
cp .env.example .env
# Modifiez le fichier .env avec vos informations
```

4. Créez la base de données et importez le schéma
```bash
# Créez une base de données dans MySQL
mysql -u root -p
CREATE DATABASE medapp;
exit;

# Importez le schéma
mysql -u root -p medapp < config/database.sql
```

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

## Sécurité

- Les informations sensibles doivent être stockées dans le fichier `.env`
- Ne jamais commiter le fichier `.env` dans Git
- Utilisez `.env.example` comme modèle pour la configuration 