# Changelog - Système d'Authentification et Gestion des Rôles

## Sprint 1 - Authentification et Gestion des utilisateurs

Date: 20/04/2025

### Résumé
Implémentation du système d'authentification avec gestion des rôles (admin, médecin, patient), inscription, connexion, récupération de mot de passe, et gestion des sessions.

### Structure des Répertoires
- **`config/`** - Configuration de la base de données et SQL
- **`models/`** - Classes de modèles d'utilisateurs
- **`controllers/`** - Contrôleurs d'authentification
- **`views/`** - Formulaires et pages d'authentification
- **`includes/`** - Fonctions utilitaires et gestion de session

### Fichiers Créés

#### Configuration de Base de Données
- **`config/database.php`** - Connexion à la base de données avec PDO
- **`config/password_reset.sql`** - Structure de la table pour les tokens de réinitialisation

#### Modèles
- **`models/User.php`** - Classe abstraite pour tous les utilisateurs
- **`models/Patient.php`** - Classe pour les patients
- **`models/Medecin.php`** - Classe pour les médecins
- **`models/Admin.php`** - Classe pour les administrateurs

#### Contrôleurs
- **`controllers/Auth.php`** - Contrôleur gérant l'authentification et récupération de mot de passe

#### Vues
- **`views/register_patient.php`** - Formulaire d'inscription pour patients
- **`views/register_medecin.php`** - Formulaire d'inscription pour médecins
- **`views/login.php`** - Page de connexion commune
- **`views/forgot_password.php`** - Formulaire de demande de réinitialisation
- **`views/reset_password.php`** - Formulaire de réinitialisation de mot de passe
- **`views/logout.php`** - Script de déconnexion

#### Utilitaires
- **`includes/session.php`** - Fonctions de gestion de session et vérification des rôles

### Fonctionnalités Implémentées

1. **Inscription des utilisateurs**
   - Formulaires distincts pour patients et médecins
   - Validation des données et vérification d'email unique
   - Hashage sécurisé des mots de passe avec BCRYPT

2. **Connexion**
   - Système unifié pour tous les types d'utilisateurs
   - Redirection automatique selon le rôle

3. **Gestion de Session**
   - Durée d'expiration de session (30 minutes d'inactivité)
   - Vérification des droits d'accès selon le rôle

4. **Récupération de Mot de Passe**
   - Génération de token unique avec durée limitée (1 heure)
   - Envoi d'email avec lien de réinitialisation
   - Système pour éviter la réutilisation des tokens

### Guide pour les Développeurs

#### Ajouter une Nouvelle Fonctionnalité Protégée
Pour créer une page accessible uniquement à un certain rôle :

```php
<?php
require_once '../includes/session.php';

// Vérifier si l'utilisateur est connecté
requireLogin();

// Vérifier si l'utilisateur a le rôle requis (admin, medecin ou patient)
requireRole('medecin');

// Suite du code de la page...
?>
```

#### Accéder aux Informations de l'Utilisateur Connecté
Une fois l'utilisateur connecté, ses informations sont stockées en session :

```php
$user_id = $_SESSION['user_id'];
$nom = $_SESSION['nom'];
$prenom = $_SESSION['prenom'];
$role = $_SESSION['role'];
```

### Mises à jour (21/04/2025)

#### Changement de Framework CSS
- Remplacement de Bootstrap par Tailwind CSS dans toutes les vues
- Interface utilisateur plus moderne et cohérente
- Pages spécifiques au rôle avec accents de couleur différents (bleu pour les patients, vert pour les médecins)

#### Configuration du Projet
- Ajout de `composer.json` pour la gestion des dépendances
- Ajout de `.gitignore` pour exclure les fichiers non nécessaires
- Ajout de README.md avec instructions d'installation

#### Mise à jour des CDN
- Utilisation de la version recommandée du CDN Tailwind CSS
- Migration vers `https://cdn.jsdelivr.net/npm/@tailwindcss/browser@4`

### Prochaines Étapes Prévues
- Implémentation du profil médecin avec téléchargement de diplômes
- Gestion du profil patient avec carnet de santé
- Création des tableaux de bord spécifiques aux rôles 