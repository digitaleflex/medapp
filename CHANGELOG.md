# Journal des modifications

## [1.2.0] - 2025-04-20

### Ajouté
- Authentification Google OAuth 2.0
  - Ajout du fichier `auth/google-login.php` pour la redirection vers Google
  - Ajout du fichier `auth/google-callback.php` pour le traitement des réponses Google
  - Ajout de la classe `GoogleAuth.php` pour la gestion de l'authentification
  - Ajout du fichier `auth/README.md` pour la documentation de la configuration
  - Ajout du fichier `auth/check-google-config.php` pour vérifier la configuration Google
- Bouton de connexion Google sur la page de connexion
- Outil de diagnostic `diagnostic.php` pour détecter les problèmes de configuration

### Modifié
- Mise à jour du fichier `composer.json` pour inclure les nouvelles dépendances
- Amélioration du fichier `includes/env_loader.php` pour supporter les cas où les dépendances ne sont pas installées
- Ajout d'un module de secours `includes/env_loader_bypass.php` pour fonctionner sans la bibliothèque Dotenv
- Mise à jour du fichier README.md avec des instructions pour l'authentification Google

### Corrigé
- Problème d'erreur 500 sur la page d'accueil lorsque les dépendances ne sont pas installées
- Ajout d'une meilleure gestion des erreurs dans `index.php`
- Création d'une page d'erreur générique `views/error.php`

## [1.1.0] - 2025-03-15

### Ajouté
- Système de réinitialisation de mot de passe
- Envoi d'emails pour la récupération de compte

### Modifié
- Amélioration de la sécurité des sessions
- Optimisation des requêtes de base de données

## [1.0.0] - 2025-02-01

### Ajouté
- Première version de l'application MedConnect
- Authentification des utilisateurs (patients, médecins, admin)
- Gestion des profils
- Prise de rendez-vous
- Consultations en ligne
- Gestion du carnet de santé 