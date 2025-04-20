# Configuration de l'authentification Google

Ce document explique comment configurer l'authentification Google OAuth 2.0 pour l'application MedApp.

## Prérequis

1. Un compte Google Developer (console.developers.google.com)
2. PHP 7.4 ou supérieur
3. Composer installé

## Étapes de configuration

### 1. Créer un projet dans la Google Cloud Console

1. Connectez-vous à la [Google Cloud Console](https://console.cloud.google.com/)
2. Créez un nouveau projet
3. Naviguez vers "APIs & Services" > "Credentials"
4. Cliquez sur "Create Credentials" > "OAuth client ID"
5. Choisissez "Web application"
6. Donnez un nom à votre client OAuth (exemple: "MedApp OAuth Client")
7. Ajoutez l'URL de redirection autorisée: `http://localhost/medapp-master/auth/google-callback.php`
   (Remplacez localhost par votre domaine en production)
8. Cliquez sur "Create"

### 2. Configurer le fichier .env

Ajoutez ou modifiez les variables suivantes dans votre fichier `.env`:

```
# Configuration Google OAuth
GOOGLE_CLIENT_ID=votre_client_id_google
GOOGLE_CLIENT_SECRET=votre_client_secret_google
GOOGLE_REDIRECT_URI=http://localhost/medapp-master/auth/google-callback.php
```

### 3. Installer les dépendances

Exécutez la commande suivante à la racine du projet:

```bash
composer install
```

Cela installera la bibliothèque Google API Client et les autres dépendances nécessaires.

### 4. Vérifier la configuration

Assurez-vous que:
- Le fichier `.env` est correctement configuré
- Les tables `users` et `patients` contiennent les champs nécessaires (notamment `google_id`)
- Les dépendances sont installées via Composer

## Utilisation

Pour ajouter un bouton de connexion Google à votre page de connexion, utilisez le code HTML suivant:

```html
<a href="/medapp-master/auth/google-login.php" class="btn btn-google">
    <i class="fab fa-google"></i> Se connecter avec Google
</a>
```

## Dépannage

Si vous rencontrez des problèmes:
1. Vérifiez les journaux d'erreurs (`/logs/error.log`)
2. Assurez-vous que les URIs de redirection correspondent exactement
3. Vérifiez que le client ID et le secret sont correctement copiés depuis la console Google 