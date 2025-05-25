<?php
require_once '../vendor/autoload.php';
require_once '../config/config.php';
require_once '../includes/session.php';

// Vérifier si l'utilisateur est connecté
requireLogin();
requireRole('patient');

$user_id = $_SESSION['user_id'];

// Charger la configuration Google
$config = require '../config/google_config.php';

// Créer le client Google
$client = new Google_Client();
$client->setClientId($config['client_id']);
$client->setClientSecret($config['client_secret']);
$client->setRedirectUri($config['redirect_uri']);
$client->addScope($config['scopes']);

// Générer l'URL d'autorisation
$auth_url = $client->createAuthUrl();

// Stocker l'état dans la session pour la vérification
$_SESSION['google_auth_state'] = $client->getState();

// Rediriger vers la page d'autorisation Google
header('Location: ' . $auth_url);
exit; 