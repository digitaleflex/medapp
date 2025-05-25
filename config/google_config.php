<?php
// Configuration Google OAuth2
return [
    'client_id' => 'VOTRE_CLIENT_ID',
    'client_secret' => 'VOTRE_CLIENT_SECRET',
    'redirect_uri' => 'http://localhost/medapp/auth/google-callback.php',
    'scopes' => [
        'https://www.googleapis.com/auth/calendar',
        'https://www.googleapis.com/auth/calendar.events'
    ]
]; 