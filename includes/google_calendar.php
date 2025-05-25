<?php
require_once __DIR__ . '/../vendor/autoload.php';
require_once __DIR__ . '/../config/config.php';
require_once __DIR__ . '/../config/google_config.php';

class GoogleCalendar {
    private $client;
    private $service;
    private $user_id;

    public function __construct($user_id) {
        $this->user_id = $user_id;
        $this->initializeClient();
    }

    private function initializeClient() {
        $this->client = new Google_Client();
        $this->client->setClientId(GOOGLE_CLIENT_ID);
        $this->client->setClientSecret(GOOGLE_CLIENT_SECRET);
        $this->client->setScopes(GOOGLE_SCOPES);

        // Récupérer le token depuis la base de données
        $stmt = db()->prepare("SELECT access_token, refresh_token, expires_at FROM google_tokens WHERE user_id = ?");
        $stmt->execute([$this->user_id]);
        $token = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($token) {
            $this->client->setAccessToken([
                'access_token' => $token['access_token'],
                'refresh_token' => $token['refresh_token'],
                'expires_in' => strtotime($token['expires_at']) - time()
            ]);

            // Rafraîchir le token si nécessaire
            if ($this->client->isAccessTokenExpired()) {
                $this->refreshToken();
            }
        }

        $this->service = new Google_Service_Calendar($this->client);
    }

    private function refreshToken() {
        if ($this->client->getRefreshToken()) {
            $this->client->fetchAccessTokenWithRefreshToken($this->client->getRefreshToken());
            $token = $this->client->getAccessToken();

            // Mettre à jour le token dans la base de données
            $stmt = db()->prepare("
                UPDATE google_tokens 
                SET access_token = ?, expires_at = ?
                WHERE user_id = ?
            ");
            $expires_at = date('Y-m-d H:i:s', time() + $token['expires_in']);
            $stmt->execute([$token['access_token'], $expires_at, $this->user_id]);
        }
    }

    public function addEvent($event) {
        try {
            $googleEvent = new Google_Service_Calendar_Event([
                'summary' => $event['title'],
                'description' => $event['description'],
                'start' => [
                    'dateTime' => date('c', strtotime($event['start'])),
                    'timeZone' => 'Europe/Paris',
                ],
                'end' => [
                    'dateTime' => date('c', strtotime($event['end'])),
                    'timeZone' => 'Europe/Paris',
                ],
                'reminders' => [
                    'useDefault' => false,
                    'overrides' => [
                        ['method' => 'email', 'minutes' => 24 * 60],
                        ['method' => 'popup', 'minutes' => 30],
                    ],
                ],
            ]);

            $createdEvent = $this->service->events->insert('primary', $googleEvent);
            return $createdEvent->getId();
        } catch (Exception $e) {
            error_log("Erreur lors de l'ajout d'un événement Google Calendar : " . $e->getMessage());
            throw $e;
        }
    }

    public function updateEvent($eventId, $event) {
        try {
            $googleEvent = $this->service->events->get('primary', $eventId);
            
            $googleEvent->setSummary($event['title']);
            $googleEvent->setDescription($event['description']);
            $googleEvent->setStart(new Google_Service_Calendar_EventDateTime([
                'dateTime' => date('c', strtotime($event['start'])),
                'timeZone' => 'Europe/Paris',
            ]));
            $googleEvent->setEnd(new Google_Service_Calendar_EventDateTime([
                'dateTime' => date('c', strtotime($event['end'])),
                'timeZone' => 'Europe/Paris',
            ]));

            $updatedEvent = $this->service->events->update('primary', $eventId, $googleEvent);
            return $updatedEvent->getId();
        } catch (Exception $e) {
            error_log("Erreur lors de la mise à jour d'un événement Google Calendar : " . $e->getMessage());
            throw $e;
        }
    }

    public function deleteEvent($eventId) {
        try {
            $this->service->events->delete('primary', $eventId);
            return true;
        } catch (Exception $e) {
            error_log("Erreur lors de la suppression d'un événement Google Calendar : " . $e->getMessage());
            throw $e;
        }
    }
} 