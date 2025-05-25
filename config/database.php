<?php
require_once 'config.php';

/**
 * Classe de gestion de la connexion à la base de données
 * Utilise la configuration centralisée de config.php
 */
class Database {
    private $conn;

    /**
     * Obtient une connexion à la base de données
     * Utilise les paramètres de config.php
     * 
     * @return PDO Instance de connexion à la base de données
     */
    public function getConnection() {
        $this->conn = null;

        try {
            // Utilisation de la classe Config pour récupérer les paramètres
            $this->conn = Config::getDbConnection();
            
            // Log de la connexion réussie en mode développement
            if (!Config::isProduction()) {
                Config::logError("Connexion à la base de données établie avec succès");
            }
        } catch(Exception $exception) {
            // La gestion des erreurs est déjà faite dans Config::getDbConnection()
            // Nous propageons simplement l'exception ici
            throw $exception;
        }

        return $this->conn;
    }
    
    /**
     * Ferme explicitement la connexion à la base de données
     * 
     * @return void
     */
    public function closeConnection() {
        $this->conn = null;
    }
} 