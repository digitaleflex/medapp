<?php
require_once 'User.php';

class Patient extends User {
    public function __construct($db) {
        parent::__construct($db);
        $this->table_name = "patient";
        $this->role = "patient";
    }
    
    // Implémentation de la méthode register pour les patients
    public function register() {
        $query = "INSERT INTO " . $this->table_name . " 
                  (nom, prenom, datenais, email, contact, password, role) 
                  VALUES (?, ?, ?, ?, ?, ?, ?)";
        
        $stmt = $this->db->prepare($query);
        
        // Nettoyage et sécurisation des entrées
        $this->nom = htmlspecialchars(strip_tags($this->nom));
        $this->prenom = htmlspecialchars(strip_tags($this->prenom));
        $this->email = htmlspecialchars(strip_tags($this->email));
        $this->contact = htmlspecialchars(strip_tags($this->contact));
        
        // Hashage du mot de passe
        $hashed_password = $this->hashPassword($this->password);
        
        // Binding des valeurs
        $stmt->bindParam(1, $this->nom);
        $stmt->bindParam(2, $this->prenom);
        $stmt->bindParam(3, $this->datenais);
        $stmt->bindParam(4, $this->email);
        $stmt->bindParam(5, $this->contact);
        $stmt->bindParam(6, $hashed_password);
        $stmt->bindParam(7, $this->role);
        
        if($stmt->execute()) {
            return true;
        }
        
        return false;
    }
    
    // Méthode pour mettre à jour un patient
    public function update() {
        $query = "UPDATE " . $this->table_name . " 
                  SET nom = ?, prenom = ?, datenais = ?, email = ?, contact = ? 
                  WHERE id = ?";
        
        $stmt = $this->db->prepare($query);
        
        // Nettoyage et sécurisation des entrées
        $this->nom = htmlspecialchars(strip_tags($this->nom));
        $this->prenom = htmlspecialchars(strip_tags($this->prenom));
        $this->email = htmlspecialchars(strip_tags($this->email));
        $this->contact = htmlspecialchars(strip_tags($this->contact));
        
        // Binding des valeurs
        $stmt->bindParam(1, $this->nom);
        $stmt->bindParam(2, $this->prenom);
        $stmt->bindParam(3, $this->datenais);
        $stmt->bindParam(4, $this->email);
        $stmt->bindParam(5, $this->contact);
        $stmt->bindParam(6, $this->id);
        
        if($stmt->execute()) {
            return true;
        }
        
        return false;
    }
    
    // Méthode pour mettre à jour le mot de passe
    public function updatePassword() {
        $query = "UPDATE " . $this->table_name . " SET password = ? WHERE id = ?";
        
        $stmt = $this->db->prepare($query);
        
        // Hashage du nouveau mot de passe
        $hashed_password = $this->hashPassword($this->password);
        
        // Binding des valeurs
        $stmt->bindParam(1, $hashed_password);
        $stmt->bindParam(2, $this->id);
        
        if($stmt->execute()) {
            return true;
        }
        
        return false;
    }
} 