<?php
abstract class User {
    protected $db;
    protected $table_name;
    
    // Propriétés communes
    public $id;
    public $nom;
    public $prenom;
    public $datenais;
    public $email;
    public $contact;
    public $password;
    public $role;
    
    // Constructeur
    public function __construct($db) {
        $this->db = $db;
    }
    
    // Méthode abstraite pour l'inscription
    abstract public function register();
    
    // Méthode pour vérifier si l'email existe déjà
    public function emailExists() {
        $query = "SELECT id, password, nom, prenom, role FROM " . $this->table_name . " WHERE email = ? LIMIT 0,1";
        $stmt = $this->db->prepare($query);
        $stmt->bindParam(1, $this->email);
        $stmt->execute();
        
        if($stmt->rowCount() > 0) {
            $row = $stmt->fetch(PDO::FETCH_ASSOC);
            $this->id = $row['id'];
            $this->password = $row['password'];
            $this->nom = $row['nom'];
            $this->prenom = $row['prenom'];
            $this->role = $row['role'];
            return true;
        }
        
        return false;
    }
    
    // Méthode pour hacher un mot de passe
    protected function hashPassword($password) {
        return password_hash($password, PASSWORD_BCRYPT);
    }
    
    // Méthode pour générer un token de réinitialisation
    public function generateResetToken() {
        $token = bin2hex(random_bytes(32));
        $expire = date('Y-m-d H:i:s', strtotime('+1 hour'));
        
        // Stocker le token dans une table de réinitialisation
        $query = "INSERT INTO password_reset (email, token, expire_date) VALUES (?, ?, ?)";
        $stmt = $this->db->prepare($query);
        $stmt->bindParam(1, $this->email);
        $stmt->bindParam(2, $token);
        $stmt->bindParam(3, $expire);
        
        if($stmt->execute()) {
            return $token;
        }
        return false;
    }
} 