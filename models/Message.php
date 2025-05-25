<?php
class Message {
    private $db;
    private $table_name = "messages";

    public $id;
    public $contenu;
    public $date_envoi;
    public $sender_id;
    public $receiver_id;
    public $sender_type;
    public $lu;

    public function __construct($db) {
        $this->db = $db;
    }

    // Envoyer un message
    public function envoyer() {
        $query = "INSERT INTO " . $this->table_name . "
                (contenu, sender_id, receiver_id, sender_type)
                VALUES
                (:contenu, :sender_id, :receiver_id, :sender_type)";

        $stmt = $this->db->prepare($query);

        // Nettoyer les données
        $this->contenu = htmlspecialchars(strip_tags($this->contenu));
        $this->sender_id = htmlspecialchars(strip_tags($this->sender_id));
        $this->receiver_id = htmlspecialchars(strip_tags($this->receiver_id));
        $this->sender_type = htmlspecialchars(strip_tags($this->sender_type));

        // Lier les valeurs
        $stmt->bindParam(":contenu", $this->contenu);
        $stmt->bindParam(":sender_id", $this->sender_id);
        $stmt->bindParam(":receiver_id", $this->receiver_id);
        $stmt->bindParam(":sender_type", $this->sender_type);

        if($stmt->execute()) {
            return true;
        }
        return false;
    }

    // Récupérer les messages entre deux utilisateurs
    public function getConversation($user1_id, $user2_id) {
        // Convertir les paramètres en entiers
        $user1_id = (int)$user1_id;
        $user2_id = (int)$user2_id;

        $query = "SELECT m.*, 
                    CASE 
                        WHEN m.sender_id = ? THEN 'patient'
                        ELSE 'medecin'
                    END as sender_type,
                    CASE 
                        WHEN m.sender_id = ? THEN CONCAT(p.nom, ' ', p.prenom)
                        ELSE CONCAT(med.nom, ' ', med.prenom)
                    END as sender_nom
                FROM messages m
                LEFT JOIN medecin med ON m.sender_id = med.id
                LEFT JOIN patient p ON m.sender_id = p.id
                WHERE (m.sender_id = ? AND m.receiver_id = ?)
                OR (m.sender_id = ? AND m.receiver_id = ?)
                ORDER BY m.date_envoi ASC";

        try {
            $stmt = $this->db->prepare($query);
            
            // Lier les paramètres positionnels
            $stmt->bindValue(1, $user1_id, PDO::PARAM_INT);
            $stmt->bindValue(2, $user1_id, PDO::PARAM_INT);
            $stmt->bindValue(3, $user1_id, PDO::PARAM_INT);
            $stmt->bindValue(4, $user2_id, PDO::PARAM_INT);
            $stmt->bindValue(5, $user2_id, PDO::PARAM_INT);
            $stmt->bindValue(6, $user1_id, PDO::PARAM_INT);
            
            $stmt->execute();
            return $stmt;
        } catch (PDOException $e) {
            error_log("Erreur dans getConversation: " . $e->getMessage());
            throw $e;
        }
    }

    // Marquer un message comme lu
    public function marquerCommeLu($message_id) {
        $query = "UPDATE " . $this->table_name . "
                SET lu = 1
                WHERE id = :id";

        $stmt = $this->db->prepare($query);

        $stmt->bindParam(":id", $message_id);

        if($stmt->execute()) {
            return true;
        }
        return false;
    }

    // Compter les messages non lus
    public function compterMessagesNonLus($user_id) {
        $query = "SELECT COUNT(*) as total
                FROM " . $this->table_name . "
                WHERE receiver_id = :user_id AND lu = 0";

        $stmt = $this->db->prepare($query);

        $stmt->bindParam(":user_id", $user_id);

        $stmt->execute();

        $row = $stmt->fetch(PDO::FETCH_ASSOC);

        return $row['total'];
    }
} 