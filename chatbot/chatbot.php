<?php
require_once __DIR__ . '/../config/database.php';

class Chatbot {
    private $conn;
    private $conversation_id;
    private $user_id;

    public function __construct($user_id) {
        global $conn;
        $this->conn = $conn;
        $this->user_id = $user_id;
        $this->initializeConversation();
    }

    private function initializeConversation() {
        $sql = "INSERT INTO conversations (user_id) VALUES (?)";
        $stmt = $this->conn->prepare($sql);
        $stmt->bind_param("i", $this->user_id);
        $stmt->execute();
        $this->conversation_id = $this->conn->insert_id;
    }

    public function processMessage($message) {
        $this->saveMessage($message, 'user');
        $symptoms = $this->extractSymptoms($message);
        $diseases = $this->analyzeDiseases($symptoms);
        $response = $this->generateResponse($symptoms, $diseases);
        $this->saveMessage($response, 'bot');
        return $response;
    }

    private function saveMessage($content, $type) {
        $sql = "INSERT INTO messages (conversation_id, message_type, content) VALUES (?, ?, ?)";
        $stmt = $this->conn->prepare($sql);
        $stmt->bind_param("iss", $this->conversation_id, $type, $content);
        $stmt->execute();
    }

    private function extractSymptoms($message) {
        $symptoms = [];
        $sql = "SELECT id, name FROM symptoms";
        $result = $this->conn->query($sql);

        while ($row = $result->fetch_assoc()) {
            if (stripos($message, $row['name']) !== false) {
                $symptoms[] = $row;
            }
        }

        return $symptoms;
    }

    private function analyzeDiseases($symptoms) {
        $diseases = [];
        if (empty($symptoms)) return $diseases;

        $symptom_ids = array_column($symptoms, 'id');
        $symptom_ids_str = implode(',', $symptom_ids);

        $sql = "SELECT d.*, COUNT(sd.disease_id) AS symptom_match_count, 
                       AVG(sd.probability) AS avg_probability
                FROM diseases d
                JOIN symptom_disease sd ON d.id = sd.disease_id
                WHERE sd.symptom_id IN ($symptom_ids_str)
                GROUP BY d.id
                ORDER BY symptom_match_count DESC, avg_probability DESC
                LIMIT 5";
        
        $result = $this->conn->query($sql);
        while ($row = $result->fetch_assoc()) {
            $diseases[] = $row;
        }

        return $diseases;
    }

    private function generateResponse($symptoms, $diseases) {
        if (empty($symptoms)) {
            return "Je n'ai pas pu identifier clairement vos symptômes. Pourriez-vous les décrire plus en détail ?";
        }

        $response = "D'après vos symptômes, voici ce que je peux vous dire :\n\n";
        $response .= "Symptômes identifiés :\n";
        foreach ($symptoms as $symptom) {
            $response .= "- " . $symptom['name'] . "\n";
        }

        if (!empty($diseases)) {
            $response .= "\nCauses possibles :\n";
            foreach ($diseases as $disease) {
                $response .= "- " . $disease['name'] . " (Niveau de gravité : " . $disease['severity_level'] . ")\n";
            }

            $specialist = $this->findAvailableSpecialist($diseases[0]['id']);
            if ($specialist) {
                $response .= "\nJe vous recommande de consulter Dr. " . $specialist['name'] . 
                             ", spécialiste en " . $specialist['specialty'] . 
                             ". Voulez-vous que je prenne rendez-vous ?";
            }
        } else {
            $response .= "\nJe ne peux pas identifier précisément la cause de vos symptômes. " .
                         "Je vous recommande de consulter un médecin généraliste.";
        }

        return $response;
    }

    private function findAvailableSpecialist($disease_id) {
        $sql = "SELECT s.* FROM specialists s
                JOIN disease_specialist ds ON s.id = ds.specialist_id
                WHERE ds.disease_id = ? AND s.availability = 1
                LIMIT 1";
        $stmt = $this->conn->prepare($sql);
        $stmt->bind_param("i", $disease_id);
        $stmt->execute();
        $result = $stmt->get_result();
        return $result->fetch_assoc();
    }
}
?>
