<?php
session_start();

// Base de données des symptômes et spécialités (à étendre selon les besoins)
$symptomsDatabase = [
    'maux de tête' => [
        'speciality' => 'Neurologue',
        'urgence' => 'moyenne',
        'questions' => [
            'Depuis combien de temps avez-vous ces maux de tête ?',
            'La douleur est-elle pulsatile ?',
            'Avez-vous des nausées ?'
        ]
    ],
    'douleur poitrine' => [
        'speciality' => 'Cardiologue',
        'urgence' => 'haute',
        'questions' => [
            'Ressentez-vous une pression ou un serrement ?',
            'La douleur irradie-t-elle dans le bras gauche ?'
        ]
    ],
    'problèmes de peau' => [
        'speciality' => 'Dermatologue',
        'urgence' => 'basse',
        'questions' => [
            'Avez-vous des démangeaisons ?',
            'Depuis quand avez-vous ces symptômes ?'
        ]
    ],
    'mal de ventre' => [
        'speciality' => 'Gastro-entérologue',
        'urgence' => 'moyenne',
        'questions' => [
            'La douleur est-elle localisée ?',
            'Avez-vous des nausées ou vomissements ?'
        ]
    ]
];

// Initialiser la session si nécessaire
if (!isset($_SESSION['conversation_state'])) {
    $_SESSION['conversation_state'] = [
        'step' => 0,
        'current_symptoms' => [],
        'current_specialty' => null,
        'questions_asked' => []
    ];
}

// Recevoir le message de l'utilisateur
$userMessage = strtolower($_POST['message'] ?? '');
$state = &$_SESSION['conversation_state'];

function analyzeSymptoms($message) {
    global $symptomsDatabase;
    foreach ($symptomsDatabase as $symptom => $data) {
        if (strpos($message, $symptom) !== false) {
            return [
                'symptom' => $symptom,
                'data' => $data
            ];
        }
    }
    return null;
}

function getResponse() {
    global $state, $symptomsDatabase, $userMessage;

    // Si c'est le début de la conversation
    if ($state['step'] === 0) {
        $symptomMatch = analyzeSymptoms($userMessage);
        
        if ($symptomMatch) {
            $state['current_symptoms'][] = $symptomMatch['symptom'];
            $state['current_specialty'] = $symptomMatch['data']['speciality'];
            $state['step'] = 1;
            
            // Poser la première question de suivi
            if (!empty($symptomMatch['data']['questions'])) {
                $question = $symptomMatch['data']['questions'][0];
                $state['questions_asked'][] = $question;
                return "D'après vos symptômes, je pense que vous devriez consulter un {$symptomMatch['data']['speciality']}. " .
                       "Pour mieux vous orienter, j'ai besoin de quelques précisions. " . $question;
            }
        } else {
            return "Je ne suis pas sûr de comprendre vos symptômes. Pouvez-vous les décrire plus précisément ? " .
                   "Par exemple : maux de tête, douleur poitrine, problèmes de peau, etc.";
        }
    }
    
    // Si nous sommes en train de poser des questions de suivi
    if ($state['step'] === 1) {
        $currentSymptom = $state['current_symptoms'][0];
        $questions = $symptomsDatabase[$currentSymptom]['questions'];
        
        if (count($state['questions_asked']) < count($questions)) {
            // Poser la question suivante
            $nextQuestion = $questions[count($state['questions_asked'])];
            $state['questions_asked'][] = $nextQuestion;
            return $nextQuestion;
        } else {
            // Toutes les questions ont été posées, donner la recommandation finale
            $state['step'] = 2;
            $urgence = $symptomsDatabase[$currentSymptom]['urgence'];
            $speciality = $state['current_specialty'];
            
            // Réinitialiser l'état pour la prochaine conversation
            $_SESSION['conversation_state'] = [
                'step' => 0,
                'current_symptoms' => [],
                'current_specialty' => null,
                'questions_asked' => []
            ];
            
            return "Basé sur vos réponses, je vous recommande de consulter un $speciality. " .
                   ($urgence === 'haute' ? "Cette consultation est urgente, veuillez prendre rendez-vous le plus tôt possible. " : 
                    "Vous pouvez prendre rendez-vous dans les prochains jours. ") .
                   "Voulez-vous que je vous aide à trouver un spécialiste près de chez vous ?";
        }
    }
    
    return "Je suis désolé, je ne comprends pas. Pouvez-vous reformuler vos symptômes ?";
}

// Envoyer la réponse
echo getResponse();
?> 
