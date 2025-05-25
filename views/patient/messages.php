<?php
require_once '../../includes/session.php';
require_once '../../config/database.php';

requireLogin();
requireRole('patient');

$user_id = $_SESSION['user_id'];
$db = (new Database())->getConnection();

// Liste des médecins avec qui le patient a eu un rendez-vous
$stmt = $db->prepare("SELECT DISTINCT m.id, m.nom, m.prenom FROM medecin m JOIN rendezvous r ON m.id = r.idmedecin WHERE r.idpatient = ? ORDER BY m.nom, m.prenom");
$stmt->execute([$user_id]);
$medecins = $stmt->fetchAll(PDO::FETCH_ASSOC);
$selected_medecin = isset($_GET['medecin_id']) ? (int)$_GET['medecin_id'] : ($medecins[0]['id'] ?? null);
?>

<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Messagerie - MedConnect</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        .chat-bubble {
            max-width: 70%;
            padding: 0.75rem 1rem;
            border-radius: 1.25rem;
            margin-bottom: 0.5rem;
            display: inline-block;
            word-break: break-word;
            animation: fadeIn 0.3s ease-in-out;
        }
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }
        .bubble-me {
            background: #1e40af;
            color: white;
            border-bottom-right-radius: 0.25rem;
            margin-left: auto;
        }
        .bubble-them {
            background: #e5e7eb;
            color: #1e293b;
            border-bottom-left-radius: 0.25rem;
            margin-right: auto;
        }
        .chat-container {
            height: 60vh;
            overflow-y: auto;
            padding: 1rem;
            background: #f1f5f9;
        }
        .loading {
            display: none;
            text-align: center;
            padding: 1rem;
            color: #666;
        }
        .loading.active {
            display: block;
        }
        .typing-indicator {
            display: none;
            padding: 0.5rem;
            color: #666;
            font-style: italic;
        }
        .typing-indicator.active {
            display: block;
        }
        .message-status {
            font-size: 0.75rem;
            margin-top: 0.25rem;
            opacity: 0.7;
        }
        .message-status i {
            margin-left: 0.25rem;
        }
    </style>
</head>
<body class="bg-gradient-to-br from-[#EFF6FF] to-[#DBEAFE] min-h-screen">
    <div class="flex min-h-screen">
        <!-- Liste des médecins -->
        <aside class="w-72 bg-white shadow-lg flex flex-col py-6 px-4">
            <h2 class="text-xl font-bold text-[#1B5E20] mb-6"><i class="fas fa-user-md mr-2"></i>Mes Médecins</h2>
            <ul>
                <?php foreach ($medecins as $m): ?>
                    <li class="mb-2">
                        <a href="?medecin_id=<?php echo $m['id']; ?>" class="block px-4 py-2 rounded-lg <?php echo ($selected_medecin == $m['id']) ? 'bg-[#E8F5E9] font-bold text-[#1B5E20]' : 'hover:bg-[#F1F8E9]'; ?>">
                            <?php echo htmlspecialchars($m['prenom'] . ' ' . $m['nom']); ?>
                        </a>
                    </li>
                <?php endforeach; ?>
            </ul>
        </aside>
        <!-- Zone de chat -->
        <main class="flex-1 flex flex-col">
            <header class="bg-white shadow-sm px-6 py-4 flex items-center">
                <h1 class="text-2xl font-bold text-[#1B5E20] flex-1"><i class="fas fa-comments mr-2"></i>Conversation</h1>
                <?php if ($selected_medecin): ?>
                    <span class="text-[#1e40af] font-semibold">
                        <?php
                        $med = array_filter($medecins, fn($md) => $md['id'] == $selected_medecin);
                        $med = $med ? array_values($med)[0] : null;
                        if ($med) echo htmlspecialchars($med['prenom'] . ' ' . $med['nom']);
                        ?>
                    </span>
                <?php endif; ?>
            </header>
            <div id="chat" class="chat-container flex-1"></div>
            <div id="loading" class="loading">
                <i class="fas fa-spinner fa-spin mr-2"></i>Chargement des messages...
                        </div>
            <div id="typing" class="typing-indicator">
                Le médecin est en train d'écrire...
                    </div>
            <form id="sendForm" class="flex items-center p-4 bg-white border-t">
                <input type="hidden" name="receiver_id" id="receiver_id" value="<?php echo $selected_medecin; ?>">
                <input type="text" name="contenu" id="contenu" class="flex-1 px-4 py-2 rounded-lg border border-gray-300 focus:outline-none focus:border-[#2E7D32] mr-2" placeholder="Écrire un message..." autocomplete="off" required>
                <button type="submit" class="bg-[#1e40af] hover:bg-[#2563eb] text-white px-6 py-2 rounded-lg font-semibold" id="sendButton">
                                            <i class="fas fa-paper-plane"></i>
                                        </button>
                                    </form>
            </main>
    </div>
    <script>
    const chat = document.getElementById('chat');
    const form = document.getElementById('sendForm');
    const contenu = document.getElementById('contenu');
    const receiver_id = document.getElementById('receiver_id').value;
    const loading = document.getElementById('loading');
    const typing = document.getElementById('typing');
    const sendButton = document.getElementById('sendButton');
    let isTyping = false;
    let typingTimeout;

    function escapeHtml(text) {
        var map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' };
        return text.replace(/[&<>"']/g, function(m) { return map[m]; });
    }

    function showLoading() {
        loading.classList.add('active');
    }

    function hideLoading() {
        loading.classList.remove('active');
    }

    function showTyping() {
        if (!isTyping) {
            isTyping = true;
            typing.classList.add('active');
        }
        clearTimeout(typingTimeout);
        typingTimeout = setTimeout(() => {
            isTyping = false;
            typing.classList.remove('active');
        }, 3000);
    }

        function loadMessages() {
        if (!receiver_id) return;
        showLoading();
        fetch('../../api/messages.php?other_id=' + receiver_id)
            .then(res => res.json())
            .then(messages => {
                chat.innerHTML = '';
                messages.forEach(msg => {
                    const isMe = msg.sender_type === 'patient';
                    const bubble = document.createElement('div');
                    bubble.className = 'chat-bubble ' + (isMe ? 'bubble-me' : 'bubble-them');
                    
                    const messageContent = document.createElement('div');
                    messageContent.innerHTML = escapeHtml(msg.contenu);
                    
                    const messageStatus = document.createElement('div');
                    messageStatus.className = 'message-status';
                    messageStatus.innerHTML = `
                                            ${new Date(msg.date_envoi).toLocaleString('fr-FR')}
                        ${isMe ? '<i class="fas fa-check-double"></i>' : ''}
                    `;
                    
                    bubble.appendChild(messageContent);
                    bubble.appendChild(messageStatus);
                    chat.appendChild(bubble);
                });
                chat.scrollTop = chat.scrollHeight;
                hideLoading();
            })
            .catch(error => {
                console.error('Erreur lors du chargement des messages:', error);
                hideLoading();
            });
    }

    form.onsubmit = function(e) {
        e.preventDefault();
        if (!contenu.value.trim()) return;

        const data = new FormData(form);
        data.append('sender_type', 'patient');
        
        sendButton.disabled = true;
        sendButton.innerHTML = '<i class="fas fa-spinner fa-spin"></i>';
        
        fetch('../../api/envoyer_message.php', {
                    method: 'POST',
            body: data
        })
        .then(res => res.json())
        .then(resp => {
            if (resp.success) {
                contenu.value = '';
                        loadMessages();
                    } else {
                alert('Erreur lors de l\'envoi du message. Veuillez réessayer.');
            }
        })
        .catch(error => {
            console.error('Erreur lors de l\'envoi du message:', error);
            alert('Erreur lors de l\'envoi du message. Veuillez réessayer.');
        })
        .finally(() => {
            sendButton.disabled = false;
            sendButton.innerHTML = '<i class="fas fa-paper-plane"></i>';
        });
    };

    // Rafraîchissement auto
    setInterval(loadMessages, 2000);
    window.onload = loadMessages;

    // Vérification du statut de frappe
    function checkTyping() {
        if (!receiver_id) return;
        fetch('../../api/check_typing.php?user_id=' + receiver_id)
            .then(res => res.json())
            .then(data => {
                if (data.is_typing) {
                    showTyping();
                }
            })
            .catch(error => console.error('Erreur lors de la vérification du statut de frappe:', error));
    }

    // Vérification périodique du statut de frappe
    setInterval(checkTyping, 2000);

    // Gestion du focus et du blur sur l'input
    contenu.addEventListener('focus', () => {
        if (receiver_id) {
            fetch('../../api/typing.php', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    receiver_id: receiver_id,
                    is_typing: true
                })
            });
        }
    });

    contenu.addEventListener('blur', () => {
        if (receiver_id) {
            fetch('../../api/typing.php', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    receiver_id: receiver_id,
                    is_typing: false
                })
            });
        }
    });
    </script>
</body>
</html> 