<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Assistant Médical Virtuel</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        .chat-container {
            max-width: 600px;
            margin: 20px auto;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }
        .chat-messages {
            height: 400px;
            overflow-y: auto;
            padding: 20px;
            border: 1px solid #ddd;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        .message {
            margin-bottom: 10px;
            padding: 10px;
            border-radius: 5px;
        }
        .bot-message {
            background-color: #f0f0f0;
            margin-right: 20%;
        }
        .user-message {
            background-color: #007bff;
            color: white;
            margin-left: 20%;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="chat-container">
            <h2 class="text-center mb-4">Assistant Médical Virtuel</h2>
            <div class="chat-messages" id="chatMessages"></div>
            <form id="chatForm" class="d-flex">
                <input type="text" id="userInput" class="form-control me-2" placeholder="Décrivez vos symptômes..." required>
                <button type="submit" class="btn btn-primary">Envoyer</button>
            </form>
        </div>
    </div>

    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    <script>
        $(document).ready(function() {
            addBotMessage("Bonjour ! Je suis votre assistant médical virtuel. Quels sont vos symptômes ?");

            $("#chatForm").on("submit", function(e) {
                e.preventDefault();
                const userInput = $("#userInput").val().trim();
                if (userInput) {
                    addUserMessage(userInput);
                    $.post('process.php', { message: userInput }, function(response) {
                        addBotMessage(response);
                    }).fail(function() {
                        addBotMessage("Désolé, une erreur est survenue.");
                    });
                    $("#userInput").val('');
                }
            });
        });

        function addUserMessage(message) {
            $("#chatMessages").append(`<div class="message user-message">${message}</div>`);
            scrollToBottom();
        }

        function addBotMessage(message) {
            $("#chatMessages").append(`<div class="message bot-message">${message}</div>`);
            scrollToBottom();
        }

        function scrollToBottom() {
            const chat = document.getElementById('chatMessages');
            chat.scrollTop = chat.scrollHeight;
        }
    </script>
</body>
</html>
