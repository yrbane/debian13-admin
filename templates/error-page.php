<?php
require_once __DIR__ . '/trusted-ips.php';

// Récupérer le code d'erreur depuis l'URL ou la variable d'environnement
$error_code = $_GET['code'] ?? $_SERVER['REDIRECT_STATUS'] ?? 500;
$error_code = (int) $error_code;

// Messages d'erreur
$errors = [
    400 => ['title' => 'Requête invalide', 'message' => 'Le serveur n\'a pas pu comprendre votre requête.', 'icon' => '🚫'],
    401 => ['title' => 'Authentification requise', 'message' => 'Vous devez vous identifier pour accéder à cette ressource.', 'icon' => '🔐'],
    403 => ['title' => 'Accès interdit', 'message' => 'Vous n\'avez pas les permissions pour accéder à cette ressource.', 'icon' => '⛔'],
    404 => ['title' => 'Page introuvable', 'message' => 'La page que vous recherchez n\'existe pas ou a été déplacée.', 'icon' => '🔍'],
    500 => ['title' => 'Erreur serveur', 'message' => 'Une erreur interne s\'est produite. Nos équipes sont informées.', 'icon' => '⚙️'],
    502 => ['title' => 'Passerelle incorrecte', 'message' => 'Le serveur a reçu une réponse invalide d\'un serveur en amont.', 'icon' => '🔗'],
    503 => ['title' => 'Service indisponible', 'message' => 'Le serveur est temporairement indisponible. Réessayez dans quelques instants.', 'icon' => '🔧'],
];

$error = $errors[$error_code] ?? $errors[500];
$is_trusted = is_trusted_ip();

http_response_code($error_code);
?>
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="robots" content="noindex, nofollow">
    <title>Erreur <?= $error_code ?> - <?= htmlspecialchars($error['title']) ?></title>
    <style>
        :root {
            --primary: #2563eb;
            --danger: #dc2626;
            --warning: #f59e0b;
            --bg: #f8fafc;
            --card: #ffffff;
            --text: #1e293b;
            --muted: #64748b;
            --border: #e2e8f0;
        }

        @media (prefers-color-scheme: dark) {
            :root {
                --bg: #0f172a;
                --card: #1e293b;
                --text: #f1f5f9;
                --muted: #94a3b8;
                --border: #334155;
            }
        }

        * { box-sizing: border-box; margin: 0; padding: 0; }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: var(--bg);
            color: var(--text);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 1rem;
            line-height: 1.6;
        }

        .container {
            max-width: 600px;
            width: 100%;
        }

        .card {
            background: var(--card);
            border-radius: 1rem;
            box-shadow: 0 4px 6px -1px rgb(0 0 0 / 0.1), 0 2px 4px -2px rgb(0 0 0 / 0.1);
            overflow: hidden;
        }

        .header {
            background: linear-gradient(135deg, var(--danger) 0%, #991b1b 100%);
            color: white;
            padding: 2rem;
            text-align: center;
        }

        .error-code {
            font-size: 5rem;
            font-weight: 800;
            line-height: 1;
            opacity: 0.9;
        }

        .error-icon {
            font-size: 3rem;
            margin-bottom: 0.5rem;
        }

        .content {
            padding: 2rem;
        }

        h1 {
            font-size: 1.5rem;
            margin-bottom: 0.5rem;
            color: var(--text);
        }

        .message {
            color: var(--muted);
            margin-bottom: 1.5rem;
        }

        .btn {
            display: inline-block;
            padding: 0.75rem 1.5rem;
            background: var(--primary);
            color: white;
            text-decoration: none;
            border-radius: 0.5rem;
            font-weight: 500;
            transition: opacity 0.2s;
        }

        .btn:hover { opacity: 0.9; }

        .debug {
            margin-top: 2rem;
            padding-top: 1.5rem;
            border-top: 1px solid var(--border);
        }

        .debug-title {
            font-size: 0.875rem;
            font-weight: 600;
            color: var(--warning);
            margin-bottom: 1rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        .debug-grid {
            display: grid;
            gap: 0.5rem;
            font-size: 0.8rem;
        }

        .debug-item {
            display: grid;
            grid-template-columns: 140px 1fr;
            gap: 0.5rem;
            padding: 0.5rem;
            background: var(--bg);
            border-radius: 0.25rem;
        }

        .debug-key {
            font-weight: 600;
            color: var(--muted);
        }

        .debug-value {
            word-break: break-all;
            font-family: monospace;
        }

        .footer {
            text-align: center;
            padding: 1rem 2rem 2rem;
            color: var(--muted);
            font-size: 0.75rem;
        }

        @media (max-width: 480px) {
            .error-code { font-size: 4rem; }
            .debug-item { grid-template-columns: 1fr; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="card">
            <div class="header">
                <div class="error-icon"><?= $error['icon'] ?></div>
                <div class="error-code"><?= $error_code ?></div>
            </div>

            <div class="content">
                <h1><?= htmlspecialchars($error['title']) ?></h1>
                <p class="message"><?= htmlspecialchars($error['message']) ?></p>

                <a href="/" class="btn">← Retour à l'accueil</a>

                <?php if ($is_trusted): ?>
                <div class="debug">
                    <div class="debug-title">
                        🔧 Informations de debug (IP de confiance)
                    </div>
                    <div class="debug-grid">
                        <div class="debug-item">
                            <span class="debug-key">Votre IP</span>
                            <span class="debug-value"><?= htmlspecialchars($_SERVER['REMOTE_ADDR'] ?? 'N/A') ?></span>
                        </div>
                        <div class="debug-item">
                            <span class="debug-key">URI demandée</span>
                            <span class="debug-value"><?= htmlspecialchars($_SERVER['REQUEST_URI'] ?? 'N/A') ?></span>
                        </div>
                        <div class="debug-item">
                            <span class="debug-key">Méthode</span>
                            <span class="debug-value"><?= htmlspecialchars($_SERVER['REQUEST_METHOD'] ?? 'N/A') ?></span>
                        </div>
                        <div class="debug-item">
                            <span class="debug-key">Referer</span>
                            <span class="debug-value"><?= htmlspecialchars($_SERVER['HTTP_REFERER'] ?? 'Direct') ?></span>
                        </div>
                        <div class="debug-item">
                            <span class="debug-key">User-Agent</span>
                            <span class="debug-value"><?= htmlspecialchars($_SERVER['HTTP_USER_AGENT'] ?? 'N/A') ?></span>
                        </div>
                        <div class="debug-item">
                            <span class="debug-key">Serveur</span>
                            <span class="debug-value"><?= htmlspecialchars($_SERVER['SERVER_NAME'] ?? 'N/A') ?></span>
                        </div>
                        <div class="debug-item">
                            <span class="debug-key">Port</span>
                            <span class="debug-value"><?= htmlspecialchars($_SERVER['SERVER_PORT'] ?? 'N/A') ?></span>
                        </div>
                        <div class="debug-item">
                            <span class="debug-key">Protocole</span>
                            <span class="debug-value"><?= htmlspecialchars($_SERVER['SERVER_PROTOCOL'] ?? 'N/A') ?></span>
                        </div>
                        <div class="debug-item">
                            <span class="debug-key">Document Root</span>
                            <span class="debug-value"><?= htmlspecialchars($_SERVER['DOCUMENT_ROOT'] ?? 'N/A') ?></span>
                        </div>
                        <div class="debug-item">
                            <span class="debug-key">Script</span>
                            <span class="debug-value"><?= htmlspecialchars($_SERVER['SCRIPT_FILENAME'] ?? 'N/A') ?></span>
                        </div>
                        <div class="debug-item">
                            <span class="debug-key">Timestamp</span>
                            <span class="debug-value"><?= date('Y-m-d H:i:s T') ?></span>
                        </div>
                        <?php if (!empty($_SERVER['REDIRECT_URL'])): ?>
                        <div class="debug-item">
                            <span class="debug-key">Redirect URL</span>
                            <span class="debug-value"><?= htmlspecialchars($_SERVER['REDIRECT_URL']) ?></span>
                        </div>
                        <?php endif; ?>
                        <?php if (!empty($_SERVER['REDIRECT_QUERY_STRING'])): ?>
                        <div class="debug-item">
                            <span class="debug-key">Query String</span>
                            <span class="debug-value"><?= htmlspecialchars($_SERVER['REDIRECT_QUERY_STRING']) ?></span>
                        </div>
                        <?php endif; ?>
                    </div>
                </div>
                <?php endif; ?>
            </div>

            <div class="footer">
                <?= htmlspecialchars($_SERVER['SERVER_SOFTWARE'] ?? 'Web Server') ?>
            </div>
        </div>
    </div>
</body>
</html>
