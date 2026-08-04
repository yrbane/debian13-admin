<?php
/**
 * Error notification (5xx) with throttle mechanism
 * Deployed by debian13-server.sh — Do not edit manually
 *
 * Placeholders replaced at deploy time:
 *   __ADMIN_EMAIL__, __HOSTNAME_FQDN__, __ERROR_THROTTLE_SECONDS__
 */

define('ERROR_ADMIN_EMAIL', '__ADMIN_EMAIL__');
define('ERROR_HOSTNAME', '__HOSTNAME_FQDN__');
define('ERROR_THROTTLE_SECONDS', __ERROR_THROTTLE_SECONDS__);

/**
 * Check if we should send a notification (throttle per error code)
 */
function should_notify(int $code): bool {
    if ($code < 500) {
        return false;
    }

    $lock_file = '/tmp/error_notify_' . $code . '.lock';

    if (file_exists($lock_file)) {
        $last_time = filemtime($lock_file);
        if ($last_time !== false && (time() - $last_time) < ERROR_THROTTLE_SECONDS) {
            return false;
        }
    }

    // Touch the lock file
    @touch($lock_file);
    return true;
}

/**
 * Send error notification email for 5xx errors
 */
function send_error_notification(int $code, array $context = []): void {
    // Ne JAMAIS laisser un warning fuiter dans la sortie de la sous-requete
    // ErrorDocument (sinon reponse FCGI corrompue -> AH01071 -> 502).
    $prev_display = ini_set('display_errors', '0');
    try {
        _send_error_notification($code, $context);
    } finally {
        if ($prev_display !== false) {
            ini_set('display_errors', $prev_display);
        }
    }
}

function _send_error_notification(int $code, array $context = []): void {
    if (!should_notify($code)) {
        return;
    }

    $ip       = $context['ip']       ?? ($_SERVER['REMOTE_ADDR'] ?? 'unknown');
    $uri      = $context['uri']      ?? ($_SERVER['REQUEST_URI'] ?? '/');
    $method   = $context['method']   ?? ($_SERVER['REQUEST_METHOD'] ?? 'GET');
    $referer  = $context['referer']  ?? ($_SERVER['HTTP_REFERER'] ?? 'Direct');
    $ua       = $context['ua']       ?? ($_SERVER['HTTP_USER_AGENT'] ?? 'unknown');
    $host     = $context['host']     ?? ($_SERVER['SERVER_NAME'] ?? ERROR_HOSTNAME);
    $port     = $context['port']     ?? ($_SERVER['SERVER_PORT'] ?? '443');
    $protocol = $context['protocol'] ?? ($_SERVER['SERVER_PROTOCOL'] ?? 'HTTP/1.1');
    $time     = date('Y-m-d H:i:s T');

    $subject = sprintf('[%s] Erreur %d sur %s', ERROR_HOSTNAME, $code, $uri);

    $throttle = ERROR_THROTTLE_SECONDS;

    $body = <<<EOT
Erreur HTTP {$code} detectee sur {$host}

Timestamp : {$time}
Code      : {$code}
URI       : {$uri}
Methode   : {$method}
IP client : {$ip}
Referer   : {$referer}
User-Agent: {$ua}

Serveur   : {$host}:{$port}
Protocole : {$protocol}
Hostname  : {$host}

---
Notification automatique - throttle: 1 email / {$code} toutes les {$throttle} secondes
Serveur: {$host}
EOT;

    $headers = [
        'From: noreply@' . ERROR_HOSTNAME,
        'X-Mailer: ErrorNotify/1.0',
        'X-Error-Code: ' . $code,
        'Content-Type: text/plain; charset=UTF-8',
    ];

    @mail(ERROR_ADMIN_EMAIL, $subject, $body, implode("\r\n", $headers));

    // Log to syslog for audit trail
    openlog('error-notify', LOG_PID, LOG_LOCAL0);
    syslog(LOG_WARNING, sprintf(
        'HTTP %d | IP=%s | URI=%s | Method=%s | UA=%s',
        $code, $ip, $uri, $method, $ua
    ));
    closelog();
}
