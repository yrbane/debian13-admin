#!/bin/bash
set -euo pipefail

MAILTO="root@example.com"
LOGFILE="/var/log/aide/aide_check_$(date +%Y%m%d).log"

mkdir -p /var/log/aide

send_report() {
    local subject="$1" body="$2"
    { echo "To: $MAILTO"
      echo "Subject: $subject"
      echo "Content-Type: text/html; charset=UTF-8"
      echo "MIME-Version: 1.0"
      echo ""
      echo "$body"
    } | sendmail -t
}

# Vérifie si la base existe
if [ ! -f /var/lib/aide/aide.db ]; then
    echo "Base AIDE non initialisée" > "$LOGFILE"
    exit 1
fi

# Exécute la vérification
aide --config=/etc/aide/aide.conf --check > "$LOGFILE" 2>&1
RESULT=$?

# Si des changements sont détectés (exit code != 0)
if [ $RESULT -ne 0 ]; then
    CHANGES=$(head -100 "$LOGFILE")
    BODY="<html><body>"
    BODY+="<h2 style='color:#cc0000;'>AIDE - Fichiers modifiés détectés</h2>"
    BODY+="<p><strong>Serveur :</strong> $(hostname)</p>"
    BODY+="<p><strong>Date :</strong> $(date '+%Y-%m-%d %H:%M:%S')</p>"
    BODY+="<p>Des modifications de fichiers système ont été détectées :</p>"
    BODY+="<pre style='background:#f5f5f5;padding:10px;font-size:11px;'>$CHANGES</pre>"
    BODY+="<p><strong>Actions recommandées :</strong></p>"
    BODY+="<ul>"
    BODY+="<li>Vérifier si les changements sont légitimes (mises à jour système)</li>"
    BODY+="<li>Si OK, mettre à jour la base : <code>aide --update && mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db</code></li>"
    BODY+="</ul>"
    BODY+="</body></html>"
    send_report "[AIDE] Modifications détectées sur $(hostname)" "$BODY"
else
    # Rapport hebdomadaire "all clear" le lundi (jour 1)
    DAYOFWEEK=$(date +%u)
    if [[ $DAYOFWEEK -eq 1 ]]; then
        BODY="<html><body>"
        BODY+="<h2 style='color:#00aa00;'>AIDE - Rapport hebdomadaire sur $(hostname)</h2>"
        BODY+="<p><strong>Serveur :</strong> $(hostname)</p>"
        BODY+="<p><strong>Date :</strong> $(date '+%Y-%m-%d %H:%M:%S')</p>"
        BODY+="<p>Aucune modification de fichiers système détectée cette semaine.</p>"
        BODY+="<p>La vérification d'intégrité s'est exécutée correctement.</p>"
        BODY+="</body></html>"
        send_report "[AIDE] Rapport hebdomadaire $(hostname)" "$BODY"
    fi
fi

# Nettoyage logs > 30 jours
find /var/log/aide -name "aide_check_*.log" -mtime +30 -delete 2>/dev/null || true
