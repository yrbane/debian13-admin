#!/bin/bash
set -euo pipefail

MAILTO="root@example.com"
LOGFILE="/var/log/rkhunter_scan_$(date +%Y%m%d).log"

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

# Exécute le scan
rkhunter --check --skip-keypress --report-warnings-only > "$LOGFILE" 2>&1

# Si des warnings sont détectés, envoie un mail
if grep -qE "(Warning|Infected)" "$LOGFILE"; then
    WARNINGS=$(grep -E "(Warning|Infected)" "$LOGFILE")
    BODY="<html><body>"
    BODY+="<h2 style='color:#cc0000;'>rkhunter - Alertes détectées</h2>"
    BODY+="<p><strong>Serveur :</strong> $(hostname)</p>"
    BODY+="<p><strong>Date :</strong> $(date '+%Y-%m-%d %H:%M:%S')</p>"
    BODY+="<pre style='background:#f5f5f5;padding:10px;'>$WARNINGS</pre>"
    BODY+="<p>Consulter le log complet : $LOGFILE</p>"
    BODY+="</body></html>"
    send_report "[rkhunter] Alertes sur $(hostname)" "$BODY"
else
    # Rapport hebdomadaire "all clear" le dimanche (jour 7)
    DAYOFWEEK=$(date +%u)
    if [[ $DAYOFWEEK -eq 7 ]]; then
        BODY="<html><body>"
        BODY+="<h2 style='color:#00aa00;'>rkhunter - Rapport hebdomadaire sur $(hostname)</h2>"
        BODY+="<p><strong>Serveur :</strong> $(hostname)</p>"
        BODY+="<p><strong>Date :</strong> $(date '+%Y-%m-%d %H:%M:%S')</p>"
        BODY+="<p>Aucune alerte détectée cette semaine.</p>"
        BODY+="<p>Le scan rkhunter s'est exécuté correctement.</p>"
        BODY+="</body></html>"
        send_report "[rkhunter] Rapport hebdomadaire $(hostname)" "$BODY"
    fi
fi

# Nettoyage logs > 30 jours
find /var/log -name "rkhunter_scan_*.log" -mtime +30 -delete 2>/dev/null || true
