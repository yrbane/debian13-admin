#!/bin/bash

# Destinataire du mail
MAILTO="root@example.com"

# Logs
LOG_DIR="/var/log/clamav"
TODAY=$(date +'%Y-%m-%d')
LOG_FILE="$LOG_DIR/scan-$TODAY.log"
mkdir -p "$LOG_DIR"

# Ne lance pas freshclam si le démon tourne, utilise les signatures déjà à jour
if ! systemctl is-active --quiet clamav-freshclam; then
    echo "Freshclam daemon non actif, mise à jour des signatures..."
    freshclam --quiet --stdout > /tmp/freshclam.log 2>&1
else
    echo "Freshclam daemon actif, signatures déjà à jour."
fi

# Scan complet (exclut /sys, /proc, /dev)
clamscan -r -i --exclude-dir="^/sys" --exclude-dir="^/proc" --exclude-dir="^/dev" / > "$LOG_FILE" 2>&1

# Filtrer uniquement les fichiers infectés
INFECTED=$(grep "FOUND$" "$LOG_FILE")
NUMINFECTED=$(echo "$INFECTED" | grep -c "FOUND$" || echo 0)

# Fonction pour envoyer le mail HTML
send_mail() {
    local subject="$1"
    local body="$2"
    echo -e "$body" | mail -a "Content-Type: text/html; charset=UTF-8" -s "$subject" "$MAILTO"
}

# Préparer le tableau HTML
prepare_table() {
    local data="$1"
    local table="<table border='1' cellpadding='5' cellspacing='0' style='border-collapse: collapse;'>"
    table+="<tr style='background-color:#f2f2f2;'><th>Fichier</th><th>Virus</th><th>Gravité</th></tr>"

    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        FILE=$(echo "$line" | awk -F: '{print $1}')
        VIRUS=$(echo "$line" | awk -F: '{print $2}' | sed 's/ FOUND//')
        if [[ "$VIRUS" =~ Eicar ]]; then
            COLOR="#ffff99"; GRAVITY="Test (faible)"
        else
            COLOR="#ff9999"; GRAVITY="Critique"
        fi
        table+="<tr style='background-color:$COLOR;'><td>$FILE</td><td>$VIRUS</td><td>$GRAVITY</td></tr>"
    done <<< "$data"

    table+="</table>"
    echo "$table"
}

# Générer graphique mensuel
generate_graph() {
    MONTH=$(date +'%Y-%m')
    local GRAPH="<h3>Historique mensuel des virus détectés</h3>"
    GRAPH+="<table border='1' cellpadding='3' cellspacing='0' style='border-collapse: collapse;'>"
    GRAPH+="<tr style='background-color:#f2f2f2;'><th>Date</th><th>Virus détectés</th></tr>"

    for FILE in "$LOG_DIR/$MONTH"/*.log 2>/dev/null; do
        [[ -f "$FILE" ]] || continue
        DATE=$(basename "$FILE" | sed 's/scan-//;s/.log//')
        COUNT=$(grep -c "FOUND$" "$FILE" 2>/dev/null || echo 0)
        COLOR="#99ff99"
        [[ $COUNT -gt 0 ]] && COLOR="#ff9999"
        GRAPH+="<tr style='background-color:$COLOR;'><td>$DATE</td><td>$COUNT</td></tr>"
    done

    GRAPH+="</table>"
    echo "$GRAPH"
}

# Envoyer le mail
if [[ $NUMINFECTED -gt 0 ]]; then
    TABLE=$(prepare_table "$INFECTED")
    GRAPH=$(generate_graph)
    MAILBODY="<html><body>"
    MAILBODY+="<h2 style='color:#cc0000;'>⚠️ ClamAV - Virus détectés sur $(hostname)</h2>"
    MAILBODY+="<p><strong>Date :</strong> $(date '+%Y-%m-%d %H:%M:%S')</p>"
    MAILBODY+="<p><strong>Nombre de fichiers infectés :</strong> $NUMINFECTED</p>"
    MAILBODY+="$TABLE"
    MAILBODY+="<br>"
    MAILBODY+="$GRAPH"
    MAILBODY+="</body></html>"
    send_mail "ClamAV - $NUMINFECTED virus détecté(s) sur $(hostname)" "$MAILBODY"
else
    # Mail hebdomadaire si aucun virus (lundi = 1)
    DAYOFWEEK=$(date +%u)
    if [[ $DAYOFWEEK -eq 1 ]]; then
        GRAPH=$(generate_graph)
        MAILBODY="<html><body>"
        MAILBODY+="<h2 style='color:#00aa00;'>✅ ClamAV - Rapport hebdomadaire sur $(hostname)</h2>"
        MAILBODY+="<p><strong>Date :</strong> $(date '+%Y-%m-%d %H:%M:%S')</p>"
        MAILBODY+="<p>Aucun virus détecté cette semaine.</p>"
        MAILBODY+="<p>Les signatures et le scan se sont exécutés correctement.</p>"
        MAILBODY+="$GRAPH"
        MAILBODY+="</body></html>"
        send_mail "ClamAV - Rapport hebdomadaire $(hostname)" "$MAILBODY"
    fi
fi

# Archiver le log dans le dossier mensuel
MONTH_DIR="$LOG_DIR/$(date +'%Y-%m')"
mkdir -p "$MONTH_DIR"
mv "$LOG_FILE" "$MONTH_DIR/"

# Nettoyage des logs > 6 mois
find "$LOG_DIR" -type d -mtime +180 -exec rm -rf {} \; 2>/dev/null || true
