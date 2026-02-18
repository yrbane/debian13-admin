#!/bin/bash
set -euo pipefail

# Destinataire du mail
MAILTO="root@example.com"

# Force une sortie non localisée (évite "En train de lister…", "Installé", etc.)
export LC_ALL=C

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

# Fichier temporaire
TMPFILE="$(mktemp)"
trap 'rm -f "$TMPFILE"' EXIT

# Met à jour la liste des paquets silencieusement
apt-get update -qq >/dev/null

# Début du HTML
{
  echo "<html><body>"
  echo "<h2>Mises à jour disponibles sur $(hostname)</h2>"
  echo "<p><strong>Date :</strong> $(date '+%Y-%m-%d %H:%M:%S')</p>"
  echo "<table border='1' cellpadding='5' cellspacing='0' style='border-collapse: collapse;'>"
  echo "<tr style='background-color: #f2f2f2;'><th>Paquet</th><th>Version installée</th><th>Version disponible</th><th>Dépôt</th></tr>"
} > "$TMPFILE"

COUNT=0

# NOTE: on saute la 1ère ligne ("Listing..." / "En train de lister…") sans dépendre de la langue
while IFS= read -r line; do
  [[ -z "$line" ]] && continue

  PKG="$(awk -F/ '{print $1}' <<<"$line")"

  INSTALLED="$(apt-cache policy "$PKG" 2>/dev/null | awk '/Installed:/ {print $2; exit}')"
  CANDIDATE="$(apt-cache policy "$PKG" 2>/dev/null | awk '/Candidate:/ {print $2; exit}')"
  REPO="$(apt-cache policy "$PKG" 2>/dev/null | awk '/https?:\/\// {print; exit}')"

  echo "<tr style='background-color: #ffeb99;'><td>$PKG</td><td>${INSTALLED:-?}</td><td>${CANDIDATE:-?}</td><td>${REPO:-}</td></tr>" >> "$TMPFILE"
  COUNT=$((COUNT + 1))
done < <(apt list --upgradable 2>/dev/null | sed '1d')

echo "</table>" >> "$TMPFILE"

if [[ $COUNT -eq 0 ]]; then
  echo "<p style='color: green;'><strong>Tous les paquets sont à jour.</strong></p>" >> "$TMPFILE"
fi

echo "</body></html>" >> "$TMPFILE"

if [[ $COUNT -gt 0 ]]; then
  send_report "[MAJ] $COUNT mise(s) a jour disponible(s) sur $(hostname)" "$(cat "$TMPFILE")"
else
  send_report "[MAJ] Systeme a jour sur $(hostname)" "$(cat "$TMPFILE")"
fi
