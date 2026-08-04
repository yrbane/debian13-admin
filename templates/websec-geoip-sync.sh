#!/bin/bash
# websec-geoip-sync.sh — peuple /etc/websec/geoip avec les zones CIDR par pays
# (ipdeny.com, IPv4 + IPv6) pour la politique GeoIP par domaine de WebSec.
#
# WebSec lit un fichier <cc>.zone par pays au démarrage (CountryDb::load_dir).
# Contrairement au blocage pare-feu (~90 pays Asie+Afrique), WebSec a besoin
# de TOUS les pays : une règle "allow-only FR" doit pouvoir identifier les
# visiteurs FR, même si FR n'est pas dans la liste bloquée globalement.
#
# Idempotent, déploiement atomique : en cas d'échec réseau, l'ancien jeu de
# données reste en place (WebSec continue de fonctionner avec les zones
# précédentes).
set -euo pipefail

DEST="/etc/websec/geoip"
CURL_TIMEOUT=60
V4_URL="https://www.ipdeny.com/ipblocks/data/countries/all-zones.tar.gz"
V6_URL="https://www.ipdeny.com/ipv6/ipaddresses/blocks/ipv6-all-zones.tar.gz"

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

fetch() { # url destdir
  local url="$1" dir="$2"
  mkdir -p "$dir"
  if curl -sfS --max-time "$CURL_TIMEOUT" "$url" -o "$TMP/z.tgz"; then
    tar -xzf "$TMP/z.tgz" -C "$dir" 2>/dev/null || true
  else
    echo "WARN: échec téléchargement $url" >&2
  fi
}

fetch "$V4_URL" "$TMP/v4"
fetch "$V6_URL" "$TMP/v6"

# Fusionner IPv4 + IPv6 par pays dans un répertoire de staging.
# ipdeny nomme les deux fichiers <cc>.zone : on les concatène par pays,
# CountryDb détecte v4/v6 ligne par ligne.
STAGE="$TMP/stage"
mkdir -p "$STAGE"
while IFS= read -r f; do
  cc=$(basename "$f")
  cat "$f" >> "$STAGE/$cc"
done < <(find "$TMP/v4" "$TMP/v6" -type f -name '*.zone' 2>/dev/null)

count=$(find "$STAGE" -type f -name '*.zone' 2>/dev/null | wc -l)
if [[ "$count" -eq 0 ]]; then
  echo "ERREUR: aucune zone téléchargée, $DEST inchangé" >&2
  exit 1
fi

# Déploiement atomique : on installe les nouvelles zones puis on retire les
# obsolètes, sans jamais laisser le répertoire vide.
mkdir -p "$DEST"
install -m 0644 "$STAGE"/*.zone "$DEST"/
# Purger les .zone qui n'existent plus dans le nouveau jeu
for old in "$DEST"/*.zone; do
  [[ -e "$old" ]] || continue
  base=$(basename "$old")
  [[ -e "$STAGE/$base" ]] || rm -f "$old"
done
chown -R websec:websec "$DEST" 2>/dev/null || true

ranges=$(cat "$DEST"/*.zone 2>/dev/null | grep -c '^[0-9a-fA-F]' || echo 0)
echo "$(date): WebSec GeoIP sync — ${count} pays / ${ranges} plages dans $DEST"
