#!/usr/bin/env bash
# lib/fleet.sh — Orchestration multi-serveurs (fleet)
# Sourcé par debian13-server.sh — Dépend de: lib/core.sh, lib/clone.sh
#
# Gère un inventaire de serveurs (fleet.conf) et permet d'exécuter des
# commandes ou de synchroniser des configurations sur l'ensemble de la flotte.
#
# Format fleet.conf : "nom:ip:port" (un serveur par ligne).
# Les connexions utilisent la clé SSH de clonage (clone_rsa).
#
# Cas d'usage :
#   - fleet_exec "apt-get update -y"  → mise à jour de tous les serveurs
#   - fleet_status                     → uptime de chaque serveur
#   - Combiné avec clone_sync()       → déploiement de config en flotte
#
# Limitations :
#   - Exécution séquentielle (pas de parallélisme) pour simplifier les logs
#   - Pas de gestion de groupes (tous les serveurs sont traités)
#   - ConnectTimeout=5s pour ne pas bloquer sur un serveur injoignable

: "${FLEET_CONF:=${SCRIPTS_DIR:-/root/scripts}/fleet.conf}"
: "${CLONE_SSH_KEY:=/root/.ssh/clone_rsa}"

fleet_add() {
  local name="$1" ip="$2" port="${3:-22}"
  [[ -f "$FLEET_CONF" ]] && grep -q "^${name}:" "$FLEET_CONF" && return 0
  echo "${name}:${ip}:${port}" >> "$FLEET_CONF"
  log "Fleet: ${name} (${ip}:${port}) ajouté"
}

# Lister les serveurs de la flotte
fleet_list() {
  [[ -f "$FLEET_CONF" ]] || return 0
  grep -v '^#' "$FLEET_CONF" | grep -v '^$'
}

# Retirer un serveur de la flotte
# $1 = nom
fleet_remove() {
  local name="$1"
  [[ -f "$FLEET_CONF" ]] || return 0
  local tmp
  tmp=$(grep -v "^${name}:" "$FLEET_CONF")
  echo "$tmp" > "$FLEET_CONF"
  # Clean empty lines
  sed -i '/^$/d' "$FLEET_CONF"
  log "Fleet: ${name} retiré"
}

# Exécuter une commande sur tous les serveurs
# $* = commande à exécuter
fleet_exec() {
  local cmd="$*"
  local entry name ip port
  while IFS= read -r entry; do
    [[ -z "$entry" ]] && continue
    name="${entry%%:*}"
    local rest="${entry#*:}"
    ip="${rest%%:*}"
    port="${rest#*:}"
    log "Fleet [${name}] ${ip}:${port} → ${cmd}"
    ssh -i "$CLONE_SSH_KEY" -o StrictHostKeyChecking=no -p "$port" "root@${ip}" "$cmd" 2>/dev/null || warn "Fleet [${name}]: échec"
  done < <(fleet_list)
}

# Afficher le statut de tous les serveurs
fleet_status() {
  local entry name ip port
  local count=0
  while IFS= read -r entry; do
    [[ -z "$entry" ]] && continue
    name="${entry%%:*}"
    local rest="${entry#*:}"
    ip="${rest%%:*}"
    port="${rest#*:}"
    local result
    result=$(ssh -i "$CLONE_SSH_KEY" -o StrictHostKeyChecking=no -o ConnectTimeout=5 -p "$port" "root@${ip}" "uptime -p" 2>/dev/null) || result="UNREACHABLE"
    printf "%-15s %-20s %-6s %s\n" "$name" "$ip" "$port" "$result"
    ((count++))
  done < <(fleet_list)
  [[ "$count" -eq 0 ]] && log "Aucun serveur dans la flotte."
}
