#!/usr/bin/env bash
# lib/fleet.sh — Gestion multi-serveurs (fleet)
# Sourcé par debian13-server.sh — Dépend de: lib/core.sh, lib/clone.sh

: "${FLEET_CONF:=${SCRIPTS_DIR:-/root/scripts}/fleet.conf}"
: "${CLONE_SSH_KEY:=/root/.ssh/clone_rsa}"

# Ajouter un serveur à la flotte
# $1 = nom, $2 = IP, $3 = port (défaut: 22)
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
