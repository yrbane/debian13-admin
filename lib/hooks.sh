#!/usr/bin/env bash
# lib/hooks.sh — Système de hooks/plugins (extensibilité sans modification du code)
# Sourcé par debian13-server.sh
#
# Les hooks permettent d'ajouter du comportement custom sans toucher aux
# scripts principaux. Un hook est un script shell exécutable dans hooks.d/
# nommé selon la convention : <événement>-<nom>.sh
#
# Événements émis par le système :
#   pre-install, post-install
#   pre-domain-add, post-domain-add
#   pre-domain-remove, post-domain-remove
#   pre-backup, post-backup
#
# Exemples de hooks :
#   hooks.d/post-domain-add-slack.sh  → notification Slack après ajout
#   hooks.d/pre-backup-db-dump.sh     → dump MariaDB avant backup
#
# Note technique : on utilise "bash $hook" plutôt que "./$hook" car /tmp
# est monté noexec sur ce serveur. Le test de permission utilise stat -c %a
# au lieu de [[ -x ]] pour la même raison.

: "${HOOKS_DIR:=${SCRIPTS_DIR:-/root/scripts}/hooks.d}"

run_hooks() {
  local event="$1"; shift
  [[ -d "$HOOKS_DIR" ]] || return 0

  local hook found=false
  for hook in "${HOOKS_DIR}/${event}"-*.sh; do
    [[ -f "$hook" ]] || continue
    # stat -c %a retourne les permissions octales (ex: 755).
    # On vérifie que le dernier chiffre contient le bit d'exécution (1/3/5/7).
    # Alternative à [[ -x ]] qui échoue sur les montages noexec.
    [[ $(stat -c %a "$hook") =~ [1357] ]] || continue
    found=true
    log "Hook: exécution $(basename "$hook")"
    bash "$hook" "$@" || warn "Hook: $(basename "$hook") a retourné une erreur"
  done

  $found || return 0
}
