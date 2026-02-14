#!/usr/bin/env bash
# lib/hooks.sh — Système de hooks/plugins
# Les hooks sont des scripts exécutables dans HOOKS_DIR nommés <event>-<name>.sh
# Événements supportés : pre-install, post-install, pre-domain-add, post-domain-add,
#   pre-domain-remove, post-domain-remove, pre-backup, post-backup

: "${HOOKS_DIR:=${SCRIPTS_DIR:-/root/scripts}/hooks.d}"

# Exécuter tous les hooks correspondant à un événement
# $1 = nom de l'événement (ex: post-install, pre-backup)
# $2..n = arguments passés aux hooks
run_hooks() {
  local event="$1"; shift
  [[ -d "$HOOKS_DIR" ]] || return 0

  local hook found=false
  for hook in "${HOOKS_DIR}/${event}"-*.sh; do
    [[ -f "$hook" ]] || continue
    # Check permission bits (not -x which fails on noexec mounts)
    [[ $(stat -c %a "$hook") =~ [1357] ]] || continue
    found=true
    log "Hook: exécution $(basename "$hook")"
    bash "$hook" "$@" || warn "Hook: $(basename "$hook") a retourné une erreur"
  done

  $found || return 0
}
