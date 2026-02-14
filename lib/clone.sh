#!/usr/bin/env bash
# lib/clone.sh — Clonage de serveur vers une machine cible
# Sourcé par debian13-server.sh — Dépend de: lib/core.sh, lib/helpers.sh
#
# Permet de dupliquer la configuration complète d'un serveur vers un autre.
# Workflow en deux étapes :
#   1. --clone-keygen  : génère une paire de clés SSH ed25519 dédiée au clonage
#   2. --clone <ip>    : synchronise toutes les configs via rsync over SSH
#
# Ce qui est synchronisé :
#   - Scripts et configuration (/root/scripts, domains.conf, domains.d/)
#   - Clés DKIM et tables OpenDKIM
#   - VHosts Apache et logrotate
#   - Fichiers web (/var/www/*)
#   - Certificats Let's Encrypt
#
# Ce qui n'est PAS synchronisé (volontairement) :
#   - Bases MariaDB (utiliser mysqldump + restore séparément)
#   - Hostname/IP (à reconfigurer sur la cible)
#   - Clés SSH du serveur (/etc/ssh/ssh_host_*)
#
# Sécurité : la clé de clonage est distincte des clés SSH utilisateur pour
# pouvoir la révoquer indépendamment. StrictHostKeyChecking=no est utilisé
# car la cible est souvent une fresh install sans known_hosts préexistant.

: "${CLONE_KEY_DIR:=/root/.ssh}"
: "${CLONE_SSH_KEY:=${CLONE_KEY_DIR}/clone_rsa}"
: "${SCRIPTS_DIR:=/root/scripts}"
: "${DKIM_KEYDIR:=/etc/opendkim/keys}"

clone_generate_key() {
  mkdir -p "$CLONE_KEY_DIR"
  if [[ -f "$CLONE_SSH_KEY" && -f "${CLONE_SSH_KEY}.pub" ]]; then
    log "Clé SSH de clonage déjà existante : ${CLONE_SSH_KEY}"
    echo "Clé publique à copier sur le serveur cible :"
    cat "${CLONE_SSH_KEY}.pub"
    return 0
  fi
  ssh-keygen -t ed25519 -f "$CLONE_SSH_KEY" -N "" -C "clone@$(hostname -f 2>/dev/null || echo server)"
  chmod 600 "$CLONE_SSH_KEY"
  log "Clé SSH générée : ${CLONE_SSH_KEY}"
  echo "Clé publique à copier sur le serveur cible :"
  cat "${CLONE_SSH_KEY}.pub"
}

# Pre-flight checks before cloning
# $1 = target IP
clone_preflight() {
  local target="$1"
  if [[ -z "$target" ]]; then
    err "Adresse IP cible requise."
    return 1
  fi
  if [[ ! -f "$CLONE_SSH_KEY" ]]; then
    err "Clé SSH non trouvée. Exécutez d'abord : sudo $0 --clone-keygen"
    return 1
  fi
  return 0
}

# Sync server configuration to target
# $1 = target IP, $2 = SSH port (default: 22)
clone_sync() {
  local target="$1"
  local port="${2:-22}"
  local ssh_opts="-i ${CLONE_SSH_KEY} -o StrictHostKeyChecking=no -p ${port}"

  section "Synchronisation vers ${target}:${port}"

  # 1. Sync scripts directory (includes domains.conf, config, libs)
  log "Sync: répertoire scripts → ${target}:${SCRIPTS_DIR}"
  rsync -avz --delete -e "ssh ${ssh_opts}" \
    "${SCRIPTS_DIR}/" "root@${target}:${SCRIPTS_DIR}/"

  # 2. Sync DKIM keys
  if [[ -d "$DKIM_KEYDIR" ]]; then
    log "Sync: clés DKIM → ${target}:${DKIM_KEYDIR}"
    rsync -avz -e "ssh ${ssh_opts}" \
      "${DKIM_KEYDIR}/" "root@${target}:${DKIM_KEYDIR}/"
  fi

  # 3. Sync OpenDKIM config
  local opendkim_dir="${OPENDKIM_DIR:-/etc/opendkim}"
  if [[ -d "$opendkim_dir" ]]; then
    log "Sync: config OpenDKIM → ${target}:${opendkim_dir}"
    rsync -avz -e "ssh ${ssh_opts}" \
      "${opendkim_dir}/" "root@${target}:${opendkim_dir}/"
  fi

  # 4. Sync Apache VHosts
  local apache_dir="${APACHE_SITES_DIR:-/etc/apache2/sites-available}"
  if [[ -d "$apache_dir" ]]; then
    log "Sync: VHosts Apache → ${target}:${apache_dir}"
    rsync -avz -e "ssh ${ssh_opts}" \
      "${apache_dir}/" "root@${target}:${apache_dir}/"
  fi

  # 5. Sync web roots for all domains
  local web_root="${WEB_ROOT:-/var/www}"
  if [[ -d "$web_root" ]]; then
    log "Sync: fichiers web → ${target}:${web_root}"
    rsync -avz -e "ssh ${ssh_opts}" \
      "${web_root}/" "root@${target}:${web_root}/"
  fi

  # 6. Sync Let's Encrypt certificates
  if [[ -d "/etc/letsencrypt" ]]; then
    log "Sync: certificats Let's Encrypt → ${target}:/etc/letsencrypt"
    rsync -avz -e "ssh ${ssh_opts}" \
      "/etc/letsencrypt/" "root@${target}:/etc/letsencrypt/"
  fi

  # 7. Sync logrotate configs
  local logrotate_dir="${LOGROTATE_DIR:-/etc/logrotate.d}"
  log "Sync: logrotate → ${target}:${logrotate_dir}"
  rsync -avz -e "ssh ${ssh_opts}" \
    "${logrotate_dir}/apache-vhost-"* "root@${target}:${logrotate_dir}/" 2>/dev/null || true

  # 8. Sync per-domain configs
  local conf_dir="${DOMAINS_CONF_DIR:-${SCRIPTS_DIR}/domains.d}"
  if [[ -d "$conf_dir" ]]; then
    log "Sync: configs domaines → ${target}:${conf_dir}"
    rsync -avz -e "ssh ${ssh_opts}" \
      "${conf_dir}/" "root@${target}:${conf_dir}/"
  fi

  log "Synchronisation terminée. Exécutez le script sur le serveur cible :"
  log "  ssh -p ${port} root@${target} '${SCRIPTS_DIR}/debian13-server.sh --audit'"
}
