#!/usr/bin/env bash
# lib/backup.sh — Sauvegarde automatisée (configs, DKIM, MariaDB, crontab)
# Sourcé par debian13-server.sh — Dépend de: lib/core.sh, lib/helpers.sh

: "${BACKUP_DIR:=/root/backups}"
: "${BACKUP_RETENTION_DAYS:=30}"

# Destination courante (initialisée par backup_init)
BACKUP_DEST=""

# Initialiser une session de sauvegarde
backup_init() {
  local timestamp
  timestamp=$(date +%Y-%m-%d_%H%M%S)
  BACKUP_DEST="${BACKUP_DIR}/${timestamp}"
  mkdir -p "$BACKUP_DEST"
  log "Backup: destination ${BACKUP_DEST}"
}

# Sauvegarder les fichiers de configuration
backup_configs() {
  local dest="${BACKUP_DEST}/configs"
  mkdir -p "$dest"

  # Config principale
  if [[ -f "${CONFIG_FILE:-}" ]]; then
    cp "$CONFIG_FILE" "$dest/" 2>/dev/null || true
  fi

  # Registre multi-domaines
  if [[ -f "${DOMAINS_CONF:-}" ]]; then
    cp "$DOMAINS_CONF" "$dest/" 2>/dev/null || true
  fi

  # Configs SSH
  [[ -f /etc/ssh/sshd_config ]] && cp /etc/ssh/sshd_config "$dest/" 2>/dev/null || true

  # Configs Apache
  if [[ -d /etc/apache2/sites-available ]]; then
    mkdir -p "$dest/apache-sites"
    cp /etc/apache2/sites-available/*.conf "$dest/apache-sites/" 2>/dev/null || true
  fi

  log "Backup: configurations sauvegardées"
}

# Sauvegarder les clés DKIM
backup_dkim() {
  if [[ ! -d "${DKIM_KEYDIR:-/etc/opendkim/keys}" ]]; then
    warn "Backup: répertoire DKIM absent, ignoré"
    return 0
  fi

  local dest="${BACKUP_DEST}/dkim"
  cp -a "${DKIM_KEYDIR}" "$dest" 2>/dev/null || true
  log "Backup: clés DKIM sauvegardées"
}

# Sauvegarder toutes les bases MariaDB
backup_mariadb() {
  local dest="${BACKUP_DEST}/mariadb"
  mkdir -p "$dest"

  if ! command -v mysqldump >/dev/null 2>&1; then
    warn "Backup: mysqldump non disponible, bases ignorées"
    return 0
  fi

  local dumpfile="${dest}/all-databases.sql"
  if mysqldump --all-databases --single-transaction --quick > "$dumpfile" 2>/dev/null; then
    gzip "$dumpfile"
    log "Backup: bases MariaDB sauvegardées ($(du -sh "${dumpfile}.gz" | cut -f1))"
  else
    warn "Backup: échec du dump MariaDB"
    rm -f "$dumpfile"
  fi
}

# Sauvegarder le crontab root
backup_crontab() {
  local dest="${BACKUP_DEST}/crontab"
  mkdir -p "$dest"

  crontab -l > "${dest}/root.crontab" 2>/dev/null || true
  log "Backup: crontab sauvegardé"
}

# Lister les sauvegardes disponibles
backup_list() {
  if [[ ! -d "$BACKUP_DIR" ]]; then
    return 0
  fi

  local count=0
  local entry size
  for entry in "${BACKUP_DIR}"/*/; do
    [[ -d "$entry" ]] || continue
    size=$(du -sh "$entry" 2>/dev/null | cut -f1)
    echo "$(basename "$entry")  ${size:-?}"
    ((++count))
  done

  if [[ "$count" -eq 0 ]]; then
    note "Aucune sauvegarde trouvée dans ${BACKUP_DIR}"
  fi
}

# Supprimer les sauvegardes plus anciennes que BACKUP_RETENTION_DAYS
backup_cleanup() {
  [[ -d "$BACKUP_DIR" ]] || return 0

  local entry age_days entry_date entry_epoch
  for entry in "${BACKUP_DIR}"/*/; do
    [[ -d "$entry" ]] || continue
    entry_date=$(basename "$entry" | cut -d_ -f1)
    entry_epoch=$(date -d "$entry_date" +%s 2>/dev/null) || continue
    age_days=$(( ($(date +%s) - entry_epoch) / ${SECONDS_PER_DAY:-86400} ))
    if (( age_days > BACKUP_RETENTION_DAYS )); then
      rm -rf "$entry"
      log "Backup: supprimé $(basename "$entry") (${age_days} jours)"
    fi
  done
}

# Sauvegarde complète
backup_full() {
  backup_init
  backup_configs
  backup_dkim
  backup_mariadb
  backup_crontab
  backup_cleanup
  log "Backup complet terminé: ${BACKUP_DEST}"
}
