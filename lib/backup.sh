#!/usr/bin/env bash
# lib/backup.sh — Sauvegarde automatisée (configs, DKIM, MariaDB, crontab)
# Sourcé par debian13-server.sh — Dépend de: lib/core.sh, lib/helpers.sh
#
# Stratégie de sauvegarde :
#   Chaque appel à backup_full() crée un répertoire horodaté dans BACKUP_DIR
#   contenant 4 sous-répertoires (configs/, dkim/, mariadb/, crontab/).
#   Les sauvegardes au-delà de BACKUP_RETENTION_DAYS sont purgées automatiquement.
#
#   Structure générée :
#     /root/backups/
#       2025-01-15_143022/
#         configs/          ← debian13-server.conf, domains.conf, sshd_config, VHosts
#         dkim/             ← copie miroir de /etc/opendkim/keys (arborescence complète)
#         mariadb/          ← all-databases.sql.gz (dump complet compressé)
#         crontab/          ← root.crontab
#
#   La rétention par date (et non par nombre) garantit qu'on conserve toujours
#   N jours d'historique, même si la fréquence de backup varie.
#
# Interaction avec les snapshots (lib/helpers.sh) :
#   Les snapshots sont des backups légers déclenchés automatiquement avant
#   chaque opération destructive (--domain-add, --domain-remove, --rollback).
#   backup_full() est la version complète, incluant les bases de données.
#
# Chemins injectables (pour les tests) :
#   BACKUP_DIR, BACKUP_RETENTION_DAYS — redéfinissables avant le source.

: "${BACKUP_DIR:=/root/backups}"
: "${BACKUP_RETENTION_DAYS:=30}"

# Destination courante (initialisée par backup_init à chaque session)
BACKUP_DEST=""

# ---- Initialisation ----

# backup_init — Créer le répertoire de destination horodaté.
# Le timestamp inclut heures/minutes/secondes pour permettre plusieurs
# backups le même jour (ex: avant et après un --domain-add).
backup_init() {
  local timestamp
  timestamp=$(date +%Y-%m-%d_%H%M%S)
  BACKUP_DEST="${BACKUP_DIR}/${timestamp}"
  mkdir -p "$BACKUP_DEST"
  log "Backup: destination ${BACKUP_DEST}"
}

# ---- Composants individuels ----

# backup_configs — Sauvegarder les fichiers de configuration critiques.
# On copie en best-effort (|| true) : un fichier manquant ne doit pas
# interrompre le backup complet (ex: MariaDB absent sur un serveur web-only).
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

# backup_dkim — Copie récursive de l'arborescence des clés DKIM.
# cp -a (archive) préserve les permissions restrictives (600) des clés privées.
# Critique : sans ces clés, les emails sortants perdent leur signature DKIM,
# ce qui dégrade immédiatement la délivrabilité (SPF seul ≠ suffisant).
backup_dkim() {
  if [[ ! -d "${DKIM_KEYDIR:-/etc/opendkim/keys}" ]]; then
    warn "Backup: répertoire DKIM absent, ignoré"
    return 0
  fi

  local dest="${BACKUP_DEST}/dkim"
  cp -a "${DKIM_KEYDIR}" "$dest" 2>/dev/null || true
  log "Backup: clés DKIM sauvegardées"
}

# backup_mariadb — Dump complet de toutes les bases MariaDB.
# --single-transaction : snapshot InnoDB cohérent sans verrou global (les écritures continuent).
# --quick : streaming row-by-row (pas de buffer en RAM pour les grosses tables).
# Le dump est compressé gzip (~10:1 sur du SQL) pour économiser l'espace disque.
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

# backup_crontab — Sauvegarder le crontab root.
# On sauvegarde uniquement root car tous les crons système (ClamAV, rkhunter,
# AIDE, updates, monitoring) sont installés sous root par ce script.
backup_crontab() {
  local dest="${BACKUP_DEST}/crontab"
  mkdir -p "$dest"

  crontab -l > "${dest}/root.crontab" 2>/dev/null || true
  log "Backup: crontab sauvegardé"
}

# ---- Gestion du cycle de vie ----

# backup_list — Afficher les sauvegardes disponibles avec leur taille.
# Format de sortie : "YYYY-MM-DD_HHMMSS  <taille>" (une ligne par backup).
# Utilisé par --backup-list pour l'affichage utilisateur.
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

# backup_cleanup — Purger les sauvegardes au-delà de la rétention.
# Le calcul d'âge se fait sur le nom du répertoire (YYYY-MM-DD), pas sur
# le mtime filesystem, pour éviter les faux positifs après un rsync ou tar.
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

# ---- Orchestrateur ----

# backup_full — Point d'entrée principal : exécute les 4 composants + purge.
# Appelé par --backup. Le cleanup en fin de chaîne garantit que les vieux
# backups sont purgés même si l'utilisateur oublie de le faire manuellement.
backup_full() {
  backup_init
  backup_configs
  backup_dkim
  backup_mariadb
  backup_crontab
  backup_cleanup
  log "Backup complet terminé: ${BACKUP_DEST}"
}
