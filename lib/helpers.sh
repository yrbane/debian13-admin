#!/usr/bin/env bash
# lib/helpers.sh — Fichiers temporaires, utilitaires système, fonctions d'aide
# Sourcé par debian13-server.sh — Dépend de: lib/core.sh, lib/constants.sh

# ---------------------------------- Fichiers temporaires & cleanup -------------------
declare -a _TMPFILES=()

mktempfile() {
  local suffix="${1:-.tmp}"
  local f
  f=$(mktemp --tmpdir "bootstrap-XXXXXX${suffix}")
  _TMPFILES+=("$f")
  echo "$f"
}

cleanup_tmpfiles() {
  local f
  for f in "${_TMPFILES[@]+"${_TMPFILES[@]}"}"; do
    [[ -f "$f" ]] && rm -f "$f"
  done
  return 0
}
# ERR : signaler l'erreur (ne se declenche PAS sur exit normal)
trap 'err "Erreur a la ligne $LINENO. Consulte le journal si necessaire."' ERR
# EXIT : nettoyage silencieux (se declenche toujours, y compris exit 0)
trap 'cleanup_tmpfiles' EXIT

# ---------------------------------- Prérequis -----------------------------------------
require_root() { [[ $EUID -eq 0 ]] || die "Exécute ce script en root (sudo)."; }

preflight_checks() {
  local errors=0

  local avail_kb
  avail_kb=$(df / --output=avail | tail -1 | tr -d ' ')
  if (( avail_kb < MIN_DISK_KB )); then
    err "Espace disque insuffisant sur / : $(( avail_kb / 1024 )) Mo disponibles (minimum $(( MIN_DISK_KB / 1024 )) Mo)"
    ((errors++))
  fi

  if ! curl -sf --max-time "$CURL_TIMEOUT" https://deb.debian.org/ >/dev/null 2>&1; then
    err "Pas de connectivité vers les dépôts Debian (https://deb.debian.org/)"
    ((errors++))
  fi

  if ! host -W "$DNS_TIMEOUT" deb.debian.org >/dev/null 2>&1; then
    warn "Résolution DNS lente ou absente — vérifiez /etc/resolv.conf"
  fi

  if [[ -f /etc/os-release ]]; then
    local version_id
    version_id=$(grep -oP 'VERSION_ID="\K[^"]+' /etc/os-release 2>/dev/null || echo "")
    if [[ -n "$version_id" && "$version_id" -lt 13 ]] 2>/dev/null; then
      warn "Debian ${version_id} détectée. Ce script est conçu pour Debian 13 (trixie)."
    fi
  fi

  if (( errors > 0 )); then
    die "Vérifications pré-installation échouées (${errors} erreur(s)). Corrigez avant de relancer."
  fi

  log "Vérifications pré-installation OK."
}

# ---------------------------------- Utilitaires ---------------------------------------
backup_file() {
  local f="$1"
  if [[ -f "$f" ]]; then
    local bak
    bak="${f}.$(date +%Y%m%d%H%M%S).bak"
    if ! cp -a "$f" "$bak"; then
      warn "Impossible de sauvegarder ${f} → ${bak}"
      return 1
    fi
  fi
}

run_as_user() {
  if [[ -z "${ADMIN_USER:-}" ]]; then
    warn "ADMIN_USER non défini, commande ignorée: $1"
    return 1
  fi
  if ! id "$ADMIN_USER" &>/dev/null; then
    warn "L'utilisateur ${ADMIN_USER} n'existe pas, commande ignorée: $1"
    return 1
  fi
  sudo -u "$ADMIN_USER" -H bash -c "$1"
}

get_user_home() {
  if [[ -z "${ADMIN_USER:-}" ]]; then
    echo "/root"
    return
  fi
  local home_dir
  home_dir=$(getent passwd "$ADMIN_USER" 2>/dev/null | cut -d: -f6)
  if [[ -n "$home_dir" ]]; then
    echo "$home_dir"
  else
    echo "/home/${ADMIN_USER}"
  fi
}

apt_install() {
  local retries=2 attempt=1
  while (( attempt <= retries )); do
    if apt-get install -y "$@" 2>&1 | tee -a "$LOG_FILE"; then
      return 0
    fi
    warn "apt-get install échoué (tentative ${attempt}/${retries}), nouvel essai après apt-get update..."
    apt-get update -y >> "$LOG_FILE" 2>&1
    ((attempt++))
  done
  err "Échec d'installation de : $*"
  return 1
}

apt_update_upgrade() {
  section "Mises à jour APT"
  apt-get update -y | tee -a "$LOG_FILE"
  apt-get full-upgrade -y | tee -a "$LOG_FILE"
  apt_install apt-transport-https ca-certificates gnupg lsb-release
}

add_cron_job() {
  local pattern="$1" line="$2" comment="${3:-}"
  local current new
  current=$(crontab -l 2>/dev/null || true)
  new=$(echo "$current" | grep -v "$pattern" || true)
  if [[ -n "$comment" ]]; then
    echo -e "${new}\n# ${comment}\n${line}" | grep -v '^$' | crontab -
  else
    echo -e "${new}\n${line}" | grep -v '^$' | crontab -
  fi
}

set_cron_mailto() {
  local email="$1"
  local current
  current=$(crontab -l 2>/dev/null || true)
  # Supprimer tout ancien MAILTO
  local clean
  clean=$(echo "$current" | grep -v '^MAILTO=' || true)
  echo -e "MAILTO=${email}\n${clean}" | grep -v '^$' | crontab -
}

deploy_script() {
  local path="$1" content="$2" cron_schedule="${3:-}" cron_comment="${4:-}"
  shift 4 2>/dev/null || true
  local dir
  dir="$(dirname "$path")"
  mkdir -p "$dir"

  echo "$content" > "$path"
  sed -i "s|__EMAIL__|${EMAIL_FOR_CERTBOT}|g" "$path"
  while [[ $# -ge 2 ]]; do
    sed -i "s|${1}|${2}|g" "$path"
    shift 2
  done
  chmod +x "$path"

  if [[ -n "$cron_schedule" ]]; then
    local cron_line="${cron_schedule} ${path} >/dev/null 2>&1"
    local script_name
    script_name="$(basename "$path")"
    add_cron_job "$script_name" "$cron_line" "$cron_comment"
  fi
}

check_service_active() {
  local service="$1" label="$2"
  if systemctl is-active --quiet "$service"; then
    emit_check ok "${label} : actif"
    return 0
  else
    emit_check fail "${label} : inactif"
    return 1
  fi
}

check_db_freshness() {
  local target="$1" label="$2" fresh="${3:-$DB_FRESH_DAYS}" stale="${4:-$DB_STALE_DAYS}"
  local db_epoch age_days

  if [[ -d "$target" ]]; then
    db_epoch=$(find "$target" -type f -printf '%T@\n' 2>/dev/null | sort -n | tail -1)
  elif [[ -f "$target" ]]; then
    db_epoch=$(stat -c %Y "$target" 2>/dev/null)
  else
    emit_check warn "${label} : base non trouvée"
    return 1
  fi

  [[ -z "$db_epoch" ]] && return 1
  db_epoch=${db_epoch%.*}
  age_days=$(( ($(date +%s) - db_epoch) / ${SECONDS_PER_DAY:-86400} ))

  local status msg
  if (( age_days <= fresh )); then
    status="ok"; msg="${label} : base à jour (${age_days} jour(s))"
  elif (( age_days <= stale )); then
    status="warn"; msg="${label} : base date de ${age_days} jours"
  else
    status="fail"; msg="${label} : base obsolète (${age_days} jours)"
  fi

  emit_check "$status" "$msg"
}

php_ini_set() {
  local key="$1" value="$2" ini="$3"
  sed -ri "s/^;?\s*${key}\s*=.*/${key} = ${value}/" "$ini"
}

check_file_perms() {
  local path="$1" label="$2" expected="$3"
  local perms
  perms=$(stat -c %a "$path" 2>/dev/null) || return 1
  if [[ "$perms" =~ ^(${expected})$ ]]; then
    emit_check ok "${label} : permissions correctes (${perms})"
  else
    emit_check warn "${label} : permissions = ${perms} (attendu : ${expected})"
  fi
}

check_config_grep() {
  local file="$1" regex="$2" ok_msg="$3" fail_msg="$4"
  if grep -qE "$regex" "$file" 2>/dev/null; then
    emit_check ok "$ok_msg"
  else
    emit_check fail "$fail_msg"
  fi
}

safe_count() {
  local pattern="$1" source="$2"
  local count
  if [[ -f "$source" ]]; then
    count=$(grep -c "$pattern" "$source" 2>/dev/null) || true
  else
    count=$(echo "$source" | grep -c "$pattern" 2>/dev/null) || true
  fi
  echo "${count:-0}"
}

days_since() {
  local epoch="${1:-0}"
  echo $(( ($(date +%s) - epoch) / ${SECONDS_PER_DAY:-86400} ))
}
days_until() {
  local epoch="${1:-0}"
  echo $(( (epoch - $(date +%s)) / ${SECONDS_PER_DAY:-86400} ))
}

add_line_if_missing() {
  local pattern="$1" line="$2" file="$3"
  grep -q "$pattern" "$file" 2>/dev/null || echo "$line" >> "$file"
}

sanitize_int() {
  local v="${1//[^0-9]/}"
  echo "${v:-0}"
}

threshold_color() {
  local val="$1" warn="${2:-70}" crit="${3:-90}"
  if [[ "$val" -gt "$crit" ]]; then
    echo "red"
  elif [[ "$val" -gt "$warn" ]]; then
    echo "orange"
  else
    echo "green"
  fi
}

# ---------------------------------- AppArmor profiles --------------------------------

# Déployer les profils AppArmor locaux pour Apache, MariaDB et Postfix
# Utilise APPARMOR_LOCAL (overridable pour les tests)
deploy_apparmor_profiles() {
  local local_dir="${APPARMOR_LOCAL:-/etc/apparmor.d/local}"
  mkdir -p "$local_dir"

  # Apache : autoriser /var/www, SSL, logs, modules
  cat > "${local_dir}/usr.sbin.apache2" <<'EOF'
# Local AppArmor overrides for Apache
/var/www/** r,
/var/log/apache2/** rw,
/var/log/apache2/ rw,
/etc/letsencrypt/** r,
/run/apache2/** rw,
/var/cache/modsecurity/** rw,
EOF

  # MariaDB : autoriser data, logs, tmp
  cat > "${local_dir}/usr.sbin.mariadbd" <<'EOF'
# Local AppArmor overrides for MariaDB
/var/lib/mysql/** rwk,
/var/lib/mysql/ r,
/var/log/mysql/** rw,
/tmp/** rw,
/run/mysqld/** rw,
EOF

  # Postfix SMTP daemon
  cat > "${local_dir}/usr.lib.postfix.smtpd" <<'EOF'
# Local AppArmor overrides for Postfix smtpd
/etc/postfix/** r,
/var/spool/postfix/** rwk,
/var/log/mail.* rw,
/etc/opendkim/** r,
EOF

  log "AppArmor: profils locaux déployés (Apache, MariaDB, Postfix)"
}

# ---------------------------------- auditd rules ------------------------------------

# Déployer les règles auditd pour le hardening serveur
# Utilise AUDIT_RULES_DIR (overridable pour les tests)
deploy_auditd_rules() {
  local rules_dir="${AUDIT_RULES_DIR:-/etc/audit/rules.d}"
  mkdir -p "$rules_dir"

  cat > "${rules_dir}/99-server-hardening.rules" <<'EOF'
# === Identity & authentication files ===
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/gshadow -p wa -k identity

# === SSH configuration & keys ===
-w /etc/ssh/sshd_config -p wa -k sshd_config
-w /root/.ssh/authorized_keys -p wa -k ssh_keys
-w /home/ -p wa -k ssh_keys

# === Privilege escalation ===
-w /etc/sudoers -p wa -k privilege
-w /etc/sudoers.d/ -p wa -k privilege
-a always,exit -F arch=b64 -S execve -F euid=0 -F auid>=1000 -F auid!=4294967295 -k privilege_exec

# === Cron jobs ===
-w /etc/crontab -p wa -k cron
-w /etc/cron.d/ -p wa -k cron
-w /var/spool/cron/ -p wa -k cron

# === Network configuration ===
-w /etc/hosts -p wa -k network
-w /etc/resolv.conf -p wa -k network

# === System startup ===
-w /etc/systemd/ -p wa -k systemd
EOF

  log "auditd: règles de hardening déployées"
}

# ---------------------------------- Egress filtering ---------------------------------

# Configurer le filtrage sortant UFW (deny par défaut + whitelist)
deploy_egress_rules() {
  ufw default deny outgoing

  # DNS
  ufw allow out 53 comment "DNS"
  # HTTP/HTTPS (apt, certbot, API calls)
  ufw allow out 80/tcp comment "HTTP out"
  ufw allow out 443/tcp comment "HTTPS out"
  # SMTP
  ufw allow out 25/tcp comment "SMTP"
  ufw allow out 587/tcp comment "SMTP submission"
  ufw allow out 465/tcp comment "SMTPS"
  # NTP
  ufw allow out 123/udp comment "NTP"
  # Whois (certbot, DNS checks)
  ufw allow out 43/tcp comment "WHOIS"

  log "UFW: filtrage egress activé (deny par défaut + whitelist)"
}

# ---------------------------------- Fail2ban extended --------------------------------

# Déployer filtres et jails Fail2ban avancés
# Utilise FAIL2BAN_FILTER_DIR et FAIL2BAN_JAIL_DIR (overridable pour les tests)
deploy_fail2ban_extended() {
  local filter_dir="${FAIL2BAN_FILTER_DIR:-/etc/fail2ban/filter.d}"
  local jail_dir="${FAIL2BAN_JAIL_DIR:-/etc/fail2ban/jail.d}"
  mkdir -p "$filter_dir" "$jail_dir"

  # Filtre : flood POST (formulaires, API)
  cat > "${filter_dir}/apache-post-flood.conf" <<'EOF'
[Definition]
failregex = ^<HOST> .* "POST .* HTTP/.*" [245]\d\d
ignoreregex =
EOF

  # Filtre : credential stuffing (401/403 en rafale)
  cat > "${filter_dir}/apache-auth-flood.conf" <<'EOF'
[Definition]
failregex = ^<HOST> .* "(?:GET|POST) .* HTTP/.*" (?:401|403)
ignoreregex =
EOF

  # Jails étendus
  cat > "${jail_dir}/custom-extended.conf" <<'EOF'
[apache-post-flood]
enabled = true
port = http,https
filter = apache-post-flood
logpath = /var/log/apache2/*access.log
maxretry = 30
findtime = 60
bantime = 600

[apache-auth-flood]
enabled = true
port = http,https
filter = apache-auth-flood
logpath = /var/log/apache2/*access.log
maxretry = 10
findtime = 120
bantime = 1800

[recidive]
enabled = true
logpath = /var/log/fail2ban.log
banaction = %(banaction_allports)s
maxretry = 3
findtime = 86400
bantime = 604800
EOF

  log "Fail2ban: filtres et jails étendus déployés"
}

# ---------------------------------- Health endpoint -----------------------------------

# Déployer un script /healthz pour un domaine
# $1 = domain — crée un script CGI retournant du JSON
deploy_healthz() {
  local domain="$1"
  local docroot="${WEB_ROOT}/${domain}/www/public"
  mkdir -p "$docroot"

  cat > "${docroot}/healthz" <<'HEALTHZ'
#!/bin/bash
echo "Content-Type: application/json"
echo ""
cat <<JSON
{
  "status": "ok",
  "hostname": "$(hostname -f 2>/dev/null || echo unknown)",
  "uptime": "$(uptime -p 2>/dev/null || echo unknown)",
  "load": "$(cat /proc/loadavg 2>/dev/null | cut -d' ' -f1-3)",
  "disk_used": "$(df -h / 2>/dev/null | awk 'NR==2{print $5}')",
  "disk_avail": "$(df -h / 2>/dev/null | awk 'NR==2{print $4}')",
  "memory_used": "$(free -m 2>/dev/null | awk '/Mem:/{printf "%d/%dMB", $3, $2}')",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
JSON
HEALTHZ
  chmod +x "${docroot}/healthz"

  log "Healthz endpoint déployé pour ${domain}"
}

# ---------------------------------- Dry-run mode (Point 23) ---------------------------

# Wrapper : exécute la commande sauf si DRY_RUN=true
dry_run_wrap() {
  if [[ "${DRY_RUN:-false}" == "true" ]]; then
    echo "[DRY-RUN] $*"
    return 0
  fi
  "$@"
}

# ---------------------------------- Notifications multi-canal (Point 24) --------------

# Envoyer une notification Slack
notify_slack() {
  local message="$1"
  [[ -n "${SLACK_WEBHOOK:-}" ]] || return 0
  curl -s -X POST -H 'Content-type: application/json' \
    --data "{\"text\":\"${message}\"}" \
    "$SLACK_WEBHOOK" >/dev/null 2>&1 || true
}

# Envoyer une notification Telegram
notify_telegram() {
  local message="$1"
  [[ -n "${TELEGRAM_BOT_TOKEN:-}" && -n "${TELEGRAM_CHAT_ID:-}" ]] || return 0
  curl -s -X POST \
    "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
    -d "chat_id=${TELEGRAM_CHAT_ID}" \
    -d "text=${message}" >/dev/null 2>&1 || true
}

# Envoyer une notification Discord
notify_discord() {
  local message="$1"
  [[ -n "${DISCORD_WEBHOOK:-}" ]] || return 0
  curl -s -X POST -H 'Content-type: application/json' \
    --data "{\"content\":\"${message}\"}" \
    "$DISCORD_WEBHOOK" >/dev/null 2>&1 || true
}

# Envoyer sur tous les canaux configurés
notify_all() {
  local message="$1"
  notify_slack "$message"
  notify_telegram "$message"
  notify_discord "$message"
}
