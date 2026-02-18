#!/usr/bin/env bash
# lib/helpers.sh — Utilitaires transversaux et fonctionnalités opérationnelles
# Sourcé par debian13-server.sh — Dépend de: lib/core.sh, lib/constants.sh
#
# Ce fichier est le « couteau suisse » du projet. Il regroupe :
#
#   1. Infrastructure bas-niveau   (tmpfiles, backup, apt wrappers)
#   2. Vérifications système       (emit_check, permissions, freshness)
#   3. Sécurité                    (AppArmor, auditd, egress, Fail2ban, WAF, mTLS)
#   4. Opérations                  (monitoring, snapshots, dashboard, backup distant)
#   5. Notifications               (Slack, Telegram, Discord)
#   6. Observabilité               (structured logging, HTML report)
#
# Principe de conception : chaque fonction est autonome (pas d'état partagé
# implicite entre fonctions) et tous les chemins sont injectables via
# variables d'environnement pour faciliter les tests unitaires.
#
# Le fichier est organisé par blocs thématiques séparés par des bandeaux
# commentés. Chaque bloc peut être lu indépendamment.

# ---------------------------------- Fichiers temporaires & cleanup -------------------
# Registre global des fichiers temporaires créés pendant l'exécution.
# Le trap EXIT garantit le nettoyage même en cas d'erreur.
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
# Deux traps séparés par intention :
# - ERR : notification (ne stoppe rien grâce à set -E qui propage le trap)
# - EXIT : nettoyage garanti (s'exécute même sur exit 0, Ctrl-C ou erreur)
# Ne pas combiner les deux dans un seul trap — le trap EXIT ne connaît pas
# $LINENO du point d'erreur, et le trap ERR ne s'exécute pas sur exit normal.
trap 'err "Erreur a la ligne $LINENO. Consulte le journal si necessaire."; err "Relancez le script pour reprendre a partir de la derniere etape reussie."' ERR
trap 'cleanup_tmpfiles' EXIT

# ---------------------------------- Prérequis -----------------------------------------
# Vérifications exécutées AVANT toute modification du système.
# Principe : échouer tôt avec un message clair plutôt que planter à mi-parcours.
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
# Fonctions réutilisables par toutes les bibliothèques d'installation.
# Nommage : verbe_objet() pour les actions, check_*() pour les vérifications.

# backup_file — Sauvegarde horodatée d'un fichier avant modification.
# Appelée systématiquement avant tout sed/cp sur un fichier de config système.
# Crée une copie avec suffixe .YYYYMMDDHHMMSS.bak (préserve permissions via cp -a).
# Usage : backup_file /etc/ssh/sshd_config
# Retourne 0 si OK, 1 si échec de copie (non bloquant : warn et continue).
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

# apt_install — Wrapper apt-get install avec retry automatique.
# Un premier échec relance apt-get update puis réessaie (2 tentatives max).
# Couvre le cas classique d'un cache APT périmé sur une fresh install OVH.
# Usage : apt_install nginx certbot python3-certbot-apache
# Retourne 0 si OK, 1 si échec après retries (err + return 1).
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

# Ajout idempotent d'une entrée crontab. Le pattern sert de clé unique :
# on supprime toute ligne matchant le pattern avant d'ajouter la nouvelle.
# Permet de relancer le script sans dupliquer les crons.
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

# deploy_script — Déployer un script cron depuis un template.
# Écriture + substitution de placeholders + chmod +x + enregistrement crontab.
# Les paires de substitution supplémentaires sont passées en arguments variadiques.
# Usage : deploy_script "/root/scripts/scan.sh" "$TEMPLATE" "0 2 * * *" "Scan quotidien" "__VAR__" "value"
# $1=chemin destination  $2=contenu  $3=schedule cron  $4=commentaire cron  $5,$6...=paires clé/valeur
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

# Vérifier la fraîcheur d'une base de données (ClamAV, rkhunter, AIDE).
# Trois paliers : fresh (OK), stale (warn), obsolète (fail).
# Fonctionne avec un fichier ou un répertoire (prend le fichier le plus récent).
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

# ================================== SÉCURITÉ =========================================
# Bloc regroupant : AppArmor, auditd, egress filtering, Fail2ban, WAF, mTLS.
# Chaque fonction est indépendante et peut être appelée individuellement
# (via --domain-add ou lors de l'installation initiale).

# ---------------------------------- AppArmor profiles --------------------------------
# deploy_apparmor_profiles — Déployer les profils AppArmor locaux.
# AppArmor confine chaque démon dans un profil restrictif (MAC : Mandatory Access Control).
# Les fichiers dans /etc/apparmor.d/local/ étendent les profils stock sans les écraser,
# ce qui survit aux mises à jour de paquets (apt ne touche pas local/).
# On autorise uniquement les chemins nécessaires (DocumentRoot, logs, TLS, sockets).
# Ref : CIS Debian 13 Benchmark §1.6 — Mandatory Access Controls
# Usage : deploy_apparmor_profiles (pas d'arguments, utilise APPARMOR_LOCAL)
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
# deploy_auditd_rules — Déployer les règles d'audit système.
# auditd trace les accès aux fichiers sensibles (passwd, shadow, sudoers, ssh),
# les exécutions privilégiées, les changements d'horloge et les modules kernel.
# Les règles sont dans un fichier numéroté 99- pour être chargées en dernier (priorité max).
# Le filtre auid>=1000 cible les humains (UID système < 1000 exclus).
# Ref : CIS Debian 13 Benchmark §4.1 — Configure System Accounting (auditd)
# Usage : deploy_auditd_rules (pas d'arguments, utilise AUDIT_RULES_DIR)
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

# === Kernel module loading ===
-a always,exit -F arch=b64 -S init_module,finit_module -k kernel_modules

# === Time changes (détection manipulation horodatage pour masquer intrusion) ===
-a always,exit -F arch=b64 -S adjtimex,settimeofday,clock_settime -k time_change
-w /etc/localtime -p wa -k time_change

# === PAM configuration (modification auth = potentielle backdoor) ===
-w /etc/pam.d/ -p wa -k pam_config
-w /etc/security/ -p wa -k pam_config

# === Login/logout tracking ===
-w /var/log/lastlog -p wa -k login_tracking
-w /var/log/faillog -p wa -k login_tracking
-w /var/log/wtmp -p wa -k login_tracking
-w /var/log/btmp -p wa -k login_tracking

# === Firewall rules (modification UFW/iptables) ===
-w /etc/ufw/ -p wa -k firewall
-w /etc/default/ufw -p wa -k firewall

# === Mount operations (détection montage USB, NFS) ===
-a always,exit -F arch=b64 -S mount,umount2 -F auid>=1000 -F auid!=4294967295 -k mount_ops
EOF

  log "auditd: règles de hardening déployées"
}

# ---------------------------------- Egress filtering ---------------------------------
# Par défaut, UFW ne filtre que l'entrant. Activer le deny outgoing + whitelist
# empêche un processus compromis de contacter un C2 ou d'exfiltrer des données.
# Seuls les ports strictement nécessaires sont ouverts en sortie.
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
# Au-delà du jail SSH par défaut, on ajoute :
#   - apache-post-flood : brute-force de formulaires (30 POST/min → ban 10min)
#   - apache-auth-flood : credential stuffing (10 x 401/403 en 2min → ban 30min)
#   - recidive : ban longue durée (7j) pour les IP déjà bannies 3 fois en 24h
# Le jail recidive lit le propre log de Fail2ban (boucle de rétroaction).
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

# ---------------------------------- WAF rules per domain ------------------------------
# Règles ModSecurity par domaine : permet de différencier les seuils de
# rate-limiting et les whitelists IP selon le domaine hébergé.
# Les règles sont dans des fichiers séparés inclus par la config ModSecurity
# principale (IncludeOptional /etc/modsecurity/rules.d/*.conf).

: "${WAF_RULES_DIR:=/etc/modsecurity/rules.d}"

deploy_waf_domain_rules() {
  local domain="$1" whitelist_ip="${2:-}" rate_limit="${3:-}"
  mkdir -p "$WAF_RULES_DIR"
  local conf="${WAF_RULES_DIR}/${domain}.conf"

  {
    echo "# WAF rules for ${domain}"
    echo "# Generated by debian13-server.sh"
    echo ""
    # Rate limiting
    echo "SecRule REQUEST_HEADERS:Host \"@contains ${domain}\" \"id:100000,phase:1,pass,nolog,setvar:ip.domain_hits=+1\""
    echo "SecRule IP:domain_hits \"@gt ${rate_limit:-200}\" \"id:100001,phase:1,deny,status:429,msg:'Rate limit exceeded for ${domain}'\""
    echo ""
    # IP whitelist
    if [[ -n "$whitelist_ip" ]]; then
      echo "# Whitelist"
      echo "SecRule REMOTE_ADDR \"@ipMatch ${whitelist_ip}\" \"id:100002,phase:1,allow,ctl:ruleEngine=Off\""
    fi
  } > "$conf"

  # Store rate limit in per-domain config if specified
  if [[ -n "$rate_limit" ]] && declare -f dm_set_domain_config >/dev/null 2>&1; then
    dm_set_domain_config "$domain" "WAF_RATE_LIMIT" "$rate_limit"
  fi

  log "WAF: règles déployées pour ${domain}"
}

# Supprimer les règles WAF d'un domaine
remove_waf_domain_rules() {
  local domain="$1"
  rm -f "${WAF_RULES_DIR}/${domain}.conf"
}

# ---------------------------------- mTLS client certificates --------------------------
# mTLS (mutual TLS) ajoute l'authentification client par certificat.
# Workflow : on crée une CA interne auto-signée, on génère des certificats
# clients signés par cette CA, et Apache vérifie le certificat client
# (SSLVerifyClient require) lors de la connexion.
# Usage typique : accès admin, API internes, VPN applicatif.
#
# Structure :
#   $MTLS_CA_DIR/ca.pem          Certificat racine CA
#   $MTLS_CA_DIR/ca-key.pem      Clé privée CA (à protéger !)
#   $MTLS_CA_DIR/clients/*.pem   Certificats clients signés

: "${MTLS_CA_DIR:=/etc/ssl/mtls-ca}"

mtls_init_ca() {
  mkdir -p "$MTLS_CA_DIR"
  if [[ -f "${MTLS_CA_DIR}/ca.pem" && -f "${MTLS_CA_DIR}/ca-key.pem" ]]; then
    log "mTLS: CA déjà initialisée"
    return 0
  fi
  openssl req -x509 -newkey rsa:4096 -days 3650 -nodes \
    -keyout "${MTLS_CA_DIR}/ca-key.pem" \
    -out "${MTLS_CA_DIR}/ca.pem" \
    -subj "/CN=Internal mTLS CA/O=${HOSTNAME_FQDN:-server}" 2>/dev/null
  log "mTLS: CA initialisée dans ${MTLS_CA_DIR}"
}

# Générer un certificat client
# $1 = nom du client
mtls_generate_client_cert() {
  local client_name="$1"
  local client_dir="${MTLS_CA_DIR}/clients"
  mkdir -p "$client_dir"

  # Generate client key and CSR
  openssl req -newkey rsa:2048 -nodes \
    -keyout "${client_dir}/${client_name}-key.pem" \
    -out "${client_dir}/${client_name}.csr" \
    -subj "/CN=${client_name}" 2>/dev/null

  # Sign with CA
  openssl x509 -req -days 365 \
    -in "${client_dir}/${client_name}.csr" \
    -CA "${MTLS_CA_DIR}/ca.pem" \
    -CAkey "${MTLS_CA_DIR}/ca-key.pem" \
    -CAcreateserial \
    -out "${client_dir}/${client_name}.pem" 2>/dev/null

  rm -f "${client_dir}/${client_name}.csr"
  log "mTLS: certificat client généré pour ${client_name}"
}

# Déployer un VHost Apache avec authentification mTLS
# $1 = domain
mtls_deploy_vhost() {
  local domain="$1"
  local conf="${APACHE_SITES_DIR:-/etc/apache2/sites-available}/015-${domain}-mtls.conf"

  cat > "$conf" <<MTLS
<VirtualHost *:443>
    ServerName ${domain}

    SSLEngine on
    SSLCertificateFile /etc/letsencrypt/live/${domain}/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/${domain}/privkey.pem

    # mTLS client certificate verification
    SSLVerifyClient require
    SSLVerifyDepth 1
    SSLCACertificateFile ${MTLS_CA_DIR}/ca.pem

    DocumentRoot /var/www/${domain}/www/public

    ErrorLog \${APACHE_LOG_DIR}/${domain}/error.log
    CustomLog \${APACHE_LOG_DIR}/${domain}/access.log combined
</VirtualHost>
MTLS
  log "mTLS: VHost déployé pour ${domain}"
}

# ================================== OPÉRATIONS ========================================
# Bloc regroupant : backup distant, monitoring, snapshots, dashboard, health.

# ---------------------------------- Backup distant ------------------------------------
# Stratégie de backup 3-2-1 : un backup local (lib/backup.sh) + un backup
# distant chiffré (GPG) envoyé par rsync over SSH.
# La config est stockée dans un fichier .conf séparé pour ne pas mélanger
# les credentials de backup avec la config du serveur.

: "${BACKUP_REMOTE_CONF:=/etc/debian13-backup-remote.conf}"

backup_remote_config() {
  local host="$1" path="$2" port="${3:-22}"
  {
    echo "BACKUP_REMOTE_HOST=${host}"
    echo "BACKUP_REMOTE_PATH=${path}"
    echo "BACKUP_REMOTE_PORT=${port}"
  } > "$BACKUP_REMOTE_CONF"
  log "Backup distant configuré : ${host}:${path} (port ${port})"
}

# Chiffrer un fichier avec GPG
# $1 = fichier source
backup_remote_encrypt() {
  local src="$1"
  if [[ -z "${GPG_RECIPIENT:-}" ]]; then
    err "Pas de GPG_RECIPIENT configuré"
    return 1
  fi
  gpg --encrypt --recipient "$GPG_RECIPIENT" --output "${src}.gpg" "$src"
  log "Backup chiffré : ${src}.gpg"
}

# Envoyer un backup vers le serveur distant via rsync
# $1 = répertoire source
backup_remote_rsync() {
  local src="$1"
  local host="${BACKUP_REMOTE_HOST:-}"
  local path="${BACKUP_REMOTE_PATH:-/backups}"
  local port="${BACKUP_REMOTE_PORT:-22}"
  rsync -avz -e "ssh -p ${port}" "${src}/" "root@${host}:${path}/"
  log "Backup envoyé vers ${host}:${path}"
}

# ---------------------------------- Monitoring & alertes proactives --------------------
# Checks légers exécutables par cron toutes les 5 minutes.
# Chaque check retourne 0 (OK) ou 1 (alerte) — monitor_run_all() agrège
# les résultats et envoie une notification si un problème est détecté.
# La liste des services surveillés est configurable via MONITOR_SERVICES.

MONITOR_SERVICES="${MONITOR_SERVICES:-apache2 postfix fail2ban ufw mariadb}"

monitor_check_services() {
  local failed=0
  for svc in $MONITOR_SERVICES; do
    local status
    status=$(systemctl is-active "$svc" 2>/dev/null || echo "inactive")
    if [[ "$status" != "active" ]]; then
      warn "Service arrêté : ${svc}"
      failed=1
    fi
  done
  return $failed
}

# Vérifier l'espace disque
# $1 = seuil en % (défaut: 85)
monitor_check_disk() {
  local threshold="${1:-85}"
  local usage
  usage=$(df / 2>/dev/null | awk 'NR==2{print $5}' | tr -d '%')
  if [[ "$usage" -ge "$threshold" ]]; then
    warn "Disque utilisé à ${usage}% (seuil: ${threshold}%)"
    return 1
  fi
  return 0
}

# Vérifier l'expiration SSL
# $1 = jours minimum (défaut: 14)
monitor_check_ssl() {
  local min_days="${1:-14}"
  local le_dir="${LETSENCRYPT_DIR:-/etc/letsencrypt}"
  local alerts=0
  for cert_dir in "${le_dir}"/live/*/; do
    [[ -d "$cert_dir" ]] || continue
    local cert="${cert_dir}fullchain.pem"
    [[ -f "$cert" ]] || continue
    local domain
    domain=$(basename "$cert_dir")
    local exp
    exp=$(openssl x509 -in "$cert" -noout -enddate 2>/dev/null | cut -d= -f2)
    [[ -z "$exp" ]] && continue
    local exp_epoch now_epoch days_left
    exp_epoch=$(date -d "$exp" +%s 2>/dev/null || echo 0)
    now_epoch=$(date +%s)
    days_left=$(( (exp_epoch - now_epoch) / 86400 ))
    if [[ "$days_left" -lt "$min_days" ]]; then
      warn "SSL ${domain} expire dans ${days_left} jours"
      alerts=1
    fi
  done
  return $alerts
}

# Vérifier la file Postfix
# $1 = seuil nombre de messages (défaut: 50)
monitor_check_postfix() {
  local threshold="${1:-50}"
  local queue_size
  queue_size=$(mailq 2>/dev/null | grep -oP '\d+ Request' | grep -oP '^\d+' || echo 0)
  [[ -z "$queue_size" ]] && queue_size=0
  if [[ "$queue_size" -ge "$threshold" ]]; then
    warn "File Postfix : ${queue_size} messages (seuil: ${threshold})"
    return 1
  fi
  return 0
}

# Exécuter tous les checks de monitoring
monitor_run_all() {
  local issues=0
  monitor_check_services || { notify_all "ALERTE ${HOSTNAME_FQDN}: service(s) arrêté(s)"; ((issues++)); }
  monitor_check_disk    || { notify_all "ALERTE ${HOSTNAME_FQDN}: disque plein (>85%)"; ((issues++)); }
  monitor_check_ssl     || { notify_all "ALERTE ${HOSTNAME_FQDN}: certificat SSL expire bientôt"; ((issues++)); }
  monitor_check_postfix || { notify_all "ALERTE ${HOSTNAME_FQDN}: file Postfix saturée"; ((issues++)); }
  if [[ "$issues" -eq 0 ]]; then
    echo "Monitoring: ${issues} checks OK"
  else
    echo "Monitoring: ${issues} alertes détectées"
  fi
  return 0
}

# Déployer le script cron de monitoring
deploy_monitor_cron() {
  local script="${MONITOR_SCRIPT:-/usr/local/bin/server-monitor.sh}"
  cat > "$script" <<MONITOR
#!/bin/bash
# Monitoring proactif — généré par debian13-server.sh
source "${SCRIPTS_DIR:-/root/scripts}/lib/core.sh"
source "${SCRIPTS_DIR:-/root/scripts}/lib/helpers.sh"
HOSTNAME_FQDN="${HOSTNAME_FQDN:-\$(hostname -f)}"
monitor_run_all
MONITOR
  chmod +x "$script"
  log "Script de monitoring déployé : ${script}"
}

# ---------------------------------- Snapshots & Rollback -------------------------------
# Snapshot léger : on copie uniquement les fichiers de configuration
# (domains.conf, VHosts Apache, logrotate, per-domain configs).
# Pas de snapshot des données web ni des bases — pour ça, utiliser
# le backup complet (lib/backup.sh) ou les snapshots OVH.
#
# Un snapshot est créé automatiquement avant --domain-add et --domain-remove
# dans debian13-server.sh, pour permettre un rollback rapide en cas de problème.

: "${SNAPSHOT_DIR:=/var/lib/debian13-snapshots}"

snapshot_create() {
  local label="$1"
  local ts
  ts=$(date +%Y%m%d-%H%M%S)
  local snap_id="${ts}-${label}"
  local snap_dir="${SNAPSHOT_DIR}/${snap_id}"
  mkdir -p "${snap_dir}/apache" "${snap_dir}/logrotate"

  # Sauvegarder domains.conf
  [[ -f "${DOMAINS_CONF:-}" ]] && cp "$DOMAINS_CONF" "${snap_dir}/domains.conf"

  # Sauvegarder configs Apache
  if [[ -d "${APACHE_SITES_DIR:-}" ]]; then
    cp "${APACHE_SITES_DIR}"/*.conf "${snap_dir}/apache/" 2>/dev/null || true
  fi

  # Sauvegarder logrotate
  if [[ -d "${LOGROTATE_DIR:-}" ]]; then
    cp "${LOGROTATE_DIR}"/apache-vhost-* "${snap_dir}/logrotate/" 2>/dev/null || true
  fi

  # Sauvegarder per-domain configs
  if [[ -d "${DOMAINS_CONF_DIR:-}" ]]; then
    cp -r "$DOMAINS_CONF_DIR" "${snap_dir}/domains.d" 2>/dev/null || true
  fi

  echo "$snap_id"
}

# Lister les snapshots disponibles
snapshot_list() {
  [[ -d "$SNAPSHOT_DIR" ]] || return 0
  ls -1 "$SNAPSHOT_DIR" 2>/dev/null
}

# Restaurer un snapshot
# $1 = snapshot ID
snapshot_restore() {
  local snap_id="$1"
  local snap_dir="${SNAPSHOT_DIR}/${snap_id}"
  if [[ ! -d "$snap_dir" ]]; then
    err "Snapshot introuvable : ${snap_id}"
    return 1
  fi

  # Restaurer domains.conf
  [[ -f "${snap_dir}/domains.conf" ]] && cp "${snap_dir}/domains.conf" "$DOMAINS_CONF"

  # Restaurer Apache configs
  if [[ -d "${snap_dir}/apache" ]] && ls "${snap_dir}/apache/"*.conf >/dev/null 2>&1; then
    cp "${snap_dir}/apache/"*.conf "${APACHE_SITES_DIR}/"
  fi

  # Restaurer logrotate
  if [[ -d "${snap_dir}/logrotate" ]] && ls "${snap_dir}/logrotate/"* >/dev/null 2>&1; then
    cp "${snap_dir}/logrotate/"* "${LOGROTATE_DIR}/"
  fi

  # Restaurer per-domain configs
  if [[ -d "${snap_dir}/domains.d" ]]; then
    cp -r "${snap_dir}/domains.d/"* "${DOMAINS_CONF_DIR}/" 2>/dev/null || true
  fi

  log "Snapshot restauré : ${snap_id}"
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

# ---------------------------------- Dashboard temps réel -------------------------------
# Dashboard HTML statique avec appel AJAX vers un CGI bash qui retourne
# du JSON (métriques système, services, SSL, Fail2ban).
# Sécurité : URL secrète (hash MD5 du domaine) + restriction IP via .htaccess.
# Refresh automatique toutes les 10 secondes sans rechargement de page.
# Aucune dépendance externe (pas de Node/Python/PHP) — fonctionne avec
# le CGI handler natif d'Apache.

deploy_dashboard() {
  local domain="$1"
  local secret="${DASHBOARD_SECRET:-$(echo "${domain}dashboard" | md5sum | cut -d' ' -f1)}"
  local dashdir="${WEB_ROOT}/${domain}/www/public/dashboard-${secret}"
  mkdir -p "$dashdir"

  # --- .htaccess : restriction IP ---
  {
    echo "Require all denied"
    for ip in ${TRUSTED_IPS:-127.0.0.1}; do
      echo "Require ip ${ip}"
    done
  } > "${dashdir}/.htaccess"

  # --- API CGI endpoint ---
  cat > "${dashdir}/api.cgi" <<'APICGI'
#!/bin/bash
echo "Content-Type: application/json"
echo ""

# Services status
svc_status() {
  if systemctl is-active --quiet "$1" 2>/dev/null; then
    echo "running"
  else
    echo "stopped"
  fi
}

# SSL days remaining
ssl_days() {
  local cert="/etc/letsencrypt/live/$1/fullchain.pem"
  if [[ -f "$cert" ]]; then
    local exp
    exp=$(openssl x509 -in "$cert" -noout -enddate 2>/dev/null | cut -d= -f2)
    if [[ -n "$exp" ]]; then
      local exp_epoch now_epoch
      exp_epoch=$(date -d "$exp" +%s 2>/dev/null || echo 0)
      now_epoch=$(date +%s)
      echo $(( (exp_epoch - now_epoch) / 86400 ))
      return
    fi
  fi
  echo "N/A"
}

# Fail2ban stats
f2b_banned() {
  fail2ban-client status "$1" 2>/dev/null | grep "Currently banned" | awk '{print $NF}' || echo "0"
}

# WebSec metrics
get_websec_json() {
  if ! command -v websec >/dev/null 2>&1; then
    echo '"websec": {"status": "not_installed", "requests_total": 0, "requests_blocked": 0, "threats": {"sqli": 0, "xss": 0, "bot": 0, "scan": 0, "bruteforce": 0}, "whitelist_count": 0, "blacklist_count": 0, "uptime": "N/A"}'
    return
  fi
  local ws_status="stopped"
  if systemctl is-active --quiet websec 2>/dev/null; then
    ws_status="running"
  fi
  local req_total=0 req_blocked=0
  local sqli=0 xss=0 bot=0 scan=0 bruteforce=0
  local wl_count=0 bl_count=0 ws_uptime="N/A"
  local metrics
  metrics=$(curl -s --max-time 2 http://localhost:9090/metrics 2>/dev/null)
  if [[ -n "$metrics" ]]; then
    req_total=$(echo "$metrics" | grep -m1 '^websec_requests_total ' | awk '{print int($2)}')
    req_blocked=$(echo "$metrics" | grep -m1 '^websec_requests_blocked ' | awk '{print int($2)}')
    sqli=$(echo "$metrics" | grep 'type="sqli"' | awk '{print int($2)}')
    xss=$(echo "$metrics" | grep 'type="xss"' | awk '{print int($2)}')
    bot=$(echo "$metrics" | grep 'type="bot"' | awk '{print int($2)}')
    scan=$(echo "$metrics" | grep 'type="scan"' | awk '{print int($2)}')
    bruteforce=$(echo "$metrics" | grep 'type="bruteforce"' | awk '{print int($2)}')
  fi
  local stats
  stats=$(websec stats 2>/dev/null)
  if [[ -n "$stats" ]]; then
    [[ "$req_total" -eq 0 ]] && req_total=$(echo "$stats" | grep -i 'total' | grep -oP '\d+' | head -1)
    [[ "$req_blocked" -eq 0 ]] && req_blocked=$(echo "$stats" | grep -i 'blocked' | grep -oP '\d+' | head -1)
    wl_count=$(echo "$stats" | grep -i 'whitelist' | grep -oP '\d+' | head -1)
    bl_count=$(echo "$stats" | grep -i 'blacklist' | grep -oP '\d+' | head -1)
    ws_uptime=$(echo "$stats" | grep -i 'uptime' | sed 's/.*: *//')
  fi
  req_total=${req_total:-0}; req_blocked=${req_blocked:-0}
  sqli=${sqli:-0}; xss=${xss:-0}; bot=${bot:-0}; scan=${scan:-0}; bruteforce=${bruteforce:-0}
  wl_count=${wl_count:-0}; bl_count=${bl_count:-0}; ws_uptime=${ws_uptime:-N/A}
  echo "\"websec\": {\"status\": \"${ws_status}\", \"requests_total\": ${req_total}, \"requests_blocked\": ${req_blocked}, \"threats\": {\"sqli\": ${sqli}, \"xss\": ${xss}, \"bot\": ${bot}, \"scan\": ${scan}, \"bruteforce\": ${bruteforce}}, \"whitelist_count\": ${wl_count}, \"blacklist_count\": ${bl_count}, \"uptime\": \"${ws_uptime}\"}"
}

# Security metrics
get_security_json() {
  local aa_enforced=0 aa_profiles=0
  if command -v aa-status >/dev/null 2>&1; then
    aa_profiles=$(aa-status --json 2>/dev/null | grep -oP '"profiles":\s*\{\s*[^}]*' | tr ',' '\n' | wc -l 2>/dev/null || aa-status 2>/dev/null | grep 'profiles are loaded' | awk '{print $1}' || echo 0)
    aa_enforced=$(aa-status --json 2>/dev/null | grep -oP '"enforce":\s*\d+' | grep -oP '\d+' || aa-status 2>/dev/null | grep 'profiles are in enforce' | awk '{print $1}' || echo 0)
  fi
  aa_enforced=${aa_enforced:-0}; aa_profiles=${aa_profiles:-0}
  local auditd_alerts=0
  if command -v ausearch >/dev/null 2>&1; then
    auditd_alerts=$(ausearch -ts today --raw 2>/dev/null | wc -l || echo 0)
  fi
  local clam_date="N/A" clam_threats=0
  local clam_log="/var/log/clamav/clamav.log"
  if [[ -f "$clam_log" ]]; then
    clam_date=$(grep -oP '\d{4}-\d{2}-\d{2}' "$clam_log" 2>/dev/null | tail -1 || echo "N/A")
    clam_threats=$(grep -c 'FOUND$' "$clam_log" 2>/dev/null || echo 0)
  fi
  local rkh_warnings=0
  local rkh_log="/var/log/rkhunter.log"
  if [[ -f "$rkh_log" ]]; then
    rkh_warnings=$(grep -c 'Warning:' "$rkh_log" 2>/dev/null || echo 0)
  fi
  echo "\"security\": {\"apparmor_enforced\": ${aa_enforced}, \"apparmor_profiles\": ${aa_profiles}, \"auditd_alerts_24h\": ${auditd_alerts}, \"clamav_last_scan\": \"${clam_date}\", \"clamav_threats\": ${clam_threats}, \"rkhunter_warnings\": ${rkh_warnings}}"
}

# Network connections
get_network_json() {
  local established=0 listening=0
  established=$(ss -tun state established 2>/dev/null | tail -n +2 | wc -l || echo 0)
  listening=$(ss -tlun 2>/dev/null | tail -n +2 | wc -l || echo 0)
  local top_ips
  top_ips=$(ss -tun state established 2>/dev/null | tail -n +2 | awk '{print $5}' | rev | cut -d: -f2- | rev | sed 's/^\[//;s/\]$//' | sort | uniq -c | sort -rn | head -5)
  local top_json=""
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    local cnt ip
    cnt=$(echo "$line" | awk '{print $1}')
    ip=$(echo "$line" | awk '{print $2}')
    [[ -z "$ip" ]] && continue
    [[ -n "$top_json" ]] && top_json+=","
    top_json+="{\"ip\":\"${ip}\",\"count\":${cnt}}"
  done <<< "$top_ips"
  echo "\"network\": {\"established\": ${established}, \"listening_ports\": ${listening}, \"top_connections\": [${top_json}]}"
}

# Recent alerts
get_alerts_json() {
  local alerts_json=""
  local lines
  lines=$(journalctl -u fail2ban -u websec --since "-1 hour" --no-pager -q -o short 2>/dev/null | tail -5)
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    local ts msg atype
    ts=$(echo "$line" | awk '{print $3}')
    if echo "$line" | grep -qi 'fail2ban'; then
      atype="fail2ban"
    elif echo "$line" | grep -qi 'websec'; then
      atype="websec"
    else
      atype="system"
    fi
    msg=$(echo "$line" | sed 's/^[^ ]* [^ ]* [^ ]* [^ ]* //' | sed 's/"/\\"/g' | cut -c1-120)
    [[ -n "$alerts_json" ]] && alerts_json+=","
    alerts_json+="{\"time\":\"${ts}\",\"type\":\"${atype}\",\"msg\":\"${msg}\"}"
  done <<< "$lines"
  echo "\"recent_alerts\": [${alerts_json}]"
}

HOSTNAME_FQDN="$(hostname -f 2>/dev/null || echo unknown)"

cat <<JSON
{
  "hostname": "${HOSTNAME_FQDN}",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "uptime": "$(uptime -p 2>/dev/null || echo unknown)",
  "load": "$(cat /proc/loadavg 2>/dev/null | cut -d' ' -f1-3)",
  "cpu_count": $(nproc 2>/dev/null || echo 1),
  "memory": {
    "total_mb": $(free -m 2>/dev/null | awk '/Mem:/{print $2}' || echo 0),
    "used_mb": $(free -m 2>/dev/null | awk '/Mem:/{print $3}' || echo 0),
    "available_mb": $(free -m 2>/dev/null | awk '/Mem:/{print $7}' || echo 0)
  },
  "disk": {
    "used": "$(df -h / 2>/dev/null | awk 'NR==2{print $5}')",
    "avail": "$(df -h / 2>/dev/null | awk 'NR==2{print $4}')",
    "total": "$(df -h / 2>/dev/null | awk 'NR==2{print $2}')"
  },
  "services": {
    "apache2": "$(svc_status apache2)",
    "postfix": "$(svc_status postfix)",
    "opendkim": "$(svc_status opendkim)",
    "mariadb": "$(svc_status mariadb)",
    "fail2ban": "$(svc_status fail2ban)",
    "ufw": "$(svc_status ufw)",
    "clamav": "$(svc_status clamav-daemon)",
    "websec": "$(svc_status websec)"
  },
  "ssl": {
    "days_remaining": "$(ssl_days "${HOSTNAME_FQDN}")"
  },
  "fail2ban": {
    "sshd_banned": "$(f2b_banned sshd)",
    "recidive_banned": "$(f2b_banned recidive)"
  },
  "postfix_queue": $(mailq 2>/dev/null | tail -1 | grep -oP '\d+' | head -1 || echo 0),
  $(get_websec_json),
  $(get_security_json),
  $(get_network_json),
  $(get_alerts_json)
}
JSON
APICGI
  chmod +x "${dashdir}/api.cgi"

  # --- Dashboard HTML ---
  cat > "${dashdir}/index.html" <<DASHHTML
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Dashboard — ${domain}</title>
<style>
:root{--bg:#0a1628;--card:#142136;--card-border:rgba(107,219,219,0.08);--accent:#dc5c3b;--cyan:#6bdbdb;--ok:#2dd4bf;--warn:#fbbf24;--crit:#f87171;--text:#e0e0e0;--muted:#7a8ba5}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Segoe UI',system-ui,-apple-system,sans-serif;background:var(--bg);color:var(--text);min-height:100vh}
.header{background:linear-gradient(135deg,#0d1b2a 0%,#142136 100%);padding:1.2em 2em;border-bottom:1px solid var(--card-border);display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:.8em}
.header-left{display:flex;align-items:center;gap:1em}
.logo{font-size:1.6em;font-weight:700;color:var(--accent);letter-spacing:-0.5px}
.header-title{font-size:1.1em;color:var(--cyan);font-weight:600}
.header-right{display:flex;align-items:center;gap:1.5em;font-size:.85em;color:var(--muted)}
.live-dot{width:8px;height:8px;border-radius:50%;background:var(--ok);display:inline-block;animation:pulse 2s infinite;margin-right:4px}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.3}}
.grid{display:grid;grid-template-columns:repeat(3,1fr);gap:1em;padding:1.5em}
@media(max-width:1024px){.grid{grid-template-columns:repeat(2,1fr)}}
@media(max-width:640px){.grid{grid-template-columns:1fr;padding:1em}}
.card{background:var(--card);border:1px solid var(--card-border);border-radius:12px;padding:1.2em;transition:border-color .3s}
.card:hover{border-color:rgba(107,219,219,0.2)}
.card h2{font-size:.85em;color:var(--cyan);margin-bottom:.8em;text-transform:uppercase;letter-spacing:1.5px;display:flex;align-items:center;gap:.5em}
.card h2 .icon{font-size:1.1em}
.metric{display:flex;justify-content:space-between;align-items:center;padding:6px 0;border-bottom:1px solid rgba(107,219,219,0.05)}
.metric:last-child{border-bottom:none}
.metric .label{color:var(--muted);font-size:.9em}
.metric .value{font-weight:600;font-size:.9em}
.badge{display:inline-block;padding:2px 10px;border-radius:20px;font-size:.8em;font-weight:600}
.badge-ok{background:rgba(45,212,191,0.15);color:var(--ok)}
.badge-warn{background:rgba(251,191,36,0.15);color:var(--warn)}
.badge-crit{background:rgba(248,113,113,0.15);color:var(--crit)}
.badge-off{background:rgba(122,139,165,0.15);color:var(--muted)}
.ok{color:var(--ok)}.warn{color:var(--warn)}.crit{color:var(--crit)}
.running{color:var(--ok)}.stopped{color:var(--crit)}
.bar{background:rgba(107,219,219,0.08);border-radius:6px;height:8px;margin-top:6px;overflow:hidden}
.bar-fill{height:100%;border-radius:6px;transition:width .6s ease}
.threat-row{display:flex;gap:.5em;flex-wrap:wrap;margin-top:.5em}
.threat-tag{font-size:.75em;padding:3px 8px;border-radius:12px;background:rgba(220,92,59,0.12);color:var(--accent);font-weight:600}
.alert-list{max-height:180px;overflow-y:auto;scrollbar-width:thin;scrollbar-color:var(--card-border) transparent}
.alert-item{padding:6px 0;border-bottom:1px solid rgba(107,219,219,0.05);font-size:.85em}
.alert-item:last-child{border-bottom:none}
.alert-time{color:var(--cyan);font-weight:600;margin-right:.5em}
.alert-type{font-size:.75em;padding:1px 6px;border-radius:8px;margin-right:.5em;font-weight:600}
.alert-type-fail2ban{background:rgba(251,191,36,0.15);color:var(--warn)}
.alert-type-websec{background:rgba(220,92,59,0.15);color:var(--accent)}
.alert-type-system{background:rgba(107,219,219,0.15);color:var(--cyan)}
.top-ip{display:flex;justify-content:space-between;align-items:center;padding:4px 0;font-size:.85em}
.top-ip .ip{color:var(--text);font-family:monospace}.top-ip .cnt{color:var(--cyan);font-weight:600}
.empty{color:var(--muted);font-style:italic;font-size:.85em;padding:8px 0}
</style>
</head>
<body>
<div class="header">
  <div class="header-left">
    <span class="logo">Debian</span>
    <span class="header-title" id="hname">${domain}</span>
  </div>
  <div class="header-right">
    <span><span class="live-dot"></span> Live</span>
    <span id="huptime"></span>
    <span id="htime"></span>
  </div>
</div>
<div class="grid" id="grid"></div>
<script>
const API='api.cgi';
function pct(u,t){return t>0?Math.round(u/t*100):0}
function badge(status){
  if(status==='running') return '<span class="badge badge-ok">running</span>';
  if(status==='stopped') return '<span class="badge badge-crit">stopped</span>';
  if(status==='not_installed') return '<span class="badge badge-off">non install\\u00e9</span>';
  return '<span class="badge badge-warn">'+status+'</span>';
}
function barColor(p){return p>85?'var(--crit)':p>70?'var(--warn)':'var(--ok)'}
function render(d){
  document.getElementById('hname').textContent=d.hostname;
  document.getElementById('huptime').textContent=d.uptime;
  document.getElementById('htime').textContent=new Date(d.timestamp).toLocaleTimeString('fr-FR');
  const memPct=pct(d.memory.used_mb,d.memory.total_mb);
  const diskPct=parseInt(d.disk.used)||0;
  let h='';

  // System
  h+='<div class="card"><h2><span class="icon">&#9881;</span> Syst\\u00e8me</h2>';
  h+='<div class="metric"><span class="label">Load</span><span class="value">'+d.load+'</span></div>';
  h+='<div class="metric"><span class="label">CPUs</span><span class="value">'+d.cpu_count+'</span></div>';
  h+='</div>';

  // Memory
  h+='<div class="card"><h2><span class="icon">&#128204;</span> M\\u00e9moire</h2>';
  h+='<div class="metric"><span class="label">Utilis\\u00e9e</span><span class="value" style="color:'+barColor(memPct)+'">'+d.memory.used_mb+' / '+d.memory.total_mb+' MB ('+memPct+'%)</span></div>';
  h+='<div class="bar"><div class="bar-fill" style="width:'+memPct+'%;background:'+barColor(memPct)+'"></div></div>';
  h+='<div class="metric"><span class="label">Disponible</span><span class="value">'+d.memory.available_mb+' MB</span></div>';
  h+='</div>';

  // Disk
  h+='<div class="card"><h2><span class="icon">&#128190;</span> Disque</h2>';
  h+='<div class="metric"><span class="label">Utilis\\u00e9</span><span class="value" style="color:'+barColor(diskPct)+'">'+d.disk.used+' de '+d.disk.total+'</span></div>';
  h+='<div class="bar"><div class="bar-fill" style="width:'+diskPct+'%;background:'+barColor(diskPct)+'"></div></div>';
  h+='<div class="metric"><span class="label">Disponible</span><span class="value">'+d.disk.avail+'</span></div>';
  h+='</div>';

  // Services
  h+='<div class="card"><h2><span class="icon">&#9889;</span> Services</h2>';
  for(const[k,v]of Object.entries(d.services)){
    h+='<div class="metric"><span class="label">'+k+'</span>'+badge(v)+'</div>';
  }
  h+='</div>';

  // SSL
  h+='<div class="card"><h2><span class="icon">&#128274;</span> SSL / TLS</h2>';
  const days=parseInt(d.ssl.days_remaining)||0;
  const dStr=d.ssl.days_remaining;
  h+='<div class="metric"><span class="label">Expiration</span><span class="value '+(days<14?'crit':days<30?'warn':'ok')+'">'+dStr+' jours</span></div>';
  h+='</div>';

  // Fail2ban + Postfix
  h+='<div class="card"><h2><span class="icon">&#128737;</span> Fail2ban</h2>';
  h+='<div class="metric"><span class="label">SSH bannis</span><span class="value">'+d.fail2ban.sshd_banned+'</span></div>';
  h+='<div class="metric"><span class="label">R\\u00e9cidive</span><span class="value">'+d.fail2ban.recidive_banned+'</span></div>';
  h+='<div class="metric"><span class="label">File Postfix</span><span class="value">'+d.postfix_queue+'</span></div>';
  h+='</div>';

  // WebSec
  if(d.websec){
    h+='<div class="card"><h2><span class="icon">&#128737;</span> WebSec WAF</h2>';
    h+='<div class="metric"><span class="label">Status</span>'+badge(d.websec.status)+'</div>';
    if(d.websec.status!=='not_installed'){
      h+='<div class="metric"><span class="label">Requ\\u00eates</span><span class="value">'+d.websec.requests_total.toLocaleString()+'</span></div>';
      const blkPct=pct(d.websec.requests_blocked,d.websec.requests_total);
      h+='<div class="metric"><span class="label">Bloqu\\u00e9es</span><span class="value" style="color:var(--accent)">'+d.websec.requests_blocked.toLocaleString()+' ('+blkPct+'%)</span></div>';
      h+='<div class="bar"><div class="bar-fill" style="width:'+blkPct+'%;background:var(--accent)"></div></div>';
      const th=d.websec.threats;
      h+='<div class="threat-row">';
      if(th.sqli) h+='<span class="threat-tag">SQLi: '+th.sqli+'</span>';
      if(th.xss) h+='<span class="threat-tag">XSS: '+th.xss+'</span>';
      if(th.bot) h+='<span class="threat-tag">Bot: '+th.bot+'</span>';
      if(th.scan) h+='<span class="threat-tag">Scan: '+th.scan+'</span>';
      if(th.bruteforce) h+='<span class="threat-tag">Brute: '+th.bruteforce+'</span>';
      if(!th.sqli&&!th.xss&&!th.bot&&!th.scan&&!th.bruteforce) h+='<span class="empty">Aucune menace</span>';
      h+='</div>';
      h+='<div class="metric"><span class="label">Whitelist</span><span class="value">'+d.websec.whitelist_count+'</span></div>';
      h+='<div class="metric"><span class="label">Blacklist</span><span class="value">'+d.websec.blacklist_count+'</span></div>';
      if(d.websec.uptime&&d.websec.uptime!=='N/A') h+='<div class="metric"><span class="label">Uptime</span><span class="value">'+d.websec.uptime+'</span></div>';
    } else {
      h+='<div class="empty">Module WebSec non install\\u00e9</div>';
    }
    h+='</div>';
  }

  // Security
  if(d.security){
    h+='<div class="card"><h2><span class="icon">&#128272;</span> S\\u00e9curit\\u00e9</h2>';
    h+='<div class="metric"><span class="label">AppArmor profils</span><span class="value">'+d.security.apparmor_enforced+' / '+d.security.apparmor_profiles+'</span></div>';
    const au=d.security.auditd_alerts_24h;
    h+='<div class="metric"><span class="label">Auditd alertes (24h)</span><span class="value '+(au>10?'warn':'ok')+'">'+au+'</span></div>';
    h+='<div class="metric"><span class="label">ClamAV scan</span><span class="value">'+d.security.clamav_last_scan+'</span></div>';
    const ct=d.security.clamav_threats;
    h+='<div class="metric"><span class="label">ClamAV menaces</span><span class="value '+(ct>0?'crit':'ok')+'">'+ct+'</span></div>';
    const rk=d.security.rkhunter_warnings;
    h+='<div class="metric"><span class="label">Rkhunter warnings</span><span class="value '+(rk>0?'warn':'ok')+'">'+rk+'</span></div>';
    h+='</div>';
  }

  // Network
  if(d.network){
    h+='<div class="card"><h2><span class="icon">&#127760;</span> R\\u00e9seau</h2>';
    h+='<div class="metric"><span class="label">Connexions \\u00e9tablies</span><span class="value">'+d.network.established+'</span></div>';
    h+='<div class="metric"><span class="label">Ports en \\u00e9coute</span><span class="value">'+d.network.listening_ports+'</span></div>';
    if(d.network.top_connections&&d.network.top_connections.length>0){
      h+='<div style="margin-top:.5em;font-size:.8em;color:var(--muted);text-transform:uppercase;letter-spacing:1px">Top connexions</div>';
      d.network.top_connections.forEach(function(c){
        h+='<div class="top-ip"><span class="ip">'+c.ip+'</span><span class="cnt">'+c.count+'</span></div>';
      });
    }
    h+='</div>';
  }

  // Recent alerts
  if(d.recent_alerts){
    h+='<div class="card"><h2><span class="icon">&#128680;</span> Alertes r\\u00e9centes</h2>';
    if(d.recent_alerts.length>0){
      h+='<div class="alert-list">';
      d.recent_alerts.forEach(function(a){
        h+='<div class="alert-item">';
        h+='<span class="alert-time">'+a.time+'</span>';
        h+='<span class="alert-type alert-type-'+a.type+'">'+a.type+'</span>';
        h+='<span>'+a.msg+'</span>';
        h+='</div>';
      });
      h+='</div>';
    } else {
      h+='<div class="empty">Aucune alerte r\\u00e9cente</div>';
    }
    h+='</div>';
  }

  document.getElementById('grid').innerHTML=h;
}
function refresh(){fetch(API).then(function(r){return r.json()}).then(render).catch(function(){document.getElementById('htime').textContent='Erreur de connexion'})}
refresh();
setInterval(refresh,10000);
</script>
</body>
</html>
DASHHTML

  log "Dashboard déployé : https://${domain}/dashboard-${secret}/"
}

# ================================== MODES D'EXÉCUTION =================================

# ---------------------------------- Dry-run mode --------------------------------------
# Enrober les commandes destructives avec dry_run_wrap() pour simuler
# l'exécution sans modifier le système. Activé par --dry-run.
# Usage : dry_run_wrap apt-get install -y nginx
dry_run_wrap() {
  if [[ "${DRY_RUN:-false}" == "true" ]]; then
    echo "[DRY-RUN] $*"
    return 0
  fi
  "$@"
}

# ---------------------------------- Notifications multi-canal -------------------------
# Chaque canal est optionnel : si la variable webhook/token n'est pas définie,
# la fonction retourne silencieusement 0 (pas d'erreur).
# notify_all() dispatche vers tous les canaux configurés en un seul appel.
# Les erreurs réseau sont avalées (|| true) — une notification ratée ne
# doit jamais bloquer le déroulement du script principal.

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

# ================================== OBSERVABILITÉ =====================================

# ---------------------------------- Structured logging --------------------------------
# Logs JSON (une ligne = un objet) vers $STRUCTURED_LOG pour ingestion par
# des outils comme jq, Loki, Elasticsearch. Complémentaire aux logs console
# (core.sh) qui sont pour l'humain. Format NDJSON (newline-delimited JSON).
# Activé uniquement si STRUCTURED_LOG est défini (chemin du fichier de sortie).
#
# Usage : slog "info" "Domaine ajouté" "domain=example.com" "selector=mail"
# Produit : {"ts":"...","level":"info","msg":"Domaine ajouté","domain":"example.com","selector":"mail"}
slog() {
  [[ -n "${STRUCTURED_LOG:-}" ]] || return 0
  local level="$1" msg="$2"; shift 2
  # Escape double quotes in message
  msg="${msg//\\/\\\\}"
  msg="${msg//\"/\\\"}"
  local ts
  ts="$(date -Iseconds)"
  local extra=""
  local kv k v
  for kv in "$@"; do
    k="${kv%%=*}"
    v="${kv#*=}"
    v="${v//\\/\\\\}"
    v="${v//\"/\\\"}"
    extra="${extra},\"${k}\":\"${v}\""
  done
  printf '{"ts":"%s","level":"%s","msg":"%s"%s}\n' "$ts" "$level" "$msg" "$extra" >> "$STRUCTURED_LOG"
}

# ---------------------------------- HTML audit report ---------------------------------
# Rapport HTML généré pendant la phase de vérification (--audit).
# Chaque emit_check() du système de vérification (lib/verify.sh) appelle
# aussi html_report_check() pour alimenter le rapport en parallèle.
# Le rapport est auto-contenu (CSS inline, pas de dépendance externe).
# Activé uniquement si HTML_REPORT est défini (chemin du fichier de sortie).

html_report_start() {
  [[ -n "${HTML_REPORT:-}" ]] || return 0
  local title="$1"
  cat > "$HTML_REPORT" <<EOF
<!DOCTYPE html>
<html lang="fr">
<head><meta charset="utf-8"><title>${title}</title>
<style>
body{font-family:sans-serif;margin:2em;background:#f5f5f5}
h1{color:#333}h2{color:#555;border-bottom:1px solid #ddd;padding-bottom:4px}
.ok{color:#2d7d2d}.warn{color:#b8860b}.fail{color:#c0392b}
table{border-collapse:collapse;width:100%;margin-bottom:1.5em}
td,th{padding:6px 12px;text-align:left;border-bottom:1px solid #eee}
tr:hover{background:#e9e9e9}
.summary{font-size:1.2em;margin:1em 0;padding:1em;background:#fff;border-radius:8px}
</style></head>
<body><h1>${title}</h1>
EOF
}

# Add a section heading
# $1 = section name
html_report_section() {
  [[ -n "${HTML_REPORT:-}" ]] || return 0
  echo "<h2>$1</h2><table>" >> "$HTML_REPORT"
}

# Add a check result row
# $1 = status (ok|warn|fail), $2 = description
html_report_check() {
  [[ -n "${HTML_REPORT:-}" ]] || return 0
  local status="$1" desc="$2"
  local icon
  case "$status" in
    ok)   icon="&#10004;" ;;
    warn) icon="&#9888;"  ;;
    fail) icon="&#10008;" ;;
    *)    icon="?"        ;;
  esac
  echo "<tr><td class=\"${status}\">${icon} ${status}</td><td>${desc}</td></tr>" >> "$HTML_REPORT"
}

# Close the report
html_report_end() {
  [[ -n "${HTML_REPORT:-}" ]] || return 0
  cat >> "$HTML_REPORT" <<EOF
</table>
<div class="summary">
Résumé : <span class="ok">${CHECKS_OK:-0} OK</span> |
<span class="warn">${CHECKS_WARN:-0} avertissements</span> |
<span class="fail">${CHECKS_FAIL:-0} erreurs</span>
</div>
<p><em>Généré le $(date '+%F %T')</em></p>
</body></html>
EOF
}

# ================================== CHECKPOINT / RESUME ===============================
# Système de reprise après interruption. Un fichier texte .install-progress enregistre
# chaque étape terminée. Au redémarrage, le script détecte le fichier et propose de
# reprendre à la dernière étape réussie.
PROGRESS_FILE="${SCRIPT_DIR:-.}/.install-progress"

step_needed() {
  [[ -f "$PROGRESS_FILE" ]] || return 0
  grep -qxF "$1" "$PROGRESS_FILE" && return 1 || return 0
}

mark_done() {
  if [[ ! -f "$PROGRESS_FILE" ]]; then
    echo "# debian13-server progress" > "$PROGRESS_FILE"
    echo "# started=$(date -Iseconds)" >> "$PROGRESS_FILE"
    echo "# config_hash=$(config_hash)" >> "$PROGRESS_FILE"
  fi
  grep -qxF "$1" "$PROGRESS_FILE" 2>/dev/null || echo "$1" >> "$PROGRESS_FILE"
}

clear_progress() { rm -f "$PROGRESS_FILE"; }

show_progress() {
  [[ -f "$PROGRESS_FILE" ]] || return 0
  local done=0
  while IFS= read -r line; do
    [[ "$line" == \#* || -z "$line" ]] && continue
    ((done++)) || true
  done < "$PROGRESS_FILE"
  log "${done} etape(s) deja completee(s)."
  if [[ "$done" -gt 0 ]]; then
    note "Dernieres etapes terminees :"
    grep -v '^#' "$PROGRESS_FILE" | grep -v '^$' | tail -5 | while read -r s; do
      printf "  ${GREEN}✓${RESET} %s\n" "$s"
    done || true
  fi
}

config_hash() {
  local h=""
  for v in INSTALL_LOCALES INSTALL_SSH_HARDEN INSTALL_UFW GEOIP_BLOCK \
           INSTALL_FAIL2BAN INSTALL_APACHE_PHP INSTALL_MARIADB INSTALL_PHPMYADMIN \
           INSTALL_POSTFIX_DKIM INSTALL_CERTBOT INSTALL_DEVTOOLS INSTALL_NODE \
           INSTALL_RUST INSTALL_PYTHON3 INSTALL_COMPOSER INSTALL_SYMFONY \
           INSTALL_SHELL_FUN INSTALL_CLAMAV INSTALL_RKHUNTER INSTALL_LOGWATCH \
           INSTALL_SSH_ALERT INSTALL_AIDE INSTALL_MODSEC_CRS INSTALL_WEBSEC \
           INSTALL_APPARMOR INSTALL_AUDITD SECURE_TMP INSTALL_BASHRC_GLOBAL; do
    h+="${v}=${!v:-};"
  done
  echo "$h" | md5sum | cut -c1-12
}
