#!/usr/bin/env bash
# lib/install-security.sh — ClamAV, rkhunter, Logwatch, SSH alerts, AIDE, ModSec, /tmp, sysctl, logrotate, bashrc
# Sourcé par debian13-server.sh — Dépend de: lib/core.sh, lib/constants.sh, lib/helpers.sh, lib/config.sh

# ---------------------------------- 14) ClamAV ----------------------------------------
if $INSTALL_CLAMAV; then
  section "ClamAV"
  apt_install clamav clamav-daemon mailutils cron
  systemctl enable --now cron || true
  systemctl stop clamav-freshclam || true
  freshclam || true
  systemctl enable --now clamav-freshclam || true
  systemctl enable --now clamav-daemon || true

  mkdir -p "${SCRIPTS_DIR}"
  deploy_script "${SCRIPTS_DIR}/clamav_scan.sh" \
    "$(cat "${SCRIPT_DIR}/templates/clamav_scan.sh.template" 2>/dev/null || cat "${SCRIPTS_DIR}/templates/clamav_scan.sh.template")" \
    "${CRON_CLAMAV}" \
    "ClamAV scan quotidien" \
    "__CLAMAV_RETENTION__" "${CLAMAV_LOG_RETENTION_DAYS}"

  log "ClamAV opérationnel (signatures à jour si freshclam OK)."
  log "Script de scan quotidien : ${SCRIPTS_DIR}/clamav_scan.sh"
  log "Cron configuré : tous les jours à 2h00"
fi

# ---------------------------------- 14b) rkhunter -------------------------------------
if $INSTALL_RKHUNTER; then
  section "rkhunter (détection rootkits)"
  apt_install rkhunter

  backup_file /etc/rkhunter.conf
  sed -i 's/^CRON_DAILY_RUN=.*/CRON_DAILY_RUN="true"/' /etc/default/rkhunter
  sed -i 's/^CRON_DB_UPDATE=.*/CRON_DB_UPDATE="false"/' /etc/default/rkhunter
  sed -i 's/^APT_AUTOGEN=.*/APT_AUTOGEN="true"/' /etc/default/rkhunter

  sed -i 's/^UPDATE_MIRRORS=.*/UPDATE_MIRRORS=0/' /etc/rkhunter.conf
  sed -i 's/^MIRRORS_MODE=.*/MIRRORS_MODE=0/' /etc/rkhunter.conf
  sed -i 's/^WEB_CMD=.*/WEB_CMD=""/' /etc/rkhunter.conf
  sed -i 's/^ALLOWDEVFILE=.*/ALLOWDEVFILE=\/dev\/.udev\/rules.d\/root.rules/' /etc/rkhunter.conf
  if ! grep -q "SCRIPTWHITELIST=/usr/bin/egrep" /etc/rkhunter.conf; then
    cat >> /etc/rkhunter.conf <<'RKHCONF'

# Whitelist pour Debian (éviter faux positifs)
SCRIPTWHITELIST=/usr/bin/egrep
SCRIPTWHITELIST=/usr/bin/fgrep
SCRIPTWHITELIST=/usr/bin/which
SCRIPTWHITELIST=/usr/bin/ldd
ALLOWHIDDENDIR=/etc/.java
ALLOWHIDDENFILE=/etc/.gitignore
ALLOWHIDDENFILE=/etc/.mailname
RKHCONF
  fi

  rkhunter --propupd

  mkdir -p "${SCRIPTS_DIR}"
  deploy_script "${SCRIPTS_DIR}/rkhunter_scan.sh" \
    "$(cat "${SCRIPT_DIR}/templates/rkhunter_scan.sh.template" 2>/dev/null || cat "${SCRIPTS_DIR}/templates/rkhunter_scan.sh.template")" \
    "${CRON_RKHUNTER}" \
    "rkhunter scan hebdomadaire (dimanche 3h00)" \
    "__RKHUNTER_RETENTION__" "${RKHUNTER_LOG_RETENTION_DAYS}"

  log "rkhunter installé et configuré (scan hebdomadaire dimanche 3h00)"
fi

# ---------------------------------- 14c) Logwatch -------------------------------------
if $INSTALL_LOGWATCH; then
  section "Logwatch (résumé quotidien des logs)"
  apt_install logwatch

  mkdir -p /etc/logwatch/conf
  cat >/etc/logwatch/conf/logwatch.conf <<LOGWATCHCONF
MailTo = ${EMAIL_FOR_CERTBOT}
MailFrom = logwatch@${HOSTNAME_FQDN}
Detail = Med
Service = All
Range = yesterday
Format = html
Output = mail
LOGWATCHCONF

  log "Logwatch installé (rapport quotidien par email)"
fi

# ---------------------------------- 14d) SSH Login Alert ------------------------------
if $INSTALL_SSH_ALERT; then
  section "Alerte email connexion SSH"

  cat >/etc/profile.d/ssh-alert.sh <<'SSHALERT'
#!/bin/bash
# Alerte email à chaque connexion SSH

if [ -z "$SSH_CONNECTION" ] || [ -z "$PS1" ]; then
    return 2>/dev/null || exit 0
fi

if ! command -v sendmail &>/dev/null; then
    return 2>/dev/null || exit 0
fi

MAILTO="__EMAIL__"
IP=$(echo "$SSH_CONNECTION" | awk '{print $1}')
USER=$(whoami)
HOSTNAME=$(hostname -f)
DATE=$(date '+%Y-%m-%d %H:%M:%S')

GEO=$(curl -s --max-time 3 "https://ipinfo.io/${IP}/json" 2>/dev/null)
CITY=$(echo "$GEO" | grep -oP '"city"\s*:\s*"\K[^"]+' 2>/dev/null || echo "Inconnu")
COUNTRY=$(echo "$GEO" | grep -oP '"country"\s*:\s*"\K[^"]+' 2>/dev/null || echo "??")
ORG=$(echo "$GEO" | grep -oP '"org"\s*:\s*"\K[^"]+' 2>/dev/null || echo "Inconnu")

(
    echo "To: $MAILTO"
    echo "Subject: [SSH] Connexion ${USER}@${HOSTNAME} depuis ${IP}"
    echo "Content-Type: text/html; charset=UTF-8"
    echo "MIME-Version: 1.0"
    echo ""
    echo "<html><body>"
    echo "<h2 style='color:#0066cc;'>🔐 Nouvelle connexion SSH</h2>"
    echo "<table style='border-collapse:collapse;'>"
    echo "<tr><td style='padding:5px;'><strong>Serveur :</strong></td><td style='padding:5px;'>${HOSTNAME}</td></tr>"
    echo "<tr><td style='padding:5px;'><strong>Utilisateur :</strong></td><td style='padding:5px;'>${USER}</td></tr>"
    echo "<tr><td style='padding:5px;'><strong>IP source :</strong></td><td style='padding:5px;'>${IP}</td></tr>"
    echo "<tr><td style='padding:5px;'><strong>Localisation :</strong></td><td style='padding:5px;'>${CITY}, ${COUNTRY}</td></tr>"
    echo "<tr><td style='padding:5px;'><strong>FAI/Org :</strong></td><td style='padding:5px;'>${ORG}</td></tr>"
    echo "<tr><td style='padding:5px;'><strong>Date :</strong></td><td style='padding:5px;'>${DATE}</td></tr>"
    echo "</table>"
    echo "<p style='color:#888;font-size:12px;'>Si cette connexion n'est pas de vous, vérifiez immédiatement !</p>"
    echo "</body></html>"
) | sendmail -t &
SSHALERT

  sed -i "s|__EMAIL__|${EMAIL_FOR_CERTBOT}|g" /etc/profile.d/ssh-alert.sh
  chmod +x /etc/profile.d/ssh-alert.sh

  log "Alerte SSH configurée (email à chaque connexion)"
fi

# ---------------------------------- 14e) AIDE ------------------------------------------
if $INSTALL_AIDE; then
  section "AIDE (détection modifications fichiers)"
  apt_install aide

  cat >/etc/aide/aide.conf.d/99_local_excludes <<'AIDECONF'
# Exclure les fichiers qui changent fréquemment
!/var/log
!/var/cache
!/var/tmp
!/tmp
!/var/lib/apt
!/var/lib/dpkg
!/var/lib/mysql
!/var/lib/fail2ban
!/var/lib/clamav
!/var/spool
!/run
!/proc
!/sys
AIDECONF

  if [[ -f /var/lib/aide/aide.db ]]; then
    log "AIDE : base existante détectée, initialisation ignorée."
    AIDE_PID=""
  else
    log "Initialisation de la base AIDE (peut prendre plusieurs minutes)..."
    aideinit &
    AIDE_PID=$!
  fi

  mkdir -p "${SCRIPTS_DIR}"
  deploy_script "${SCRIPTS_DIR}/aide_check.sh" \
    "$(cat "${SCRIPT_DIR}/templates/aide_check.sh.template" 2>/dev/null || cat "${SCRIPTS_DIR}/templates/aide_check.sh.template")" \
    "${CRON_AIDE}" \
    "AIDE vérification quotidienne (4h00)" \
    "__AIDE_RETENTION__" "${AIDE_LOG_RETENTION_DAYS}"

  log "AIDE installé (vérification quotidienne 4h00, initialisation en cours...)"
fi

# ---------------------------------- 14f) ModSecurity OWASP CRS ------------------------
if $INSTALL_MODSEC_CRS && $INSTALL_APACHE_PHP; then
  section "ModSecurity OWASP Core Rule Set"

  apt_install modsecurity-crs

  backup_file ${MODSEC_CONFIG}
  if [ -f ${MODSEC_CONFIG}-recommended ]; then
    cp ${MODSEC_CONFIG}-recommended ${MODSEC_CONFIG}
  fi

  if $MODSEC_ENFORCE; then
    sed -i 's/^SecRuleEngine .*/SecRuleEngine On/' ${MODSEC_CONFIG}
  else
    sed -i 's/^SecRuleEngine .*/SecRuleEngine DetectionOnly/' ${MODSEC_CONFIG}
  fi
  sed -i 's|SecAuditLog .*|SecAuditLog ${MODSEC_AUDIT_LOG}|' ${MODSEC_CONFIG}

  if [[ -n "${TRUSTED_IPS:-}" ]]; then
    cat >/etc/modsecurity/whitelist-trusted-ips.conf <<'WHITELIST_HEADER'
# Whitelist des IPs de confiance
# Ces IPs bypassent les règles ModSecurity (générées par install.sh)
WHITELIST_HEADER
    rule_id=1000001
    for ip in $TRUSTED_IPS; do
      ip_escaped=$(echo "$ip" | sed 's/[.[\/*+?{}()|^$]/\\\\&/g')
      echo "SecRule REMOTE_ADDR \"^${ip_escaped}\$\" \"id:${rule_id},phase:1,allow,nolog,msg:'Trusted IP whitelist: ${ip}'\"" >> /etc/modsecurity/whitelist-trusted-ips.conf
      ((rule_id++))
    done
    log "ModSecurity: IPs de confiance whitelistées: $TRUSTED_IPS"
  fi

  if [ -d /usr/share/modsecurity-crs ]; then
    cat >/etc/apache2/mods-available/security2.conf <<'MODSECCONF'
<IfModule security2_module>
    SecDataDir /var/cache/modsecurity
    IncludeOptional /etc/modsecurity/*.conf
    IncludeOptional /etc/modsecurity/crs/crs-setup.conf
    IncludeOptional /usr/share/modsecurity-crs/rules/*.conf
</IfModule>
MODSECCONF
  fi

  mkdir -p /var/cache/modsecurity
  chown "${WEB_USER}:${WEB_USER}" /var/cache/modsecurity

  systemctl restart apache2

  # Déployer block_hack.sh (blocage IPs suspectes depuis les logs ModSec)
  mkdir -p "${SCRIPTS_DIR}"
  deploy_script "${SCRIPTS_DIR}/block_hack.sh" \
    "$(cat "${SCRIPT_DIR}/templates/block_hack.sh.template" 2>/dev/null || cat "${SCRIPTS_DIR}/templates/block_hack.sh.template")" \
    "${CRON_BLOCK_HACK}" \
    "Bloquer tentatives de hack (toutes les heures)" \
    "__TRUSTED_IPS__" "${TRUSTED_IPS:-}"

  if $MODSEC_ENFORCE; then
    log "ModSecurity OWASP CRS installé (mode blocage actif)"
  else
    log "ModSecurity OWASP CRS installé (mode DetectionOnly)"
    log "Pour activer le blocage : sed -i 's/SecRuleEngine DetectionOnly/SecRuleEngine On/' ${MODSEC_CONFIG} && systemctl restart apache2"
  fi
  log "block_hack.sh déployé (blocage IPs suspectes toutes les heures)"
fi

# ---------------------------------- 14g) Secure /tmp ----------------------------------
if $SECURE_TMP; then
  section "Sécurisation /tmp (noexec, nosuid, nodev)"

  if mount | grep -q "on /tmp type"; then
    # Vérifier si /tmp est dans fstab et s'il a déjà noexec
    if grep -q "[[:space:]]/tmp[[:space:]]" /etc/fstab; then
      if ! grep "[[:space:]]/tmp[[:space:]]" /etc/fstab | grep -q "noexec"; then
        backup_file /etc/fstab
        sed -i '/[[:space:]]\/tmp[[:space:]]/ s/defaults/defaults,noexec,nosuid,nodev/' /etc/fstab
        mount -o remount /tmp
        log "/tmp remonté avec noexec,nosuid,nodev"
      else
        log "/tmp déjà configuré avec noexec dans fstab"
      fi
    else
      backup_file /etc/fstab
      echo "tmpfs /tmp tmpfs defaults,noexec,nosuid,nodev,size=1G 0 0" >> /etc/fstab
      mount -o remount /tmp 2>/dev/null || mount /tmp
      log "/tmp ajouté au fstab avec noexec,nosuid,nodev"
    fi
  else
    if ! grep -q "tmpfs.*/tmp" /etc/fstab; then
      backup_file /etc/fstab
      echo "tmpfs /tmp tmpfs defaults,noexec,nosuid,nodev,size=1G 0 0" >> /etc/fstab
      mount -o remount /tmp 2>/dev/null || mount /tmp
      log "/tmp configuré en tmpfs avec noexec,nosuid,nodev (1G)"
    else
      log "/tmp déjà configuré en tmpfs"
    fi
  fi

  if [ ! -L /var/tmp ]; then
    if ! grep -q "/var/tmp" /etc/fstab; then
      echo "tmpfs /var/tmp tmpfs defaults,noexec,nosuid,nodev,size=1G 0 0" >> /etc/fstab
      mount /var/tmp 2>/dev/null || true
    fi
  fi

  log "/tmp et /var/tmp sécurisés"
fi

# ---------------------------------- 14h) Durcissement sudo ----------------------------
section "Durcissement sudo"
cat > /etc/sudoers.d/99-hardening <<EOF
# Timeout de session sudo (5 minutes)
Defaults timestamp_timeout=5
# Log des commandes sudo
Defaults logfile=${SUDO_LOG}
# PATH sécurisé
Defaults secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
EOF
chmod 440 /etc/sudoers.d/99-hardening
if visudo -c -f /etc/sudoers.d/99-hardening >/dev/null 2>&1; then
  log "Durcissement sudo : timeout 5min, log dans ${SUDO_LOG}, secure_path"
else
  err "Fichier sudoers invalide, suppression par sécurité"
  rm -f /etc/sudoers.d/99-hardening
fi

# ---------------------------------- 15) Sysctl/journald/updates -----------------------
section "Durcissements kernel et journald + MAJ auto sécurité"
cat >/etc/sysctl.d/99-hardening.conf <<'EOF'
# Réseau & durcissements
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.default.rp_filter=1
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.default.accept_source_route=0
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.send_redirects=0
net.ipv6.conf.all.accept_redirects=0
net.ipv6.conf.default.accept_redirects=0
net.ipv6.conf.all.accept_ra=0
net.ipv6.conf.default.accept_ra=0
net.ipv4.tcp_syncookies=1
kernel.kptr_restrict=2
kernel.dmesg_restrict=1
fs.protected_hardlinks=1
fs.protected_symlinks=1
fs.suid_dumpable=0
EOF
sysctl --system | tee -a "$LOG_FILE"

# Désactiver le module USB storage (serveur headless)
cat > /etc/modprobe.d/disable-usb-storage.conf <<'EOF'
install usb-storage /bin/true
EOF
modprobe -r usb-storage 2>/dev/null || true
log "Module usb-storage désactivé"

# Core dumps à 0
add_line_if_missing '^\* .*hard .*core .*0$' '* hard core 0' /etc/security/limits.conf
log "Core dumps désactivés dans limits.conf"

# Umask 027
if [[ -f /etc/login.defs ]]; then
  if grep -q "^UMASK" /etc/login.defs; then
    sed -i '/^UMASK/c\UMASK\t\t027' /etc/login.defs
  else
    printf 'UMASK\t\t027\n' >> /etc/login.defs
  fi
  log "Umask durci à 027 dans /etc/login.defs"
fi

sed -ri 's|^#?Storage=.*|Storage=persistent|' /etc/systemd/journald.conf
systemctl restart systemd-journald

apt_install unattended-upgrades
dpkg-reconfigure -f noninteractive unattended-upgrades

mkdir -p "${SCRIPTS_DIR}"
deploy_script "${SCRIPTS_DIR}/check-updates.sh" \
  "$(cat "${SCRIPT_DIR}/templates/check-updates.sh.template" 2>/dev/null || cat "${SCRIPTS_DIR}/templates/check-updates.sh.template")" \
  "${CRON_UPDATES}" \
  "Vérification mises à jour hebdomadaire (lundi 7h00)"

log "Script check-updates.sh créé : ${SCRIPTS_DIR}/check-updates.sh"
log "Cron configuré : lundi à 7h00"

# ---------------------------------- 15b) Logrotate -----------------------------------
section "Rotation des logs (logrotate)"
apt_install logrotate

cat > /etc/logrotate.d/custom-bootstrap <<'EOF'
/var/log/sudo.log {
    weekly
    rotate 12
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root adm
}

/var/log/bootstrap_ovh_debian13.log {
    monthly
    rotate 3
    compress
    missingok
    notifempty
    create 0640 root root
}
EOF

log "Logrotate : rotation configurée pour sudo.log et bootstrap"

if $INSTALL_MODSEC_CRS && $INSTALL_APACHE_PHP; then
  cat > /etc/logrotate.d/modsecurity-audit <<'EOF'
/var/log/apache2/modsec_audit.log {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root adm
    postrotate
        systemctl reload apache2 > /dev/null 2>&1 || true
    endscript
}
EOF
  log "Logrotate : rotation quotidienne configurée pour modsec_audit.log"
fi

if logrotate --debug /etc/logrotate.d/custom-bootstrap > /dev/null 2>&1; then
  log "Logrotate : test de configuration OK"
else
  warn "Logrotate : erreur dans la configuration custom-bootstrap"
fi

# ---------------------------------- 16) .bashrc global -------------------------------
if $INSTALL_BASHRC_GLOBAL; then
  section "Déploiement .bashrc (tous utilisateurs)"

  BASHRC_TEMPLATE="${SCRIPT_DIR}/templates/bashrc.template"
  if [[ ! -f "$BASHRC_TEMPLATE" ]]; then
    BASHRC_TEMPLATE="${SCRIPTS_DIR}/templates/bashrc.template"
  fi
  if [[ ! -f "$BASHRC_TEMPLATE" ]]; then
    warn "Template .bashrc non trouvé. Section ignorée."
  else

  install_bashrc_for() {
    local target="$1"
    [[ -d "$(dirname "$target")" ]] || return 0
    backup_file "$target"
    cp "$BASHRC_TEMPLATE" "$target"
  }

  install_bashrc_for /etc/skel/.bashrc

  install_bashrc_for /root/.bashrc
  if id -u "$ADMIN_USER" >/dev/null 2>&1; then
    install_bashrc_for "/home/${ADMIN_USER}/.bashrc"
    chown "${ADMIN_USER}:${ADMIN_USER}" "/home/${ADMIN_USER}/.bashrc"
  fi

  while IFS=: read -r user _ uid _ _ home shell; do
    if [[ "$uid" -ge 1000 && -d "$home" && -w "$home" && "$user" != "nobody" ]]; then
      install_bashrc_for "${home}/.bashrc"
      chown "${user}:${user}" "${home}/.bashrc" || true
    fi
  done < /etc/passwd

  echo -n > /etc/motd
  [[ -d /etc/update-motd.d ]] && chmod -x /etc/update-motd.d/* 2>/dev/null || true

  log ".bashrc déployé, /etc/motd vidé."
  fi # fin template check
fi
