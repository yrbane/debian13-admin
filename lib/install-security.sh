#!/usr/bin/env bash
# lib/install-security.sh — ClamAV, rkhunter, Logwatch, SSH alerts, AIDE, ModSec, /tmp, sysctl, logrotate, bashrc
# Sourcé par debian13-server.sh — Dépend de: lib/core.sh, lib/constants.sh, lib/helpers.sh, lib/config.sh
#
# Sécurité applicative et monitoring post-intrusion. Contrairement à install-base.sh
# qui sécurise le périmètre réseau (SSH, UFW, Fail2ban), ce fichier déploie les
# couches de détection et de réponse :
#
#   14)  ClamAV        → antivirus (signatures + scan quotidien)
#   14b) rkhunter      → détection rootkits (scan hebdomadaire)
#   14c) Logwatch      → résumé quotidien des logs par email
#   14d) SSH alert     → notification email à chaque connexion SSH (avec géolocalisation)
#   14e) AIDE          → intégrité filesystem (détecte les modifications de binaires)
#   14f) ModSecurity   → WAF Apache avec OWASP Core Rule Set
#   14g) AppArmor      → confinement des processus (MAC)
#   14g2) auditd       → journalisation des accès sensibles (syscalls, fichiers)
#   14h) /tmp sécurisé → noexec,nosuid,nodev (empêche l'exécution depuis /tmp)
#   15)  sysctl        → durcissement kernel (ASLR, syncookies, redirects, etc.)
#   15b) logrotate     → rotation des logs pour éviter le remplissage disque
#   16)  bashrc        → confort shell (couleurs, alias, fortune|cowsay|lolcat)
#
# Chaque composant est optionnel (contrôlé par une variable $INSTALL_*).
# Tous les scripts cron sont déployés via deploy_script() qui gère la création
# du fichier, le chmod +x, l'ajout au crontab et la substitution de placeholders.

# ---------------------------------- 14) ClamAV ----------------------------------------
# ClamAV : antivirus libre avec mises à jour de signatures via freshclam.
# Le service freshclam tourne en daemon pour télécharger les signatures en continu.
# Le scan quotidien (cron 2h00) parcourt tout le filesystem et envoie un rapport
# email si des fichiers suspects sont détectés. Les rapports au-delà de
# CLAMAV_LOG_RETENTION_DAYS sont purgés automatiquement.
if $INSTALL_CLAMAV; then
  if step_needed "sec_clamav"; then
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
    mark_done "sec_clamav"
  else
    log "sec_clamav (deja fait)"
  fi
fi

# ---------------------------------- 14b) rkhunter -------------------------------------
# rkhunter compare les binaires système contre une base de référence (--propupd).
# Il détecte : rootkits connus, fichiers cachés suspects, modifications de binaires,
# ports en écoute inhabituels, comptes sans mot de passe.
#
# Les whitelist SCRIPTWHITELIST/ALLOWHIDDEN évitent les faux positifs classiques
# sur Debian (egrep/fgrep sont des wrappers shell, .java/.gitignore sont légitimes).
# UPDATE_MIRRORS=0 + WEB_CMD="" = pas de mise à jour réseau automatique des signatures
# (on utilise APT_AUTOGEN=true pour que les mises à jour apt régénèrent la base).
if $INSTALL_RKHUNTER; then
  if step_needed "sec_rkhunter"; then
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
    mark_done "sec_rkhunter"
  else
    log "sec_rkhunter (deja fait)"
  fi
fi

# ---------------------------------- 14c) Logwatch -------------------------------------
# Logwatch parse les logs système (auth, apache, postfix, etc.) et génère un rapport
# HTML quotidien envoyé par email. Detail=Med est un bon compromis entre verbosité
# et lisibilité. Range=yesterday couvre les dernières 24h (exécution via cron.daily).
if $INSTALL_LOGWATCH; then
  if step_needed "sec_logwatch"; then
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
    mark_done "sec_logwatch"
  else
    log "sec_logwatch (deja fait)"
  fi
fi

# ---------------------------------- 14d) SSH Login Alert ------------------------------
# Script dans /etc/profile.d/ : exécuté à chaque login interactif (bash/zsh).
# On vérifie SSH_CONNECTION (ne s'exécute pas pour les sessions locales) et
# $PS1 (ne s'exécute pas pour les sessions non-interactives comme scp/rsync).
# La géolocalisation via ipinfo.io est best-effort (timeout 3s, pas bloquant).
# L'email est envoyé en background (&) pour ne pas ralentir le login.
if $INSTALL_SSH_ALERT; then
  if step_needed "sec_ssh_alert"; then
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
    mark_done "sec_ssh_alert"
  else
    log "sec_ssh_alert (deja fait)"
  fi
fi

# ---------------------------------- 14e) AIDE ------------------------------------------
# AIDE (Advanced Intrusion Detection Environment) : IDS basé sur l'intégrité des fichiers.
# Principe : on crée une base de référence (aideinit) contenant les hash de tous les
# fichiers système. Le check quotidien compare l'état actuel à cette base et signale
# toute modification (binaire modifié = potentielle compromission).
#
# Les exclusions (/var/log, /var/cache, etc.) sont critiques pour éviter les faux
# positifs massifs — ces répertoires changent légitimement en permanence.
# L'initialisation est lancée en background (&) car elle peut prendre 5-10 minutes.
if $INSTALL_AIDE; then
  if step_needed "sec_aide"; then
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
    mark_done "sec_aide"
  else
    log "sec_aide (deja fait)"
  fi
fi

# ---------------------------------- 14f) ModSecurity OWASP CRS ------------------------
# ModSecurity = WAF (Web Application Firewall) qui inspecte chaque requête HTTP.
# OWASP CRS (Core Rule Set) = ensemble de règles communautaires couvrant :
#   - Injection SQL, XSS, LFI/RFI, command injection
#   - Scanner fingerprinting, protocol anomalies
#   - Session fixation, file upload abuse
#
# Deux modes : DetectionOnly (log sans bloquer, pour tester) ou On (blocage actif).
# MODSEC_ENFORCE=true dans le .conf active le mode blocage.
#
# Les TRUSTED_IPS sont whitelistées (bypass complet des règles) pour éviter
# les faux positifs pendant le développement. En production, ces IPs devraient
# être limitées aux postes d'administration.
#
# block_hack.sh (cron horaire) parse le log d'audit ModSecurity et ajoute les IPs
# récurrentes dans les règles UFW (ban permanent au niveau réseau).
if $INSTALL_MODSEC_CRS && $INSTALL_APACHE_PHP; then
  if step_needed "sec_modsecurity"; then
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
  sed -i "s|SecAuditLog .*|SecAuditLog ${MODSEC_AUDIT_LOG}|" ${MODSEC_CONFIG}

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
    mark_done "sec_modsecurity"
  else
    log "sec_modsecurity (deja fait)"
  fi
fi

# ---------------------------------- 14f2) WebSec (reverse proxy sécurité) -----------
# WebSec est un reverse proxy de sécurité Rust qui se place devant Apache pour
# détecter les menaces HTTP en temps réel (SQLi, XSS, bots, scans, brute-force...).
# Il écoute sur :80/:443 (avec TLS termination) et forward vers Apache sur un port interne.
# La commande `websec setup --noninteractive` migre automatiquement les VHosts Apache.
if $INSTALL_WEBSEC && $INSTALL_APACHE_PHP; then
  if step_needed "sec_websec"; then
    section "WebSec (reverse proxy securite)"

    # 1. Dependances (Rust est deja gere par install-devtools.sh si INSTALL_RUST=true)
    apt_install git pkg-config libssl-dev

    # 2. Installer Rust si pas deja present
    if ! command -v cargo &>/dev/null; then
      log "Installation de Rust (requis pour WebSec)..."
      curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
      source "$HOME/.cargo/env"
    fi

    # 3. Utilisateur systeme
    if ! id websec &>/dev/null; then
      useradd -r -s /usr/sbin/nologin -d /opt/websec websec
    fi
    mkdir -p /opt/websec /etc/websec /var/log/websec /var/lib/websec
    chown websec:websec /opt/websec /var/log/websec /var/lib/websec

    # 4. Clone ou update
    if [[ -d /opt/websec/.git ]]; then
      cd /opt/websec
      sudo -u websec git pull --ff-only || true
    else
      git clone https://github.com/yrbane/websec.git /opt/websec
      chown -R websec:websec /opt/websec
    fi

    # 5. Compiler
    cd /opt/websec
    cargo build --release --features tls
    cp /opt/websec/target/release/websec /usr/local/bin/websec
    chmod 755 /usr/local/bin/websec
    setcap 'cap_net_bind_service=+ep' /usr/local/bin/websec

    # 6. Config initiale (si absente)
    if [[ ! -f /etc/websec/websec.toml ]]; then
      cp /opt/websec/config/websec.toml.example /etc/websec/websec.toml
      chown root:websec /etc/websec/websec.toml
      chmod 640 /etc/websec/websec.toml
      # Defaut sled au lieu de redis (pas de dependance externe)
      sed -i 's|type = "redis"|type = "sled"|' /etc/websec/websec.toml
      sed -i 's|# path = "websec.db"|path = "/var/lib/websec/websec.db"|' /etc/websec/websec.toml
    fi

    # 7. Service systemd
    cp /opt/websec/systemd/websec.service /etc/systemd/system/websec.service
    # Remplacer NoNewPrivileges par AmbientCapabilities (compatibilite setcap)
    if grep -q "NoNewPrivileges=yes" /etc/systemd/system/websec.service; then
      sed -i '/NoNewPrivileges=yes/d' /etc/systemd/system/websec.service
      sed -i '/\[Service\]/a AmbientCapabilities=CAP_NET_BIND_SERVICE' /etc/systemd/system/websec.service
    fi
    systemctl daemon-reload

    # 8. Setup Apache (non-interactif) — migre les ports et met a jour websec.toml
    websec setup --noninteractive -c /etc/websec/websec.toml

    # 9. Whitelist des IPs de confiance dans WebSec
    if [[ -n "${TRUSTED_IPS:-}" ]]; then
      for ip in $TRUSTED_IPS; do
        websec lists whitelist add "$ip" 2>/dev/null || true
      done
    fi
    # Toujours whitelister localhost
    websec lists whitelist add "127.0.0.1" 2>/dev/null || true
    websec lists whitelist add "::1" 2>/dev/null || true

    # 10. Demarrer
    systemctl enable --now websec
    systemctl reload apache2

    log "WebSec installe et actif devant Apache."
    log "Dashboard: http://localhost:9090/metrics"
    log "Pour desactiver: websec restore -c /etc/websec/websec.toml"

    mark_done "sec_websec"
  else
    log "sec_websec (deja fait)"
  fi
fi

# ---------------------------------- 14g) AppArmor ------------------------------------
# AppArmor = Mandatory Access Control (MAC) qui confine les processus dans des profils.
# Même si Apache est compromis, AppArmor limite ce que le processus peut lire/écrire/exécuter.
# deploy_apparmor_profiles() crée des profils pour Apache, MariaDB et Postfix.
if $INSTALL_APPARMOR; then
  if step_needed "sec_apparmor"; then
    section "AppArmor"
  apt_install apparmor apparmor-utils

  systemctl enable --now apparmor || true

  deploy_apparmor_profiles

  # Reload profiles
  if command -v apparmor_parser >/dev/null 2>&1; then
    apparmor_parser -r /etc/apparmor.d/ 2>/dev/null || true
  fi

  log "AppArmor activé avec profils locaux pour Apache, MariaDB et Postfix"
    mark_done "sec_apparmor"
  else
    log "sec_apparmor (deja fait)"
  fi
fi

# ---------------------------------- 14g2) auditd ------------------------------------
# auditd journalise les appels système sensibles (accès aux fichiers critiques,
# modifications de permissions, exécutions de binaires suspects). Utile pour
# l'analyse post-incident : "qui a fait quoi, quand, depuis quel processus".
# Les règles de hardening surveillent /etc/passwd, /etc/shadow, les clés SSH, etc.
if $INSTALL_AUDITD; then
  if step_needed "sec_auditd"; then
    section "auditd (audit de sécurité)"
  apt_install auditd audispd-plugins

  systemctl enable --now auditd || true

  deploy_auditd_rules

  # Recharger les règles
  augenrules --load 2>/dev/null || auditctl -R "${AUDIT_RULES_DIR:-/etc/audit/rules.d}/99-server-hardening.rules" 2>/dev/null || true

  log "auditd activé avec règles de hardening"
    mark_done "sec_auditd"
  else
    log "sec_auditd (deja fait)"
  fi
fi

# ---------------------------------- 14h) Secure /tmp ----------------------------------
# /tmp en noexec,nosuid,nodev empêche un attaquant de :
#   - Déposer et exécuter un binaire dans /tmp (noexec)
#   - Exploiter un binaire SUID déposé dans /tmp (nosuid)
#   - Créer des device nodes dans /tmp (nodev)
# C'est un vecteur d'attaque classique : l'attaquant télécharge un payload dans
# /tmp (world-writable), puis l'exécute. Avec noexec, l'exécution est bloquée par le kernel.
if $SECURE_TMP; then
  if step_needed "sec_secure_tmp"; then
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
    mark_done "sec_secure_tmp"
  else
    log "sec_secure_tmp (deja fait)"
  fi
fi

# ---------------------------------- 14h) Durcissement sudo ----------------------------
# timestamp_timeout=5 : le cache sudo expire après 5 min (défaut Debian : 15 min).
# logfile : toutes les commandes sudo sont journalisées (utile pour l'audit).
# secure_path : empêche l'injection de binaires via un PATH utilisateur modifié.
# Le fichier est vérifié par visudo -c avant activation (si invalide → suppression).
if step_needed "sec_sudo"; then
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
  mark_done "sec_sudo"
else
  log "sec_sudo (deja fait)"
fi

# ---------------------------------- 15) Sysctl/journald/updates -----------------------
# Durcissement kernel via sysctl — chaque paramètre a un rôle précis :
#
#   rp_filter=1          → Reverse Path Filtering : droppe les paquets avec IP source
#                           qui ne correspond pas à la route de retour (anti-spoofing)
#   icmp_echo_ignore_broadcasts=1 → bloque les Smurf attacks (ICMP broadcast flood)
#   accept_source_route=0 → refuse le routage source (empêche le détournement de route)
#   accept_redirects=0   → ignore les redirects ICMP (empêche le MitM par redirect)
#   send_redirects=0     → ne pas envoyer de redirects (pas un routeur)
#   accept_ra=0          → ignore les Router Advertisements IPv6 (pas auto-configuré)
#   tcp_syncookies=1     → protection SYN flood (génère des cookies au lieu d'allouer de la RAM)
#   kptr_restrict=2      → masque les pointeurs kernel dans /proc (anti-exploitation)
#   dmesg_restrict=1     → restreint l'accès au log kernel (informations sensibles)
#   protected_hardlinks/symlinks=1 → protège contre les race conditions sur les liens
#   suid_dumpable=0      → pas de core dump pour les binaires SUID (leak de données sensibles)
if step_needed "sec_sysctl"; then
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

  # Désactiver le module USB storage — un serveur dédié n'a aucune raison d'accepter
  # des périphériques USB. Empêche l'exfiltration de données via clé USB (compliance).
  cat > /etc/modprobe.d/disable-usb-storage.conf <<'EOF'
install usb-storage /bin/true
EOF
  modprobe -r usb-storage 2>/dev/null || true
  log "Module usb-storage désactivé"

  # Core dumps à 0
  add_line_if_missing '^\* .*hard .*core .*0$' '* hard core 0' /etc/security/limits.conf
  log "Core dumps désactivés dans limits.conf"

  # Umask 027 : les fichiers créés ne sont pas lisibles par "others" (rwxr-x---)
  # Essentiel pour éviter que les fichiers de config, logs, ou données soient
  # lisibles par tous les utilisateurs du système.
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
  mark_done "sec_sysctl"
else
  log "sec_sysctl (deja fait)"
fi

# ---------------------------------- 15b) Logrotate -----------------------------------
if step_needed "sec_logrotate"; then
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
  mark_done "sec_logrotate"
else
  log "sec_logrotate (deja fait)"
fi

# ---------------------------------- 16) .bashrc global -------------------------------
# Déploiement d'un .bashrc commun à tous les utilisateurs (existants et futurs via /etc/skel).
# Inclut : couleurs PS1, alias utiles (ll, gs, ...), fortune|cowsay|lolcat au login,
# fonctions utilitaires (mkcd, extract, etc.). On vide /etc/motd et on désactive
# update-motd.d pour que le .bashrc gère l'affichage au login (plus flexible).
if $INSTALL_BASHRC_GLOBAL; then
  if step_needed "sec_bashrc"; then
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
    mark_done "sec_bashrc"
  else
    log "sec_bashrc (deja fait)"
  fi
fi
