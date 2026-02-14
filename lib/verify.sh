#!/usr/bin/env bash
# lib/verify.sh — Moteur de vérification unifié + 14 fonctions verify_*()
# Sourcé par debian13-server.sh — Dépend de: lib/core.sh, lib/constants.sh, lib/helpers.sh, lib/config.sh

# ================================== VÉRIFICATIONS =====================================
# (#11 Phase 4) Moteur de vérification unifié — emit_check() dispatche CLI ou HTML
# CHECK_MODE : "cli" (sortie terminal) ou "html" (sortie fichier HTML)
CHECK_MODE="cli"

# Compteurs
CHECKS_OK=0
CHECKS_WARN=0
CHECKS_FAIL=0

check_ok()   { printf "${GREEN}  ✔ %s${RESET}\n" "$1"; ((++CHECKS_OK)) || true; }
check_warn() { printf "${YELLOW}  ⚠ %s${RESET}\n" "$1"; ((++CHECKS_WARN)) || true; }
check_fail() { printf "${RED}  ✖ %s${RESET}\n" "$1"; ((++CHECKS_FAIL)) || true; }
check_skip() { printf "${CYAN}  ○ %s (ignoré)${RESET}\n" "$1"; }

# Dispatche vers CLI ou HTML selon CHECK_MODE
emit_check() {
  local status="$1" msg="$2"
  if [[ "$CHECK_MODE" == "html" ]]; then
    add_html_check "$status" "$msg"
  else
    case "$status" in
      ok)   check_ok "$msg" ;;
      warn) check_warn "$msg" ;;
      fail) check_fail "$msg" ;;
      info) printf "${CYAN}  ℹ %s${RESET}\n" "$msg" ;;
    esac
  fi
}

emit_section() {
  local title="$1"
  if [[ "$CHECK_MODE" == "html" ]]; then
    add_html_section "$title"
  else
    echo ""
    printf "${BOLD}${MAGENTA}── %s ──${RESET}\n" "$title"
  fi
}

emit_section_close() {
  [[ "$CHECK_MODE" == "html" ]] && close_section || true
}

# ---- Fonctions de vérification (partagées CLI/HTML via emit_check) ----

verify_services() {
  emit_section "Services"

  # SSH
  check_service_active ssh "SSH" || check_service_active sshd "SSH" || true

  # UFW
  if $INSTALL_UFW; then
    if ufw status | grep -qiE "(Status|État).*acti"; then
      emit_check ok "UFW : actif"
    else
      emit_check fail "UFW : inactif"
    fi
  fi

  # GeoIP Block
  if $GEOIP_BLOCK; then
    if ipset list geoip_blocked >/dev/null 2>&1; then
      local geoip_count
      geoip_count=$(ipset list geoip_blocked 2>/dev/null | grep -c '^[0-9]') || geoip_count=0
      emit_check ok "GeoIP : ${geoip_count} plages bloquées"
    else
      emit_check fail "GeoIP : ipset geoip_blocked non trouvé"
    fi
  fi

  # Fail2ban
  if $INSTALL_FAIL2BAN; then
    if check_service_active fail2ban "Fail2ban"; then
      local jails banned_total banned
      jails=$(fail2ban-client status 2>/dev/null | grep "Jail list" | sed 's/.*:\s*//' | tr -d ' ')
      [[ -n "$jails" ]] && emit_check ok "Fail2ban jails : $jails"
      banned_total=0
      for jail in $(echo "$jails" | tr ',' ' '); do
        banned=$(fail2ban-client status "$jail" 2>/dev/null | grep "Currently banned" | awk '{print $NF}')
        banned_total=$((banned_total + ${banned:-0}))
      done
      [[ "$banned_total" -gt 0 ]] && emit_check ok "Fail2ban : ${banned_total} IP(s) actuellement bannie(s)"
      if [[ -n "${TRUSTED_IPS:-}" ]]; then
        local f2b_ignoreip
        f2b_ignoreip=$(grep "^ignoreip" /etc/fail2ban/jail.local 2>/dev/null | cut -d= -f2 || true)
        emit_check ok "Fail2ban ignoreip : ${f2b_ignoreip:-non configuré}"
      fi
    fi
  fi

  # IPs de confiance
  if [[ -n "${TRUSTED_IPS:-}" ]]; then
    emit_check ok "IPs de confiance configurées : $TRUSTED_IPS"
    if [[ -f /etc/modsecurity/whitelist-trusted-ips.conf ]]; then
      local modsec_wl_count
      modsec_wl_count=$(safe_count "SecRule REMOTE_ADDR" /etc/modsecurity/whitelist-trusted-ips.conf)
      emit_check ok "ModSecurity whitelist : ${modsec_wl_count} règle(s)"
    fi
  fi

  # Apache
  $INSTALL_APACHE_PHP && check_service_active apache2 "Apache"

  # MariaDB
  $INSTALL_MARIADB && check_service_active mariadb "MariaDB"

  # phpMyAdmin
  if $INSTALL_PHPMYADMIN; then
    if [[ -f /etc/phpmyadmin/apache.conf ]]; then
      emit_check ok "phpMyAdmin : installé"
      if [[ -f /root/.phpmyadmin_alias ]]; then
        local pma_alias
        pma_alias=$(cat /root/.phpmyadmin_alias)
        emit_check ok "phpMyAdmin : URL sécurisée (/${pma_alias})"
      else
        emit_check warn "phpMyAdmin : URL par défaut /phpmyadmin (risque sécurité)"
      fi
    else
      emit_check fail "phpMyAdmin : non installé"
    fi
  fi

  # Postfix
  if $INSTALL_POSTFIX_DKIM; then
    check_service_active postfix "Postfix"
    check_service_active opendkim "OpenDKIM"
  fi

  # ClamAV
  if $INSTALL_CLAMAV; then
    check_service_active clamav-daemon "ClamAV"
    [[ -x ${SCRIPTS_DIR}/clamav_scan.sh ]] && emit_check ok "ClamAV : script de scan présent" || emit_check fail "ClamAV : script de scan absent"
    crontab -l 2>/dev/null | grep -q "clamav_scan.sh" && emit_check ok "ClamAV : cron quotidien configuré" || emit_check warn "ClamAV : cron non configuré"
    check_db_freshness /var/lib/clamav "ClamAV" 1 "$DB_FRESH_DAYS"
  fi

  emit_section_close
}

verify_ssh() {
  emit_section "Sécurité SSH"
  if $INSTALL_SSH_HARDEN; then
    check_config_grep "$SSHD_CONFIG" "^PermitRootLogin\s+no" "SSH : connexion root désactivée" "SSH : connexion root NON désactivée"
    check_config_grep "$SSHD_CONFIG" "^PasswordAuthentication\s+no" "SSH : auth par mot de passe désactivée" "SSH : auth par mot de passe NON désactivée"
    check_config_grep "$SSHD_CONFIG" "^Port\s+${SSH_PORT}" "SSH : port ${SSH_PORT} configuré" "SSH : port ${SSH_PORT} non trouvé"
    check_config_grep "$SSHD_CONFIG" "^AllowUsers\s+.*${ADMIN_USER}" "SSH : AllowUsers contient ${ADMIN_USER}" "SSH : AllowUsers sans ${ADMIN_USER}"

    # Root authorized_keys (doit être vide si PermitRootLogin=no)
    if [[ -f /root/.ssh/authorized_keys ]]; then
      if [[ -s /root/.ssh/authorized_keys ]]; then
        local root_keys
        root_keys=$(grep -c "^ssh-" /root/.ssh/authorized_keys 2>/dev/null || echo "0")
        emit_check warn "SSH : /root/.ssh/authorized_keys contient ${root_keys} clé(s) (inutile avec PermitRootLogin=no)"
      else
        emit_check ok "SSH : /root/.ssh/authorized_keys vide"
      fi
    else
      emit_check ok "SSH : pas de /root/.ssh/authorized_keys"
    fi
  fi
  emit_section_close
}

verify_web() {
  emit_section "Sécurité Web"
  if $INSTALL_APACHE_PHP; then
    # Headers de sécurité Apache
    if [[ -f /etc/apache2/conf-available/security-headers.conf ]]; then
      if a2query -c security-headers >/dev/null 2>&1; then
        emit_check ok "Apache : headers de sécurité activés"
      else
        emit_check warn "Apache : headers de sécurité non activés"
      fi
    fi

    # ServerTokens
    if grep -rq "ServerTokens Prod" /etc/apache2/ 2>/dev/null; then
      emit_check ok "Apache : ServerTokens Prod"
    else
      emit_check warn "Apache : ServerTokens non configuré à Prod"
    fi

    # PHP expose_php
    if curl -sI http://localhost/ 2>/dev/null | grep -qi "X-Powered-By:.*PHP"; then
      emit_check warn "PHP : expose_php n'est pas Off (header X-Powered-By visible)"
    else
      emit_check ok "PHP : expose_php = Off (pas de header X-Powered-By)"
    fi

    # display_errors
    local php_ini
    php_ini=$(find /etc/php -path "*/apache2/php.ini" 2>/dev/null | head -1)
    if [[ -n "$php_ini" ]] && grep -qE "^\s*display_errors\s*=\s*Off" "$php_ini"; then
      emit_check ok "PHP : display_errors = Off"
    elif [[ -n "$php_ini" ]]; then
      emit_check warn "PHP : display_errors n'est pas Off dans $php_ini"
    else
      emit_check warn "PHP : php.ini apache2 non trouvé"
    fi

    # disable_functions
    local disabled_funcs
    disabled_funcs=$(php -i 2>/dev/null | grep "^disable_functions" | head -1)
    if [[ "$disabled_funcs" == *"exec"* ]]; then
      emit_check ok "PHP : fonctions dangereuses désactivées"
    elif $PHP_DISABLE_FUNCTIONS; then
      emit_check warn "PHP : disable_functions non configuré"
    else
      emit_check info "PHP : fonctions exec/shell autorisées (choix utilisateur)"
    fi

    # HSTS
    if grep -q "Strict-Transport-Security" /etc/apache2/conf-available/security-headers.conf 2>/dev/null; then
      emit_check ok "Apache : header HSTS configuré"
    else
      emit_check warn "Apache : header HSTS absent (Strict-Transport-Security)"
    fi

    # mod_security
    if a2query -m security2 >/dev/null 2>&1; then
      emit_check ok "Apache : mod_security activé"
    else
      emit_check warn "Apache : mod_security non activé"
    fi

    # Version PHP
    local php_ver
    php_ver=$(php -v 2>/dev/null | head -1 | awk '{print $2}')
    [[ -n "$php_ver" ]] && emit_check ok "PHP : version ${php_ver}"

    # SSL/TLS Certificats
    if $INSTALL_CERTBOT; then
      if [[ -d /etc/letsencrypt/live/${HOSTNAME_FQDN} ]]; then
        local cert_file="/etc/letsencrypt/live/${HOSTNAME_FQDN}/cert.pem"
        if [[ -f "$cert_file" ]]; then
          local cert_expiry cert_expiry_epoch days_left
          cert_expiry=$(openssl x509 -enddate -noout -in "$cert_file" 2>/dev/null | cut -d= -f2)
          cert_expiry_epoch=$(date -d "$cert_expiry" +%s 2>/dev/null || echo 0)
          days_left=$(days_until "$cert_expiry_epoch")
          if [[ "$days_left" -gt "$SSL_WARN_DAYS" ]]; then
            emit_check ok "SSL : certificat valide (expire dans ${days_left} jours)"
          elif [[ "$days_left" -gt 7 ]]; then
            emit_check warn "SSL : certificat expire dans ${days_left} jours"
          elif [[ "$days_left" -gt 0 ]]; then
            emit_check fail "SSL : certificat expire dans ${days_left} jours - renouveler !"
          else
            emit_check fail "SSL : certificat expiré !"
          fi

          # Vérifier la couverture wildcard
          if $CERTBOT_WILDCARD; then
            if openssl x509 -in "$cert_file" -noout -text 2>/dev/null | grep -q "\\*.${HOSTNAME_FQDN}"; then
              emit_check ok "SSL : certificat wildcard *.${HOSTNAME_FQDN} actif"
            else
              emit_check warn "SSL : certificat sans wildcard (*.${HOSTNAME_FQDN} absent)"
            fi
          fi
        fi
      else
        emit_check warn "SSL : certificat Let's Encrypt non trouvé pour ${HOSTNAME_FQDN}"
      fi

      # Timer de renouvellement
      if systemctl is-active --quiet certbot.timer 2>/dev/null || systemctl is-enabled --quiet certbot.timer 2>/dev/null; then
        emit_check ok "SSL : renouvellement automatique activé"
      else
        emit_check warn "SSL : timer certbot non actif"
      fi

      # Hook de renouvellement
      if [[ -x /etc/letsencrypt/renewal-hooks/deploy/reload-apache.sh ]]; then
        emit_check ok "SSL : hook de renouvellement Apache présent"
      else
        emit_check warn "SSL : hook de renouvellement Apache absent"
      fi

      # VirtualHosts
      if [[ -f "/etc/apache2/sites-enabled/010-${HOSTNAME_FQDN}.conf" ]]; then
        emit_check ok "VHost : 010-${HOSTNAME_FQDN}.conf activé"
      else
        emit_check warn "VHost : 010-${HOSTNAME_FQDN}.conf non activé"
      fi

      # DocumentRoot
      if [[ -d "/var/www/${HOSTNAME_FQDN}/www/public" ]]; then
        emit_check ok "VHost : DocumentRoot /var/www/${HOSTNAME_FQDN}/www/public existe"
      else
        emit_check warn "VHost : DocumentRoot /var/www/${HOSTNAME_FQDN}/www/public absent"
      fi

      # Page de parking
      if [[ -f "/var/www/${HOSTNAME_FQDN}/www/public/index.html" ]]; then
        emit_check ok "Parking : page index.html déployée"
      else
        emit_check warn "Parking : page index.html absente"
      fi

      # Pages d'erreur WebGL
      if [[ -f "${ERROR_PAGES_DIR}/error.php" ]]; then
        emit_check ok "Error pages : error.php WebGL déployé"
      else
        emit_check warn "Error pages : error.php non trouvé dans ${ERROR_PAGES_DIR}"
      fi
      if [[ -f "${ERROR_PAGES_DIR}/css/error.css" ]]; then
        emit_check ok "Error pages : CSS déployé"
      else
        emit_check warn "Error pages : CSS absent"
      fi

      # Credentials OVH (pour wildcard)
      if $CERTBOT_WILDCARD; then
        if [[ -f "${OVH_DNS_CREDENTIALS}" ]]; then
          local ovh_perms
          ovh_perms=$(stat -c %a "${OVH_DNS_CREDENTIALS}" 2>/dev/null)
          if [[ "$ovh_perms" == "600" ]]; then
            emit_check ok "SSL : credentials OVH présents (mode 600)"
          else
            emit_check warn "SSL : credentials OVH permissions ${ovh_perms} (attendu: 600)"
          fi
          # Vérifier que le renewal config utilise dns-ovh
          if grep -q "authenticator = dns-ovh" "/etc/letsencrypt/renewal/${HOSTNAME_FQDN}.conf" 2>/dev/null; then
            emit_check ok "SSL : renouvellement configuré via DNS OVH"
          else
            emit_check warn "SSL : renouvellement non configuré via DNS OVH"
          fi
        else
          emit_check fail "SSL : credentials OVH absents (${OVH_DNS_CREDENTIALS})"
        fi
      fi
    fi
  fi
  emit_section_close
}

verify_system() {
  emit_section "Sécurité Système"

  # Kernel hardening
  if [[ -f /etc/sysctl.d/99-hardening.conf ]]; then
    emit_check ok "Sysctl : fichier de durcissement présent"
    sysctl net.ipv4.tcp_syncookies 2>/dev/null | grep -q "= 1" && emit_check ok "Kernel : TCP SYN cookies activés"
    sysctl kernel.kptr_restrict 2>/dev/null | grep -q "= 2" && emit_check ok "Kernel : pointeurs kernel masqués"
  else
    emit_check warn "Sysctl : fichier de durcissement absent"
  fi

  # Unattended upgrades
  if dpkg -l | grep -q unattended-upgrades; then
    emit_check ok "Mises à jour automatiques : installées"
  else
    emit_check warn "Mises à jour automatiques : non installées"
  fi

  # Mises à jour en attente
  local updates_pending
  updates_pending=$(apt-get -s upgrade 2>/dev/null | grep -c "^Inst " || true)
  updates_pending=$(sanitize_int "$updates_pending")
  if [[ "$updates_pending" -eq 0 ]]; then
    emit_check ok "Système : à jour (pas de mises à jour en attente)"
  elif [[ "$updates_pending" -lt 10 ]]; then
    emit_check warn "Système : ${updates_pending} mise(s) à jour en attente"
  else
    emit_check warn "Système : ${updates_pending} mises à jour en attente - apt upgrade recommandé"
  fi

  # Redémarrage requis
  if [[ -f /var/run/reboot-required ]]; then
    emit_check warn "Système : redémarrage requis"
  else
    emit_check ok "Système : pas de redémarrage requis"
  fi

  # Script check-updates
  [[ -x ${SCRIPTS_DIR}/check-updates.sh ]] && emit_check ok "Script check-updates : présent" || emit_check warn "Script check-updates : absent"
  crontab -l 2>/dev/null | grep -q "check-updates.sh" && emit_check ok "Script check-updates : cron hebdo configuré (lundi 7h00)" || emit_check warn "Script check-updates : cron non configuré"

  # Journald persistent
  if grep -q "Storage=persistent" /etc/systemd/journald.conf 2>/dev/null; then
    emit_check ok "Journald : stockage persistant"
  else
    emit_check warn "Journald : stockage non persistant"
  fi

  # Logrotate
  if [[ -f /etc/logrotate.conf ]]; then
    emit_check ok "Logrotate : configuré"
    if [[ -f /var/lib/logrotate/status ]]; then
      local logrotate_date logrotate_age
      logrotate_date=$(stat -c %Y /var/lib/logrotate/status 2>/dev/null)
      if [[ -n "$logrotate_date" ]]; then
        logrotate_age=$(days_since "$logrotate_date")
        if [[ "$logrotate_age" -le 1 ]]; then
          emit_check ok "Logrotate : exécuté dans les dernières 24h"
        elif [[ "$logrotate_age" -le 7 ]]; then
          emit_check warn "Logrotate : dernière exécution il y a ${logrotate_age} jours"
        else
          emit_check warn "Logrotate : pas exécuté depuis ${logrotate_age} jours"
        fi
      fi
    fi
  else
    emit_check warn "Logrotate : non configuré"
  fi

  # Configs logrotate custom
  [[ -f /etc/logrotate.d/custom-bootstrap ]] && emit_check ok "Logrotate : config custom-bootstrap présente" || emit_check warn "Logrotate : config custom-bootstrap absente"
  if $INSTALL_MODSEC_CRS && $INSTALL_APACHE_PHP; then
    [[ -f /etc/logrotate.d/modsecurity-audit ]] && emit_check ok "Logrotate : config modsecurity-audit présente" || emit_check warn "Logrotate : config modsecurity-audit absente"
  fi

  # Taille des logs
  local log_size log_size_mb
  log_size=$(du -sh /var/log 2>/dev/null | awk '{print $1}')
  if [[ -n "$log_size" ]]; then
    log_size_mb=$(du -sm /var/log 2>/dev/null | awk '{print $1}')
    if [[ "$log_size_mb" -lt "$LOG_SIZE_WARN_MB" ]]; then
      emit_check ok "Logs : ${log_size} utilisés"
    elif [[ "$log_size_mb" -lt "$LOG_SIZE_FAIL_MB" ]]; then
      emit_check warn "Logs : ${log_size} utilisés (envisager nettoyage)"
    else
      emit_check fail "Logs : ${log_size} utilisés - nettoyage recommandé"
    fi
  fi

  # rkhunter
  if $INSTALL_RKHUNTER; then
    if command -v rkhunter >/dev/null 2>&1; then
      emit_check ok "rkhunter : installé"
      [[ -x ${SCRIPTS_DIR}/rkhunter_scan.sh ]] && emit_check ok "rkhunter : script de scan présent"
      crontab -l 2>/dev/null | grep -q "rkhunter_scan" && emit_check ok "rkhunter : cron hebdo configuré (dimanche 3h00)"
      check_db_freshness /var/lib/rkhunter/db/rkhunter.dat "rkhunter" "$DB_FRESH_DAYS" "$DB_STALE_DAYS"
    else
      emit_check warn "rkhunter : non installé"
    fi
  fi

  # Logwatch
  if $INSTALL_LOGWATCH; then
    if command -v logwatch >/dev/null 2>&1; then
      emit_check ok "Logwatch : installé"
      [[ -f /etc/logwatch/conf/logwatch.conf ]] && emit_check ok "Logwatch : configuré (rapport quotidien)"
    else
      emit_check warn "Logwatch : non installé"
    fi
  fi

  # SSH Alert
  if $INSTALL_SSH_ALERT; then
    [[ -f /etc/profile.d/ssh-alert.sh ]] && emit_check ok "SSH Alert : script d'alerte actif" || emit_check warn "SSH Alert : script absent"
  fi

  # AIDE
  if $INSTALL_AIDE; then
    if command -v aide >/dev/null 2>&1; then
      emit_check ok "AIDE : installé"
      check_db_freshness /var/lib/aide/aide.db "AIDE" "$DB_FRESH_DAYS" "$DB_STALE_DAYS"
      [[ -x ${SCRIPTS_DIR}/aide_check.sh ]] && emit_check ok "AIDE : script de vérification présent"
      crontab -l 2>/dev/null | grep -q "aide_check" && emit_check ok "AIDE : cron quotidien configuré (4h00)"
    else
      emit_check warn "AIDE : non installé"
    fi
  fi

  # ModSecurity CRS
  if $INSTALL_MODSEC_CRS && $INSTALL_APACHE_PHP; then
    if [[ -d /usr/share/modsecurity-crs ]]; then
      emit_check ok "ModSecurity CRS : règles OWASP installées"
      if grep -q "SecRuleEngine On" ${MODSEC_CONFIG} 2>/dev/null; then
        emit_check ok "ModSecurity CRS : mode blocage actif"
      else
        emit_check warn "ModSecurity CRS : mode DetectionOnly (logs uniquement)"
      fi
    else
      emit_check warn "ModSecurity CRS : non installé"
    fi
  fi

  # Secure /tmp
  if $SECURE_TMP; then
    if mount | grep -E "/tmp.*noexec" >/dev/null 2>&1; then
      emit_check ok "/tmp : monté avec noexec,nosuid,nodev"
    elif grep -q "noexec" /etc/fstab 2>/dev/null && grep -q "/tmp" /etc/fstab 2>/dev/null; then
      emit_check warn "/tmp : configuré dans fstab mais pas encore remonté"
    else
      emit_check warn "/tmp : pas sécurisé (noexec non actif)"
    fi
  fi

  # LLMNR/mDNS
  if [[ -f "${RESOLVED_DROPIN_DIR}/90-no-llmnr.conf" ]]; then
    emit_check ok "LLMNR/mDNS : désactivé (drop-in présent)"
  else
    if ss -tlnp 2>/dev/null | grep -q ":5355 "; then
      emit_check fail "LLMNR : port 5355 ouvert (créer ${RESOLVED_DROPIN_DIR}/90-no-llmnr.conf)"
    else
      emit_check ok "LLMNR : port 5355 fermé"
    fi
  fi

  # USB storage
  if [[ -f /etc/modprobe.d/disable-usb-storage.conf ]]; then
    emit_check ok "USB storage : module désactivé"
  else
    emit_check warn "USB storage : module non désactivé"
  fi

  # Core dumps
  if grep -qE '^\* .*hard .*core .*0$' /etc/security/limits.conf 2>/dev/null; then
    emit_check ok "Core dumps : désactivés (limits.conf)"
  else
    emit_check warn "Core dumps : non restreints dans limits.conf"
  fi
  local suid_dump
  suid_dump=$(sysctl -n fs.suid_dumpable 2>/dev/null || echo "?")
  if [[ "$suid_dump" == "0" ]]; then
    emit_check ok "Sysctl : fs.suid_dumpable = 0"
  else
    emit_check warn "Sysctl : fs.suid_dumpable = ${suid_dump} (attendu: 0)"
  fi

  # Umask
  if grep -qP '^UMASK\s+027' /etc/login.defs 2>/dev/null; then
    emit_check ok "Umask : 027 dans login.defs"
  else
    emit_check warn "Umask : non durci dans login.defs (attendu: 027)"
  fi

  # Sudo hardening
  if [[ -f /etc/sudoers.d/99-hardening ]]; then
    if visudo -c -f /etc/sudoers.d/99-hardening >/dev/null 2>&1; then
      emit_check ok "Sudo : durcissement actif (timeout, log, secure_path)"
    else
      emit_check fail "Sudo : fichier 99-hardening invalide"
    fi
  else
    emit_check warn "Sudo : pas de durcissement (99-hardening absent)"
  fi

  emit_section_close
}

verify_devtools() {
  emit_section "Outils de développement"

  # Node.js
  if $INSTALL_NODE; then
    if sudo -u "$ADMIN_USER" -H bash -c "source ${USER_HOME}/.nvm/nvm.sh 2>/dev/null && node --version" >/dev/null 2>&1; then
      local node_ver
      node_ver=$(sudo -u "$ADMIN_USER" -H bash -c "source ${USER_HOME}/.nvm/nvm.sh && node --version" 2>/dev/null)
      emit_check ok "Node.js : ${node_ver} (pour ${ADMIN_USER})"
    else
      emit_check fail "Node.js : non installé pour ${ADMIN_USER}"
    fi
  fi

  # Rust
  if $INSTALL_RUST; then
    if [[ -f "${USER_HOME}/.cargo/bin/rustc" ]]; then
      local rust_ver
      rust_ver=$(sudo -u "$ADMIN_USER" -H bash -c "${USER_HOME}/.cargo/bin/rustc --version" 2>/dev/null | awk '{print $2}')
      emit_check ok "Rust : ${rust_ver} (pour ${ADMIN_USER})"
    else
      emit_check fail "Rust : non installé pour ${ADMIN_USER}"
    fi
  fi

  # Python 3
  if $INSTALL_PYTHON3; then
    if command -v python3 >/dev/null 2>&1; then
      local python_ver pip_ver pipx_ver
      python_ver=$(python3 --version 2>/dev/null | awk '{print $2}')
      emit_check ok "Python : ${python_ver}"
      if python3 -m pip --version >/dev/null 2>&1; then
        pip_ver=$(python3 -m pip --version 2>/dev/null | awk '{print $2}')
        emit_check ok "pip : ${pip_ver}"
      else
        emit_check warn "pip : non installé"
      fi
      if command -v pipx >/dev/null 2>&1; then
        pipx_ver=$(pipx --version 2>/dev/null)
        emit_check ok "pipx : ${pipx_ver}"
      else
        emit_check warn "pipx : non installé"
      fi
    else
      emit_check fail "Python 3 : non installé"
    fi
  fi

  # Composer
  if $INSTALL_COMPOSER; then
    if [[ -f "${USER_HOME}/.local/bin/composer" ]]; then
      local composer_ver
      composer_ver=$(sudo -u "$ADMIN_USER" -H bash -c "${USER_HOME}/.local/bin/composer --version" 2>/dev/null | awk '{print $3}')
      emit_check ok "Composer : ${composer_ver} (pour ${ADMIN_USER})"
    else
      emit_check fail "Composer : non installé pour ${ADMIN_USER}"
    fi
  fi

  # Symfony CLI
  if $INSTALL_SYMFONY; then
    if command -v symfony >/dev/null 2>&1; then
      local symfony_ver
      symfony_ver=$(symfony version 2>/dev/null | head -1 | awk '{print $4}')
      emit_check ok "Symfony CLI : ${symfony_ver}"
    else
      emit_check fail "Symfony CLI : non installé"
    fi
  fi

  # Git
  if $INSTALL_DEVTOOLS; then
    if command -v git >/dev/null 2>&1; then
      local git_ver
      git_ver=$(git --version | awk '{print $3}')
      emit_check ok "Git : ${git_ver}"
    else
      emit_check fail "Git : non installé"
    fi
  fi

  emit_section_close
}

verify_dkim() {
  emit_section "DKIM"
  if $INSTALL_POSTFIX_DKIM; then
    local dkim_key="${DKIM_KEYDIR}/${DKIM_SELECTOR}.private"
    local dkim_pub="${DKIM_KEYDIR}/${DKIM_SELECTOR}.txt"

    if [[ -f "$dkim_key" ]]; then
      emit_check ok "DKIM : clé privée présente"
      check_file_perms "$dkim_key" "DKIM : clé privée" "600"
    else
      emit_check fail "DKIM : clé privée absente"
    fi

    if [[ -f "$dkim_pub" ]]; then
      emit_check ok "DKIM : clé publique générée"
      emit_check info "→ Contenu à publier dans DNS : ${dkim_pub}"
    else
      emit_check warn "DKIM : clé publique non générée"
    fi

    # Test DKIM
    if command -v opendkim-testkey >/dev/null 2>&1; then
      if opendkim-testkey -d "${DKIM_DOMAIN}" -s "${DKIM_SELECTOR}" -x /etc/opendkim.conf 2>&1 | grep -q "key OK"; then
        emit_check ok "DKIM : clé DNS valide et correspondante"
      else
        emit_check warn "DKIM : clé DNS non vérifiée (à configurer dans DNS)"
      fi
    fi

    # Comparaison clé locale vs DNS
    if command -v dig >/dev/null 2>&1 && [[ -f "$dkim_pub" ]]; then
      local dns_key local_key
      dns_key=$(dig +short +timeout="${DNS_TIMEOUT}" TXT "${DKIM_SELECTOR}._domainkey.${DKIM_DOMAIN}" @8.8.8.8 2>/dev/null | tr -d '"\n ' | grep -oP 'p=\K[^;]+')
      local_key=$(cat "$dkim_pub" 2>/dev/null | tr -d '"\n\t ()' | grep -oP 'p=\K[^;]+' | head -1)

      if [[ -z "$dns_key" ]]; then
        emit_check warn "DKIM DNS : enregistrement ${DKIM_SELECTOR}._domainkey.${DKIM_DOMAIN} non trouvé"
      elif [[ -z "$local_key" ]]; then
        emit_check warn "DKIM : impossible d'extraire la clé locale"
      elif [[ "$dns_key" == "$local_key" ]]; then
        emit_check ok "DKIM : clé DNS identique à ${dkim_pub}"
      else
        emit_check fail "DKIM : clé DNS différente de ${dkim_pub}"
        emit_check info "→ DNS: ${dns_key:0:40}..."
        emit_check info "→ Local: ${local_key:0:40}..."
      fi
    fi

    # File d'attente emails
    local mail_queue
    mail_queue=$(mailq 2>/dev/null | tail -1)
    if [[ "$mail_queue" == *"Mail queue is empty"* ]]; then
      emit_check ok "Postfix : file d'attente vide (tous les emails envoyés)"
    elif [[ "$mail_queue" =~ ^[0-9]+[[:space:]]Kbytes ]]; then
      local queued_count
      queued_count=$(mailq 2>/dev/null | grep -c "^[A-F0-9]") || queued_count=0
      emit_check warn "Postfix : ${queued_count} email(s) en attente (mailq pour détails)"
    fi

    # Derniers envois
    if [[ -f ${MAIL_LOG} ]]; then
      local bounced deferred sent
      bounced=$(safe_count "status=bounced" ${MAIL_LOG})
      deferred=$(safe_count "status=deferred" ${MAIL_LOG})
      sent=$(safe_count "status=sent" ${MAIL_LOG})
      if [[ "$bounced" -gt 0 ]]; then
        emit_check fail "Postfix : ${bounced} email(s) rejeté(s) (vérifier SPF/DKIM)"
      elif [[ "$deferred" -gt 0 ]]; then
        emit_check warn "Postfix : ${deferred} email(s) différé(s), ${sent} envoyé(s)"
      elif [[ "$sent" -gt 0 ]]; then
        emit_check ok "Postfix : ${sent} email(s) envoyé(s) avec succès"
      else
        emit_check info "Postfix : aucun email récent dans les logs"
      fi
    fi
  fi
  emit_section_close
}

verify_sysconfig() {
  emit_section "Configuration système"

  # Hostname
  local current_hostname
  current_hostname=$(hostname -f 2>/dev/null || hostname)
  if [[ "$current_hostname" == "$HOSTNAME_FQDN" ]]; then
    emit_check ok "Hostname : ${current_hostname}"
  else
    emit_check warn "Hostname : ${current_hostname} (attendu: ${HOSTNAME_FQDN})"
  fi

  # Timezone
  local current_tz
  current_tz=$(timedatectl show --property=Timezone --value 2>/dev/null || cat /etc/timezone 2>/dev/null)
  if [[ "$current_tz" == "$TIMEZONE" ]]; then
    emit_check ok "Timezone : ${current_tz}"
  else
    emit_check warn "Timezone : ${current_tz} (attendu: ${TIMEZONE})"
  fi

  # NTP
  if timedatectl show --property=NTPSynchronized --value 2>/dev/null | grep -q "yes"; then
    emit_check ok "NTP : synchronisé"
  else
    emit_check warn "NTP : non synchronisé"
  fi

  # Locale
  local current_lang
  current_lang=$(locale 2>/dev/null | grep "^LANG=" | cut -d= -f2)
  if [[ "$current_lang" =~ fr_FR ]]; then
    emit_check ok "Locale : ${current_lang}"
  else
    emit_check warn "Locale : ${current_lang} (attendu: fr_FR.UTF-8)"
  fi

  # DNS résolution
  if host -W 2 google.com >/dev/null 2>&1 || ping -c1 -W2 8.8.8.8 >/dev/null 2>&1; then
    emit_check ok "DNS/Réseau : fonctionnel"
  else
    emit_check warn "DNS/Réseau : problème de résolution"
  fi

  emit_section_close
}

verify_users() {
  emit_section "Sécurité utilisateurs"

  # Clé SSH admin
  if [[ -f "${USER_HOME}/.ssh/authorized_keys" ]] && [[ -s "${USER_HOME}/.ssh/authorized_keys" ]]; then
    local key_count
    key_count=$(safe_count "^ssh-" "${USER_HOME}/.ssh/authorized_keys")
    emit_check ok "SSH : ${key_count} clé(s) autorisée(s) pour ${ADMIN_USER}"
  else
    emit_check fail "SSH : aucune clé autorisée pour ${ADMIN_USER}"
  fi

  # Permissions .ssh
  [[ -d "${USER_HOME}/.ssh" ]] && check_file_perms "${USER_HOME}/.ssh" "SSH : .ssh" "700"

  # Root login direct
  if passwd -S root 2>/dev/null | grep -qE "^root\s+(L|LK|NP)"; then
    emit_check ok "Root : compte verrouillé (accès via sudo uniquement)"
  else
    emit_check warn "Root : compte non verrouillé"
  fi

  # Sudo
  if groups "$ADMIN_USER" 2>/dev/null | grep -qE "(sudo|wheel)"; then
    emit_check ok "Sudo : ${ADMIN_USER} membre du groupe sudo"
  else
    emit_check warn "Sudo : ${ADMIN_USER} pas dans le groupe sudo"
  fi

  # UID 0
  local root_users
  root_users=$(awk -F: '$3 == 0 {print $1}' /etc/passwd | tr '\n' ' ')
  if [[ "$root_users" == "root " || "$root_users" == "root" ]]; then
    emit_check ok "UID 0 : seul root a l'UID 0"
  else
    emit_check fail "UID 0 : plusieurs utilisateurs (${root_users})"
  fi

  # Échecs SSH
  if [[ -f ${AUTH_LOG} ]]; then
    local failed_ssh
    failed_ssh=$(safe_count "Failed password" ${AUTH_LOG})
    if [[ "$failed_ssh" -eq 0 ]]; then
      emit_check ok "SSH : pas de tentatives échouées récentes"
    elif [[ "$failed_ssh" -lt 50 ]]; then
      emit_check info "SSH : ${failed_ssh} tentative(s) échouée(s) dans les logs"
    else
      emit_check warn "SSH : ${failed_ssh} tentatives échouées (brute-force possible)"
    fi
  fi

  # Dernière connexion
  local last_login
  last_login=$(lastlog -u "$ADMIN_USER" 2>/dev/null | tail -1 | awk '{print $4, $5, $6, $7, $9}' | grep -v "Never" || true)
  [[ -n "$last_login" && "$last_login" != *"Never"* ]] && emit_check info "Dernière connexion ${ADMIN_USER} : ${last_login}"

  emit_section_close
}

verify_files() {
  emit_section "Sécurité fichiers"

  # World-writable in /var/www
  if $INSTALL_APACHE_PHP; then
    local ww_count
    ww_count=$(find /var/www -type f -perm -002 2>/dev/null | wc -l)
    if [[ "$ww_count" -eq 0 ]]; then
      emit_check ok "Web : pas de fichiers world-writable dans /var/www"
    else
      emit_check warn "Web : ${ww_count} fichiers world-writable dans /var/www"
    fi

    local www_owner
    www_owner=$(stat -c %U /var/www/html 2>/dev/null)
    if [[ "$www_owner" == "${WEB_USER}" || "$www_owner" == "root" ]]; then
      emit_check ok "Web : /var/www/html propriétaire ${www_owner}"
    else
      emit_check warn "Web : /var/www/html propriétaire inattendu (${www_owner})"
    fi
  fi

  # SUID
  local suid_count
  suid_count=$(find /usr/local -type f -perm -4000 2>/dev/null | wc -l)
  if [[ "$suid_count" -eq 0 ]]; then
    emit_check ok "SUID : pas de binaires SUID dans /usr/local"
  else
    emit_check warn "SUID : ${suid_count} binaires SUID dans /usr/local"
  fi

  # /etc/shadow
  check_file_perms /etc/shadow "Shadow" "0|640|600"

  emit_section_close
}

verify_database() {
  emit_section "Base de données"
  if $INSTALL_MARIADB; then
    # Version
    local mariadb_ver
    mariadb_ver=$(mysql --version 2>/dev/null | grep -oP 'Ver \K[0-9.]+' || echo "")
    [[ -n "$mariadb_ver" ]] && emit_check ok "MariaDB : version ${mariadb_ver}"

    # Écoute
    if ss -tlnp 2>/dev/null | grep mysql | grep -q "127.0.0.1:3306"; then
      emit_check ok "MariaDB : écoute localhost uniquement"
    elif ss -tlnp 2>/dev/null | grep mysql | grep -q "0.0.0.0:3306"; then
      emit_check warn "MariaDB : écoute toutes interfaces (0.0.0.0)"
    else
      emit_check ok "MariaDB : socket Unix (pas de port TCP exposé)"
    fi

    # Root distant
    if mysql -u root -e "SELECT User,Host FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost','127.0.0.1','::1');" 2>/dev/null | grep -q root; then
      emit_check fail "MariaDB : root accessible à distance"
    else
      emit_check ok "MariaDB : root localhost uniquement"
    fi

    # Utilisateur anonyme
    local anon_users
    anon_users=$(mysql -u root -e "SELECT COUNT(*) FROM mysql.user WHERE User='';" -sN 2>/dev/null || echo "?")
    if [[ "$anon_users" == "0" ]]; then
      emit_check ok "MariaDB : pas d'utilisateur anonyme"
    elif [[ "$anon_users" == "?" ]]; then
      emit_check warn "MariaDB : impossible de vérifier les utilisateurs"
    else
      emit_check fail "MariaDB : ${anon_users} utilisateur(s) anonyme(s)"
    fi

    # Base test
    local test_db
    test_db=$(mysql -u root -e "SHOW DATABASES LIKE 'test';" -sN 2>/dev/null || echo "")
    if [[ -z "$test_db" ]]; then
      emit_check ok "MariaDB : base 'test' supprimée"
    else
      emit_check warn "MariaDB : base 'test' existe encore"
    fi

    # Nombre de bases
    local db_count
    db_count=$(mysql -u root -e "SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME NOT IN ('information_schema','mysql','performance_schema','sys');" -sN 2>/dev/null || echo "?")
    [[ "$db_count" != "?" ]] && emit_check info "MariaDB : ${db_count} base(s) de données utilisateur"
  fi
  emit_section_close
}

verify_resources() {
  emit_section "Ressources système"

  # Disque
  local disk_usage disk_avail
  disk_usage=$(df -h / | awk 'NR==2 {print $5}' | tr -d '%')
  disk_avail=$(df -h / | awk 'NR==2 {print $4}')
  if [[ "$disk_usage" -lt 80 ]]; then
    emit_check ok "Disque / : ${disk_usage}% utilisé (${disk_avail} libre)"
  elif [[ "$disk_usage" -lt 90 ]]; then
    emit_check warn "Disque / : ${disk_usage}% utilisé (${disk_avail} libre)"
  else
    emit_check fail "Disque / : ${disk_usage}% utilisé - CRITIQUE"
  fi

  # Mémoire
  local mem_total mem_avail mem_used_pct
  mem_total=$(free -h | awk '/^Mem:/ {print $2}')
  mem_avail=$(free -h | awk '/^Mem:/ {print $7}')
  mem_used_pct=$(free | awk '/^Mem:/ {printf "%.0f", $3/$2*100}')
  if [[ "$mem_used_pct" -lt 80 ]]; then
    emit_check ok "RAM : ${mem_used_pct}% utilisée (${mem_avail} disponible sur ${mem_total})"
  else
    emit_check warn "RAM : ${mem_used_pct}% utilisée (${mem_avail} disponible)"
  fi

  # Swap
  if swapon --show | grep -q .; then
    local swap_size
    swap_size=$(free -h | awk '/^Swap:/ {print $2}')
    emit_check ok "Swap : ${swap_size} configuré"
  else
    emit_check warn "Swap : non configuré"
  fi

  # Load
  local load_1 cpu_count load_pct
  load_1=$(awk '{print $1}' /proc/loadavg)
  cpu_count=$(nproc)
  load_pct=$(echo "$load_1 $cpu_count" | awk '{printf "%.0f", ($1/$2)*100}')
  if [[ "$load_pct" -lt 70 ]]; then
    emit_check ok "Load : ${load_1} (${load_pct}% de ${cpu_count} CPU)"
  else
    emit_check warn "Load : ${load_1} (${load_pct}% de ${cpu_count} CPU) - élevé"
  fi

  # Uptime
  local uptime_str
  uptime_str=$(uptime -p | sed 's/up //')
  emit_check info "Uptime : ${uptime_str}"

  # Inodes
  local inode_usage inode_avail
  inode_usage=$(df -i / | awk 'NR==2 {print $5}' | tr -d '%')
  inode_avail=$(df -i / | awk 'NR==2 {print $4}')
  if [[ "$inode_usage" -lt 80 ]]; then
    emit_check ok "Inodes / : ${inode_usage}% utilisés (${inode_avail} disponibles)"
  elif [[ "$inode_usage" -lt 95 ]]; then
    emit_check warn "Inodes / : ${inode_usage}% utilisés - surveillez"
  else
    emit_check fail "Inodes / : ${inode_usage}% utilisés - CRITIQUE"
  fi

  # Zombies
  local zombies
  zombies=$(ps aux | grep -c ' Z ' 2>/dev/null) || zombies=0
  zombies=$((zombies > 0 ? zombies - 1 : 0))
  if [[ "$zombies" -eq 0 ]]; then
    emit_check ok "Processus : pas de zombies"
  else
    emit_check warn "Processus : ${zombies} zombie(s) détecté(s)"
  fi

  # OOM
  local oom_events=0
  if dmesg &>/dev/null; then
    oom_events=$(dmesg 2>/dev/null | grep -c "Out of memory" || true)
  else
    oom_events=$(journalctl -k --since "7 days ago" 2>/dev/null | grep -c "Out of memory" || true)
  fi
  oom_events=$(sanitize_int "$oom_events")
  [[ "$oom_events" -gt 0 ]] && emit_check warn "Mémoire : ${oom_events} événement(s) OOM Killer récent(s)"

  emit_section_close
}

verify_ports() {
  emit_section "Ports ouverts (UFW)"
  if $INSTALL_UFW && command -v ufw >/dev/null 2>&1; then
    ufw status | grep -E "^\s*[0-9]+" | while read -r line; do
      emit_check info "$line"
    done
  fi
  emit_section_close
}

verify_listening() {
  emit_section "Services en écoute"
  ss -tlnp 2>/dev/null | grep LISTEN | awk '{print $4}' | sort -u | while read -r addr; do
    local port bind svc
    port=$(echo "$addr" | rev | cut -d: -f1 | rev)
    bind=$(echo "$addr" | rev | cut -d: -f2- | rev)
    case "$port" in
      22|"${SSH_PORT}") svc="SSH" ;;
      80) svc="HTTP" ;;
      443) svc="HTTPS" ;;
      3306) svc="MariaDB" ;;
      25|587) svc="SMTP" ;;
      8891) svc="OpenDKIM" ;;
      *) svc="" ;;
    esac
    if [[ "$bind" == "127.0.0.1" || "$bind" == "::1" ]]; then
      emit_check info "${svc:-Service} → port ${port} (local)"
    else
      emit_check warn "${svc:-Service} → port ${port} (${bind})"
    fi
  done
  emit_section_close
}

verify_dns() {
  emit_section "Vérification DNS"

  # IP publique IPv4
  SERVER_IP=$(curl -4 -sfS --max-time "${CURL_TIMEOUT}" https://api.ipify.org 2>/dev/null || curl -4 -sfS --max-time "${CURL_TIMEOUT}" https://ifconfig.me 2>/dev/null || echo "")
  [[ -n "$SERVER_IP" ]] && emit_check info "IP publique IPv4 : ${SERVER_IP}"

  # IP publique IPv6
  SERVER_IP6=$(curl -6 -sfS --max-time "${CURL_TIMEOUT}" https://api6.ipify.org 2>/dev/null || curl -6 -sfS --max-time "${CURL_TIMEOUT}" https://ifconfig.me 2>/dev/null || echo "")
  if [[ -n "$SERVER_IP6" ]]; then
    emit_check info "IP publique IPv6 : ${SERVER_IP6}"
  else
    emit_check info "IPv6 : non disponible sur ce serveur"
  fi

  # Cohérence hostname
  local system_fqdn
  system_fqdn=$(hostname -f 2>/dev/null || echo "")
  if [[ -n "$system_fqdn" ]]; then
    if [[ "$system_fqdn" == "$HOSTNAME_FQDN" ]]; then
      emit_check ok "Hostname : ${system_fqdn} (cohérent avec la config)"
    else
      emit_check warn "Hostname : ${system_fqdn} (config = ${HOSTNAME_FQDN})"
    fi
  fi

  # Domaine de base
  local dot_count
  dot_count=$(echo "$HOSTNAME_FQDN" | tr -cd '.' | wc -c)
  if [[ "$dot_count" -le 1 ]]; then
    BASE_DOMAIN="$HOSTNAME_FQDN"
  else
    BASE_DOMAIN="${HOSTNAME_FQDN#*.}"
  fi

  if command -v dig >/dev/null 2>&1; then
    # A record
    DNS_A=$(dig +short +timeout="${DNS_TIMEOUT}" A "$HOSTNAME_FQDN" @8.8.8.8 2>/dev/null | head -1)
    if [[ -n "$DNS_A" ]]; then
      if [[ "$DNS_A" == "$SERVER_IP" ]]; then
        emit_check ok "DNS A : ${HOSTNAME_FQDN} → ${DNS_A} (correspond à ce serveur)"
      else
        emit_check warn "DNS A : ${HOSTNAME_FQDN} → ${DNS_A} (ce serveur = ${SERVER_IP})"
      fi
    else
      emit_check warn "DNS A : ${HOSTNAME_FQDN} non résolu"
    fi

    # www
    DNS_WWW=$(dig +short +timeout="${DNS_TIMEOUT}" A "www.${HOSTNAME_FQDN}" @8.8.8.8 2>/dev/null | head -1)
    if [[ -n "$DNS_WWW" ]]; then
      if [[ "$DNS_WWW" == "$SERVER_IP" || "$DNS_WWW" == "$DNS_A" ]]; then
        emit_check ok "DNS A : www.${HOSTNAME_FQDN} → ${DNS_WWW}"
      else
        emit_check warn "DNS A : www.${HOSTNAME_FQDN} → ${DNS_WWW} (différent)"
      fi
    else
      emit_check warn "DNS A : www.${HOSTNAME_FQDN} non résolu"
    fi

    # AAAA record (IPv6)
    DNS_AAAA=$(dig +short +timeout="${DNS_TIMEOUT}" AAAA "$HOSTNAME_FQDN" @8.8.8.8 2>/dev/null | head -1)
    if [[ -n "$DNS_AAAA" ]]; then
      if [[ -n "$SERVER_IP6" && "$DNS_AAAA" == "$SERVER_IP6" ]]; then
        emit_check ok "DNS AAAA : ${HOSTNAME_FQDN} → ${DNS_AAAA} (correspond à ce serveur)"
      elif [[ -n "$SERVER_IP6" ]]; then
        emit_check warn "DNS AAAA : ${HOSTNAME_FQDN} → ${DNS_AAAA} (ce serveur = ${SERVER_IP6})"
      else
        emit_check warn "DNS AAAA : ${HOSTNAME_FQDN} → ${DNS_AAAA} (IPv6 non détecté sur ce serveur)"
      fi
    else
      if [[ -n "$SERVER_IP6" ]]; then
        emit_check warn "DNS AAAA : ${HOSTNAME_FQDN} non résolu (IPv6 disponible mais pas de record AAAA)"
      else
        emit_check info "DNS AAAA : ${HOSTNAME_FQDN} non configuré (pas d'IPv6)"
      fi
    fi

    # AAAA www
    DNS_WWW6=$(dig +short +timeout="${DNS_TIMEOUT}" AAAA "www.${HOSTNAME_FQDN}" @8.8.8.8 2>/dev/null | head -1)
    if [[ -n "$DNS_WWW6" ]]; then
      if [[ -n "$SERVER_IP6" && "$DNS_WWW6" == "$SERVER_IP6" ]]; then
        emit_check ok "DNS AAAA : www.${HOSTNAME_FQDN} → ${DNS_WWW6}"
      elif [[ -n "$SERVER_IP6" ]]; then
        emit_check warn "DNS AAAA : www.${HOSTNAME_FQDN} → ${DNS_WWW6} (ce serveur = ${SERVER_IP6})"
      else
        emit_check warn "DNS AAAA : www.${HOSTNAME_FQDN} → ${DNS_WWW6} (IPv6 non détecté)"
      fi
    elif [[ -n "$SERVER_IP6" ]]; then
      emit_check warn "DNS AAAA : www.${HOSTNAME_FQDN} non résolu"
    fi

    # MX
    DNS_MX=$(dig +short +timeout="${DNS_TIMEOUT}" MX "$BASE_DOMAIN" @8.8.8.8 2>/dev/null | head -1)
    if [[ -n "$DNS_MX" ]]; then
      emit_check ok "DNS MX : ${BASE_DOMAIN} → ${DNS_MX}"
    else
      emit_check warn "DNS MX : ${BASE_DOMAIN} non configuré"
    fi

    # SPF
    DNS_SPF=$(dig +short +timeout="${DNS_TIMEOUT}" TXT "$BASE_DOMAIN" @8.8.8.8 2>/dev/null | grep -i "v=spf1" | head -1 || true)
    if [[ -n "$DNS_SPF" ]]; then
      if [[ "$DNS_SPF" =~ (include:|a\ |mx\ |ip4:) ]]; then
        emit_check ok "DNS SPF : ${DNS_SPF}"
      else
        emit_check warn "DNS SPF : présent mais peut-être incomplet"
      fi
    else
      emit_check fail "DNS SPF : non configuré (emails risquent d'être en spam)"
    fi

    # DKIM DNS
    if [[ -n "${DKIM_SELECTOR:-}" && -n "${DKIM_DOMAIN:-}" ]]; then
      DNS_DKIM=$(dig +short +timeout="${DNS_TIMEOUT}" TXT "${DKIM_SELECTOR}._domainkey.${DKIM_DOMAIN}" @8.8.8.8 2>/dev/null | head -1)
      if [[ -n "$DNS_DKIM" ]]; then
        if [[ "$DNS_DKIM" == *"v=DKIM1"* ]]; then
          emit_check ok "DNS DKIM : ${DKIM_SELECTOR}._domainkey.${DKIM_DOMAIN} configuré"
        else
          emit_check warn "DNS DKIM : présent mais format inattendu"
        fi
      else
        emit_check warn "DNS DKIM : ${DKIM_SELECTOR}._domainkey.${DKIM_DOMAIN} non trouvé"
      fi
    fi

    # DMARC
    DNS_DMARC=$(dig +short +timeout="${DNS_TIMEOUT}" TXT "_dmarc.${BASE_DOMAIN}" @8.8.8.8 2>/dev/null | grep -i "v=DMARC1" | head -1 || true)
    if [[ -n "$DNS_DMARC" ]]; then
      if [[ "$DNS_DMARC" =~ p=(none|quarantine|reject) ]]; then
        local dmarc_policy="${BASH_REMATCH[1]}"
        if [[ "$dmarc_policy" == "none" ]]; then
          emit_check warn "DNS DMARC : policy=none (trop permissif, passer à quarantine)"
        else
          emit_check ok "DNS DMARC : politique=${dmarc_policy}"
        fi
      else
        emit_check warn "DNS DMARC : présent mais politique non définie"
      fi
    else
      emit_check warn "DNS DMARC : _dmarc.${BASE_DOMAIN} non configuré"
    fi

    # PTR IPv4
    if [[ -n "$SERVER_IP" ]]; then
      DNS_PTR=$(dig +short +timeout="${DNS_TIMEOUT}" -x "$SERVER_IP" 2>/dev/null | head -1 | sed 's/\.$//')
      if [[ -n "$DNS_PTR" ]]; then
        if [[ "$DNS_PTR" == "$HOSTNAME_FQDN" ]]; then
          emit_check ok "DNS PTR IPv4 : ${SERVER_IP} → ${DNS_PTR}"
        elif [[ "$DNS_PTR" == *"$BASE_DOMAIN"* ]]; then
          emit_check warn "DNS PTR IPv4 : ${SERVER_IP} → ${DNS_PTR} (attendu exactement: ${HOSTNAME_FQDN})"
        else
          emit_check warn "DNS PTR IPv4 : ${SERVER_IP} → ${DNS_PTR} (attendu: ${HOSTNAME_FQDN})"
        fi
      else
        emit_check warn "DNS PTR IPv4 : reverse DNS non configuré pour ${SERVER_IP}"
      fi
    fi

    # PTR IPv6
    if [[ -n "$SERVER_IP6" ]]; then
      DNS_PTR6=$(dig +short +timeout="${DNS_TIMEOUT}" -x "$SERVER_IP6" 2>/dev/null | head -1 | sed 's/\.$//')
      if [[ -n "$DNS_PTR6" ]]; then
        if [[ "$DNS_PTR6" == "$HOSTNAME_FQDN" ]]; then
          emit_check ok "DNS PTR IPv6 : ${SERVER_IP6} → ${DNS_PTR6}"
        elif [[ "$DNS_PTR6" == *"$BASE_DOMAIN"* ]]; then
          emit_check warn "DNS PTR IPv6 : ${SERVER_IP6} → ${DNS_PTR6} (attendu exactement: ${HOSTNAME_FQDN})"
        else
          emit_check warn "DNS PTR IPv6 : ${SERVER_IP6} → ${DNS_PTR6} (attendu: ${HOSTNAME_FQDN})"
        fi
      else
        emit_check warn "DNS PTR IPv6 : reverse DNS non configuré pour ${SERVER_IP6}"
      fi
    fi

    # CAA (Certificate Authority Authorization)
    DNS_CAA=$(dig +short +timeout="${DNS_TIMEOUT}" CAA "$BASE_DOMAIN" @8.8.8.8 2>/dev/null | head -3)
    if [[ -n "$DNS_CAA" ]]; then
      emit_check ok "DNS CAA : ${BASE_DOMAIN} → $(echo "$DNS_CAA" | head -1)"
    else
      emit_check info "DNS CAA : ${BASE_DOMAIN} non configuré (recommandé pour restreindre les CA autorisées)"
    fi

    # NS (nameservers)
    DNS_NS=$(dig +short +timeout="${DNS_TIMEOUT}" NS "$BASE_DOMAIN" @8.8.8.8 2>/dev/null | sort)
    if [[ -n "$DNS_NS" ]]; then
      local ns_count
      ns_count=$(echo "$DNS_NS" | wc -l)
      emit_check ok "DNS NS : ${BASE_DOMAIN} → ${ns_count} serveurs ($(echo "$DNS_NS" | head -1 | sed 's/\.$//')...)"
    else
      emit_check warn "DNS NS : ${BASE_DOMAIN} aucun nameserver trouvé"
    fi
  else
    emit_check warn "dig non disponible - installation de dnsutils requise pour les checks DNS"
  fi

  emit_section_close
}
