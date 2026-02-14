#!/usr/bin/env bash
# lib/install-web.sh — Apache/PHP, MariaDB, phpMyAdmin, Postfix/OpenDKIM, Certbot
# Sourcé par debian13-server.sh — Dépend de: lib/core.sh, lib/constants.sh, lib/helpers.sh, lib/config.sh

# ---------------------------------- 5) Apache/PHP -------------------------------------
if $INSTALL_APACHE_PHP; then
  section "Apache + PHP"
  apt_install apache2 apache2-utils
  systemctl enable --now apache2
  apt_install php php-cli php-fpm php-mysql php-curl php-xml php-gd php-mbstring php-zip php-intl php-opcache php-imagick imagemagick libapache2-mod-php
  apt_install libapache2-mod-security2 libapache2-mod-evasive

  # Activer les modules Apache utiles
  a2enmod headers rewrite ssl security2  # Sécurité & réécriture
  a2enmod expires deflate                 # Performance (cache, compression)
  a2enmod proxy proxy_http proxy_wstunnel # Reverse proxy & WebSocket
  a2enmod socache_shmcb                   # Cache SSL sessions
  a2enmod vhost_alias                     # Virtual hosts
  cat >/etc/apache2/conf-available/security-headers.conf <<'EOF'
<IfModule mod_headers.c>
  Header always set X-Frame-Options "SAMEORIGIN"
  Header always set X-Content-Type-Options "nosniff"
  Header always set Referrer-Policy "strict-origin-when-cross-origin"
  Header always set X-XSS-Protection "1; mode=block"
  Header always set Permissions-Policy "geolocation=(), microphone=(), camera=()"
  Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
</IfModule>
EOF
  a2enconf security-headers
  sed -ri 's/^ServerTokens .*/ServerTokens Prod/; s/^ServerSignature .*/ServerSignature Off/' /etc/apache2/conf-available/security.conf
  # PHP hardening
  for INI in /etc/php/*/apache2/php.ini /etc/php/*/cli/php.ini /etc/php/*/fpm/php.ini; do
    [[ -f "$INI" ]] || continue
    backup_file "$INI"
    php_ini_set "opcache\.enable" "1" "$INI"
    php_ini_set "expose_php" "Off" "$INI"
    php_ini_set "display_errors" "Off" "$INI"
    php_ini_set "display_startup_errors" "Off" "$INI"
    php_ini_set "log_errors" "On" "$INI"
    if $PHP_DISABLE_FUNCTIONS; then
      if ! grep -q "^disable_functions.*exec" "$INI"; then
        php_ini_set "disable_functions" "${PHP_DISABLED_FUNCTIONS}" "$INI"
      fi
    fi
  done
  systemctl restart apache2
  log "Apache/PHP installés et durcis."

  # ---------------------------------- Pages d'erreur personnalisées ---------------------
  section "Pages d'erreur personnalisées"

  mkdir -p ${ERROR_PAGES_DIR}

  # Fichier de configuration des IPs de confiance (pour debug)
  cat >${ERROR_PAGES_DIR}/trusted-ips.php <<'TRUSTEDIPS'
<?php
// IPs de confiance - générées par install.sh
// Ces IPs verront les informations de debug sur les pages d'erreur
$TRUSTED_IPS = [
__TRUSTED_IPS_ARRAY__
];

function is_trusted_ip() {
    global $TRUSTED_IPS;
    // Utiliser uniquement REMOTE_ADDR (non spoofable) — ne PAS faire confiance à X-Forwarded-For
    $client_ip = $_SERVER['REMOTE_ADDR'] ?? '';
    return in_array($client_ip, $TRUSTED_IPS);
}
TRUSTEDIPS

  # Générer le tableau PHP des IPs de confiance
  if [[ -n "${TRUSTED_IPS:-}" ]]; then
    TRUSTED_IPS_PHP=""
    for ip in $TRUSTED_IPS; do
      TRUSTED_IPS_PHP+="    '${ip}',\n"
    done
    sed -i "s|__TRUSTED_IPS_ARRAY__|${TRUSTED_IPS_PHP}|" ${ERROR_PAGES_DIR}/trusted-ips.php
  else
    sed -i "s|__TRUSTED_IPS_ARRAY__|    // Aucune IP configurée|" ${ERROR_PAGES_DIR}/trusted-ips.php
  fi

  # Template principal des pages d'erreur (externalisé dans templates/error-page.php)
  ERROR_PAGE_TEMPLATE="${SCRIPT_DIR}/templates/error-page.php"
  [[ ! -f "$ERROR_PAGE_TEMPLATE" ]] && ERROR_PAGE_TEMPLATE="${SCRIPTS_DIR}/templates/error-page.php"
  if [[ -f "$ERROR_PAGE_TEMPLATE" ]]; then
    cp "$ERROR_PAGE_TEMPLATE" ${ERROR_PAGES_DIR}/error.php
  else
    warn "Template error-page.php non trouvé. Pages d'erreur non déployées."
  fi

  # Configuration Apache pour les pages d'erreur
  cat >/etc/apache2/conf-available/custom-error-pages.conf <<'ERRORCONF'
# Pages d'erreur personnalisées
Alias /error-pages ${ERROR_PAGES_DIR}

<Directory ${ERROR_PAGES_DIR}>
    Options -Indexes
    AllowOverride None
    Require all granted

    <FilesMatch "\.php$">
        SetHandler application/x-httpd-php
    </FilesMatch>
</Directory>

# Rediriger les erreurs vers notre page PHP
ErrorDocument 400 /error-pages/error.php?code=400
ErrorDocument 401 /error-pages/error.php?code=401
ErrorDocument 403 /error-pages/error.php?code=403
ErrorDocument 404 /error-pages/error.php?code=404
ErrorDocument 500 /error-pages/error.php?code=500
ErrorDocument 502 /error-pages/error.php?code=502
ErrorDocument 503 /error-pages/error.php?code=503
ERRORCONF

  a2enconf custom-error-pages

  # Permissions
  chown -R "${WEB_USER}:${WEB_USER}" "${ERROR_PAGES_DIR}"
  chmod 644 ${ERROR_PAGES_DIR}/*.php

  log "Pages d'erreur personnalisées installées dans ${ERROR_PAGES_DIR}/"
fi

# ---------------------------------- 6) MariaDB ----------------------------------------
if $INSTALL_MARIADB; then
  section "MariaDB"
  apt_install mariadb-server mariadb-client
  systemctl enable --now mariadb
  mysql --user=root <<'SQL'
DELETE FROM mysql.user WHERE User='';
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db='test' OR Db='test\_%';
FLUSH PRIVILEGES;
SQL
  log "MariaDB installée (hardening de base)."
fi

# ---------------------------------- 6b) phpMyAdmin --------------------------------------
if $INSTALL_PHPMYADMIN; then
  if ! $INSTALL_MARIADB || ! $INSTALL_APACHE_PHP; then
    warn "phpMyAdmin nécessite MariaDB et Apache/PHP. Installation ignorée."
  else
    section "phpMyAdmin"

    # Préconfiguration pour éviter les questions interactives
    echo "phpmyadmin phpmyadmin/dbconfig-install boolean true" | debconf-set-selections
    echo "phpmyadmin phpmyadmin/app-password-confirm password" | debconf-set-selections
    echo "phpmyadmin phpmyadmin/mysql/admin-pass password" | debconf-set-selections
    echo "phpmyadmin phpmyadmin/mysql/app-pass password" | debconf-set-selections
    echo "phpmyadmin phpmyadmin/reconfigure-webserver multiselect apache2" | debconf-set-selections

    apt_install phpmyadmin

    # Activer la configuration Apache si pas déjà fait
    if [[ -f /etc/phpmyadmin/apache.conf ]] && [[ ! -L /etc/apache2/conf-enabled/phpmyadmin.conf ]]; then
      ln -sf /etc/phpmyadmin/apache.conf /etc/apache2/conf-enabled/phpmyadmin.conf
    fi

    # Sécurisation : changer l'URL par défaut (évite les scans automatiques)
    PMA_ALIAS="dbadmin_$(openssl rand -hex "$PMA_ALIAS_HEX_LENGTH")"
    backup_file /etc/phpmyadmin/apache.conf
    if [[ -f /etc/phpmyadmin/apache.conf ]]; then
      sed -i "s|Alias /phpmyadmin|Alias /${PMA_ALIAS}|g" /etc/phpmyadmin/apache.conf
    fi

    # Ajouter une protection .htaccess supplémentaire
    mkdir -p /etc/phpmyadmin/conf.d
    cat >/etc/phpmyadmin/conf.d/security.php <<'PMASEC'
<?php
// Sécurité supplémentaire phpMyAdmin
$cfg['LoginCookieValidity'] = __PMA_COOKIE_VALIDITY__;  // 30 minutes
$cfg['LoginCookieStore'] = 0;
$cfg['AuthLog'] = 'syslog';
$cfg['CaptchaLoginPublicKey'] = '';
$cfg['CaptchaLoginPrivateKey'] = '';
$cfg['AllowArbitraryServer'] = false;
$cfg['ShowServerInfo'] = false;
$cfg['ShowPhpInfo'] = false;
$cfg['ShowChgPassword'] = true;
PMASEC
    sed -i "s|__PMA_COOKIE_VALIDITY__|${PMA_COOKIE_VALIDITY}|g" /etc/phpmyadmin/conf.d/security.php

    # Inclure le fichier de sécurité dans la config principale
    if ! grep -q "conf.d/security.php" /etc/phpmyadmin/config.inc.php 2>/dev/null; then
      echo "include('/etc/phpmyadmin/conf.d/security.php');" >> /etc/phpmyadmin/config.inc.php
    fi

    systemctl reload apache2
    log "phpMyAdmin installé."
    warn "URL phpMyAdmin : https://${HOSTNAME_FQDN}/${PMA_ALIAS}"
    note "Conservez cette URL, elle n'est pas /phpmyadmin par sécurité."

    # Sauvegarder l'alias dans un fichier pour référence (lecture root uniquement)
    echo "${PMA_ALIAS}" > /root/.phpmyadmin_alias
    chmod 600 /root/.phpmyadmin_alias
  fi
fi

# ---------------------------------- 7) Postfix + OpenDKIM ------------------------------
if $INSTALL_POSTFIX_DKIM; then
  section "Postfix (send-only) + OpenDKIM"
  echo "postfix postfix/mailname string ${DKIM_DOMAIN}" | debconf-set-selections
  echo "postfix postfix/main_mailer_type select Internet Site" | debconf-set-selections
  apt_install postfix opendkim opendkim-tools

  backup_file /etc/postfix/main.cf
  postconf -e "myhostname=${HOSTNAME_FQDN}"
  postconf -e "mydomain=${DKIM_DOMAIN}"
  postconf -e "myorigin=${DKIM_DOMAIN}"
  postconf -e "inet_interfaces=loopback-only"
  postconf -e "mydestination=localhost"
  postconf -e "relayhost="
  postconf -e "mynetworks=127.0.0.0/8 [::1]/128"
  postconf -e "smtp_tls_security_level=may"
  postconf -e "smtp_tls_loglevel=1"
  postconf -e "smtpd_tls_security_level=may"
  postconf -e "smtp_tls_note_starttls_offer=yes"
  postconf -e "smtp_tls_CAfile=/etc/ssl/certs/ca-certificates.crt"
  postconf -e "smtputf8_enable=no"

  adduser opendkim postfix || true
  mkdir -p /etc/opendkim/{keys,conf.d,domains}
  mkdir -p "${DKIM_KEYDIR}"
  chown -R opendkim:opendkim /etc/opendkim
  chmod -R go-rwx /etc/opendkim

  # Configure OpenDKIM uniquement si la clé n'existe pas (première installation)
  # ou si les fichiers de config sont absents
  DKIM_NEEDS_CONFIG=false
  if [[ ! -f "${DKIM_KEYDIR}/${DKIM_SELECTOR}.private" ]]; then
    DKIM_NEEDS_CONFIG=true
    # S'assurer que le répertoire est accessible pour la génération
    chmod 755 "${DKIM_KEYDIR}"
    # Supprimer les fichiers partiels s'ils existent
    rm -f "${DKIM_KEYDIR}/${DKIM_SELECTOR}.txt" 2>/dev/null || true
    # Générer la clé
    if opendkim-genkey -s "${DKIM_SELECTOR}" -d "${DKIM_DOMAIN}" -b "${DKIM_KEY_BITS}" -r -D "${DKIM_KEYDIR}"; then
      chown opendkim:opendkim "${DKIM_KEYDIR}/${DKIM_SELECTOR}.private"
      chmod 600 "${DKIM_KEYDIR}/${DKIM_SELECTOR}.private"
      chmod 644 "${DKIM_KEYDIR}/${DKIM_SELECTOR}.txt"
    else
      warn "Échec de génération de clé DKIM. Vérifiez manuellement."
      DKIM_NEEDS_CONFIG=false  # Pas de config sans clé valide
    fi
    # Restaurer les permissions restrictives
    chmod 750 "${DKIM_KEYDIR}"
    chown -R opendkim:opendkim "${DKIM_KEYDIR}"
  elif [[ ! -f /etc/opendkim/signingtable ]] || [[ ! -f /etc/opendkim/keytable ]]; then
    DKIM_NEEDS_CONFIG=true
    log "Clé DKIM existante, mais fichiers de config manquants. Reconfiguration..."
  else
    log "OpenDKIM déjà configuré. Clé et config existantes conservées."
  fi

  # Ne (re)configurer que si nécessaire
  if $DKIM_NEEDS_CONFIG; then
    backup_file /etc/opendkim.conf
    cat >/etc/opendkim.conf <<EOF
Syslog                  yes
LogWhy                  yes
UMask                   007
Mode                    sv
Socket                  inet:${OPENDKIM_PORT}@localhost
PidFile                 /run/opendkim/opendkim.pid
UserID                  opendkim:opendkim
Canonicalization        relaxed/simple
Selector                ${DKIM_SELECTOR}
MinimumKeyBits          1024
KeyTable                /etc/opendkim/keytable
SigningTable            refile:/etc/opendkim/signingtable
ExternalIgnoreList      /etc/opendkim/trustedhosts
InternalHosts           /etc/opendkim/trustedhosts
SignatureAlgorithm      rsa-sha256
EOF

    cat >/etc/opendkim/signingtable <<EOF
*@${DKIM_DOMAIN} ${DKIM_SELECTOR}._domainkey.${DKIM_DOMAIN}
EOF

    cat >/etc/opendkim/keytable <<EOF
${DKIM_SELECTOR}._domainkey.${DKIM_DOMAIN} ${DKIM_DOMAIN}:${DKIM_SELECTOR}:${DKIM_KEYDIR}/${DKIM_SELECTOR}.private
EOF

    cat >/etc/opendkim/trustedhosts <<'EOF'
127.0.0.1
localhost
::1
EOF
    note "Configuration OpenDKIM créée/mise à jour."
  fi

  # Ces paramètres Postfix peuvent être réappliqués sans risque
  postconf -e "milter_default_action=accept"
  postconf -e "milter_protocol=6"
  postconf -e "smtpd_milters=inet:localhost:${OPENDKIM_PORT}"
  postconf -e "non_smtpd_milters=inet:localhost:${OPENDKIM_PORT}"

  systemctl enable --now opendkim
  systemctl restart postfix
  note "Vérifier DKIM: opendkim-testkey -d ${DKIM_DOMAIN} -s ${DKIM_SELECTOR} -x /etc/opendkim.conf"
fi

# ---------------------------------- 8) Certbot ----------------------------------------
if $INSTALL_CERTBOT; then
  section "Certbot (Let's Encrypt)"
  apt_install certbot python3-certbot-apache

  # --- Mode wildcard via DNS OVH ---
  if $CERTBOT_WILDCARD; then
    log "Mode wildcard activé — installation du plugin DNS OVH..."

    # Installer certbot-dns-ovh (pas dans les dépôts Debian 13)
    if ! python3 -c "import certbot_dns_ovh" 2>/dev/null; then
      pip3 install --break-system-packages certbot-dns-ovh 2>&1 | tee -a "$LOG_FILE"
    fi

    # Demander les credentials OVH si pas encore fournis (mode --reconfigure)
    if [[ ! -f "${OVH_DNS_CREDENTIALS}" ]]; then
      if [[ -z "${OVH_APP_KEY:-}" || -z "${OVH_APP_SECRET:-}" || -z "${OVH_CONSUMER_KEY:-}" ]]; then
        section "Credentials API OVH (pour certificat wildcard)"
        echo "Un certificat wildcard nécessite la validation DNS-01 via l'API OVH."
        echo ""
        echo "Si vous n'avez pas encore de credentials, créez-les sur :"
        echo "  ${BOLD}https://eu.api.ovh.com/createToken/${RESET}"
        echo ""
        echo "Droits requis :"
        echo "  GET    /domain/zone/*"
        echo "  POST   /domain/zone/*"
        echo "  DELETE /domain/zone/*"
        echo ""
        OVH_APP_KEY="$(prompt_default "Application Key" "")"
        OVH_APP_SECRET="$(prompt_default "Application Secret" "")"
        OVH_CONSUMER_KEY="$(prompt_default "Consumer Key" "")"
      fi

      if [[ -n "${OVH_APP_KEY:-}" && -n "${OVH_APP_SECRET:-}" && -n "${OVH_CONSUMER_KEY:-}" ]]; then
        cat > "${OVH_DNS_CREDENTIALS}" <<OVHCREDS
dns_ovh_endpoint = ${OVH_API_ENDPOINT}
dns_ovh_application_key = ${OVH_APP_KEY}
dns_ovh_application_secret = ${OVH_APP_SECRET}
dns_ovh_consumer_key = ${OVH_CONSUMER_KEY}
OVHCREDS
        chmod 600 "${OVH_DNS_CREDENTIALS}"
        log "Credentials OVH sauvegardés dans ${OVH_DNS_CREDENTIALS} (mode 600)"
      else
        warn "Credentials OVH manquants. Certificat wildcard impossible."
        warn "Créez ${OVH_DNS_CREDENTIALS} manuellement puis relancez certbot."
      fi
    else
      log "Credentials OVH existants (${OVH_DNS_CREDENTIALS})"
    fi

    # Demander le certificat wildcard si les credentials sont en place
    if [[ -f "${OVH_DNS_CREDENTIALS}" ]]; then
      if [[ -d "/etc/letsencrypt/live/${HOSTNAME_FQDN}" ]]; then
        # Vérifier si le cert actuel couvre déjà le wildcard
        if openssl x509 -in "/etc/letsencrypt/live/${HOSTNAME_FQDN}/cert.pem" -noout -text 2>/dev/null | grep -q "\\*.${HOSTNAME_FQDN}"; then
          log "Certificat wildcard existant pour ${HOSTNAME_FQDN} — pas de nouvelle demande."
        else
          warn "Certificat existant mais sans wildcard. Remplacement..."
          certbot certonly \
            --dns-ovh \
            --dns-ovh-credentials "${OVH_DNS_CREDENTIALS}" \
            --dns-ovh-propagation-seconds "${CERTBOT_DNS_PROPAGATION}" \
            -d "${HOSTNAME_FQDN}" \
            -d "*.${HOSTNAME_FQDN}" \
            --email "${EMAIL_FOR_CERTBOT}" \
            --agree-tos \
            --non-interactive \
            --force-renewal \
            2>&1 | tee -a "$LOG_FILE"
        fi
      else
        log "Demande du certificat wildcard pour ${HOSTNAME_FQDN} + *.${HOSTNAME_FQDN}..."
        certbot certonly \
          --dns-ovh \
          --dns-ovh-credentials "${OVH_DNS_CREDENTIALS}" \
          --dns-ovh-propagation-seconds "${CERTBOT_DNS_PROPAGATION}" \
          -d "${HOSTNAME_FQDN}" \
          -d "*.${HOSTNAME_FQDN}" \
          --email "${EMAIL_FOR_CERTBOT}" \
          --agree-tos \
          --non-interactive \
          2>&1 | tee -a "$LOG_FILE"
      fi
    fi

  # --- Mode classique (HTTP-01) ---
  else
    if ss -tlnp 2>/dev/null | grep -q ":80 "; then
      note "Demande manuelle du certificat quand DNS OK:"
      note "  certbot --apache -d ${HOSTNAME_FQDN} -d www.${HOSTNAME_FQDN} --email ${EMAIL_FOR_CERTBOT} --agree-tos -n"
    else
      warn "Apache n'écoute pas sur le port 80 (probablement derrière un reverse proxy)."
      note "Utilisez le mode standalone ou webroot pour obtenir le certificat :"
      note "  certbot certonly --standalone -d ${HOSTNAME_FQDN} --email ${EMAIL_FOR_CERTBOT} --agree-tos -n"
      note "  ou: certbot certonly --webroot -w /var/www/html -d ${HOSTNAME_FQDN} --email ${EMAIL_FOR_CERTBOT} --agree-tos -n"
    fi
  fi

  # Hook de renouvellement (rechargement Apache après renouvellement)
  mkdir -p /etc/letsencrypt/renewal-hooks/deploy
  cat > /etc/letsencrypt/renewal-hooks/deploy/reload-apache.sh <<'RENEWHOOK'
#!/bin/bash
# Recharger Apache après renouvellement de certificat Let's Encrypt
if systemctl is-active --quiet apache2; then
  systemctl reload apache2
fi
RENEWHOOK
  chmod +x /etc/letsencrypt/renewal-hooks/deploy/reload-apache.sh

  # S'assurer que le timer certbot est activé
  if systemctl list-unit-files certbot.timer >/dev/null 2>&1; then
    systemctl enable --now certbot.timer 2>/dev/null || true
    log "Timer certbot activé (renouvellement automatique)"
  fi

  log "Certbot installé avec hook de renouvellement Apache."
fi

# ---------------------------------- 9) DNS auto-config (SPF/DKIM/DMARC) ----------------
if $INSTALL_POSTFIX_DKIM && [[ -f "${OVH_DNS_CREDENTIALS}" ]]; then
  section "Configuration DNS automatique (SPF/DKIM/DMARC)"
  log "Credentials OVH détectés — vérification de l'accès API..."

  if ! ovh_test_credentials 2>/dev/null; then
    warn "Credentials OVH invalides ou expirés. Configuration DNS ignorée."
    warn "Recréez les credentials sur : https://eu.api.ovh.com/createToken/"
    warn "Puis mettez à jour ${OVH_DNS_CREDENTIALS}"
  else
    log "API OVH accessible — configuration automatique des enregistrements DNS..."

    # Récupérer l'IP publique du serveur
    SERVER_IP="${SERVER_IP:-$(curl -s -4 ifconfig.me 2>/dev/null || curl -s -4 icanhazip.com 2>/dev/null)}"
    if [[ -z "${SERVER_IP:-}" ]]; then
      warn "Impossible de déterminer l'IP publique. Configuration DNS ignorée."
    else
      # SPF
      log "Configuration SPF pour ${DKIM_DOMAIN} (IP: ${SERVER_IP})..."
      ovh_setup_spf "$DKIM_DOMAIN" "$SERVER_IP" && log "SPF configuré." || warn "Erreur configuration SPF."

      # DKIM
      dkim_pub="${DKIM_KEYDIR}/${DKIM_SELECTOR}.txt"
      if [[ -f "$dkim_pub" ]]; then
        log "Configuration DKIM (${DKIM_SELECTOR}._domainkey.${DKIM_DOMAIN})..."
        ovh_setup_dkim "$DKIM_DOMAIN" "$DKIM_SELECTOR" "$dkim_pub" && log "DKIM configuré." || warn "Erreur configuration DKIM."
      else
        warn "Fichier clé publique DKIM non trouvé (${dkim_pub}). DKIM DNS non configuré."
      fi

      # DMARC
      log "Configuration DMARC pour ${DKIM_DOMAIN}..."
      ovh_setup_dmarc "$DKIM_DOMAIN" "${EMAIL_FOR_CERTBOT}" && log "DMARC configuré." || warn "Erreur configuration DMARC."

      log "Enregistrements DNS configurés. Propagation en cours..."
      note "Vérification : dig TXT ${DKIM_DOMAIN} @8.8.8.8"
      note "Vérification : dig TXT ${DKIM_SELECTOR}._domainkey.${DKIM_DOMAIN} @8.8.8.8"
      note "Vérification : dig TXT _dmarc.${DKIM_DOMAIN} @8.8.8.8"
    fi
  fi

  # Test de délivrabilité email (même si DNS échoue, tester l'envoi Postfix)
  if command -v mail >/dev/null 2>&1; then
    section "Test de délivrabilité email"
    ovh_test_mail "${EMAIL_FOR_CERTBOT}" "${HOSTNAME_FQDN}" || true
  fi
fi
