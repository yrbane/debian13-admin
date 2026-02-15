#!/usr/bin/env bash
# lib/install-web.sh — Apache/PHP, MariaDB, phpMyAdmin, Postfix/OpenDKIM, Certbot
# Sourcé par debian13-server.sh — Dépend de: lib/core.sh, lib/constants.sh, lib/helpers.sh, lib/config.sh
#
# Stack applicative du serveur. L'ordre d'installation reflète les dépendances :
#
#   5)  Apache + PHP         → serveur web + interpréteur (requis par tout le reste)
#       Pages d'erreur WebGL → intercepte toutes les erreurs HTTP (400-511)
#   6)  MariaDB              → base de données (optionnel, requis par phpMyAdmin)
#   6b) phpMyAdmin           → GUI MariaDB sécurisée (URL aléatoire, cookie court)
#   7)  Postfix + OpenDKIM   → email sortant signé DKIM (loopback-only, pas de MX entrant)
#   8)  Certbot              → TLS via Let's Encrypt (wildcard DNS-01 ou HTTP-01)
#   8b) VirtualHosts         → VHosts Apache + parking page WebGL + logrotate
#   9)  DNS auto-config      → SPF/DKIM/DMARC/CAA via API OVH
#
# Philosophie sécurité web :
#   - Headers défensifs systématiques (HSTS, CSP, X-Frame-Options, etc.)
#   - ServerTokens=Prod + ServerSignature=Off → ne pas révéler la version Apache
#   - mod_security2 (WAF) + mod_evasive (anti-DDoS basique)
#   - PHP durci : fonctions dangereuses désactivées, opcache activé, display_errors=Off
#   - phpMyAdmin : URL aléatoire (hex), cookie 30min, pas de serveur arbitraire

# ---------------------------------- 5) Apache/PHP -------------------------------------
# Installation complète : Apache MPM event + PHP + modules de sécurité.
# mod_security2 = WAF (Web Application Firewall) basé sur les règles OWASP CRS.
# mod_evasive = protection basique contre les requêtes répétitives (DDoS applicatif).
if $INSTALL_APACHE_PHP; then
  if step_needed "web_apache_php"; then
    section "Apache + PHP"
    apt_install apache2 apache2-utils
  systemctl enable --now apache2
  apt_install php php-cli php-fpm php-mysql php-curl php-xml php-gd php-mbstring php-zip php-intl php-opcache php-imagick imagemagick libapache2-mod-php
  apt_install libapache2-mod-security2 libapache2-mod-evasive

  # Modules Apache — chaque groupe sert un rôle précis :
  a2enmod headers rewrite ssl security2  # Sécurité : headers HTTP, URL rewriting, TLS, WAF
  a2enmod expires deflate                 # Performance : cache navigateur, compression gzip
  a2enmod proxy proxy_http proxy_wstunnel # Reverse proxy : HTTP backend + WebSocket passthrough
  a2enmod socache_shmcb                   # SSL session cache en mémoire partagée (performance TLS)
  a2enmod vhost_alias                     # VirtualDocumentRoot dynamique (wildcard subdomains)
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
  # Masquer la version d'Apache dans les réponses HTTP et les pages d'erreur.
  # Un attaquant qui connaît la version exacte peut cibler des CVE spécifiques.
  sed -ri 's/^ServerTokens .*/ServerTokens Prod/; s/^ServerSignature .*/ServerSignature Off/' /etc/apache2/conf-available/security.conf
  # Durcissement PHP : on applique les mêmes règles à tous les SAPI (apache2, cli, fpm)
  # pour éviter les incohérences entre l'exécution web et les scripts cron.
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
    mark_done "web_apache_php"
  else
    log "web_apache_php (deja fait)"
  fi

  # ---------------------------------- Pages d'erreur WebGL --------------------------------
  # Architecture des pages d'erreur :
  #   /var/www/errorpages/
  #     error.php          ← page unique qui récupère le code HTTP via $_SERVER['REDIRECT_STATUS']
  #     error-notify.php   ← inclus par error.php si code >= 500 → envoie un email admin
  #     trusted-ips.php    ← liste des IPs autorisées à voir le debug détaillé
  #     css/error.css      ← styles partagés (thème sombre, animation code HTTP)
  #
  # Le code HTTP est affiché en 3D via Three.js (WebGL). Les IPs trusted voient en
  # plus : URI demandée, headers de la requête, variables serveur — utile pour le debug
  # sans exposer d'information aux visiteurs non autorisés.
  #
  # Le throttle email (error-notify.php) empêche le flood : un seul email par code
  # d'erreur par tranche de ERROR_THROTTLE_SECONDS (défaut 5min), via un fichier
  # lock dans /tmp. Cela protège la boîte mail en cas de DDoS déclenchant des 503.
  if step_needed "web_error_pages"; then
    section "Pages d'erreur WebGL"

    mkdir -p "${ERROR_PAGES_DIR}/css"

  # Fichier de configuration des IPs de confiance (pour debug)
  cat >"${ERROR_PAGES_DIR}/trusted-ips.php" <<'TRUSTEDIPS'
<?php
// IPs de confiance - générées par debian13-server.sh
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
    sed -i "s|__TRUSTED_IPS_ARRAY__|${TRUSTED_IPS_PHP}|" "${ERROR_PAGES_DIR}/trusted-ips.php"
  else
    sed -i "s|__TRUSTED_IPS_ARRAY__|    // Aucune IP configurée|" "${ERROR_PAGES_DIR}/trusted-ips.php"
  fi

  # Déployer error-notify.php (notification email 5xx avec throttle)
  ERROR_NOTIFY_TEMPLATE="${SCRIPT_DIR}/templates/error-notify.php"
  [[ ! -f "$ERROR_NOTIFY_TEMPLATE" ]] && ERROR_NOTIFY_TEMPLATE="${SCRIPTS_DIR}/templates/error-notify.php"
  if [[ -f "$ERROR_NOTIFY_TEMPLATE" ]]; then
    cp "$ERROR_NOTIFY_TEMPLATE" "${ERROR_PAGES_DIR}/error-notify.php"
    sed -i "s|__ADMIN_EMAIL__|${EMAIL_FOR_CERTBOT}|g" "${ERROR_PAGES_DIR}/error-notify.php"
    sed -i "s|__HOSTNAME_FQDN__|${HOSTNAME_FQDN}|g" "${ERROR_PAGES_DIR}/error-notify.php"
    sed -i "s|__ERROR_THROTTLE_SECONDS__|${ERROR_THROTTLE_SECONDS}|g" "${ERROR_PAGES_DIR}/error-notify.php"
  else
    warn "Template error-notify.php non trouvé."
  fi

  # Déployer error-page-webgl.php → error.php
  ERROR_WEBGL_TEMPLATE="${SCRIPT_DIR}/templates/error-page-webgl.php"
  [[ ! -f "$ERROR_WEBGL_TEMPLATE" ]] && ERROR_WEBGL_TEMPLATE="${SCRIPTS_DIR}/templates/error-page-webgl.php"
  if [[ -f "$ERROR_WEBGL_TEMPLATE" ]]; then
    cp "$ERROR_WEBGL_TEMPLATE" "${ERROR_PAGES_DIR}/error.php"
  else
    warn "Template error-page-webgl.php non trouvé. Pages d'erreur non déployées."
  fi

  # Déployer error-style.css
  ERROR_CSS_TEMPLATE="${SCRIPT_DIR}/templates/error-style.css"
  [[ ! -f "$ERROR_CSS_TEMPLATE" ]] && ERROR_CSS_TEMPLATE="${SCRIPTS_DIR}/templates/error-style.css"
  if [[ -f "$ERROR_CSS_TEMPLATE" ]]; then
    cp "$ERROR_CSS_TEMPLATE" "${ERROR_PAGES_DIR}/css/error.css"
  else
    warn "Template error-style.css non trouvé."
  fi

  # Configuration Apache pour les pages d'erreur
  cat >/etc/apache2/conf-available/custom-error-pages.conf <<'ERRORCONF'
# Pages d'erreur WebGL — deployed by debian13-server.sh
Alias /errorpages /var/www/errorpages

<Directory /var/www/errorpages>
    Options -Indexes
    AllowOverride None
    Require all granted

    <FilesMatch "\.php$">
        SetHandler application/x-httpd-php
    </FilesMatch>

    # CSP: allow Three.js CDN for WebGL error pages
    Header always set Content-Security-Policy "default-src 'self'; script-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; style-src 'self' 'unsafe-inline'; font-src 'self' https://cdn.jsdelivr.net; connect-src 'self' https://cdn.jsdelivr.net; img-src 'self' data:;"
</Directory>

# Error documents — all codes 400-511
ErrorDocument 400 /errorpages/error.php
ErrorDocument 401 /errorpages/error.php
ErrorDocument 402 /errorpages/error.php
ErrorDocument 403 /errorpages/error.php
ErrorDocument 404 /errorpages/error.php
ErrorDocument 405 /errorpages/error.php
ErrorDocument 406 /errorpages/error.php
ErrorDocument 407 /errorpages/error.php
ErrorDocument 408 /errorpages/error.php
ErrorDocument 409 /errorpages/error.php
ErrorDocument 410 /errorpages/error.php
ErrorDocument 411 /errorpages/error.php
ErrorDocument 412 /errorpages/error.php
ErrorDocument 413 /errorpages/error.php
ErrorDocument 414 /errorpages/error.php
ErrorDocument 415 /errorpages/error.php
ErrorDocument 416 /errorpages/error.php
ErrorDocument 417 /errorpages/error.php
ErrorDocument 421 /errorpages/error.php
ErrorDocument 422 /errorpages/error.php
ErrorDocument 423 /errorpages/error.php
ErrorDocument 424 /errorpages/error.php
ErrorDocument 426 /errorpages/error.php
ErrorDocument 428 /errorpages/error.php
ErrorDocument 429 /errorpages/error.php
ErrorDocument 431 /errorpages/error.php
ErrorDocument 451 /errorpages/error.php
ErrorDocument 500 /errorpages/error.php
ErrorDocument 501 /errorpages/error.php
ErrorDocument 502 /errorpages/error.php
ErrorDocument 503 /errorpages/error.php
ErrorDocument 504 /errorpages/error.php
ErrorDocument 505 /errorpages/error.php
ErrorDocument 506 /errorpages/error.php
ErrorDocument 507 /errorpages/error.php
ErrorDocument 508 /errorpages/error.php
ErrorDocument 510 /errorpages/error.php
ErrorDocument 511 /errorpages/error.php
ERRORCONF

  a2enconf custom-error-pages

  # Permissions
  chown -R "${WEB_USER}:${WEB_USER}" "${ERROR_PAGES_DIR}"
  find "${ERROR_PAGES_DIR}" -type f -name "*.php" -exec chmod 644 {} +
  find "${ERROR_PAGES_DIR}" -type f -name "*.css" -exec chmod 644 {} +

  log "Pages d'erreur WebGL installées dans ${ERROR_PAGES_DIR}/"
    mark_done "web_error_pages"
  else
    log "web_error_pages (deja fait)"
  fi
fi

# ---------------------------------- 6) MariaDB ----------------------------------------
# Hardening minimal mais efficace : suppression des utilisateurs anonymes, de la base
# de test, et flush des privilèges. Équivalent au mysql_secure_installation interactif,
# mais scriptable et idempotent (les DELETE/DROP IF EXISTS ne cassent rien si déjà fait).
if $INSTALL_MARIADB; then
  if step_needed "web_mariadb"; then
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
    mark_done "web_mariadb"
  else
    log "web_mariadb (deja fait)"
  fi
fi

# ---------------------------------- 6b) phpMyAdmin --------------------------------------
# Stratégie de sécurisation phpMyAdmin :
#   1. URL aléatoire : /dbadmin_<hex> au lieu de /phpmyadmin (anti-scan automatisé)
#   2. Cookie session courte (30min) → réduit la fenêtre en cas de vol de session
#   3. AllowArbitraryServer=false → empêche d'utiliser PMA comme proxy vers d'autres DBs
#   4. Logs d'auth vers syslog → intégration Fail2ban possible
#   L'alias est sauvegardé dans /root/.phpmyadmin_alias (mode 600, root-only).
if $INSTALL_PHPMYADMIN; then
  if ! $INSTALL_MARIADB || ! $INSTALL_APACHE_PHP; then
    warn "phpMyAdmin nécessite MariaDB et Apache/PHP. Installation ignorée."
  elif step_needed "web_phpmyadmin"; then
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
    mark_done "web_phpmyadmin"
  else
    log "web_phpmyadmin (deja fait)"
  fi
fi

# ---------------------------------- 7) Postfix + OpenDKIM ------------------------------
# Configuration email sortant uniquement (pas de MX entrant — les MX OVH gèrent la réception).
#
# Postfix est en mode loopback-only (inet_interfaces=loopback-only) :
#   - Seuls les processus locaux (cron, PHP mail(), logwatch) peuvent envoyer
#   - Aucun port SMTP exposé au réseau → pas de relay ouvert possible
#   - TLS opportuniste en sortie (smtp_tls_security_level=may)
#
# OpenDKIM signe les emails sortants pour prouver l'authenticité du domaine.
# Architecture multi-domaines :
#   /etc/opendkim/keys/{domaine}/{selecteur}.private  ← clés RSA 2048 bits
#   /etc/opendkim/keytable     ← mapping sélecteur → fichier clé
#   /etc/opendkim/signingtable ← mapping expéditeur → sélecteur (regex: *@domaine)
#   /etc/opendkim/trustedhosts ← IPs autorisées à signer (localhost uniquement)
#
# Le milter protocol 6 (postconf milter_protocol=6) est la version la plus récente,
# supportant les headers étendus et la gestion des erreurs améliorée.
if $INSTALL_POSTFIX_DKIM; then
  if step_needed "web_postfix_dkim"; then
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
  dm_keydir="${DKIM_KEYDIR_BASE}/${DKIM_DOMAIN}"
  mkdir -p "$dm_keydir"
  chown -R opendkim:opendkim /etc/opendkim
  chmod -R go-rwx /etc/opendkim

  # Migration de layout DKIM : avant le multi-domaines, les clés étaient stockées à plat
  # dans keys/{selector}.private. Le nouveau layout keys/{domain}/{selector}.private
  # permet de gérer N domaines sur le même serveur sans collision de noms.
  old_key="${DKIM_KEYDIR_BASE}/${DKIM_SELECTOR}.private"
  new_key="${dm_keydir}/${DKIM_SELECTOR}.private"
  if [[ -f "$old_key" && ! -f "$new_key" ]]; then
    log "Migration DKIM: ${old_key} -> ${new_key}"
    mv "$old_key" "$new_key"
    [[ -f "${DKIM_KEYDIR_BASE}/${DKIM_SELECTOR}.txt" ]] && mv "${DKIM_KEYDIR_BASE}/${DKIM_SELECTOR}.txt" "${dm_keydir}/${DKIM_SELECTOR}.txt"
    chown -R opendkim:opendkim "$dm_keydir"
  fi

  # Générer la clé si absente
  DKIM_NEEDS_CONFIG=false
  if [[ ! -f "$new_key" ]]; then
    DKIM_NEEDS_CONFIG=true
    dm_generate_dkim_key "${DKIM_DOMAIN}" "${DKIM_SELECTOR}" || DKIM_NEEDS_CONFIG=false
  elif [[ ! -f /etc/opendkim/signingtable ]] || [[ ! -f /etc/opendkim/keytable ]]; then
    DKIM_NEEDS_CONFIG=true
    log "Clé DKIM existante, mais fichiers de config manquants. Reconfiguration..."
  else
    log "OpenDKIM déjà configuré. Clé et config existantes conservées."
  fi

  # Enregistrer le domaine principal et reconstruire la config OpenDKIM
  if $DKIM_NEEDS_CONFIG || ! dm_domain_exists "${DKIM_DOMAIN}"; then
    dm_register_domain "${DKIM_DOMAIN}" "${DKIM_SELECTOR}"

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

    dm_rebuild_opendkim --no-restart
    note "Configuration OpenDKIM créée/mise à jour (multi-domaines)."
  fi

  # Ces paramètres Postfix peuvent être réappliqués sans risque
  postconf -e "milter_default_action=accept"
  postconf -e "milter_protocol=6"
  postconf -e "smtpd_milters=inet:localhost:${OPENDKIM_PORT}"
  postconf -e "non_smtpd_milters=inet:localhost:${OPENDKIM_PORT}"

  systemctl enable --now opendkim
  systemctl restart postfix
  note "Vérifier DKIM: opendkim-testkey -d ${DKIM_DOMAIN} -s ${DKIM_SELECTOR} -x /etc/opendkim.conf"
    mark_done "web_postfix_dkim"
  else
    log "web_postfix_dkim (deja fait)"
  fi
fi

# ---------------------------------- 8) Certbot ----------------------------------------
# Deux modes de validation Let's Encrypt selon la configuration :
#
#   DNS-01 (wildcard, via API OVH) :
#     - Crée un enregistrement TXT _acme-challenge.{domaine} pour prouver le contrôle
#     - Permet les certificats wildcard (*.domaine.tld) → un seul cert pour tous les sous-domaines
#     - Nécessite des credentials API OVH avec droits GET/POST/DELETE sur /domain/zone/*
#     - Propagation DNS : on attend CERTBOT_DNS_PROPAGATION secondes (défaut 60s)
#
#   HTTP-01 (fallback, sans credentials OVH) :
#     - Let's Encrypt accède à http://{domaine}/.well-known/acme-challenge/
#     - Pas de wildcard possible → un certificat par sous-domaine
#     - Nécessite que le port 80 soit accessible depuis Internet
#
# Le hook de renouvellement (renewal-hooks/deploy/) recharge Apache automatiquement
# après chaque renouvellement, évitant un cert expiré en production.
if $INSTALL_CERTBOT; then
  if step_needed "web_certbot"; then
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
    mark_done "web_certbot"
  else
    log "web_certbot (deja fait)"
  fi
fi

# ---------------------------------- 8b) VirtualHost + Parking ----------------------------
# Architecture VHost multi-domaines (3 fichiers par domaine) :
#
#   000-{domain}-redirect.conf  → HTTP:80 → HTTPS 301 (y compris www)
#   010-{domain}.conf           → HTTPS:443 apex + www, DocumentRoot /var/www/{domain}/www/public
#   020-{domain}-wildcard.conf  → HTTPS:443 *.{domain} via VirtualDocumentRoot (si cert wildcard)
#
# La numérotation 000/010/020 garantit l'ordre de chargement par Apache :
#   - 000 = redirection HTTP (doit matcher en premier sur :80)
#   - 010 = VHost HTTPS principal (apex + www)
#   - 020 = VHost wildcard (catch-all pour les sous-domaines)
#
# Le parking page est une page WebGL (Three.js) affichant le nom de domaine
# en 3D avec des animations. Elle sert de placeholder visible pour confirmer
# que le domaine est correctement configuré. robots.txt Disallow:/ empêche
# l'indexation pendant que le site n'est pas encore déployé.
if $INSTALL_APACHE_PHP; then
  if step_needed "web_vhosts"; then
    section "VirtualHost HTTPS + Page de parking"

  # Page de parking + robots.txt (via domain-manager)
  dm_deploy_parking "${HOSTNAME_FQDN}"
  chown -R "${WEB_USER}:${WEB_USER}" "/var/www/${HOSTNAME_FQDN}"

  # Déployer les VHosts si le certificat SSL existe
  CERT_DIR="/etc/letsencrypt/live/${HOSTNAME_FQDN}"
  if [[ -f "${CERT_DIR}/fullchain.pem" && -f "${CERT_DIR}/privkey.pem" ]]; then
    log "Certificat SSL détecté — déploiement des VirtualHosts..."

    # Désactiver les sites par défaut
    a2dissite 000-default.conf 2>/dev/null || true
    a2dissite default-ssl.conf 2>/dev/null || true

    # VHosts HTTP redirect + HTTPS (via domain-manager)
    dm_deploy_vhosts "${HOSTNAME_FQDN}"
    a2ensite "000-${HOSTNAME_FQDN}-redirect.conf"
    a2ensite "010-${HOSTNAME_FQDN}.conf"

    # VHost wildcard (seulement si certificat wildcard détecté)
    if openssl x509 -in "${CERT_DIR}/cert.pem" -noout -text 2>/dev/null | grep -q "\\*.${HOSTNAME_FQDN}"; then
      dm_deploy_vhost_wildcard "${HOSTNAME_FQDN}"
      a2ensite "020-${HOSTNAME_FQDN}-wildcard.conf"
    else
      note "Certificat non-wildcard — VHost wildcard non déployé."
      note "Pour activer : certbot certonly --dns-ovh -d ${HOSTNAME_FQDN} -d '*.${HOSTNAME_FQDN}'"
    fi

    # Vérifier la configuration Apache
    if apache2ctl configtest 2>&1 | grep -q "Syntax OK"; then
      systemctl reload apache2
      log "VirtualHosts déployés et Apache rechargé."
    else
      warn "Erreur de syntaxe Apache — VHosts déployés mais non rechargés."
      warn "Exécutez : apache2ctl configtest"
    fi
  else
    warn "Certificat SSL non trouvé (${CERT_DIR})."
    note "Les VirtualHosts seront activés après obtention du certificat :"
    note "  certbot certonly --dns-ovh --dns-ovh-credentials ${OVH_DNS_CREDENTIALS} -d ${HOSTNAME_FQDN} -d '*.${HOSTNAME_FQDN}'"
    note "  Puis relancez ce script pour déployer les VHosts."
  fi

  # Logrotate (via domain-manager)
  dm_deploy_logrotate "${HOSTNAME_FQDN}"
    mark_done "web_vhosts"
  else
    log "web_vhosts (deja fait)"
  fi
fi

# ---------------------------------- 9) DNS auto-config (SPF/DKIM/DMARC) ----------------
# Configuration automatique des enregistrements DNS nécessaires à la délivrabilité email.
# Sans ces enregistrements, les emails sortants risquent d'atterrir en spam :
#
#   SPF  → "qui a le droit d'envoyer pour ce domaine" (IP du serveur + MX OVH)
#   DKIM → "ce message a été signé par le serveur autorisé" (clé publique dans le DNS)
#   DMARC → "que faire si SPF ou DKIM échoue" (quarantine + rapport à l'admin)
#   CAA  → "seul Let's Encrypt peut émettre des certificats pour ce domaine"
#
# La fonction dm_setup_dns() gère aussi les enregistrements A, AAAA et www.
# Tous les appels API OVH sont idempotents (upsert : update si existe, create sinon).
if $INSTALL_POSTFIX_DKIM && [[ -f "${OVH_DNS_CREDENTIALS}" ]]; then
  if step_needed "web_dns_config"; then
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
      dm_setup_dns "${DKIM_DOMAIN}" "${DKIM_SELECTOR}"
      log "DNS: ${DM_DNS_OK} OK, ${DM_DNS_FAIL} échec(s)"
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
    mark_done "web_dns_config"
  else
    log "web_dns_config (deja fait)"
  fi
fi
