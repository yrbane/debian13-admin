#!/usr/bin/env bash
# lib/install-base.sh — Locales, hostname, SSH, UFW, GeoIP, Fail2ban
# Sourcé par debian13-server.sh — Dépend de: lib/core.sh, lib/constants.sh, lib/helpers.sh, lib/config.sh

install_locales() {
  section "Locales fr_FR"
  apt_install locales tzdata
  sed -i 's/^# *fr_FR.UTF-8 UTF-8/fr_FR.UTF-8 UTF-8/' /etc/locale.gen
  add_line_if_missing '^fr_FR ISO-8859-1' 'fr_FR ISO-8859-1' /etc/locale.gen
  add_line_if_missing '^fr_FR@euro ISO-8859-15' 'fr_FR@euro ISO-8859-15' /etc/locale.gen
  locale-gen | tee -a "$LOG_FILE"
  update-locale LANG=fr_FR.UTF-8 LANGUAGE=fr_FR:fr LC_TIME=fr_FR.UTF-8 LC_NUMERIC=fr_FR.UTF-8 LC_MONETARY=fr_FR.UTF-8 LC_PAPER=fr_FR.UTF-8 LC_MEASUREMENT=fr_FR.UTF-8
  timedatectl set-timezone "$TIMEZONE" || true
  log "Locales fr_FR et timezone configurées."
}

install_hostname() {
  section "Hostname & /etc/hosts"
  hostnamectl set-hostname "$HOSTNAME_FQDN"
  if ! grep -q "$HOSTNAME_FQDN" /etc/hosts; then
    backup_file /etc/hosts
    IP4=$(hostname -I | awk '{print $1}')
    # Supprimer l'ancienne entrée de l'IP si présente, puis ajouter
    sed -i "/^${IP4}\s/d" /etc/hosts
    # S'assurer que 127.0.0.1 localhost et ::1 localhost existent
    grep -q "^127\.0\.0\.1\s" /etc/hosts || echo "127.0.0.1   localhost" >> /etc/hosts
    grep -q "^::1\s" /etc/hosts || echo "::1         localhost ip6-localhost ip6-loopback" >> /etc/hosts
    echo "${IP4}   ${HOSTNAME_FQDN} ${HOSTNAME_FQDN%%.*}" >> /etc/hosts
  fi
  log "Hostname défini sur ${HOSTNAME_FQDN}"
}

# ---- Exécution ----
$INSTALL_LOCALES && install_locales
install_hostname

# ---------------------------------- 2) SSH durci --------------------------------------
if $INSTALL_SSH_HARDEN; then
  section "SSH durci (clé uniquement) + port ${SSH_PORT}"
  apt_install openssh-server
  backup_file ${SSHD_CONFIG}
  cat >${SSHD_CONFIG} <<EOF
Include ${SSHD_CONFIG}.d/*.conf
Port ${SSH_PORT}
AddressFamily any
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
PubkeyAuthentication yes
AllowUsers ${ADMIN_USER}
HostKey /etc/ssh/ssh_host_ed25519_key
HostKey /etc/ssh/ssh_host_rsa_key
Ciphers ${SSH_CIPHERS}
MACs ${SSH_MACS}
# Post-quantum hybrid (protection contre "store now, decrypt later")
KexAlgorithms ${SSH_KEX}
ClientAliveInterval 300
ClientAliveCountMax 2
LoginGraceTime 20
MaxAuthTries 3
MaxSessions 3
X11Forwarding no
UsePAM yes
Subsystem sftp  /usr/lib/openssh/sftp-server
EOF
  systemctl restart ssh || systemctl reload ssh
  warn "Garde une session SSH ouverte lors du changement de port ! Nouvelle connexion : ssh -p ${SSH_PORT} ${ADMIN_USER}@${HOSTNAME_FQDN}"

  # Nettoyer /root/.ssh/authorized_keys (PermitRootLogin=no rend ces clés inutiles)
  if [[ -f /root/.ssh/authorized_keys ]] && [[ -s /root/.ssh/authorized_keys ]]; then
    backup_file /root/.ssh/authorized_keys
    > /root/.ssh/authorized_keys
    log "Clés SSH de root nettoyées (PermitRootLogin=no, clés inutiles)"
  fi
fi

# ---------------------------------- 2b) Désactiver LLMNR/mDNS -------------------------
section "Désactivation LLMNR/mDNS"
mkdir -p "${RESOLVED_DROPIN_DIR}"
cat > "${RESOLVED_DROPIN_DIR}/90-no-llmnr.conf" <<'EOF'
[Resolve]
LLMNR=no
MulticastDNS=no
EOF
systemctl restart systemd-resolved 2>/dev/null || true
log "LLMNR et mDNS désactivés (port 5355 fermé)"

# ---------------------------------- 3) UFW --------------------------------------------
if $INSTALL_UFW; then
  section "Pare-feu UFW"
  apt_install ufw
  ufw default deny incoming
  ufw default allow outgoing
  ufw allow "${SSH_PORT}/tcp" comment "SSH"
  ufw allow 80/tcp comment "HTTP"
  ufw allow 443/tcp comment "HTTPS"
  yes | ufw enable || true
  ufw status verbose
  log "UFW activé. Ports ouverts: ${SSH_PORT}/80/443."

  # Filtrage egress (optionnel)
  if $EGRESS_FILTER; then
    deploy_egress_rules
  fi
fi

# ---------------------------------- 3b) GeoIP Block ------------------------------------
if $GEOIP_BLOCK && $INSTALL_UFW; then
  section "Blocage GeoIP (${GEOIP_COUNTRY_COUNT} pays : Asie + Afrique)"
  apt_install ipset

  # Créer l'ipset s'il n'existe pas
  ipset list geoip_blocked >/dev/null 2>&1 || ipset create geoip_blocked hash:net

  # Script de mise à jour des IPs bloquées
  cat > /usr/local/bin/geoip-update.sh << 'GEOIPSCRIPT'
#!/bin/bash
CURL_TIMEOUT=10
# Mise à jour des IPs bloquées par pays (Asie + Afrique)
# Pour débloquer un pays: retirer son code de COUNTRIES et relancer le script
# Codes pays: https://www.ipdeny.com/ipblocks/data/countries/

# AFRIQUE (54 pays)
AFRICA="dz ao bj bw bf bi cv cm cf td km cg cd ci dj eg gq er sz et ga gm gh gn gw ke ls lr ly mg mw ml mr mu ma mz na ne ng rw st sn sc sl so za ss sd tz tg tn ug zm zw"

# ASIE (49 pays) - inclut Russie et Moyen-Orient
ASIA="af am az bh bd bt bn kh cn ge in id ir iq il jo kz kw kg la lb my mv mn mm np kp om pk ps ph qa ru sa sg kr lk sy tw tj th tl tr tm ae uz vn ye"

COUNTRIES="$AFRICA $ASIA"

# Créer un ipset temporaire
ipset create geoip_blocked_new hash:net -exist

for country in $COUNTRIES; do
  url="https://www.ipdeny.com/ipblocks/data/countries/${country}.zone"
  while read -r ip; do
    [[ -n "$ip" ]] && ipset add geoip_blocked_new "$ip" 2>/dev/null || true
  done < <(curl -sfS --max-time "${CURL_TIMEOUT}" "$url" 2>/dev/null)
done

# Remplacer l'ancien set par le nouveau
ipset swap geoip_blocked_new geoip_blocked 2>/dev/null || \
  ipset rename geoip_blocked_new geoip_blocked 2>/dev/null
ipset destroy geoip_blocked_new 2>/dev/null

echo "$(date): GeoIP updated - $(ipset list geoip_blocked | grep -c '^[0-9]') ranges blocked"
GEOIPSCRIPT
  chmod +x /usr/local/bin/geoip-update.sh

  # Exécuter la première mise à jour
  log "Téléchargement des plages IP à bloquer (peut prendre quelques minutes)..."
  /usr/local/bin/geoip-update.sh | tee -a "$LOG_FILE"

  # Ajouter la règle UFW (dans before.rules)
  if ! grep -q "geoip_blocked" /etc/ufw/before.rules; then
    sed -i '/^# End required lines/a \
# GeoIP blocking\
-A ufw-before-input -m set --match-set geoip_blocked src -j DROP' /etc/ufw/before.rules
  fi

  # Cron hebdomadaire pour mise à jour
  cat > /etc/cron.weekly/geoip-update << 'CRONEOF'
#!/bin/bash
/usr/local/bin/geoip-update.sh >> /var/log/geoip-update.log 2>&1
ufw reload
CRONEOF
  chmod +x /etc/cron.weekly/geoip-update

  # Recharger UFW
  ufw reload
  log "Blocage GeoIP activé. $(ipset list geoip_blocked | grep -c '^[0-9]' || true) plages bloquées."
fi

# ---------------------------------- 4) Fail2ban ---------------------------------------
if $INSTALL_FAIL2BAN; then
  section "Fail2ban"
  apt_install fail2ban
  backup_file /etc/fail2ban/jail.local

  # Construire la liste des IPs à ignorer
  FAIL2BAN_IGNOREIP="127.0.0.1/8 ::1"
  if [[ -n "${TRUSTED_IPS:-}" ]]; then
    FAIL2BAN_IGNOREIP="$FAIL2BAN_IGNOREIP $TRUSTED_IPS"
    log "fail2ban: IPs de confiance ajoutées à ignoreip: $TRUSTED_IPS"
  fi

  cat >/etc/fail2ban/jail.local <<EOF
[DEFAULT]
bantime  = 1h
findtime = 10m
maxretry = 5
backend = systemd
ignoreip = ${FAIL2BAN_IGNOREIP}
destemail = ${EMAIL_FOR_CERTBOT}
sender = fail2ban@${DKIM_DOMAIN:-\$(hostname -d)}
mta = sendmail

[sshd]
enabled = true
port = ${SSH_PORT}
filter = sshd
logpath = %(sshd_log)s
maxretry = 5

[apache-auth]
enabled = true
logpath = /var/log/apache2/*error.log

[apache-badbots]
enabled = true
logpath = /var/log/apache2/*access.log
bantime = 24h
maxretry = 1

[apache-noscript]
enabled = true
logpath = /var/log/apache2/*error.log

[apache-botsearch]
enabled = true
logpath = /var/log/apache2/*error.log
bantime = 24h
maxretry = 2

[apache-vulnscan]
enabled = true
port = http,https
logpath = /var/log/apache2/*access.log
filter = apache-vulnscan
bantime = 48h
findtime = 1h
maxretry = 3

[apache-badagent]
enabled = true
port = http,https
logpath = /var/log/apache2/*access.log
filter = apache-badagent
bantime = 24h
findtime = 10m
maxretry = 1
EOF

  # Filtre personnalisé pour scanners de vulnérabilités
  # Note: %% est requis pour échapper % dans les fichiers fail2ban
  cat >/etc/fail2ban/filter.d/apache-vulnscan.conf <<'FILTEREOF'
[Definition]
# Détection des scanners de vulnérabilités et tentatives d'exploitation
failregex = ^<HOST> -.*"(GET|POST|HEAD).*(wp-login|wp-admin|wp-content|wp-includes|xmlrpc\.php|\.env|\.git|config\.php|phpinfo|phpmyadmin|pma|adminer|\.sql|\.bak|shell|eval\(|base64_decode|/etc/passwd|\.\.\/|%%2e%%2e|%%00|<script|\.asp|\.aspx|cgi-bin|\.cgi|myadmin|mysql|setup\.php|install\.php).*".*$
            ^<HOST> -.*"(GET|POST).*(union.*select|concat\(|information_schema|load_file|into.*outfile|benchmark\().*".*$
            ^<HOST> -.*"(GET|POST|OPTIONS|PUT|DELETE).*" 400 .*$
ignoreregex =
FILTEREOF

  # Filtre pour User-Agents malveillants
  cat >/etc/fail2ban/filter.d/apache-badagent.conf <<'FILTEREOF'
[Definition]
# Détection des User-Agents de bots malveillants et scanners
failregex = ^<HOST> -.*".*".*(nikto|sqlmap|nmap|masscan|zgrab|censys|shodan|nuclei|dirbuster|gobuster|wfuzz|ffuf|burp|acunetix|nessus|openvas|w3af|arachni|skipfish|wpscan|joomscan|droopescan|hydra|medusa).*$
          ^<HOST> -.*".*".*(python-requests/|python-urllib|curl/|wget/|libwww-perl|lwp-trivial|Go-http-client|Java/|Ruby|Scrapy|HttpClient|okhttp).*$
          ^<HOST> -.*"-" "-"$
ignoreregex = ^<HOST> -.*".*".*(Googlebot|bingbot|Baiduspider|YandexBot|DuckDuckBot|facebookexternalhit|Twitterbot|LinkedInBot|WhatsApp|Slackbot|TelegramBot).*$
FILTEREOF
  systemctl enable --now fail2ban
  fail2ban-client reload
  log "Fail2ban actif (SSH + filtres Apache)."
fi
