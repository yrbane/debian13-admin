#!/usr/bin/env bash
# lib/install-base.sh — Locales, hostname, SSH, UFW, GeoIP, Fail2ban
# Sourcé par debian13-server.sh — Dépend de: lib/core.sh, lib/constants.sh, lib/helpers.sh, lib/config.sh
#
# Couche fondation du serveur : tout ce qui doit être configuré avant les
# services applicatifs (Apache, MariaDB, etc.). L'ordre d'exécution suit
# une logique de dépendances :
#
#   1) Locales/hostname  → identité du serveur (nécessaire pour les certificats)
#   2) SSH hardening     → premier rempart, à sécuriser immédiatement
#   2b) LLMNR/mDNS off  → fermer les protocoles de découverte inutiles sur un serveur
#   3) UFW + GeoIP       → périmètre réseau (deny-all + whitelist explicite)
#   4) Fail2ban          → détection/réponse aux attaques brute-force
#
# Philosophie sécurité :
#   On applique le principe de moindre privilège à chaque couche. Un attaquant
#   qui franchit Fail2ban se heurte à UFW, puis à SSH key-only, puis à
#   l'absence de root login. La défense en profondeur est cumulative.

# ---------------------------------- 1) Locales & hostname ------------------------------
# On active fr_FR.UTF-8 + les variantes ISO pour la compatibilité avec certains
# outils système (cron, logwatch) qui formatent les dates en locale C ou ISO.

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
# Stratégie SSH :
#   - Authentification par clé uniquement (pas de mot de passe, pas de keyboard-interactive)
#   - Port non standard (défaut 65222) → réduit le bruit des scans automatisés de 90%+
#   - Algorithmes post-quantiques : sntrup761x25519-sha512 protège contre les attaques
#     "store now, decrypt later" où un adversaire enregistre le trafic chiffré aujourd'hui
#     pour le déchiffrer quand des ordinateurs quantiques seront disponibles
#   - AllowUsers restreint l'accès à un seul compte (ADMIN_USER)
#   - PermitRootLogin=no + nettoyage des clés root → même si root avait des clés,
#     elles deviennent inutilisables (défense en profondeur)
#   - LoginGraceTime=20s + MaxAuthTries=3 → limite l'exposition pendant l'auth
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
# LLMNR (Link-Local Multicast Name Resolution, port 5355) et mDNS (port 5353)
# sont des protocoles de découverte réseau pour les postes de travail.
# Sur un serveur dédié, ils n'ont aucune utilité et offrent une surface d'attaque
# supplémentaire (empoisonnement de noms, rebinding DNS). On les désactive via
# un drop-in systemd-resolved (priorité 90 = après les réglages par défaut).
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
# Politique : deny-all par défaut + whitelist explicite des ports nécessaires.
# On n'ouvre que SSH (port custom), HTTP (80, nécessaire pour ACME HTTP-01)
# et HTTPS (443). Tout le reste est silencieusement droppé.
#
# L'egress filtering (optionnel) restreint aussi les connexions sortantes :
# seuls DNS (53), HTTP/HTTPS (80/443), SMTP (25/587), NTP (123) sont autorisés.
# Cela empêche un processus compromis de communiquer avec un C2 sur un port exotique.
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
  if ${EGRESS_FILTER:-false}; then
    deploy_egress_rules
  fi
fi

# ---------------------------------- 3b) GeoIP Block ------------------------------------
# Principe : un serveur européen recevant 0% de trafic légitime depuis certaines
# zones géographiques peut bloquer ces plages IP au niveau kernel (ipset + iptables).
# Résultat typique : -70% de bruit dans les logs, -90% de scans automatisés.
#
# Implémentation :
#   - ipset hash:net stocke efficacement des milliers de CIDR en mémoire kernel
#   - La règle iptables (via ufw before.rules) droppe AVANT la table NAT → zéro overhead
#   - Le swap atomique (create new → populate → swap → destroy old) évite tout downtime
#   - Mise à jour hebdomadaire via cron (les plages IP changent, ipdeny.com les publie)
#
# Attention : ce blocage est géographique, pas chirurgical. Si vous avez des
# utilisateurs légitimes dans ces zones, désactivez GEOIP_BLOCK dans le .conf.
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
# Fail2ban surveille les logs en temps réel et bannit (via iptables) les IPs
# qui déclenchent des patterns d'attaque. Architecture en 3 niveaux :
#
#   Niveau 1 — Filtres standards (ssh, apache-auth, apache-badbots)
#     Détection d'échecs d'authentification, bots connus, scans de scripts.
#     Paramètres modérés : 5 tentatives en 10 min → ban 1h.
#
#   Niveau 2 — Filtres personnalisés (vulnscan, badagent)
#     Regex ciblant les scanners automatisés (nikto, sqlmap, zgrab...) et les
#     URLs de vulnérabilités courantes (wp-admin sur un serveur sans WordPress).
#     Paramètres agressifs : 1-3 tentatives → ban 24-48h.
#
#   Niveau 3 — Filtres étendus (deploy_fail2ban_extended)
#     POST flood, credential stuffing, ban progressif (récidive).
#     Le ban progressif multiplie la durée à chaque récidive (1h → 24h → 7j).
#
# Les TRUSTED_IPS sont exclues pour éviter de se bannir soi-même pendant le dev.
# Le backend systemd (au lieu de polling) est plus efficace sur Debian 13.
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

  # Filtre personnalisé : scanners de vulnérabilités
  # Cible les URLs typiques des outils automatisés (wp-admin, .env, phpinfo,
  # SQLi patterns). La 3e regex attrape les requêtes 400 (Bad Request) qui
  # indiquent souvent un outil qui forge des requêtes malformées.
  cat >/etc/fail2ban/filter.d/apache-vulnscan.conf <<'FILTEREOF'
[Definition]
# Détection des scanners de vulnérabilités et tentatives d'exploitation
failregex = ^<HOST> -.*"(GET|POST|HEAD).*(wp-login|wp-admin|wp-content|wp-includes|xmlrpc\.php|\.env|\.git|config\.php|phpinfo|phpmyadmin|pma|adminer|\.sql|\.bak|shell|eval\(|base64_decode|/etc/passwd|\.\.\/|%%2e%%2e|%%00|<script|\.asp|\.aspx|cgi-bin|\.cgi|myadmin|mysql|setup\.php|install\.php).*".*$
            ^<HOST> -.*"(GET|POST).*(union.*select|concat\(|information_schema|load_file|into.*outfile|benchmark\().*".*$
            ^<HOST> -.*"(GET|POST|OPTIONS|PUT|DELETE).*" 400 .*$
ignoreregex =
FILTEREOF

  # Filtre User-Agents malveillants : deux catégories distinctes.
  # - Ligne 1 : outils de pentest nommés (nikto, sqlmap, nuclei, burp...)
  # - Ligne 2 : clients HTTP génériques souvent utilisés par des scripts (python-requests, curl/)
  # - Ligne 3 : requêtes sans User-Agent ni Referer (bots primitifs)
  # L'ignoreregex protège les bots légitimes (Googlebot, bingbot, etc.).
  cat >/etc/fail2ban/filter.d/apache-badagent.conf <<'FILTEREOF'
[Definition]
# Détection des User-Agents de bots malveillants et scanners
failregex = ^<HOST> -.*".*".*(nikto|sqlmap|nmap|masscan|zgrab|censys|shodan|nuclei|dirbuster|gobuster|wfuzz|ffuf|burp|acunetix|nessus|openvas|w3af|arachni|skipfish|wpscan|joomscan|droopescan|hydra|medusa).*$
          ^<HOST> -.*".*".*(python-requests/|python-urllib|curl/|wget/|libwww-perl|lwp-trivial|Go-http-client|Java/|Ruby|Scrapy|HttpClient|okhttp).*$
          ^<HOST> -.*"-" "-"$
ignoreregex = ^<HOST> -.*".*".*(Googlebot|bingbot|Baiduspider|YandexBot|DuckDuckBot|facebookexternalhit|Twitterbot|LinkedInBot|WhatsApp|Slackbot|TelegramBot).*$
FILTEREOF
  # Filtres étendus (POST flood, credential stuffing, ban progressif)
  deploy_fail2ban_extended

  systemctl enable --now fail2ban
  fail2ban-client reload
  log "Fail2ban actif (SSH + filtres Apache + protection étendue)."
fi
