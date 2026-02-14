#!/usr/bin/env bash
# lib/constants.sh — Constantes readonly (chemins, seuils, versions, patterns)
# Sourcé par debian13-server.sh

# Espace disque & versions
readonly MIN_DISK_KB=2097152          # 2 Go minimum d'espace libre
readonly NVM_VERSION="v0.40.1"
readonly DKIM_KEY_BITS=2048
readonly CONFIG_VERSION=2

# Timeouts (secondes)
readonly CURL_TIMEOUT=5
readonly DNS_TIMEOUT=3
readonly CURL_TIMEOUT_SHORT=2
readonly PING_TIMEOUT=2

# Seuils de rétention (jours)
readonly CLAMAV_LOG_RETENTION_DAYS=180
readonly RKHUNTER_LOG_RETENTION_DAYS=30
readonly AIDE_LOG_RETENTION_DAYS=30
readonly SSL_WARN_DAYS=30
readonly DB_FRESH_DAYS=7
readonly DB_STALE_DAYS=30

# Seuils système
readonly LOG_SIZE_WARN_MB=1000
readonly LOG_SIZE_FAIL_MB=5000

# Cron schedules
readonly CRON_CLAMAV="0 2 * * *"              # quotidien 2h00
readonly CRON_RKHUNTER="0 3 * * 0"            # hebdo dimanche 3h00
readonly CRON_AIDE="0 4 * * *"                # quotidien 4h00
readonly CRON_BLOCK_HACK="0 * * * *"            # toutes les heures
readonly CRON_UPDATES="0 7 * * 1"             # hebdo lundi 7h00
readonly CRON_AUDIT="0 7 * * 1"               # hebdo lundi 7h00

# Réseau
readonly OPENDKIM_PORT=8891
readonly PMA_ALIAS_HEX_LENGTH=4
readonly PMA_COOKIE_VALIDITY=1800             # 30 minutes

# GeoIP — listes de pays (Afrique 54 + Asie 49 = 103)
readonly GEOIP_COUNTRIES_AFRICA="dz ao bj bw bf bi cv cm cf td km cg cd ci dj eg gq er sz et ga gm gh gn gw ke ls lr ly mg mw ml mr mu ma mz na ne ng rw st sn sc sl so za ss sd tz tg tn ug zm zw"
readonly GEOIP_COUNTRIES_ASIA="af am az bh bd bt bn kh cn ge in id ir iq il jo kz kw kg la lb my mv mn mm np kp om pk ps ph qa ru sa sg kr lk sy tw tj th tl tr tm ae uz vn ye"
readonly GEOIP_COUNTRY_COUNT=103

# SSH hardening — algorithmes
readonly SSH_CIPHERS="chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes256-ctr"
readonly SSH_MACS="hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com"
readonly SSH_KEX="sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org"

# PHP — fonctions dangereuses à désactiver
readonly PHP_DISABLED_FUNCTIONS="exec,passthru,shell_exec,system,proc_open,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source"

# Patterns de détection (sécurité web)
readonly SUSPICIOUS_URL_PATTERNS='(wp-login|wp-admin|wp-content|wp-includes|xmlrpc\.php|\.env|\.git|phpinfo|phpmyadmin|pma|adminer|\.sql|\.bak|\.zip|\.tar|\.rar|shell|eval\(|base64|union.*select|concat\(|etc/passwd|\.\.\/|%2e%2e|<script|\.asp|\.aspx|cgi-bin|\.cgi)'
readonly BAD_BOT_AGENTS='(nikto|sqlmap|nmap|masscan|zgrab|census|shodan|curl/|wget/|python-requests|go-http|libwww|scanner|exploit|vulnerability|attack)'

# Chemins système
readonly SSHD_CONFIG="/etc/ssh/sshd_config"
readonly APACHE_ACCESS_LOG="/var/log/apache2/access.log"
readonly APACHE_ERROR_LOG="/var/log/apache2/error.log"
readonly MAIL_LOG="/var/log/mail.log"
readonly AUTH_LOG="/var/log/auth.log"
readonly MODSEC_CONFIG="/etc/modsecurity/modsecurity.conf"
readonly MODSEC_AUDIT_LOG="/var/log/apache2/modsec_audit.log"
readonly SUDO_LOG="/var/log/sudo.log"
readonly RESOLVED_DROPIN_DIR="/etc/systemd/resolved.conf.d"
readonly OVH_DNS_CREDENTIALS="/root/.ovh-dns.ini"
readonly OVH_API_ENDPOINT="ovh-eu"
readonly CERTBOT_DNS_PROPAGATION=60
readonly ERROR_PAGES_DIR="/var/www/error-pages"
readonly SCRIPTS_DIR="/root/scripts"
readonly WEB_USER="www-data"

# Couleurs HTML (charte Since & Co)
readonly HTML_COLOR_DARK="#142136"
readonly HTML_COLOR_ACCENT="#dc5c3b"
readonly HTML_COLOR_CYAN="#6bdbdb"
readonly HTML_COLOR_GREEN="#99c454"
