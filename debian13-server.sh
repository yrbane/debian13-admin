#!/usr/bin/env bash
# =======================================================================================
#  Bootstrap & Hardening Debian 13 (trixie) — OVH
#  Auteur : Seb 
#
#  DESCRIPTION (en français car documentation) :
#    - Script interactif, coloré, auto-documenté (--help) pour configurer et sécuriser
#      un serveur Debian 13 (trixie) chez OVH en partant d’une installation vierge.
#    - Tous les paramètres clés sont des variables, posées au démarrage.
#    - Possibilité de choisir les composants à installer (Apache/PHP, MariaDB, DKIM, etc.).
#
#  PRINCIPALES ACTIONS :
#    * Mises à jour système + correctifs sécurité automatiques
#    * Locales fr_FR complètes + fuseau Europe/Paris
#    * Hostname/FQDN + /etc/hosts
#    * SSH durci (clé uniquement), port configurable (par défaut 65222)
#    * UFW (politique stricte) + Fail2ban (SSH + filtres Apache)
#    * Apache + PHP + durcissement (headers/mod_security)
#    * MariaDB (hardening de base)
#    * Postfix (send-only) + OpenDKIM (sélecteur ‘mail’) pour mails signés
#    * Certbot (Let's Encrypt) pour HTTPS
#    * Outils dev : Git, Curl, build-essential, Node (nvm), Rust (rustup), Composer
#    * Confort shell : neofetch, fortune-mod, cowsay, lolcat, grc, (youtube-dl optionnel), p7zip/rar
#    * ClamAV (freshclam + service)
#    * .bashrc commun (tous utilisateurs) — coloré/fonctions/alias + fortune|cowsay|lolcat
#
#  REMARQUES DNS IMPORTANTES :
#    - Vos MX pointent chez OVH → le serveur N’ACCEPTE PAS d’email entrant (Postfix en loopback).
#      Il n’envoie que des mails sortants (alertes/cron/app) signés DKIM.
#    - Enregistrement wildcard suspect dans votre exemple : "*  IN A  42.44.139.193"
#      → Probablement une faute : "142.44.139.193".
#    - DKIM : sélecteur "mail" déjà publié (TXT long). La clé privée locale DOIT correspondre.
#      Le script NE REMPLACE PAS une clé existante. Si mismatch → régénérer clé & mettre à jour DNS.
#
#  USAGE RAPIDE :
#    sudo /root/bootstrap.sh
#    sudo /root/bootstrap.sh --noninteractive    # passe en mode non interactif (utilise défauts)
#    sudo /root/bootstrap.sh --help              # affiche l’aide détaillée
#
#  NOTE LÉGALE :
#    Exécuter en connaissance de cause. Sauvegardes automatiques des fichiers sensibles *.bak.
#
# =======================================================================================

set -Eeuo pipefail

# ---------------------------------- Couleurs & Logs (sortie jolie) ---------------------
if [[ -t 1 ]]; then
  RED="\e[31m"; GREEN="\e[32m"; YELLOW="\e[33m"; BLUE="\e[34m"; MAGENTA="\e[35m"; CYAN="\e[36m"; BOLD="\e[1m"; RESET="\e[0m"
else
  RED=""; GREEN=""; YELLOW=""; BLUE=""; MAGENTA=""; CYAN=""; BOLD=""; RESET=""
fi

log()     { printf "${GREEN}[+]${RESET} %b\n" "$*"; }
warn()    { printf "${YELLOW}[!]${RESET} %b\n" "$*"; }
err()     { printf "${RED}[✗]${RESET} %b\n" "$*" >&2; }
note()    { printf "${CYAN}[-]${RESET} %b\n" "$*"; }
section() { printf "\n${BOLD}${MAGENTA}==> %b${RESET}\n" "$*"; }
die()     { err "$1"; exit 1; }

# ---------------------------------- Constantes (chemins, seuils, versions) -----------
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

# Couleurs HTML (charte Since & Co)
readonly HTML_COLOR_DARK="#142136"
readonly HTML_COLOR_ACCENT="#dc5c3b"
readonly HTML_COLOR_CYAN="#6bdbdb"
readonly HTML_COLOR_GREEN="#99c454"

# ---------------------------------- Valeurs par défaut -------------------------------
HOSTNAME_FQDN_DEFAULT="example.com"
SSH_PORT_DEFAULT="65222"
ADMIN_USER_DEFAULT="debian"
DKIM_SELECTOR_DEFAULT="mail"
DKIM_DOMAIN_DEFAULT="example.com"
EMAIL_FOR_CERTBOT_DEFAULT="root@example.com"
TIMEZONE_DEFAULT="Europe/Paris"

# Répertoire et nom du script
SCRIPT_NAME="debian13-server"
SCRIPT_VERSION="1.2.3"
if [[ -n "${BASH_SOURCE[0]:-}" && "${BASH_SOURCE[0]}" != "bash" ]]; then
  SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
else
  # Exécution via pipe
  SCRIPT_DIR="/root/scripts"
fi

# Fichier de configuration (à côté du script, même nom avec .conf)
CONFIG_FILE="${SCRIPT_DIR}/${SCRIPT_NAME}.conf"

# ---------------------------------- Aide / usage --------------------------------------
show_help() {
  cat <<EOF
Bootstrap & Hardening Debian 13 (OVH)

USAGE:
  sudo ./bootstrap.sh [--noninteractive] [--help]

OPTIONS:
  --noninteractive    N'affiche pas les questions ; utilise les valeurs par défaut et installe ce qui est activé par défaut.
  --help              Affiche cette aide, la liste des composants et toutes les notes de sécurité/DNS.

PARAMÈTRES (posés au démarrage en mode interactif, sinon valeurs par défaut) :
  - HOSTNAME_FQDN (défaut: ${HOSTNAME_FQDN_DEFAULT})
  - SSH_PORT (défaut: ${SSH_PORT_DEFAULT})
  - ADMIN_USER (défaut: ${ADMIN_USER_DEFAULT})
  - DKIM_SELECTOR (défaut: ${DKIM_SELECTOR_DEFAULT})
  - DKIM_DOMAIN (défaut: ${DKIM_DOMAIN_DEFAULT})
  - EMAIL_FOR_CERTBOT (défaut: ${EMAIL_FOR_CERTBOT_DEFAULT})
  - TIMEZONE (défaut: ${TIMEZONE_DEFAULT})

COMPOSANTS INSTALLABLES (question par question) :
  - Locales fr_FR complètes
  - Durcissement SSH + port personnalisé
  - UFW (deny in, allow out) + Fail2ban
  - Apache + PHP + durcissements
  - MariaDB (hardening basique)
  - phpMyAdmin (URL sécurisée aléatoire)
  - Postfix send-only + OpenDKIM (signature DKIM sortante)
  - Certbot (Let's Encrypt) + intégration Apache
  - Outils dev (Git, Curl, build-essential)
  - Node.js via nvm (LTS)
  - Rust via rustup (stable)
  - Composer (global)
  - Confort shell (neofetch, fortune-mod, cowsay, lolcat, grc, zip/unzip, p7zip, unrar, beep, youtube-dl optionnel)
  - ClamAV (freshclam + daemon)
  - .bashrc commun pour tous les utilisateurs (avec bannière et aliases)

NOTES DNS & SÉCURITÉ :
  - Vos MX pointent chez OVH : le serveur n'écoute pas SMTP entrant (relay local désactivé).
  - SPF : votre entrée contient "a" → l'IP du A (142.44.139.193) est autorisée à émettre.
  - DKIM (sélecteur "mail") : vérifiez la correspondance clé publique/privée avec:
      opendkim-testkey -d <domaine> -s <selector> -x /etc/opendkim.conf
  - DMARC présent (p=quarantine) : conforme.
  - Wildcard A suspect: "* IN A 42.44.139.193" → corrigez en "142.44.139.193".

FICHIER DE CONFIGURATION :
  Après avoir répondu aux questions, un fichier .bootstrap.conf est créé à côté du script.
  Lors des exécutions suivantes, le script propose de réutiliser cette configuration.
  Pour forcer une nouvelle configuration, supprimez le fichier ou répondez 'n' à la question.

EXEMPLES :
  # Exécution standard (crée .bootstrap.conf après les questions)
  sudo ./bootstrap.sh

  # Relance rapide (réutilise .bootstrap.conf si présent)
  sudo ./bootstrap.sh

  # Non interactif (valeurs par défaut, ignore .bootstrap.conf)
  sudo ./bootstrap.sh --noninteractive

  # Audit uniquement (vérifications + rapport email, sans installation)
  sudo ./bootstrap.sh --audit

EOF
}

# ---------------------------------- Arguments -----------------------------------------
NONINTERACTIVE=false
AUDIT_MODE=false
PIPED_MODE=false
for arg in "$@"; do
  case "$arg" in
    --noninteractive) NONINTERACTIVE=true ;;
    --audit) AUDIT_MODE=true ;;
    --help|-h) show_help; exit 0 ;;
    *) err "Option inconnue: $arg"; show_help; exit 1 ;;
  esac
done

# Détection exécution via pipe (curl | bash)
if [[ ! -t 0 ]]; then
  PIPED_MODE=true
  if [[ ! -f "/root/.bootstrap.conf" ]]; then
    echo ""
    echo -e "${RED}[✗] Erreur : Exécution via pipe détectée sans configuration existante.${RESET}"
    echo ""
    echo "Le mode interactif ne fonctionne pas via 'curl | bash'."
    echo ""
    echo "Solutions :"
    echo "  1. Téléchargez d'abord le script :"
    echo "     wget https://raw.githubusercontent.com/yrbane/debian13-web-server/main/install.sh"
    echo "     chmod +x install.sh && sudo ./install.sh"
    echo ""
    echo "  2. Ou si vous avez déjà une config, relancez la commande."
    echo ""
    exit 1
  fi
  # Config existante : forcer le mode non-interactif
  note "Exécution via pipe détectée - utilisation de la configuration existante."
  NONINTERACTIVE=true
fi

# ---------------------------------- Prérequis -----------------------------------------
require_root() { [[ $EUID -eq 0 ]] || die "Exécute ce script en root (sudo)."; }
require_root

if ! grep -qi 'debian' /etc/os-release; then
  warn "Distribution non détectée comme Debian. Le script cible Debian 13 (trixie)."
fi

# ---------------------------------- Vérifications pré-installation ----------------------
preflight_checks() {
  local errors=0

  # Espace disque minimum
  local avail_kb
  avail_kb=$(df / --output=avail | tail -1 | tr -d ' ')
  if (( avail_kb < MIN_DISK_KB )); then
    err "Espace disque insuffisant sur / : $(( avail_kb / 1024 )) Mo disponibles (minimum $(( MIN_DISK_KB / 1024 )) Mo)"
    ((errors++))
  fi

  # Connectivité réseau
  if ! curl -sf --max-time "$CURL_TIMEOUT" https://deb.debian.org/ >/dev/null 2>&1; then
    err "Pas de connectivité vers les dépôts Debian (https://deb.debian.org/)"
    ((errors++))
  fi

  # Résolution DNS
  if ! host -W "$DNS_TIMEOUT" deb.debian.org >/dev/null 2>&1; then
    warn "Résolution DNS lente ou absente — vérifiez /etc/resolv.conf"
  fi

  # Version Debian
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

# Ne lancer les vérifications que en mode installation (pas audit)
if [[ "${AUDIT_MODE:-false}" != "true" ]]; then
  preflight_checks
fi

# ---------------------------------- Entrées utilisateur -------------------------------
# (Code en anglais, documentation/texte en français)
prompt_default() {
  # $1=prompt, $2=default -> returns via echo
  local p="$1" d="${2:-}"
  local ans=""
  read -r -p "$(printf "${BOLD}${p}${RESET} [${d}]: ")" ans || true
  echo "${ans:-$d}"
}

prompt_yes_no() {
  # $1=question, $2=default(y/n)
  local q="$1" d="${2:-y}" ans=""
  local def="[Y/n]"; [[ "$d" =~ ^[Nn]$ ]] && def="[y/N]"
  read -r -p "$(printf "${BOLD}${q}${RESET} ${def}: ")" ans || true
  ans="${ans:-$d}"
  [[ "$ans" =~ ^[Yy]$ ]] && return 0 || return 1
}

# ---------------------------------- Config file ---------------------------------------
save_config() {
  cat >"$CONFIG_FILE" <<CONF
# Configuration générée le $(date '+%Y-%m-%d %H:%M:%S')
CONFIG_VERSION=${CONFIG_VERSION}
HOSTNAME_FQDN="${HOSTNAME_FQDN}"
SSH_PORT="${SSH_PORT}"
ADMIN_USER="${ADMIN_USER}"
DKIM_SELECTOR="${DKIM_SELECTOR}"
DKIM_DOMAIN="${DKIM_DOMAIN}"
EMAIL_FOR_CERTBOT="${EMAIL_FOR_CERTBOT}"
TIMEZONE="${TIMEZONE}"
INSTALL_LOCALES=${INSTALL_LOCALES}
INSTALL_SSH_HARDEN=${INSTALL_SSH_HARDEN}
INSTALL_UFW=${INSTALL_UFW}
GEOIP_BLOCK=${GEOIP_BLOCK}
INSTALL_FAIL2BAN=${INSTALL_FAIL2BAN}
INSTALL_APACHE_PHP=${INSTALL_APACHE_PHP}
PHP_DISABLE_FUNCTIONS=${PHP_DISABLE_FUNCTIONS}
INSTALL_MARIADB=${INSTALL_MARIADB}
INSTALL_PHPMYADMIN=${INSTALL_PHPMYADMIN}
INSTALL_POSTFIX_DKIM=${INSTALL_POSTFIX_DKIM}
INSTALL_CERTBOT=${INSTALL_CERTBOT}
INSTALL_DEVTOOLS=${INSTALL_DEVTOOLS}
INSTALL_NODE=${INSTALL_NODE}
INSTALL_RUST=${INSTALL_RUST}
INSTALL_PYTHON3=${INSTALL_PYTHON3}
INSTALL_COMPOSER=${INSTALL_COMPOSER}
INSTALL_SYMFONY=${INSTALL_SYMFONY}
INSTALL_SHELL_FUN=${INSTALL_SHELL_FUN}
INSTALL_YTDL=${INSTALL_YTDL}
INSTALL_CLAMAV=${INSTALL_CLAMAV}
INSTALL_RKHUNTER=${INSTALL_RKHUNTER}
INSTALL_LOGWATCH=${INSTALL_LOGWATCH}
INSTALL_SSH_ALERT=${INSTALL_SSH_ALERT}
INSTALL_AIDE=${INSTALL_AIDE}
INSTALL_MODSEC_CRS=${INSTALL_MODSEC_CRS}
SECURE_TMP=${SECURE_TMP}
INSTALL_BASHRC_GLOBAL=${INSTALL_BASHRC_GLOBAL}
CONF
  log "Configuration sauvegardée dans ${CONFIG_FILE}"
}

load_config() {
  if [[ -f "$CONFIG_FILE" ]]; then
    # Vérifier que le fichier ne contient que des affectations de variables attendues
    if grep -qvE '^\s*#|^\s*$|^[A-Z_]+=' "$CONFIG_FILE"; then
      warn "Le fichier de config ${CONFIG_FILE} contient des lignes suspectes :"
      grep -vE '^\s*#|^\s*$|^[A-Z_]+=' "$CONFIG_FILE" | head -5
      die "Corrigez le fichier de config ou supprimez-le pour le recréer."
    fi
    # Désactiver temporairement set -u pour gérer les anciennes configs
    set +u
    # shellcheck disable=SC1090
    source "$CONFIG_FILE"
    set -u
    # Vérifier la version du fichier de config
    local file_version="${CONFIG_VERSION:-1}"
    if (( file_version < CONFIG_VERSION )); then
      warn "Fichier de config version ${file_version}, version courante ${CONFIG_VERSION}. Migration automatique."
    fi
    return 0
  fi
  return 1
}

# Demande les nouvelles options manquantes dans un ancien fichier de config
ask_missing_options() {
  local has_missing=false
  local config_updated=false

  # Liste des nouvelles variables avec leurs prompts et valeurs par défaut
  # Format: "VARIABLE|prompt|default"
  local new_options=(
    "INSTALL_PYTHON3|Installer Python 3 + pip + venv ?|y"
    "INSTALL_RKHUNTER|Installer rkhunter (détection rootkits) ?|y"
    "INSTALL_LOGWATCH|Installer Logwatch (résumé quotidien des logs par email) ?|y"
    "INSTALL_SSH_ALERT|Activer les alertes email à chaque connexion SSH ?|y"
    "INSTALL_AIDE|Installer AIDE (détection modifications fichiers) ?|y"
    "INSTALL_MODSEC_CRS|Installer les règles OWASP CRS pour ModSecurity ?|y"
    "SECURE_TMP|Sécuriser /tmp (noexec, nosuid, nodev) ?|y"
    "INSTALL_BASHRC_GLOBAL|Déployer le .bashrc commun pour tous les utilisateurs ?|y"
    "PHP_DISABLE_FUNCTIONS|Désactiver les fonctions PHP dangereuses (exec, system...) ?|y"
  )

  # Vérifier quelles options sont manquantes
  for opt in "${new_options[@]}"; do
    local var_name="${opt%%|*}"
    if [[ -z "${!var_name:-}" ]]; then
      has_missing=true
      break
    fi
  done

  # Si des options manquent, les demander
  if $has_missing; then
    echo ""
    warn "Nouvelles options détectées (absentes de votre configuration) :"
    echo ""

    for opt in "${new_options[@]}"; do
      local var_name="${opt%%|*}"
      local rest="${opt#*|}"
      local prompt="${rest%%|*}"
      local default="${rest##*|}"

      # Si la variable n'est pas définie, poser la question
      if [[ -z "${!var_name:-}" ]]; then
        config_updated=true
        declare -g "$var_name=true"
        prompt_yes_no "$prompt" "$default" || declare -g "$var_name=false"
      fi
    done

    # Gérer TRUSTED_IPS (variable string, pas yes/no)
    if [[ -z "${TRUSTED_IPS:-}" ]]; then
      config_updated=true
      echo ""
      echo "IPs de confiance (whitelist fail2ban + ModSecurity)."
      echo "Exemples: votre IP maison, IP bureau. Séparées par des espaces."
      echo "Laisser vide pour ignorer."
      TRUSTED_IPS="$(prompt_default "IPs de confiance" "")"
    fi

    # Sauvegarder la config mise à jour
    if $config_updated; then
      echo ""
      save_config
    fi
  fi
}

show_config() {
  note "Configuration actuelle :"
  printf "  %-25s %s\n" "Hostname:" "$HOSTNAME_FQDN"
  printf "  %-25s %s\n" "Port SSH:" "$SSH_PORT"
  printf "  %-25s %s\n" "Admin:" "$ADMIN_USER"
  printf "  %-25s %s\n" "DKIM:" "${DKIM_SELECTOR}@${DKIM_DOMAIN}"
  printf "  %-25s %s\n" "Email Certbot:" "$EMAIL_FOR_CERTBOT"
  printf "  %-25s %s\n" "Timezone:" "$TIMEZONE"
  printf "  %-25s %s\n" "IPs de confiance:" "${TRUSTED_IPS:-aucune}"
  echo ""
  local comps=""
  $INSTALL_LOCALES && comps+="locales "
  $INSTALL_SSH_HARDEN && comps+="ssh "
  $INSTALL_UFW && comps+="ufw "
  $GEOIP_BLOCK && comps+="geoip-block "
  $INSTALL_FAIL2BAN && comps+="fail2ban "
  $INSTALL_APACHE_PHP && comps+="apache/php "
  $INSTALL_APACHE_PHP && ! $PHP_DISABLE_FUNCTIONS && comps+="(php-exec-ok) "
  $INSTALL_MARIADB && comps+="mariadb "
  $INSTALL_PHPMYADMIN && comps+="phpmyadmin "
  $INSTALL_POSTFIX_DKIM && comps+="postfix/dkim "
  $INSTALL_CERTBOT && comps+="certbot "
  $INSTALL_DEVTOOLS && comps+="devtools "
  $INSTALL_NODE && comps+="node "
  $INSTALL_RUST && comps+="rust "
  $INSTALL_PYTHON3 && comps+="python3 "
  $INSTALL_COMPOSER && comps+="composer "
  $INSTALL_SYMFONY && comps+="symfony "
  $INSTALL_SHELL_FUN && comps+="shell-fun "
  $INSTALL_YTDL && comps+="youtube-dl "
  $INSTALL_CLAMAV && comps+="clamav "
  $INSTALL_BASHRC_GLOBAL && comps+="bashrc "
  printf "  %-25s %s\n" "Composants:" "$comps"
}

# ---------------------------------- Questions -----------------------------------------
ask_all_questions() {
  section "Paramètres de base"
  HOSTNAME_FQDN="$(prompt_default "Nom d'hôte (FQDN)" "$HOSTNAME_FQDN_DEFAULT")"
  # Validation FQDN basique
  if [[ ! "$HOSTNAME_FQDN" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)+$ ]]; then
    warn "Le hostname '${HOSTNAME_FQDN}' ne semble pas être un FQDN valide (ex: server.example.com)"
  fi
  SSH_PORT="$(prompt_default 'Port SSH' "$SSH_PORT_DEFAULT")"
  ADMIN_USER="$(prompt_default 'Utilisateur admin (clé SSH déjà en place)' "$ADMIN_USER_DEFAULT")"
  DKIM_SELECTOR="$(prompt_default 'DKIM selector' "$DKIM_SELECTOR_DEFAULT")"
  DKIM_DOMAIN="$(prompt_default 'Domaine DKIM' "$DKIM_DOMAIN_DEFAULT")"
  EMAIL_FOR_CERTBOT="$(prompt_default "Email Let's Encrypt" "$EMAIL_FOR_CERTBOT_DEFAULT")"
  TIMEZONE="$(prompt_default 'Fuseau horaire' "$TIMEZONE_DEFAULT")"

  section "Choix des composants"
  INSTALL_LOCALES=true
  prompt_yes_no "Installer et activer toutes les locales fr_FR ?" "y" || INSTALL_LOCALES=false
  INSTALL_SSH_HARDEN=true
  prompt_yes_no "Durcir SSH (clé uniquement) et déplacer le port ?" "y" || INSTALL_SSH_HARDEN=false
  INSTALL_UFW=true
  prompt_yes_no "Configurer UFW (pare-feu) ?" "y" || INSTALL_UFW=false
  GEOIP_BLOCK=false
  if $INSTALL_UFW; then
    prompt_yes_no "Bloquer les connexions depuis Asie/Afrique (103 pays via GeoIP) ?" "n" && GEOIP_BLOCK=true
  fi
  INSTALL_FAIL2BAN=true
  prompt_yes_no "Installer Fail2ban ?" "y" || INSTALL_FAIL2BAN=false
  INSTALL_APACHE_PHP=true
  prompt_yes_no "Installer Apache + PHP + durcissements ?" "y" || INSTALL_APACHE_PHP=false
  PHP_DISABLE_FUNCTIONS=true
  if $INSTALL_APACHE_PHP; then
    prompt_yes_no "Désactiver les fonctions PHP dangereuses (exec, shell_exec, system...) ?" "y" || PHP_DISABLE_FUNCTIONS=false
  else
    PHP_DISABLE_FUNCTIONS=false
  fi
  INSTALL_MARIADB=true
  prompt_yes_no "Installer MariaDB (server+client) ?" "y" || INSTALL_MARIADB=false
  INSTALL_PHPMYADMIN=true
  prompt_yes_no "Installer phpMyAdmin ?" "y" || INSTALL_PHPMYADMIN=false
  INSTALL_POSTFIX_DKIM=true
  prompt_yes_no "Installer Postfix (send-only) + OpenDKIM ?" "y" || INSTALL_POSTFIX_DKIM=false
  INSTALL_CERTBOT=true
  prompt_yes_no "Installer Certbot (Let's Encrypt) + module Apache ?" "y" || INSTALL_CERTBOT=false
  INSTALL_DEVTOOLS=true
  prompt_yes_no "Installer Git/Curl/build-essential/grc ?" "y" || INSTALL_DEVTOOLS=false
  INSTALL_NODE=true
  prompt_yes_no "Installer Node.js via nvm (LTS) ?" "y" || INSTALL_NODE=false
  INSTALL_RUST=true
  prompt_yes_no "Installer Rust (rustup stable) ?" "y" || INSTALL_RUST=false
  INSTALL_PYTHON3=true
  prompt_yes_no "Installer Python 3 + pip + venv ?" "y" || INSTALL_PYTHON3=false
  INSTALL_COMPOSER=true
  prompt_yes_no "Installer Composer (global) ?" "y" || INSTALL_COMPOSER=false
  INSTALL_SYMFONY=false
  if $INSTALL_COMPOSER; then
    prompt_yes_no "Installer Symfony CLI ?" "y" && INSTALL_SYMFONY=true
  fi
  INSTALL_SHELL_FUN=true
  prompt_yes_no "Installer fastfetch, fortune-mod, cowsay, lolcat, grc, p7zip/zip/unzip, beep ?" "y" || INSTALL_SHELL_FUN=false
  INSTALL_YTDL=false
  prompt_yes_no "Installer youtube-dl ?" "n" && INSTALL_YTDL=true
  INSTALL_CLAMAV=true
  prompt_yes_no "Installer ClamAV (freshclam + daemon) ?" "y" || INSTALL_CLAMAV=false
  INSTALL_RKHUNTER=true
  prompt_yes_no "Installer rkhunter (détection rootkits) ?" "y" || INSTALL_RKHUNTER=false
  INSTALL_LOGWATCH=true
  prompt_yes_no "Installer Logwatch (résumé quotidien des logs par email) ?" "y" || INSTALL_LOGWATCH=false
  INSTALL_SSH_ALERT=true
  prompt_yes_no "Activer les alertes email à chaque connexion SSH ?" "y" || INSTALL_SSH_ALERT=false
  INSTALL_AIDE=true
  prompt_yes_no "Installer AIDE (détection modifications fichiers) ?" "y" || INSTALL_AIDE=false
  INSTALL_MODSEC_CRS=true
  prompt_yes_no "Installer les règles OWASP CRS pour ModSecurity ?" "y" || INSTALL_MODSEC_CRS=false
  SECURE_TMP=true
  prompt_yes_no "Sécuriser /tmp (noexec, nosuid, nodev) ?" "y" || SECURE_TMP=false
  INSTALL_BASHRC_GLOBAL=true
  prompt_yes_no "Déployer le .bashrc commun pour tous les utilisateurs ?" "y" || INSTALL_BASHRC_GLOBAL=false

  section "IPs de confiance (whitelist)"
  echo "IPs qui seront whitelistées dans fail2ban et ModSecurity."
  echo "Exemples: votre IP maison, IP bureau. Séparées par des espaces."
  echo "Laisser vide pour ignorer."
  TRUSTED_IPS="$(prompt_default "IPs de confiance" "${TRUSTED_IPS:-}")"

  save_config
}

if $AUDIT_MODE; then
  # Mode audit : charge la config silencieusement avec valeurs par défaut pour nouvelles options
  if [[ -f "$CONFIG_FILE" ]]; then
    load_config
    # Valeurs par défaut silencieuses pour le mode audit
    INSTALL_PYTHON3=${INSTALL_PYTHON3:-true}
    INSTALL_RKHUNTER=${INSTALL_RKHUNTER:-true}
    INSTALL_LOGWATCH=${INSTALL_LOGWATCH:-true}
    INSTALL_SSH_ALERT=${INSTALL_SSH_ALERT:-true}
    INSTALL_AIDE=${INSTALL_AIDE:-true}
    INSTALL_MODSEC_CRS=${INSTALL_MODSEC_CRS:-true}
    SECURE_TMP=${SECURE_TMP:-true}
    INSTALL_BASHRC_GLOBAL=${INSTALL_BASHRC_GLOBAL:-true}
    PHP_DISABLE_FUNCTIONS=${PHP_DISABLE_FUNCTIONS:-true}
    TRUSTED_IPS=${TRUSTED_IPS:-}
    INSTALL_SYMFONY=${INSTALL_SYMFONY:-false}
    GEOIP_BLOCK=${GEOIP_BLOCK:-false}
  else
    die "Mode audit : fichier de configuration ${CONFIG_FILE} requis. Exécutez d'abord le script normalement."
  fi
elif ! $NONINTERACTIVE; then
  # Vérifie si un fichier de config existe
  if [[ -f "$CONFIG_FILE" ]]; then
    section "Configuration existante détectée"
    load_config
    # Demander les nouvelles options si absentes
    ask_missing_options
    show_config
    echo ""
    if prompt_yes_no "Utiliser cette configuration ?" "y"; then
      log "Utilisation de la configuration existante."
    else
      ask_all_questions
    fi
  else
    ask_all_questions
  fi
else
  # Mode non-interactif
  if $PIPED_MODE && [[ -f "$CONFIG_FILE" ]]; then
    # Mode pipe avec config existante : charger la config + defaults pour nouvelles options
    load_config
    INSTALL_PYTHON3=${INSTALL_PYTHON3:-true}
    INSTALL_RKHUNTER=${INSTALL_RKHUNTER:-true}
    INSTALL_LOGWATCH=${INSTALL_LOGWATCH:-true}
    INSTALL_SSH_ALERT=${INSTALL_SSH_ALERT:-true}
    INSTALL_AIDE=${INSTALL_AIDE:-true}
    INSTALL_MODSEC_CRS=${INSTALL_MODSEC_CRS:-true}
    SECURE_TMP=${SECURE_TMP:-true}
    INSTALL_BASHRC_GLOBAL=${INSTALL_BASHRC_GLOBAL:-true}
    PHP_DISABLE_FUNCTIONS=${PHP_DISABLE_FUNCTIONS:-true}
    INSTALL_SYMFONY=${INSTALL_SYMFONY:-false}
    GEOIP_BLOCK=${GEOIP_BLOCK:-false}
    section "Configuration existante chargée (mode pipe)"
    show_config
  else
    # Mode non-interactif classique : utiliser les valeurs par défaut
    HOSTNAME_FQDN="$HOSTNAME_FQDN_DEFAULT"
    SSH_PORT="$SSH_PORT_DEFAULT"
    ADMIN_USER="$ADMIN_USER_DEFAULT"
    DKIM_SELECTOR="$DKIM_SELECTOR_DEFAULT"
    DKIM_DOMAIN="$DKIM_DOMAIN_DEFAULT"
    EMAIL_FOR_CERTBOT="$EMAIL_FOR_CERTBOT_DEFAULT"
    TIMEZONE="$TIMEZONE_DEFAULT"
    INSTALL_LOCALES=true
    INSTALL_SSH_HARDEN=true
    INSTALL_UFW=true
    GEOIP_BLOCK=false
    INSTALL_FAIL2BAN=true
    INSTALL_APACHE_PHP=true
    PHP_DISABLE_FUNCTIONS=true
    INSTALL_MARIADB=true
    INSTALL_PHPMYADMIN=true
    INSTALL_POSTFIX_DKIM=true
    INSTALL_CERTBOT=true
    INSTALL_DEVTOOLS=true
    INSTALL_NODE=true
    INSTALL_RUST=true
    INSTALL_PYTHON3=true
    INSTALL_COMPOSER=true
    INSTALL_SHELL_FUN=true
    INSTALL_YTDL=false
    INSTALL_CLAMAV=true
    INSTALL_RKHUNTER=true
    INSTALL_LOGWATCH=true
    INSTALL_SSH_ALERT=true
    INSTALL_AIDE=true
    INSTALL_MODSEC_CRS=true
    SECURE_TMP=true
    INSTALL_BASHRC_GLOBAL=true
  fi
fi

# Chemins/constantes dérivées (readonly après affectation)
readonly DKIM_KEYDIR="/etc/opendkim/keys/${DKIM_DOMAIN}"
readonly LOG_FILE="/var/log/bootstrap_ovh_debian13.log"
DEBIAN_FRONTEND=noninteractive
export DEBIAN_FRONTEND

# ---------------------------------- Fichiers temporaires & cleanup (#17, #18) ---------
declare -a _TMPFILES=()

# Crée un fichier temporaire sécurisé et l'enregistre pour le cleanup
mktempfile() {
  local suffix="${1:-.tmp}"
  local f
  f=$(mktemp --tmpdir "bootstrap-XXXXXX${suffix}")
  _TMPFILES+=("$f")
  echo "$f"
}

# Nettoyage automatique des fichiers temporaires à la sortie
cleanup_tmpfiles() {
  for f in "${_TMPFILES[@]:-}"; do
    [[ -f "$f" ]] && rm -f "$f"
  done
}
trap 'cleanup_tmpfiles; err "Erreur à la ligne $LINENO. Consulte le journal si nécessaire."' ERR EXIT

# ---------------------------------- Utilitaires ---------------------------------------
backup_file() {
  local f="$1"
  if [[ -f "$f" ]]; then
    local bak="${f}.$(date +%Y%m%d%H%M%S).bak"
    if ! cp -a "$f" "$bak"; then
      warn "Impossible de sauvegarder ${f} → ${bak}"
      return 1
    fi
  fi
}

# Exécute une commande en tant qu'utilisateur admin (pas root)
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

# Récupère le home de l'utilisateur admin
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

# (#11, #16) Installe des paquets avec retry et logging
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

# (#1) Gestion idempotente des cron jobs
# Usage: add_cron_job <grep_pattern> <cron_line> [comment]
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

# (#2) Déploie un script de monitoring (écriture + email + chmod + cron optionnel)
# Usage: deploy_script <path> <content> [cron_schedule] [cron_comment]
deploy_script() {
  local path="$1" content="$2" cron_schedule="${3:-}" cron_comment="${4:-}"
  local dir
  dir="$(dirname "$path")"
  mkdir -p "$dir"

  echo "$content" > "$path"
  sed -i "s|__EMAIL__|${EMAIL_FOR_CERTBOT}|g" "$path"
  chmod +x "$path"

  if [[ -n "$cron_schedule" ]]; then
    local cron_line="${cron_schedule} ${path} >/dev/null 2>&1"
    local script_name
    script_name="$(basename "$path")"
    add_cron_job "$script_name" "$cron_line" "$cron_comment"
  fi
}

# (#5) Vérifie si un service est actif (pour CLI et HTML)
# Usage: check_service_active <service_name> <label> [mode: cli|html]
check_service_active() {
  local service="$1" label="$2" mode="${3:-cli}"
  if systemctl is-active --quiet "$service"; then
    if [[ "$mode" == "html" ]]; then
      add_html_check ok "${label} : actif"
    else
      check_ok "${label} : actif"
    fi
    return 0
  else
    if [[ "$mode" == "html" ]]; then
      add_html_check warn "${label} : inactif"
    else
      check_fail "${label} : inactif"
    fi
    return 1
  fi
}

# (#6) Vérifie la fraîcheur d'une base de données (ClamAV, rkhunter, AIDE)
# Usage: check_db_freshness <file_or_dir> <label> <fresh_days> <stale_days> [mode: cli|html]
check_db_freshness() {
  local target="$1" label="$2" fresh="${3:-$DB_FRESH_DAYS}" stale="${4:-$DB_STALE_DAYS}" mode="${5:-cli}"
  local db_epoch age_days

  # Obtenir le timestamp de la cible
  if [[ -d "$target" ]]; then
    db_epoch=$(find "$target" -type f -printf '%T@\n' 2>/dev/null | sort -n | tail -1)
  elif [[ -f "$target" ]]; then
    db_epoch=$(stat -c %Y "$target" 2>/dev/null)
  else
    if [[ "$mode" == "html" ]]; then
      add_html_check warn "${label} : base non trouvée"
    else
      check_warn "${label} : base non trouvée"
    fi
    return 1
  fi

  [[ -z "$db_epoch" ]] && return 1
  db_epoch=${db_epoch%.*}  # Supprime la partie décimale éventuelle
  age_days=$(( ($(date +%s) - db_epoch) / 86400 ))

  local status msg
  if (( age_days <= fresh )); then
    status="ok"; msg="${label} : base à jour (${age_days} jour(s))"
  elif (( age_days <= stale )); then
    status="warn"; msg="${label} : base date de ${age_days} jours"
  else
    status="fail"; msg="${label} : base obsolète (${age_days} jours)"
  fi

  if [[ "$mode" == "html" ]]; then
    add_html_check "$status" "$msg"
  else
    case "$status" in
      ok)   check_ok "$msg" ;;
      warn) check_warn "$msg" ;;
      fail) check_fail "$msg" ;;
    esac
  fi
}

# ================================== MODULES D'INSTALLATION ============================
# Chaque module est une fonction install_<nom>() suivant le principe SRP (Single Responsibility)
#
# Registre déclaratif des modules (#8 — Open/Closed Principle) :
#   FLAG                  → FONCTION / SECTION
#   INSTALL_LOCALES       → install_locales()
#   (toujours)            → install_hostname()
#   INSTALL_SSH_HARDEN    → section 2) SSH durci
#   INSTALL_UFW           → section 3) UFW + 3b) GeoIP
#   INSTALL_FAIL2BAN      → section 4) Fail2ban
#   INSTALL_APACHE_PHP    → section 5) Apache/PHP + pages d'erreur
#   INSTALL_MARIADB       → section 6) MariaDB
#   INSTALL_PHPMYADMIN    → section 6b) phpMyAdmin
#   INSTALL_POSTFIX_DKIM  → section 7) Postfix + OpenDKIM
#   INSTALL_CERTBOT       → section 8) Certbot
#   INSTALL_DEVTOOLS      → section 9) Dev tools
#   INSTALL_NODE          → section 10) Node (nvm)
#   INSTALL_RUST          → section 11) Rust
#   INSTALL_PYTHON3       → section 11b) Python 3
#   INSTALL_COMPOSER      → section 12) Composer
#   INSTALL_SYMFONY       → section 12b) Symfony CLI
#   INSTALL_SHELL_FUN     → section 13) Shell fun
#   INSTALL_CLAMAV        → section 14) ClamAV
#   INSTALL_RKHUNTER      → section 14b) rkhunter
#   INSTALL_LOGWATCH      → section 14c) Logwatch
#   INSTALL_SSH_ALERT     → section 14d) SSH Alert
#   INSTALL_AIDE          → section 14e) AIDE
#   INSTALL_MODSEC_CRS    → section 14f) ModSecurity CRS
#   SECURE_TMP            → section 14g) Secure /tmp
#   INSTALL_BASHRC_GLOBAL → section 16) .bashrc global
#
# Pour ajouter un nouveau module :
#   1. Ajouter le flag INSTALL_XXX dans save_config/ask_all_questions
#   2. Créer la fonction install_xxx() ou le bloc if $INSTALL_XXX
#   3. Ajouter la vérification dans la section VÉRIFICATIONS
#   4. Mettre à jour ce registre

install_locales() {
  section "Locales fr_FR"
  apt_install locales tzdata
  sed -i 's/^# *fr_FR.UTF-8 UTF-8/fr_FR.UTF-8 UTF-8/' /etc/locale.gen
  grep -q '^fr_FR ISO-8859-1' /etc/locale.gen || echo 'fr_FR ISO-8859-1' >> /etc/locale.gen
  grep -q '^fr_FR@euro ISO-8859-15' /etc/locale.gen || echo 'fr_FR@euro ISO-8859-15' >> /etc/locale.gen
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
    {
      echo "127.0.0.1   localhost"
      echo "${IP4}   ${HOSTNAME_FQDN} ${HOSTNAME_FQDN%%.*}"
    } > /etc/hosts
  fi
  log "Hostname défini sur ${HOSTNAME_FQDN}"
}

# ================================== INSTALLATION ======================================
# Skip toute l'installation en mode audit
if ! $AUDIT_MODE; then

# ---------------------------------- 0) APT & locales ----------------------------------
apt_update_upgrade
$INSTALL_LOCALES && install_locales

# ---------------------------------- 1) Hostname/hosts ---------------------------------
install_hostname

# ---------------------------------- 2) SSH durci --------------------------------------
if $INSTALL_SSH_HARDEN; then
  section "SSH durci (clé uniquement) + port ${SSH_PORT}"
  apt_install openssh-server
  backup_file /etc/ssh/sshd_config
  cat >/etc/ssh/sshd_config <<EOF
Include /etc/ssh/sshd_config.d/*.conf
Port ${SSH_PORT}
Protocol 2
AddressFamily any
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
PubkeyAuthentication yes
AllowUsers ${ADMIN_USER}
HostKey /etc/ssh/ssh_host_ed25519_key
HostKey /etc/ssh/ssh_host_rsa_key
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes256-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
# Post-quantum hybrid (protection contre "store now, decrypt later")
KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org
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
fi

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
  done < <(curl -s "$url" 2>/dev/null)
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
  log "Blocage GeoIP activé. $(ipset list geoip_blocked | grep -c '^[0-9]') plages bloquées."
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
</IfModule>
EOF
  a2enconf security-headers
  sed -ri 's/^ServerTokens .*/ServerTokens Prod/; s/^ServerSignature .*/ServerSignature Off/' /etc/apache2/conf-available/security.conf
  # PHP hardening
  for INI in /etc/php/*/apache2/php.ini /etc/php/*/cli/php.ini /etc/php/*/fpm/php.ini; do
    [[ -f "$INI" ]] || continue
    backup_file "$INI"
    # Activer opcache
    sed -ri 's/^;?\s*opcache\.enable\s*=.*/opcache.enable=1/' "$INI"
    # Masquer la version PHP
    sed -ri 's/^;?\s*expose_php\s*=.*/expose_php = Off/' "$INI"
    # Désactiver l'affichage des erreurs en production
    sed -ri 's/^;?\s*display_errors\s*=.*/display_errors = Off/' "$INI"
    # Désactiver les erreurs de startup
    sed -ri 's/^;?\s*display_startup_errors\s*=.*/display_startup_errors = Off/' "$INI"
    # Logger les erreurs au lieu de les afficher
    sed -ri 's/^;?\s*log_errors\s*=.*/log_errors = On/' "$INI"
    # Désactiver les fonctions dangereuses (optionnel)
    if $PHP_DISABLE_FUNCTIONS; then
      if ! grep -q "^disable_functions.*exec" "$INI"; then
        sed -ri 's/^;?\s*disable_functions\s*=.*/disable_functions = exec,passthru,shell_exec,system,proc_open,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source/' "$INI"
      fi
    fi
  done
  systemctl restart apache2
  log "Apache/PHP installés et durcis."

  # ---------------------------------- Pages d'erreur personnalisées ---------------------
  section "Pages d'erreur personnalisées"

  mkdir -p /var/www/error-pages

  # Fichier de configuration des IPs de confiance (pour debug)
  cat >/var/www/error-pages/trusted-ips.php <<'TRUSTEDIPS'
<?php
// IPs de confiance - générées par install.sh
// Ces IPs verront les informations de debug sur les pages d'erreur
$TRUSTED_IPS = [
__TRUSTED_IPS_ARRAY__
];

function is_trusted_ip() {
    global $TRUSTED_IPS;
    $client_ip = $_SERVER['REMOTE_ADDR'] ?? '';

    // Vérifier les headers de proxy
    if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $ips = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
        $client_ip = trim($ips[0]);
    }

    return in_array($client_ip, $TRUSTED_IPS);
}
TRUSTEDIPS

  # Générer le tableau PHP des IPs de confiance
  if [[ -n "${TRUSTED_IPS:-}" ]]; then
    TRUSTED_IPS_PHP=""
    for ip in $TRUSTED_IPS; do
      TRUSTED_IPS_PHP+="    '${ip}',\n"
    done
    sed -i "s|__TRUSTED_IPS_ARRAY__|${TRUSTED_IPS_PHP}|" /var/www/error-pages/trusted-ips.php
  else
    sed -i "s|__TRUSTED_IPS_ARRAY__|    // Aucune IP configurée|" /var/www/error-pages/trusted-ips.php
  fi

  # Template principal des pages d'erreur
  cat >/var/www/error-pages/error.php <<'ERRORPAGE'
<?php
require_once __DIR__ . '/trusted-ips.php';

// Récupérer le code d'erreur depuis l'URL ou la variable d'environnement
$error_code = $_GET['code'] ?? $_SERVER['REDIRECT_STATUS'] ?? 500;
$error_code = (int) $error_code;

// Messages d'erreur
$errors = [
    400 => ['title' => 'Requête invalide', 'message' => 'Le serveur n\'a pas pu comprendre votre requête.', 'icon' => '🚫'],
    401 => ['title' => 'Authentification requise', 'message' => 'Vous devez vous identifier pour accéder à cette ressource.', 'icon' => '🔐'],
    403 => ['title' => 'Accès interdit', 'message' => 'Vous n\'avez pas les permissions pour accéder à cette ressource.', 'icon' => '⛔'],
    404 => ['title' => 'Page introuvable', 'message' => 'La page que vous recherchez n\'existe pas ou a été déplacée.', 'icon' => '🔍'],
    500 => ['title' => 'Erreur serveur', 'message' => 'Une erreur interne s\'est produite. Nos équipes sont informées.', 'icon' => '⚙️'],
    502 => ['title' => 'Passerelle incorrecte', 'message' => 'Le serveur a reçu une réponse invalide d\'un serveur en amont.', 'icon' => '🔗'],
    503 => ['title' => 'Service indisponible', 'message' => 'Le serveur est temporairement indisponible. Réessayez dans quelques instants.', 'icon' => '🔧'],
];

$error = $errors[$error_code] ?? $errors[500];
$is_trusted = is_trusted_ip();

http_response_code($error_code);
?>
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="robots" content="noindex, nofollow">
    <title>Erreur <?= $error_code ?> - <?= htmlspecialchars($error['title']) ?></title>
    <style>
        :root {
            --primary: #2563eb;
            --danger: #dc2626;
            --warning: #f59e0b;
            --bg: #f8fafc;
            --card: #ffffff;
            --text: #1e293b;
            --muted: #64748b;
            --border: #e2e8f0;
        }

        @media (prefers-color-scheme: dark) {
            :root {
                --bg: #0f172a;
                --card: #1e293b;
                --text: #f1f5f9;
                --muted: #94a3b8;
                --border: #334155;
            }
        }

        * { box-sizing: border-box; margin: 0; padding: 0; }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: var(--bg);
            color: var(--text);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 1rem;
            line-height: 1.6;
        }

        .container {
            max-width: 600px;
            width: 100%;
        }

        .card {
            background: var(--card);
            border-radius: 1rem;
            box-shadow: 0 4px 6px -1px rgb(0 0 0 / 0.1), 0 2px 4px -2px rgb(0 0 0 / 0.1);
            overflow: hidden;
        }

        .header {
            background: linear-gradient(135deg, var(--danger) 0%, #991b1b 100%);
            color: white;
            padding: 2rem;
            text-align: center;
        }

        .error-code {
            font-size: 5rem;
            font-weight: 800;
            line-height: 1;
            opacity: 0.9;
        }

        .error-icon {
            font-size: 3rem;
            margin-bottom: 0.5rem;
        }

        .content {
            padding: 2rem;
        }

        h1 {
            font-size: 1.5rem;
            margin-bottom: 0.5rem;
            color: var(--text);
        }

        .message {
            color: var(--muted);
            margin-bottom: 1.5rem;
        }

        .btn {
            display: inline-block;
            padding: 0.75rem 1.5rem;
            background: var(--primary);
            color: white;
            text-decoration: none;
            border-radius: 0.5rem;
            font-weight: 500;
            transition: opacity 0.2s;
        }

        .btn:hover { opacity: 0.9; }

        .debug {
            margin-top: 2rem;
            padding-top: 1.5rem;
            border-top: 1px solid var(--border);
        }

        .debug-title {
            font-size: 0.875rem;
            font-weight: 600;
            color: var(--warning);
            margin-bottom: 1rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        .debug-grid {
            display: grid;
            gap: 0.5rem;
            font-size: 0.8rem;
        }

        .debug-item {
            display: grid;
            grid-template-columns: 140px 1fr;
            gap: 0.5rem;
            padding: 0.5rem;
            background: var(--bg);
            border-radius: 0.25rem;
        }

        .debug-key {
            font-weight: 600;
            color: var(--muted);
        }

        .debug-value {
            word-break: break-all;
            font-family: monospace;
        }

        .footer {
            text-align: center;
            padding: 1rem 2rem 2rem;
            color: var(--muted);
            font-size: 0.75rem;
        }

        @media (max-width: 480px) {
            .error-code { font-size: 4rem; }
            .debug-item { grid-template-columns: 1fr; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="card">
            <div class="header">
                <div class="error-icon"><?= $error['icon'] ?></div>
                <div class="error-code"><?= $error_code ?></div>
            </div>

            <div class="content">
                <h1><?= htmlspecialchars($error['title']) ?></h1>
                <p class="message"><?= htmlspecialchars($error['message']) ?></p>

                <a href="/" class="btn">← Retour à l'accueil</a>

                <?php if ($is_trusted): ?>
                <div class="debug">
                    <div class="debug-title">
                        🔧 Informations de debug (IP de confiance)
                    </div>
                    <div class="debug-grid">
                        <div class="debug-item">
                            <span class="debug-key">Votre IP</span>
                            <span class="debug-value"><?= htmlspecialchars($_SERVER['REMOTE_ADDR'] ?? 'N/A') ?></span>
                        </div>
                        <div class="debug-item">
                            <span class="debug-key">URI demandée</span>
                            <span class="debug-value"><?= htmlspecialchars($_SERVER['REQUEST_URI'] ?? 'N/A') ?></span>
                        </div>
                        <div class="debug-item">
                            <span class="debug-key">Méthode</span>
                            <span class="debug-value"><?= htmlspecialchars($_SERVER['REQUEST_METHOD'] ?? 'N/A') ?></span>
                        </div>
                        <div class="debug-item">
                            <span class="debug-key">Referer</span>
                            <span class="debug-value"><?= htmlspecialchars($_SERVER['HTTP_REFERER'] ?? 'Direct') ?></span>
                        </div>
                        <div class="debug-item">
                            <span class="debug-key">User-Agent</span>
                            <span class="debug-value"><?= htmlspecialchars($_SERVER['HTTP_USER_AGENT'] ?? 'N/A') ?></span>
                        </div>
                        <div class="debug-item">
                            <span class="debug-key">Serveur</span>
                            <span class="debug-value"><?= htmlspecialchars($_SERVER['SERVER_NAME'] ?? 'N/A') ?></span>
                        </div>
                        <div class="debug-item">
                            <span class="debug-key">Port</span>
                            <span class="debug-value"><?= htmlspecialchars($_SERVER['SERVER_PORT'] ?? 'N/A') ?></span>
                        </div>
                        <div class="debug-item">
                            <span class="debug-key">Protocole</span>
                            <span class="debug-value"><?= htmlspecialchars($_SERVER['SERVER_PROTOCOL'] ?? 'N/A') ?></span>
                        </div>
                        <div class="debug-item">
                            <span class="debug-key">Document Root</span>
                            <span class="debug-value"><?= htmlspecialchars($_SERVER['DOCUMENT_ROOT'] ?? 'N/A') ?></span>
                        </div>
                        <div class="debug-item">
                            <span class="debug-key">Script</span>
                            <span class="debug-value"><?= htmlspecialchars($_SERVER['SCRIPT_FILENAME'] ?? 'N/A') ?></span>
                        </div>
                        <div class="debug-item">
                            <span class="debug-key">Timestamp</span>
                            <span class="debug-value"><?= date('Y-m-d H:i:s T') ?></span>
                        </div>
                        <?php if (!empty($_SERVER['REDIRECT_URL'])): ?>
                        <div class="debug-item">
                            <span class="debug-key">Redirect URL</span>
                            <span class="debug-value"><?= htmlspecialchars($_SERVER['REDIRECT_URL']) ?></span>
                        </div>
                        <?php endif; ?>
                        <?php if (!empty($_SERVER['REDIRECT_QUERY_STRING'])): ?>
                        <div class="debug-item">
                            <span class="debug-key">Query String</span>
                            <span class="debug-value"><?= htmlspecialchars($_SERVER['REDIRECT_QUERY_STRING']) ?></span>
                        </div>
                        <?php endif; ?>
                    </div>
                </div>
                <?php endif; ?>
            </div>

            <div class="footer">
                <?= htmlspecialchars($_SERVER['SERVER_SOFTWARE'] ?? 'Web Server') ?>
            </div>
        </div>
    </div>
</body>
</html>
ERRORPAGE

  # Configuration Apache pour les pages d'erreur
  cat >/etc/apache2/conf-available/custom-error-pages.conf <<'ERRORCONF'
# Pages d'erreur personnalisées
Alias /error-pages /var/www/error-pages

<Directory /var/www/error-pages>
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
  chown -R www-data:www-data /var/www/error-pages
  chmod 644 /var/www/error-pages/*.php

  log "Pages d'erreur personnalisées installées dans /var/www/error-pages/"
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
  note "Demande manuelle du certificat quand DNS OK:"
  note "  certbot --apache -d ${HOSTNAME_FQDN} -d www.${HOSTNAME_FQDN} --email ${EMAIL_FOR_CERTBOT} --agree-tos -n"
fi

# ---------------------------------- 9) Dev tools --------------------------------------
if $INSTALL_DEVTOOLS; then
  section "Outils dev (Git/Curl/build-essential/grc)"
  apt_install git curl build-essential pkg-config dnsutils grc
fi

# ---------------------------------- 10) Node (nvm) ------------------------------------
if $INSTALL_NODE; then
  section "Node.js via nvm (LTS) pour ${ADMIN_USER}"
  USER_HOME="$(get_user_home)"

  # Installation de nvm pour l'utilisateur admin (download then execute)
  NVM_INSTALLER="$(mktempfile .sh)"
  curl -fsSL "https://raw.githubusercontent.com/nvm-sh/nvm/${NVM_VERSION}/install.sh" -o "$NVM_INSTALLER"
  run_as_user "
    export NVM_DIR=\"${USER_HOME}/.nvm\"
    mkdir -p \"\$NVM_DIR\"
    bash \"$NVM_INSTALLER\"
    source \"\$NVM_DIR/nvm.sh\"
    nvm install --lts
    nvm alias default 'lts/*'
  "
  rm -f "$NVM_INSTALLER"

  # Liens symboliques globaux (optionnel, pour que root puisse aussi utiliser node)
  if [[ -f "${USER_HOME}/.nvm/nvm.sh" ]]; then
    # shellcheck disable=SC1091
    NODE_PATH=$(sudo -u "$ADMIN_USER" -H bash -c "source ${USER_HOME}/.nvm/nvm.sh && command -v node")
    NPM_PATH=$(sudo -u "$ADMIN_USER" -H bash -c "source ${USER_HOME}/.nvm/nvm.sh && command -v npm")
    NPX_PATH=$(sudo -u "$ADMIN_USER" -H bash -c "source ${USER_HOME}/.nvm/nvm.sh && command -v npx")
    [[ -n "$NODE_PATH" ]] && ln -sf "$NODE_PATH" /usr/local/bin/node || true
    [[ -n "$NPM_PATH" ]] && ln -sf "$NPM_PATH" /usr/local/bin/npm || true
    [[ -n "$NPX_PATH" ]] && ln -sf "$NPX_PATH" /usr/local/bin/npx || true
  fi
  log "Node LTS installé pour ${ADMIN_USER}."
fi

# ---------------------------------- 11) Rust ------------------------------------------
if $INSTALL_RUST; then
  section "Rust (rustup stable) pour ${ADMIN_USER}"
  USER_HOME="$(get_user_home)"

  # Vérifie si rustup est déjà installé pour l'utilisateur
  if ! sudo -u "$ADMIN_USER" -H bash -c "command -v rustup" >/dev/null 2>&1; then
    RUSTUP_INSTALLER="$(mktempfile .sh)"
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs -o "$RUSTUP_INSTALLER"
    run_as_user "
      bash \"$RUSTUP_INSTALLER\" -y --default-toolchain stable
    "
    rm -f "$RUSTUP_INSTALLER"
  fi

  # Liens symboliques globaux
  if [[ -d "${USER_HOME}/.cargo/bin" ]]; then
    ln -sf "${USER_HOME}/.cargo/bin/rustup" /usr/local/bin/rustup || true
    ln -sf "${USER_HOME}/.cargo/bin/rustc" /usr/local/bin/rustc || true
    ln -sf "${USER_HOME}/.cargo/bin/cargo" /usr/local/bin/cargo || true
  fi
  log "Rust installé pour ${ADMIN_USER}."
fi

# ---------------------------------- 11b) Python 3 --------------------------------------
if $INSTALL_PYTHON3; then
  section "Python 3 + pip + venv + pipx"

  # Installation des paquets Python (pipx via apt pour respecter PEP 668)
  apt_install python3 python3-pip python3-venv python3-dev python3-setuptools python3-wheel python3-full pipx

  USER_HOME="$(get_user_home)"

  # Initialiser pipx pour l'utilisateur admin
  run_as_user "pipx ensurepath" || true

  # Ajouter ~/.local/bin au PATH si pas déjà présent
  if ! grep -q 'export PATH=.*\.local/bin' "${USER_HOME}/.bashrc" 2>/dev/null; then
    echo 'export PATH="$HOME/.local/bin:$PATH"' >> "${USER_HOME}/.bashrc"
  fi

  # Afficher les versions installées
  python3 --version
  python3 -m pip --version || true
  pipx --version || true

  log "Python 3 + pip + venv + pipx installé."
fi

# ---------------------------------- 12) Composer --------------------------------------
if $INSTALL_COMPOSER; then
  section "Composer pour ${ADMIN_USER}"
  USER_HOME="$(get_user_home)"

  # Crée le répertoire bin local si nécessaire
  run_as_user "mkdir -p ${USER_HOME}/.local/bin"

  # Télécharge et installe Composer pour l'utilisateur (download then execute)
  COMPOSER_INSTALLER="$(mktempfile .php)"
  curl -fsSL https://getcomposer.org/installer -o "$COMPOSER_INSTALLER"
  # Vérification du hash (optionnel mais recommandé)
  EXPECTED_SIG="$(curl -fsSL https://composer.github.io/installer.sig 2>/dev/null || true)"
  if [[ -n "$EXPECTED_SIG" ]]; then
    ACTUAL_SIG="$(php -r "echo hash_file('sha384', '$COMPOSER_INSTALLER');")"
    if [[ "$EXPECTED_SIG" != "$ACTUAL_SIG" ]]; then
      warn "Signature Composer invalide ! Installation annulée."
      rm -f "$COMPOSER_INSTALLER"
    fi
  fi
  if [[ -f "$COMPOSER_INSTALLER" ]]; then
    run_as_user "
      php \"$COMPOSER_INSTALLER\" --install-dir=${USER_HOME}/.local/bin --filename=composer
    "
    rm -f "$COMPOSER_INSTALLER"
  fi

  # Lien symbolique global
  if [[ -f "${USER_HOME}/.local/bin/composer" ]]; then
    ln -sf "${USER_HOME}/.local/bin/composer" /usr/local/bin/composer || true
  fi

  run_as_user "composer --version" || true
  log "Composer installé pour ${ADMIN_USER}."
fi

# ---------------------------------- 12b) Symfony CLI -----------------------------------
if $INSTALL_SYMFONY; then
  section "Symfony CLI et dépendances"
  USER_HOME="$(get_user_home)"

  # Extensions PHP supplémentaires pour Symfony
  # (les extensions de base sont déjà dans la section Apache/PHP)
  # Note: sodium est inclus dans PHP 8.x core
  apt_install php-apcu php-sqlite3 php-bcmath php-redis php-amqp php-yaml

  # Redémarrer PHP-FPM pour charger les nouvelles extensions
  systemctl restart php*-fpm 2>/dev/null || true

  # Dépendances pour Chrome Headless (génération PDF avec Browsershot/Puppeteer)
  # + Ghostscript pour manipulation PDF
  apt_install libxcomposite1 libatk-bridge2.0-0t64 libatk1.0-0t64 libnss3 \
    libxdamage1 libxfixes3 libxrandr2 libgbm1 libxkbcommon0 libasound2t64 ghostscript

  # Installer Symfony CLI (download then execute)
  SYMFONY_REPO_SETUP="$(mktempfile .sh)"
  curl -1sLf 'https://dl.cloudsmith.io/public/symfony/stable/setup.deb.sh' -o "$SYMFONY_REPO_SETUP"
  bash "$SYMFONY_REPO_SETUP"
  rm -f "$SYMFONY_REPO_SETUP"
  apt_install symfony-cli

  # Vérifier l'installation
  symfony version || true
  log "Symfony CLI et dépendances installés."
fi

# ---------------------------------- 13) Shell fun & utils -----------------------------
if $INSTALL_SHELL_FUN; then
  section "Confort shell (fastfetch, toilet, fortune-mod, cowsay, lolcat, grc, archives, beep)"
  # fastfetch remplace neofetch (abandonné), unrar-free remplace unrar (non-free)
  apt_install fastfetch toilet figlet fortune-mod cowsay lolcat grc p7zip-full zip unzip beep || true
  # unrar-free en fallback (peut ne pas être dispo)
  apt-get install -y unrar-free 2>/dev/null || true
  # fallback lolcat via pip si paquet non dispo
  if ! command -v lolcat &>/dev/null; then
    apt-get install -y python3-lolcat 2>/dev/null || pip3 install lolcat 2>/dev/null || true
  fi
  if $INSTALL_YTDL; then
    apt-get install -y yt-dlp || apt-get install -y youtube-dl || true
  fi
  log "Outils de confort installés."
fi

# ---------------------------------- 14) ClamAV ----------------------------------------
if $INSTALL_CLAMAV; then
  section "ClamAV"
  apt_install clamav clamav-daemon mailutils cron
  systemctl enable --now cron || true
  systemctl stop clamav-freshclam || true
  freshclam || true
  systemctl enable --now clamav-freshclam || true
  systemctl enable --now clamav-daemon || true

  # Créer le script de scan quotidien
  mkdir -p /root/scripts
  cat >/root/scripts/clamav_scan.sh <<'CLAMAVSCAN'
#!/bin/bash

# Destinataire du mail
MAILTO="__EMAIL__"

# Logs
LOG_DIR="/var/log/clamav"
TODAY=$(date +'%Y-%m-%d')
LOG_FILE="$LOG_DIR/scan-$TODAY.log"
mkdir -p "$LOG_DIR"

# Ne lance pas freshclam si le démon tourne, utilise les signatures déjà à jour
if ! systemctl is-active --quiet clamav-freshclam; then
    echo "Freshclam daemon non actif, mise à jour des signatures..."
    freshclam --quiet --stdout > /tmp/freshclam.log 2>&1
else
    echo "Freshclam daemon actif, signatures déjà à jour."
fi

# Scan complet (exclut /sys, /proc, /dev)
clamscan -r -i --exclude-dir="^/sys" --exclude-dir="^/proc" --exclude-dir="^/dev" / > "$LOG_FILE" 2>&1

# Filtrer uniquement les fichiers infectés
INFECTED=$(grep "FOUND$" "$LOG_FILE")
NUMINFECTED=$(echo "$INFECTED" | grep -c "FOUND$" || echo 0)

# Fonction pour envoyer le mail HTML
send_mail() {
    local subject="$1"
    local body="$2"
    echo -e "$body" | mail -a "Content-Type: text/html; charset=UTF-8" -s "$subject" "$MAILTO"
}

# Préparer le tableau HTML
prepare_table() {
    local data="$1"
    local table="<table border='1' cellpadding='5' cellspacing='0' style='border-collapse: collapse;'>"
    table+="<tr style='background-color:#f2f2f2;'><th>Fichier</th><th>Virus</th><th>Gravité</th></tr>"

    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        FILE=$(echo "$line" | awk -F: '{print $1}')
        VIRUS=$(echo "$line" | awk -F: '{print $2}' | sed 's/ FOUND//')
        if [[ "$VIRUS" =~ Eicar ]]; then
            COLOR="#ffff99"; GRAVITY="Test (faible)"
        else
            COLOR="#ff9999"; GRAVITY="Critique"
        fi
        table+="<tr style='background-color:$COLOR;'><td>$FILE</td><td>$VIRUS</td><td>$GRAVITY</td></tr>"
    done <<< "$data"

    table+="</table>"
    echo "$table"
}

# Générer graphique mensuel
generate_graph() {
    MONTH=$(date +'%Y-%m')
    local GRAPH="<h3>Historique mensuel des virus détectés</h3>"
    GRAPH+="<table border='1' cellpadding='3' cellspacing='0' style='border-collapse: collapse;'>"
    GRAPH+="<tr style='background-color:#f2f2f2;'><th>Date</th><th>Virus détectés</th></tr>"

    for FILE in "$LOG_DIR/$MONTH"/*.log 2>/dev/null; do
        [[ -f "$FILE" ]] || continue
        DATE=$(basename "$FILE" | sed 's/scan-//;s/.log//')
        COUNT=$(grep -c "FOUND$" "$FILE" 2>/dev/null || echo 0)
        COLOR="#99ff99"
        [[ $COUNT -gt 0 ]] && COLOR="#ff9999"
        GRAPH+="<tr style='background-color:$COLOR;'><td>$DATE</td><td>$COUNT</td></tr>"
    done

    GRAPH+="</table>"
    echo "$GRAPH"
}

# Envoyer le mail
if [[ $NUMINFECTED -gt 0 ]]; then
    TABLE=$(prepare_table "$INFECTED")
    GRAPH=$(generate_graph)
    MAILBODY="<html><body>"
    MAILBODY+="<h2 style='color:#cc0000;'>⚠️ ClamAV - Virus détectés sur $(hostname)</h2>"
    MAILBODY+="<p><strong>Date :</strong> $(date '+%Y-%m-%d %H:%M:%S')</p>"
    MAILBODY+="<p><strong>Nombre de fichiers infectés :</strong> $NUMINFECTED</p>"
    MAILBODY+="$TABLE"
    MAILBODY+="<br>"
    MAILBODY+="$GRAPH"
    MAILBODY+="</body></html>"
    send_mail "⚠️ ClamAV - $NUMINFECTED virus détecté(s) sur $(hostname)" "$MAILBODY"
else
    # Mail hebdomadaire si aucun virus (lundi = 1)
    DAYOFWEEK=$(date +%u)
    if [[ $DAYOFWEEK -eq 1 ]]; then
        GRAPH=$(generate_graph)
        MAILBODY="<html><body>"
        MAILBODY+="<h2 style='color:#00aa00;'>✅ ClamAV - Rapport hebdomadaire sur $(hostname)</h2>"
        MAILBODY+="<p><strong>Date :</strong> $(date '+%Y-%m-%d %H:%M:%S')</p>"
        MAILBODY+="<p>Aucun virus détecté cette semaine.</p>"
        MAILBODY+="<p>Les signatures et le scan se sont exécutés correctement.</p>"
        MAILBODY+="$GRAPH"
        MAILBODY+="</body></html>"
        send_mail "✅ ClamAV - Rapport hebdomadaire $(hostname)" "$MAILBODY"
    fi
fi

# Archiver le log dans le dossier mensuel
MONTH_DIR="$LOG_DIR/$(date +'%Y-%m')"
mkdir -p "$MONTH_DIR"
mv "$LOG_FILE" "$MONTH_DIR/"

# Nettoyage des logs > 6 mois
find "$LOG_DIR" -type d -mtime +__CLAMAV_RETENTION__ -exec rm -rf {} \; 2>/dev/null || true
CLAMAVSCAN

  # Remplacer l'email par celui configuré
  sed -i "s|__EMAIL__|${EMAIL_FOR_CERTBOT}|g; s|__CLAMAV_RETENTION__|${CLAMAV_LOG_RETENTION_DAYS}|g" /root/scripts/clamav_scan.sh
  chmod +x /root/scripts/clamav_scan.sh

  # Ajouter le cron job (quotidien)
  add_cron_job "clamav_scan.sh" "${CRON_CLAMAV} /root/scripts/clamav_scan.sh >/dev/null 2>&1" "ClamAV scan quotidien"

  log "ClamAV opérationnel (signatures à jour si freshclam OK)."
  log "Script de scan quotidien : /root/scripts/clamav_scan.sh"
  log "Cron configuré : tous les jours à 2h00"
fi

# ---------------------------------- 14b) rkhunter -------------------------------------
if $INSTALL_RKHUNTER; then
  section "rkhunter (détection rootkits)"
  apt_install rkhunter

  # Configuration /etc/default/rkhunter
  backup_file /etc/rkhunter.conf
  sed -i 's/^CRON_DAILY_RUN=.*/CRON_DAILY_RUN="true"/' /etc/default/rkhunter
  sed -i 's/^CRON_DB_UPDATE=.*/CRON_DB_UPDATE="false"/' /etc/default/rkhunter
  sed -i 's/^APT_AUTOGEN=.*/APT_AUTOGEN="true"/' /etc/default/rkhunter

  # Configuration /etc/rkhunter.conf - désactiver les miroirs web (souvent down)
  # et utiliser les mises à jour via apt (plus fiable)
  sed -i 's/^UPDATE_MIRRORS=.*/UPDATE_MIRRORS=0/' /etc/rkhunter.conf
  sed -i 's/^MIRRORS_MODE=.*/MIRRORS_MODE=0/' /etc/rkhunter.conf
  sed -i 's/^WEB_CMD=.*/WEB_CMD=""/' /etc/rkhunter.conf
  # Autoriser les scripts dans /dev (systemd)
  sed -i 's/^ALLOWDEVFILE=.*/ALLOWDEVFILE=\/dev\/.udev\/rules.d\/root.rules/' /etc/rkhunter.conf
  # Réduire les faux positifs sur Debian
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

  # Mise à jour des propriétés (baseline du système)
  rkhunter --propupd

  # Script de scan avec rapport email
  mkdir -p /root/scripts
  cat >/root/scripts/rkhunter_scan.sh <<'RKHUNTERSCAN'
#!/bin/bash
MAILTO="__EMAIL__"
LOGFILE="/var/log/rkhunter_scan_$(date +%Y%m%d).log"

# Exécute le scan
rkhunter --check --skip-keypress --report-warnings-only > "$LOGFILE" 2>&1

# Si des warnings sont détectés, envoie un mail
if grep -qE "(Warning|Infected)" "$LOGFILE"; then
    WARNINGS=$(grep -E "(Warning|Infected)" "$LOGFILE")
    (
        echo "To: $MAILTO"
        echo "Subject: [rkhunter] Alertes sur $(hostname)"
        echo "Content-Type: text/html; charset=UTF-8"
        echo "MIME-Version: 1.0"
        echo ""
        echo "<html><body>"
        echo "<h2 style='color:#cc0000;'>⚠️ rkhunter - Alertes détectées</h2>"
        echo "<p><strong>Serveur :</strong> $(hostname)</p>"
        echo "<p><strong>Date :</strong> $(date '+%Y-%m-%d %H:%M:%S')</p>"
        echo "<pre style='background:#f5f5f5;padding:10px;'>$WARNINGS</pre>"
        echo "<p>Consulter le log complet : $LOGFILE</p>"
        echo "</body></html>"
    ) | sendmail -t
fi

# Nettoyage logs > 30 jours
find /var/log -name "rkhunter_scan_*.log" -mtime +__RKHUNTER_RETENTION__ -delete 2>/dev/null || true
RKHUNTERSCAN

  # Déployer le script + cron (deploy_script gère sed __EMAIL__, chmod, et cron)
  sed -i "s|__EMAIL__|${EMAIL_FOR_CERTBOT}|g; s|__RKHUNTER_RETENTION__|${RKHUNTER_LOG_RETENTION_DAYS}|g" /root/scripts/rkhunter_scan.sh
  chmod +x /root/scripts/rkhunter_scan.sh
  add_cron_job "rkhunter_scan" "${CRON_RKHUNTER} /root/scripts/rkhunter_scan.sh >/dev/null 2>&1" "rkhunter scan hebdomadaire (dimanche 3h00)"

  log "rkhunter installé et configuré (scan hebdomadaire dimanche 3h00)"
fi

# ---------------------------------- 14c) Logwatch -------------------------------------
if $INSTALL_LOGWATCH; then
  section "Logwatch (résumé quotidien des logs)"
  apt_install logwatch

  # Configuration personnalisée
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

  # Script d'alerte SSH
  cat >/etc/profile.d/ssh-alert.sh <<'SSHALERT'
#!/bin/bash
# Alerte email à chaque connexion SSH

# Ne pas envoyer pour les connexions locales ou non-interactives
if [ -z "$SSH_CONNECTION" ] || [ -z "$PS1" ]; then
    return 2>/dev/null || exit 0
fi

# Vérifier que sendmail est disponible
if ! command -v sendmail &>/dev/null; then
    return 2>/dev/null || exit 0
fi

MAILTO="__EMAIL__"
IP=$(echo $SSH_CONNECTION | awk '{print $1}')
USER=$(whoami)
HOSTNAME=$(hostname -f)
DATE=$(date '+%Y-%m-%d %H:%M:%S')

# Géolocalisation (optionnel, utilise ipinfo.io)
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

  # Configuration personnalisée (exclure les fichiers qui changent souvent)
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

  # Initialisation de la base de données (en arrière-plan car long)
  log "Initialisation de la base AIDE (peut prendre plusieurs minutes)..."
  aideinit &
  AIDE_PID=$!

  # Script de vérification avec rapport email
  mkdir -p /root/scripts
  cat >/root/scripts/aide_check.sh <<'AIDECHECK'
#!/bin/bash
MAILTO="__EMAIL__"
LOGFILE="/var/log/aide/aide_check_$(date +%Y%m%d).log"

mkdir -p /var/log/aide

# Vérifie si la base existe
if [ ! -f /var/lib/aide/aide.db ]; then
    echo "Base AIDE non initialisée" > "$LOGFILE"
    exit 1
fi

# Exécute la vérification
aide --check > "$LOGFILE" 2>&1
RESULT=$?

# Si des changements sont détectés (exit code != 0)
if [ $RESULT -ne 0 ]; then
    CHANGES=$(cat "$LOGFILE" | head -100)
    (
        echo "To: $MAILTO"
        echo "Subject: [AIDE] Modifications détectées sur $(hostname)"
        echo "Content-Type: text/html; charset=UTF-8"
        echo "MIME-Version: 1.0"
        echo ""
        echo "<html><body>"
        echo "<h2 style='color:#cc0000;'>⚠️ AIDE - Fichiers modifiés détectés</h2>"
        echo "<p><strong>Serveur :</strong> $(hostname)</p>"
        echo "<p><strong>Date :</strong> $(date '+%Y-%m-%d %H:%M:%S')</p>"
        echo "<p>Des modifications de fichiers système ont été détectées :</p>"
        echo "<pre style='background:#f5f5f5;padding:10px;font-size:11px;'>$CHANGES</pre>"
        echo "<p><strong>Actions recommandées :</strong></p>"
        echo "<ul>"
        echo "<li>Vérifier si les changements sont légitimes (mises à jour système)</li>"
        echo "<li>Si OK, mettre à jour la base : <code>aide --update && mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db</code></li>"
        echo "</ul>"
        echo "</body></html>"
    ) | sendmail -t
fi

# Nettoyage logs > 30 jours
find /var/log/aide -name "aide_check_*.log" -mtime +__AIDE_RETENTION__ -delete 2>/dev/null || true
AIDECHECK

  sed -i "s|__EMAIL__|${EMAIL_FOR_CERTBOT}|g; s|__AIDE_RETENTION__|${AIDE_LOG_RETENTION_DAYS}|g" /root/scripts/aide_check.sh
  chmod +x /root/scripts/aide_check.sh

  # Cron quotidien — idempotent
  add_cron_job "aide_check" "${CRON_AIDE} /root/scripts/aide_check.sh >/dev/null 2>&1" "AIDE vérification quotidienne (4h00)"

  log "AIDE installé (vérification quotidienne 4h00, initialisation en cours...)"
fi

# ---------------------------------- 14f) ModSecurity OWASP CRS ------------------------
if $INSTALL_MODSEC_CRS && $INSTALL_APACHE_PHP; then
  section "ModSecurity OWASP Core Rule Set"

  # Installer le CRS
  apt_install modsecurity-crs

  # Activer ModSecurity en mode détection d'abord
  backup_file /etc/modsecurity/modsecurity.conf
  if [ -f /etc/modsecurity/modsecurity.conf-recommended ]; then
    cp /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf
  fi

  # Mode DetectionOnly pour commencer (évite les faux positifs)
  sed -i 's/^SecRuleEngine .*/SecRuleEngine DetectionOnly/' /etc/modsecurity/modsecurity.conf

  # Configurer les logs
  sed -i 's|SecAuditLog .*|SecAuditLog /var/log/apache2/modsec_audit.log|' /etc/modsecurity/modsecurity.conf

  # Whitelist des IPs de confiance (bypass ModSecurity)
  if [[ -n "${TRUSTED_IPS:-}" ]]; then
    cat >/etc/modsecurity/whitelist-trusted-ips.conf <<'WHITELIST_HEADER'
# Whitelist des IPs de confiance
# Ces IPs bypassent les règles ModSecurity (générées par install.sh)
WHITELIST_HEADER
    rule_id=1000001
    for ip in $TRUSTED_IPS; do
      # Échapper tous les caractères spéciaux regex
      ip_escaped=$(echo "$ip" | sed 's/[.[\/*+?{}()|^$]/\\\\&/g')
      echo "SecRule REMOTE_ADDR \"^${ip_escaped}\$\" \"id:${rule_id},phase:1,allow,nolog,msg:'Trusted IP whitelist: ${ip}'\"" >> /etc/modsecurity/whitelist-trusted-ips.conf
      ((rule_id++))
    done
    log "ModSecurity: IPs de confiance whitelistées: $TRUSTED_IPS"
  fi

  # Inclure les règles CRS (Debian 13 met crs-setup.conf dans /etc/modsecurity/crs/)
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

  # Créer le répertoire de cache
  mkdir -p /var/cache/modsecurity
  chown www-data:www-data /var/cache/modsecurity

  # Redémarrer Apache
  systemctl restart apache2

  log "ModSecurity OWASP CRS installé (mode DetectionOnly)"
  log "Pour activer le blocage : sed -i 's/SecRuleEngine DetectionOnly/SecRuleEngine On/' /etc/modsecurity/modsecurity.conf && systemctl restart apache2"
fi

# ---------------------------------- 14g) Secure /tmp ----------------------------------
if $SECURE_TMP; then
  section "Sécurisation /tmp (noexec, nosuid, nodev)"

  # Vérifier si /tmp est déjà une partition séparée
  if mount | grep -q "on /tmp type"; then
    # /tmp est déjà monté séparément, ajouter les options
    backup_file /etc/fstab
    if ! grep -q "noexec" /etc/fstab | grep -q "/tmp"; then
      # Modifier la ligne existante
      sed -i '/[[:space:]]\/tmp[[:space:]]/ s/defaults/defaults,noexec,nosuid,nodev/' /etc/fstab
      mount -o remount /tmp
      log "/tmp remonté avec noexec,nosuid,nodev"
    fi
  else
    # /tmp n'est pas une partition séparée, utiliser tmpfs
    if ! grep -q "tmpfs.*/tmp" /etc/fstab; then
      backup_file /etc/fstab
      echo "tmpfs /tmp tmpfs defaults,noexec,nosuid,nodev,size=1G 0 0" >> /etc/fstab
      mount -o remount /tmp 2>/dev/null || mount /tmp
      log "/tmp configuré en tmpfs avec noexec,nosuid,nodev (1G)"
    else
      log "/tmp déjà configuré en tmpfs"
    fi
  fi

  # Sécuriser aussi /var/tmp (lien symbolique vers /tmp ou mêmes options)
  if [ ! -L /var/tmp ]; then
    # Si /var/tmp n'est pas un lien, ajouter les mêmes protections
    if ! grep -q "/var/tmp" /etc/fstab; then
      echo "tmpfs /var/tmp tmpfs defaults,noexec,nosuid,nodev,size=1G 0 0" >> /etc/fstab
      mount /var/tmp 2>/dev/null || true
    fi
  fi

  log "/tmp et /var/tmp sécurisés"
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
EOF
sysctl --system | tee -a "$LOG_FILE"

sed -ri 's|^#?Storage=.*|Storage=persistent|' /etc/systemd/journald.conf
systemctl restart systemd-journald

apt_install unattended-upgrades
dpkg-reconfigure -f noninteractive unattended-upgrades

# Script de vérification des mises à jour (hebdomadaire)
mkdir -p /root/scripts
cat >/root/scripts/check-updates.sh <<'CHECKUPDATES'
#!/bin/bash

# Destinataire du mail
MAILTO="__EMAIL__"

# Fichier temporaire
TMPFILE=$(mktemp)

# Met à jour la liste des paquets silencieusement
apt update -qq

# Début du HTML
echo "<html><body>" > "$TMPFILE"
echo "<h2>Mises à jour disponibles sur $(hostname)</h2>" >> "$TMPFILE"
echo "<p><strong>Date :</strong> $(date '+%Y-%m-%d %H:%M:%S')</p>" >> "$TMPFILE"
echo "<table border='1' cellpadding='5' cellspacing='0' style='border-collapse: collapse;'>" >> "$TMPFILE"
echo "<tr style='background-color: #f2f2f2;'><th>Paquet</th><th>Version installée</th><th>Version disponible</th><th>Dépôt</th></tr>" >> "$TMPFILE"

# Compteur
COUNT=0

# Parcours tous les paquets upgradable
while read -r line; do
    [[ -z "$line" ]] && continue
    PKG=$(echo "$line" | awk -F/ '{print $1}')
    INSTALLED=$(apt-cache policy "$PKG" 2>/dev/null | grep Installed | awk '{print $2}')
    CANDIDATE=$(apt-cache policy "$PKG" 2>/dev/null | grep Candidate | awk '{print $2}')
    REPO=$(apt-cache policy "$PKG" 2>/dev/null | grep -E "http|https" | head -n1 | xargs)

    echo "<tr style='background-color: #ffeb99;'><td>$PKG</td><td>$INSTALLED</td><td>$CANDIDATE</td><td>$REPO</td></tr>" >> "$TMPFILE"
    COUNT=$((COUNT + 1))
done < <(apt list --upgradable 2>/dev/null | grep -v "^Listing")

echo "</table>" >> "$TMPFILE"

# Message si pas de paquet
if [[ $COUNT -eq 0 ]]; then
    echo "<p style='color: green;'><strong>✅ Tous les paquets sont à jour.</strong></p>" >> "$TMPFILE"
fi

# Fin du HTML
echo "</body></html>" >> "$TMPFILE"

# Envoie le mail
if [[ $COUNT -gt 0 ]]; then
    mail -a "Content-Type: text/html; charset=UTF-8" -s "⚠️ $COUNT mise(s) à jour disponible(s) sur $(hostname)" "$MAILTO" < "$TMPFILE"
else
    mail -a "Content-Type: text/html; charset=UTF-8" -s "✅ Système à jour sur $(hostname)" "$MAILTO" < "$TMPFILE"
fi

# Supprime le fichier temporaire
rm -f "$TMPFILE"
CHECKUPDATES

sed -i "s|__EMAIL__|${EMAIL_FOR_CERTBOT}|g" /root/scripts/check-updates.sh
chmod +x /root/scripts/check-updates.sh

# Cron : lundi à 7h00
add_cron_job "check-updates.sh" "${CRON_UPDATES} /root/scripts/check-updates.sh >/dev/null 2>&1" "Vérification mises à jour hebdomadaire (lundi 7h00)"

log "Script check-updates.sh créé : /root/scripts/check-updates.sh"
log "Cron configuré : lundi à 7h00"

# ---------------------------------- 16) .bashrc global -------------------------------
if $INSTALL_BASHRC_GLOBAL; then
  section "Déploiement .bashrc (tous utilisateurs)"

  # (#21 — KISS) Le template .bashrc est externalisé dans templates/bashrc.template
  BASHRC_TEMPLATE="${SCRIPT_DIR}/templates/bashrc.template"
  if [[ ! -f "$BASHRC_TEMPLATE" ]]; then
    BASHRC_TEMPLATE="/root/scripts/templates/bashrc.template"
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


  # /etc/skel pour futurs utilisateurs
  install_bashrc_for /etc/skel/.bashrc

  # Pour root et l'admin courant
  install_bashrc_for /root/.bashrc
  if id -u "$ADMIN_USER" >/dev/null 2>&1; then
    install_bashrc_for "/home/${ADMIN_USER}/.bashrc"
    chown "${ADMIN_USER}:${ADMIN_USER}" "/home/${ADMIN_USER}/.bashrc"
  fi

  # Pour tous les utilisateurs déjà existants (>1000)
  while IFS=: read -r user _ uid _ _ home shell; do
    if [[ "$uid" -ge 1000 && -d "$home" && -w "$home" && "$user" != "nobody" ]]; then
      install_bashrc_for "${home}/.bashrc"
      chown "${user}:${user}" "${home}/.bashrc" || true
    fi
  done < /etc/passwd

  # Vider /etc/motd (on utilise notre propre banner dans .bashrc)
  echo -n > /etc/motd

  # Désactiver les scripts MOTD dynamiques si présents
  [[ -d /etc/update-motd.d ]] && chmod -x /etc/update-motd.d/* 2>/dev/null || true

  log ".bashrc déployé, /etc/motd vidé."
  fi # fin template check
fi

fi # Fin du bloc if ! $AUDIT_MODE (skip installation)

# ================================== VÉRIFICATIONS =====================================
# ---------------------------------- 17) Vérifications ---------------------------------
section "Vérifications de l'installation et de la sécurité (v${SCRIPT_VERSION})"

# Compteurs
CHECKS_OK=0
CHECKS_WARN=0
CHECKS_FAIL=0

check_ok()   { printf "${GREEN}  ✔ %s${RESET}\n" "$1"; ((++CHECKS_OK)) || true; }
check_warn() { printf "${YELLOW}  ⚠ %s${RESET}\n" "$1"; ((++CHECKS_WARN)) || true; }
check_fail() { printf "${RED}  ✖ %s${RESET}\n" "$1"; ((++CHECKS_FAIL)) || true; }
check_skip() { printf "${CYAN}  ○ %s (ignoré)${RESET}\n" "$1"; }

echo ""
printf "${BOLD}${MAGENTA}── Services ──${RESET}\n"

# SSH
check_service_active ssh "SSH" || check_service_active sshd "SSH" || true

# UFW
if $INSTALL_UFW; then
  if ufw status | grep -qiE "(Status|État).*acti"; then
    check_ok "UFW : actif"
  else
    check_fail "UFW : inactif"
  fi
fi

# GeoIP Block
if $GEOIP_BLOCK; then
  if ipset list geoip_blocked >/dev/null 2>&1; then
    GEOIP_COUNT=$(ipset list geoip_blocked 2>/dev/null | grep -c '^[0-9]' || echo "0")
    check_ok "GeoIP : ${GEOIP_COUNT} plages bloquées"
  else
    check_fail "GeoIP : ipset geoip_blocked non trouvé"
  fi
fi

# Fail2ban
if $INSTALL_FAIL2BAN; then
  if check_service_active fail2ban "Fail2ban"; then
    JAILS=$(fail2ban-client status 2>/dev/null | grep "Jail list" | sed 's/.*:\s*//' | tr -d ' ')
    [[ -n "$JAILS" ]] && check_ok "Fail2ban jails : $JAILS"
    # Nombre d'IPs bannies actuellement
    BANNED_TOTAL=0
    for jail in $(echo "$JAILS" | tr ',' ' '); do
      BANNED=$(fail2ban-client status "$jail" 2>/dev/null | grep "Currently banned" | awk '{print $NF}')
      BANNED_TOTAL=$((BANNED_TOTAL + ${BANNED:-0}))
    done
    if [[ "$BANNED_TOTAL" -gt 0 ]]; then
      check_ok "Fail2ban : ${BANNED_TOTAL} IP(s) actuellement bannie(s)"
    fi
    # Vérifier les IPs de confiance
    if [[ -n "${TRUSTED_IPS:-}" ]]; then
      F2B_IGNOREIP=$(grep "^ignoreip" /etc/fail2ban/jail.local 2>/dev/null | cut -d= -f2 || true)
      check_ok "Fail2ban ignoreip : ${F2B_IGNOREIP:-non configuré}"
    fi
  fi
fi

# IPs de confiance
if [[ -n "${TRUSTED_IPS:-}" ]]; then
  check_ok "IPs de confiance configurées : $TRUSTED_IPS"
  # Vérifier ModSecurity whitelist
  if [[ -f /etc/modsecurity/whitelist-trusted-ips.conf ]]; then
    MODSEC_WHITELIST_COUNT=$(grep -c "SecRule REMOTE_ADDR" /etc/modsecurity/whitelist-trusted-ips.conf 2>/dev/null || echo "0")
    check_ok "ModSecurity whitelist : ${MODSEC_WHITELIST_COUNT} règle(s)"
  fi
fi

# Apache
$INSTALL_APACHE_PHP && check_service_active apache2 "Apache"

# MariaDB
$INSTALL_MARIADB && check_service_active mariadb "MariaDB"

# phpMyAdmin
if $INSTALL_PHPMYADMIN; then
  if [[ -f /etc/phpmyadmin/apache.conf ]]; then
    check_ok "phpMyAdmin : installé"
    if [[ -f /root/.phpmyadmin_alias ]]; then
      PMA_ALIAS_CHECK=$(cat /root/.phpmyadmin_alias)
      check_ok "phpMyAdmin : URL sécurisée (/${PMA_ALIAS_CHECK})"
    else
      check_warn "phpMyAdmin : URL par défaut /phpmyadmin (risque sécurité)"
    fi
  else
    check_fail "phpMyAdmin : non installé"
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
  [[ -x /root/scripts/clamav_scan.sh ]] && check_ok "ClamAV : script de scan présent" || check_fail "ClamAV : script de scan absent"
  crontab -l 2>/dev/null | grep -q "clamav_scan.sh" && check_ok "ClamAV : cron quotidien configuré" || check_warn "ClamAV : cron non configuré"
  check_db_freshness /var/lib/clamav "ClamAV" 1 "$DB_FRESH_DAYS" cli
fi

echo ""
printf "${BOLD}${MAGENTA}── Sécurité SSH ──${RESET}\n"

if $INSTALL_SSH_HARDEN; then
  # Vérification des paramètres SSH
  SSHD_CONFIG="/etc/ssh/sshd_config"

  if grep -qE "^PermitRootLogin\s+no" "$SSHD_CONFIG" 2>/dev/null; then
    check_ok "SSH : connexion root désactivée"
  else
    check_fail "SSH : connexion root NON désactivée"
  fi

  if grep -qE "^PasswordAuthentication\s+no" "$SSHD_CONFIG" 2>/dev/null; then
    check_ok "SSH : authentification par mot de passe désactivée"
  else
    check_fail "SSH : authentification par mot de passe NON désactivée"
  fi

  if grep -qE "^Port\s+${SSH_PORT}" "$SSHD_CONFIG" 2>/dev/null; then
    check_ok "SSH : port ${SSH_PORT} configuré"
  else
    check_warn "SSH : port ${SSH_PORT} non trouvé dans config"
  fi

  if grep -qE "^AllowUsers\s+.*${ADMIN_USER}" "$SSHD_CONFIG" 2>/dev/null; then
    check_ok "SSH : AllowUsers contient ${ADMIN_USER}"
  else
    check_warn "SSH : AllowUsers ne contient pas ${ADMIN_USER}"
  fi
fi

echo ""
printf "${BOLD}${MAGENTA}── Sécurité Web ──${RESET}\n"

if $INSTALL_APACHE_PHP; then
  # Headers de sécurité Apache
  if [[ -f /etc/apache2/conf-available/security-headers.conf ]]; then
    if a2query -c security-headers >/dev/null 2>&1; then
      check_ok "Apache : headers de sécurité activés"
    else
      check_warn "Apache : headers de sécurité non activés"
    fi
  fi

  # ServerTokens
  if grep -rq "ServerTokens Prod" /etc/apache2/ 2>/dev/null; then
    check_ok "Apache : ServerTokens Prod"
  else
    check_warn "Apache : ServerTokens non configuré à Prod"
  fi

  # PHP expose_php - vérifie via header HTTP (plus fiable que php -i qui lit la config CLI)
  if curl -sI http://localhost/ 2>/dev/null | grep -qi "X-Powered-By:.*PHP"; then
    check_warn "PHP : expose_php n'est pas Off (header X-Powered-By visible)"
  else
    check_ok "PHP : expose_php = Off (pas de header X-Powered-By)"
  fi
  # display_errors - vérifie dans php.ini apache2
  PHP_INI=$(find /etc/php -path "*/apache2/php.ini" 2>/dev/null | head -1)
  if [[ -n "$PHP_INI" ]] && grep -qE "^\s*display_errors\s*=\s*Off" "$PHP_INI"; then
    check_ok "PHP : display_errors = Off"
  elif [[ -n "$PHP_INI" ]]; then
    check_warn "PHP : display_errors n'est pas Off dans $PHP_INI"
  else
    check_warn "PHP : php.ini apache2 non trouvé"
  fi

  # Vérifier disable_functions
  DISABLED_FUNCS=$(php -i 2>/dev/null | grep "^disable_functions" | head -1)
  if echo "$DISABLED_FUNCS" | grep -q "exec"; then
    check_ok "PHP : fonctions dangereuses désactivées"
  else
    if $PHP_DISABLE_FUNCTIONS; then
      check_warn "PHP : disable_functions non configuré"
    else
      printf "  ${CYAN}PHP : fonctions exec/shell autorisées (choix utilisateur)${RESET}\n"
    fi
  fi

  # mod_security
  if a2query -m security2 >/dev/null 2>&1; then
    check_ok "Apache : mod_security activé"
  else
    check_warn "Apache : mod_security non activé"
  fi

  # Version PHP
  PHP_VER=$(php -v 2>/dev/null | head -1 | awk '{print $2}')
  if [[ -n "$PHP_VER" ]]; then
    check_ok "PHP : version ${PHP_VER}"
  fi

  # SSL/TLS Certificats
  if $INSTALL_CERTBOT; then
    if [[ -d /etc/letsencrypt/live/${HOSTNAME_FQDN} ]]; then
      CERT_FILE="/etc/letsencrypt/live/${HOSTNAME_FQDN}/cert.pem"
      if [[ -f "$CERT_FILE" ]]; then
        CERT_EXPIRY=$(openssl x509 -enddate -noout -in "$CERT_FILE" 2>/dev/null | cut -d= -f2)
        CERT_EXPIRY_EPOCH=$(date -d "$CERT_EXPIRY" +%s 2>/dev/null || echo 0)
        NOW_EPOCH=$(date +%s)
        DAYS_LEFT=$(( (CERT_EXPIRY_EPOCH - NOW_EPOCH) / 86400 ))
        if [[ "$DAYS_LEFT" -gt "$SSL_WARN_DAYS" ]]; then
          check_ok "SSL : certificat valide (expire dans ${DAYS_LEFT} jours)"
        elif [[ "$DAYS_LEFT" -gt 7 ]]; then
          check_warn "SSL : certificat expire dans ${DAYS_LEFT} jours"
        elif [[ "$DAYS_LEFT" -gt 0 ]]; then
          check_fail "SSL : certificat expire dans ${DAYS_LEFT} jours - renouveler !"
        else
          check_fail "SSL : certificat expiré !"
        fi
      fi
    else
      check_warn "SSL : certificat Let's Encrypt non trouvé pour ${HOSTNAME_FQDN}"
    fi

    # Vérifier le timer de renouvellement
    if systemctl is-active --quiet certbot.timer 2>/dev/null || systemctl is-enabled --quiet certbot.timer 2>/dev/null; then
      check_ok "SSL : renouvellement automatique activé"
    else
      check_warn "SSL : timer certbot non actif"
    fi
  fi
fi

echo ""
printf "${BOLD}${MAGENTA}── Sécurité Système ──${RESET}\n"

# Kernel hardening
if [[ -f /etc/sysctl.d/99-hardening.conf ]]; then
  check_ok "Sysctl : fichier de durcissement présent"

  # Vérifier quelques paramètres clés
  if sysctl net.ipv4.tcp_syncookies 2>/dev/null | grep -q "= 1"; then
    check_ok "Kernel : TCP SYN cookies activés"
  fi
  if sysctl kernel.kptr_restrict 2>/dev/null | grep -q "= 2"; then
    check_ok "Kernel : pointeurs kernel masqués"
  fi
else
  check_warn "Sysctl : fichier de durcissement absent"
fi

# Unattended upgrades
if dpkg -l | grep -q unattended-upgrades; then
  check_ok "Mises à jour automatiques : installées"
else
  check_warn "Mises à jour automatiques : non installées"
fi

# Mises à jour en attente
UPDATES_PENDING=$(apt-get -s upgrade 2>/dev/null | grep -c "^Inst " || true)
UPDATES_PENDING=$(echo "$UPDATES_PENDING" | tr -d '[:space:]')
UPDATES_PENDING=${UPDATES_PENDING:-0}
if [[ "$UPDATES_PENDING" -eq 0 ]]; then
  check_ok "Système : à jour (pas de mises à jour en attente)"
elif [[ "$UPDATES_PENDING" -lt 10 ]]; then
  check_warn "Système : ${UPDATES_PENDING} mise(s) à jour en attente"
else
  check_warn "Système : ${UPDATES_PENDING} mises à jour en attente - apt upgrade recommandé"
fi

# Redémarrage requis
if [[ -f /var/run/reboot-required ]]; then
  check_warn "Système : redémarrage requis"
else
  check_ok "Système : pas de redémarrage requis"
fi

# Script check-updates
if [[ -x /root/scripts/check-updates.sh ]]; then
  check_ok "Script check-updates : présent"
else
  check_warn "Script check-updates : absent"
fi
if crontab -l 2>/dev/null | grep -q "check-updates.sh"; then
  check_ok "Script check-updates : cron hebdo configuré (lundi 7h00)"
else
  check_warn "Script check-updates : cron non configuré"
fi

# Journald persistent
if grep -q "Storage=persistent" /etc/systemd/journald.conf 2>/dev/null; then
  check_ok "Journald : stockage persistant"
else
  check_warn "Journald : stockage non persistant"
fi

# Log rotation (logrotate)
if [[ -f /etc/logrotate.conf ]]; then
  check_ok "Logrotate : configuré"
  # Vérifier si logrotate a fonctionné récemment
  if [[ -f /var/lib/logrotate/status ]]; then
    LOGROTATE_DATE=$(stat -c %Y /var/lib/logrotate/status 2>/dev/null)
    if [[ -n "$LOGROTATE_DATE" ]]; then
      LOGROTATE_AGE=$(( ($(date +%s) - $LOGROTATE_DATE) / 86400 ))
      if [[ "$LOGROTATE_AGE" -le 1 ]]; then
        check_ok "Logrotate : exécuté dans les dernières 24h"
      elif [[ "$LOGROTATE_AGE" -le 7 ]]; then
        check_warn "Logrotate : dernière exécution il y a ${LOGROTATE_AGE} jours"
      else
        check_warn "Logrotate : pas exécuté depuis ${LOGROTATE_AGE} jours"
      fi
    fi
  fi
else
  check_warn "Logrotate : non configuré"
fi

# Taille des logs
LOG_SIZE=$(du -sh /var/log 2>/dev/null | awk '{print $1}')
if [[ -n "$LOG_SIZE" ]]; then
  LOG_SIZE_MB=$(du -sm /var/log 2>/dev/null | awk '{print $1}')
  if [[ "$LOG_SIZE_MB" -lt "$LOG_SIZE_WARN_MB" ]]; then
    check_ok "Logs : ${LOG_SIZE} utilisés"
  elif [[ "$LOG_SIZE_MB" -lt "$LOG_SIZE_FAIL_MB" ]]; then
    check_warn "Logs : ${LOG_SIZE} utilisés (envisager nettoyage)"
  else
    check_fail "Logs : ${LOG_SIZE} utilisés - nettoyage recommandé"
  fi
fi

# rkhunter
if $INSTALL_RKHUNTER; then
  if command -v rkhunter >/dev/null 2>&1; then
    check_ok "rkhunter : installé"
    if [[ -x /root/scripts/rkhunter_scan.sh ]]; then
      check_ok "rkhunter : script de scan présent"
    fi
    if crontab -l 2>/dev/null | grep -q "rkhunter_scan"; then
      check_ok "rkhunter : cron hebdo configuré (dimanche 3h00)"
    fi
    check_db_freshness /var/lib/rkhunter/db/rkhunter.dat "rkhunter" "$DB_FRESH_DAYS" "$DB_STALE_DAYS" cli
  else
    check_warn "rkhunter : non installé"
  fi
fi

# Logwatch
if $INSTALL_LOGWATCH; then
  if command -v logwatch >/dev/null 2>&1; then
    check_ok "Logwatch : installé"
    if [[ -f /etc/logwatch/conf/logwatch.conf ]]; then
      check_ok "Logwatch : configuré (rapport quotidien)"
    fi
  else
    check_warn "Logwatch : non installé"
  fi
fi

# SSH Alert
if $INSTALL_SSH_ALERT; then
  if [[ -f /etc/profile.d/ssh-alert.sh ]]; then
    check_ok "SSH Alert : script d'alerte actif"
  else
    check_warn "SSH Alert : script absent"
  fi
fi

# AIDE
if $INSTALL_AIDE; then
  if command -v aide >/dev/null 2>&1; then
    check_ok "AIDE : installé"
    check_db_freshness /var/lib/aide/aide.db "AIDE" "$DB_FRESH_DAYS" "$DB_STALE_DAYS" cli
    if [[ -x /root/scripts/aide_check.sh ]]; then
      check_ok "AIDE : script de vérification présent"
    fi
    if crontab -l 2>/dev/null | grep -q "aide_check"; then
      check_ok "AIDE : cron quotidien configuré (4h00)"
    fi
  else
    check_warn "AIDE : non installé"
  fi
fi

# ModSecurity CRS
if $INSTALL_MODSEC_CRS && $INSTALL_APACHE_PHP; then
  if [[ -d /usr/share/modsecurity-crs ]]; then
    check_ok "ModSecurity CRS : règles OWASP installées"
    if grep -q "SecRuleEngine On" /etc/modsecurity/modsecurity.conf 2>/dev/null; then
      check_ok "ModSecurity CRS : mode blocage actif"
    else
      check_warn "ModSecurity CRS : mode DetectionOnly (logs uniquement)"
    fi
  else
    check_warn "ModSecurity CRS : non installé"
  fi
fi

# Secure /tmp
if $SECURE_TMP; then
  if mount | grep -E "/tmp.*noexec" >/dev/null 2>&1; then
    check_ok "/tmp : monté avec noexec,nosuid,nodev"
  elif grep -q "noexec" /etc/fstab 2>/dev/null && grep -q "/tmp" /etc/fstab 2>/dev/null; then
    check_warn "/tmp : configuré dans fstab mais pas encore remonté"
  else
    check_warn "/tmp : pas sécurisé (noexec non actif)"
  fi
fi

echo ""
printf "${BOLD}${MAGENTA}── Outils de développement ──${RESET}\n"

USER_HOME="$(get_user_home)"

# Node.js
if $INSTALL_NODE; then
  if sudo -u "$ADMIN_USER" -H bash -c "source ${USER_HOME}/.nvm/nvm.sh 2>/dev/null && node --version" >/dev/null 2>&1; then
    NODE_VER=$(sudo -u "$ADMIN_USER" -H bash -c "source ${USER_HOME}/.nvm/nvm.sh && node --version" 2>/dev/null)
    check_ok "Node.js : ${NODE_VER} (pour ${ADMIN_USER})"
  else
    check_fail "Node.js : non installé pour ${ADMIN_USER}"
  fi
fi

# Rust
if $INSTALL_RUST; then
  if [[ -f "${USER_HOME}/.cargo/bin/rustc" ]]; then
    RUST_VER=$(sudo -u "$ADMIN_USER" -H bash -c "${USER_HOME}/.cargo/bin/rustc --version" 2>/dev/null | awk '{print $2}')
    check_ok "Rust : ${RUST_VER} (pour ${ADMIN_USER})"
  else
    check_fail "Rust : non installé pour ${ADMIN_USER}"
  fi
fi

# Python 3
if $INSTALL_PYTHON3; then
  if command -v python3 >/dev/null 2>&1; then
    PYTHON_VER=$(python3 --version 2>/dev/null | awk '{print $2}')
    check_ok "Python : ${PYTHON_VER}"
    # Vérifier pip
    if python3 -m pip --version >/dev/null 2>&1; then
      PIP_VER=$(python3 -m pip --version 2>/dev/null | awk '{print $2}')
      check_ok "pip : ${PIP_VER}"
    else
      check_warn "pip : non installé"
    fi
    # Vérifier pipx
    if command -v pipx >/dev/null 2>&1; then
      PIPX_VER=$(pipx --version 2>/dev/null)
      check_ok "pipx : ${PIPX_VER}"
    else
      check_warn "pipx : non installé"
    fi
  else
    check_fail "Python 3 : non installé"
  fi
fi

# Composer
if $INSTALL_COMPOSER; then
  if [[ -f "${USER_HOME}/.local/bin/composer" ]]; then
    COMPOSER_VER=$(sudo -u "$ADMIN_USER" -H bash -c "${USER_HOME}/.local/bin/composer --version" 2>/dev/null | awk '{print $3}')
    check_ok "Composer : ${COMPOSER_VER} (pour ${ADMIN_USER})"
  else
    check_fail "Composer : non installé pour ${ADMIN_USER}"
  fi
fi

# Symfony CLI
if $INSTALL_SYMFONY; then
  if command -v symfony >/dev/null 2>&1; then
    SYMFONY_VER=$(symfony version 2>/dev/null | head -1 | awk '{print $4}')
    check_ok "Symfony CLI : ${SYMFONY_VER}"
  else
    check_fail "Symfony CLI : non installé"
  fi
fi

# Git
if $INSTALL_DEVTOOLS; then
  if command -v git >/dev/null 2>&1; then
    GIT_VER=$(git --version | awk '{print $3}')
    check_ok "Git : ${GIT_VER}"
  else
    check_fail "Git : non installé"
  fi
fi

echo ""
printf "${BOLD}${MAGENTA}── DKIM ──${RESET}\n"

if $INSTALL_POSTFIX_DKIM; then
  DKIM_KEY="${DKIM_KEYDIR}/${DKIM_SELECTOR}.private"
  DKIM_PUB="${DKIM_KEYDIR}/${DKIM_SELECTOR}.txt"

  if [[ -f "$DKIM_KEY" ]]; then
    check_ok "DKIM : clé privée présente"
    # Vérifier les permissions
    DKIM_PERMS=$(stat -c %a "$DKIM_KEY" 2>/dev/null)
    if [[ "$DKIM_PERMS" == "600" ]]; then
      check_ok "DKIM : permissions clé privée correctes (600)"
    else
      check_warn "DKIM : permissions clé privée = ${DKIM_PERMS} (devrait être 600)"
    fi
  else
    check_fail "DKIM : clé privée absente"
  fi

  if [[ -f "$DKIM_PUB" ]]; then
    check_ok "DKIM : clé publique générée"
    note "  → Contenu à publier dans DNS : ${DKIM_PUB}"
  else
    check_warn "DKIM : clé publique non générée"
  fi

  # Test DKIM (si possible)
  if command -v opendkim-testkey >/dev/null 2>&1; then
    if opendkim-testkey -d "${DKIM_DOMAIN}" -s "${DKIM_SELECTOR}" -x /etc/opendkim.conf 2>&1 | grep -q "key OK"; then
      check_ok "DKIM : clé DNS valide et correspondante"
    else
      check_warn "DKIM : clé DNS non vérifiée (à configurer dans DNS)"
    fi
  fi

  # Comparaison clé locale vs DNS via dig
  if command -v dig >/dev/null 2>&1 && [[ -f "$DKIM_PUB" ]]; then
    DKIM_DNS_RECORD="${DKIM_SELECTOR}._domainkey.${DKIM_DOMAIN}"
    DNS_KEY=$(dig +short TXT "$DKIM_DNS_RECORD" @8.8.8.8 2>/dev/null | tr -d '"\n ' | grep -oP 'p=\K[^;]+')
    LOCAL_KEY=$(cat "$DKIM_PUB" 2>/dev/null | tr -d '"\n\t ()' | grep -oP 'p=\K[^;]+' | head -1)

    if [[ -z "$DNS_KEY" ]]; then
      check_warn "DKIM DNS : enregistrement ${DKIM_DNS_RECORD} non trouvé"
    elif [[ -z "$LOCAL_KEY" ]]; then
      check_warn "DKIM : impossible d'extraire la clé locale"
    elif [[ "$DNS_KEY" == "$LOCAL_KEY" ]]; then
      check_ok "DKIM : clé DNS identique à ${DKIM_PUB}"
    else
      check_fail "DKIM : clé DNS différente de ${DKIM_PUB}"
      note "  → DNS: ${DNS_KEY:0:40}..."
      note "  → Local: ${LOCAL_KEY:0:40}..."
    fi
  fi

  # Vérification file d'attente emails
  MAIL_QUEUE=$(mailq 2>/dev/null | tail -1)
  if echo "$MAIL_QUEUE" | grep -q "Mail queue is empty"; then
    check_ok "Postfix : file d'attente vide (tous les emails envoyés)"
  elif echo "$MAIL_QUEUE" | grep -qE "^[0-9]+ Kbytes"; then
    QUEUED_COUNT=$(mailq 2>/dev/null | grep -c "^[A-F0-9]" || echo "0")
    check_warn "Postfix : ${QUEUED_COUNT} email(s) en attente (mailq pour détails)"
  fi

  # Vérification derniers envois
  if [[ -f /var/log/mail.log ]]; then
    BOUNCED_24H=$(grep -c "status=bounced" /var/log/mail.log 2>/dev/null || echo "0")
    DEFERRED_24H=$(grep -c "status=deferred" /var/log/mail.log 2>/dev/null || echo "0")
    SENT_24H=$(grep -c "status=sent" /var/log/mail.log 2>/dev/null || echo "0")
    if [[ "$BOUNCED_24H" -gt 0 ]]; then
      check_fail "Postfix : ${BOUNCED_24H} email(s) rejeté(s) (vérifier SPF/DKIM)"
    elif [[ "$DEFERRED_24H" -gt 0 ]]; then
      check_warn "Postfix : ${DEFERRED_24H} email(s) différé(s), ${SENT_24H} envoyé(s)"
    elif [[ "$SENT_24H" -gt 0 ]]; then
      check_ok "Postfix : ${SENT_24H} email(s) envoyé(s) avec succès"
    else
      printf "  ${CYAN}Postfix : aucun email récent dans les logs${RESET}\n"
    fi
  fi
fi

echo ""
printf "${BOLD}${MAGENTA}── Configuration système ──${RESET}\n"

# Hostname
CURRENT_HOSTNAME=$(hostname -f 2>/dev/null || hostname)
if [[ "$CURRENT_HOSTNAME" == "$HOSTNAME_FQDN" ]]; then
  check_ok "Hostname : ${CURRENT_HOSTNAME}"
else
  check_warn "Hostname : ${CURRENT_HOSTNAME} (attendu: ${HOSTNAME_FQDN})"
fi

# Timezone
CURRENT_TZ=$(timedatectl show --property=Timezone --value 2>/dev/null || cat /etc/timezone 2>/dev/null)
if [[ "$CURRENT_TZ" == "$TIMEZONE" ]]; then
  check_ok "Timezone : ${CURRENT_TZ}"
else
  check_warn "Timezone : ${CURRENT_TZ} (attendu: ${TIMEZONE})"
fi

# NTP synchronisé
if timedatectl show --property=NTPSynchronized --value 2>/dev/null | grep -q "yes"; then
  check_ok "NTP : synchronisé"
else
  check_warn "NTP : non synchronisé"
fi

# Locale
CURRENT_LANG=$(locale 2>/dev/null | grep "^LANG=" | cut -d= -f2)
if [[ "$CURRENT_LANG" =~ fr_FR ]]; then
  check_ok "Locale : ${CURRENT_LANG}"
else
  check_warn "Locale : ${CURRENT_LANG} (attendu: fr_FR.UTF-8)"
fi

# DNS résolution
if host -W 2 google.com >/dev/null 2>&1 || ping -c1 -W2 8.8.8.8 >/dev/null 2>&1; then
  check_ok "DNS/Réseau : fonctionnel"
else
  check_warn "DNS/Réseau : problème de résolution"
fi

echo ""
printf "${BOLD}${MAGENTA}── Sécurité utilisateurs ──${RESET}\n"

# Clé SSH admin
USER_HOME="$(get_user_home)"
if [[ -f "${USER_HOME}/.ssh/authorized_keys" ]] && [[ -s "${USER_HOME}/.ssh/authorized_keys" ]]; then
  KEY_COUNT=$(grep -c "^ssh-" "${USER_HOME}/.ssh/authorized_keys" 2>/dev/null || echo 0)
  check_ok "SSH : ${KEY_COUNT} clé(s) autorisée(s) pour ${ADMIN_USER}"
else
  check_fail "SSH : aucune clé autorisée pour ${ADMIN_USER}"
fi

# Permissions .ssh
if [[ -d "${USER_HOME}/.ssh" ]]; then
  SSH_DIR_PERMS=$(stat -c %a "${USER_HOME}/.ssh" 2>/dev/null)
  if [[ "$SSH_DIR_PERMS" == "700" ]]; then
    check_ok "SSH : permissions .ssh correctes (700)"
  else
    check_warn "SSH : permissions .ssh = ${SSH_DIR_PERMS} (devrait être 700)"
  fi
fi

# Root login direct désactivé
if passwd -S root 2>/dev/null | grep -qE "^root\s+(L|LK|NP)"; then
  check_ok "Root : compte verrouillé (accès via sudo uniquement)"
else
  check_warn "Root : compte non verrouillé"
fi

# Sudo configuré pour admin
if groups "$ADMIN_USER" 2>/dev/null | grep -qE "(sudo|wheel)"; then
  check_ok "Sudo : ${ADMIN_USER} membre du groupe sudo"
else
  check_warn "Sudo : ${ADMIN_USER} pas dans le groupe sudo"
fi

# Utilisateurs avec UID 0
ROOT_USERS=$(awk -F: '$3 == 0 {print $1}' /etc/passwd | tr '\n' ' ')
if [[ "$ROOT_USERS" == "root " || "$ROOT_USERS" == "root" ]]; then
  check_ok "UID 0 : seul root a l'UID 0"
else
  check_fail "UID 0 : plusieurs utilisateurs (${ROOT_USERS})"
fi

# Dernières connexions SSH (échecs)
if [[ -f /var/log/auth.log ]]; then
  FAILED_SSH_24H=$(grep -c "Failed password" /var/log/auth.log 2>/dev/null || echo 0)
  if [[ "$FAILED_SSH_24H" -eq 0 ]]; then
    check_ok "SSH : pas de tentatives échouées récentes"
  elif [[ "$FAILED_SSH_24H" -lt 50 ]]; then
    printf "  ${CYAN}SSH : ${FAILED_SSH_24H} tentative(s) échouée(s) dans les logs${RESET}\n"
  else
    check_warn "SSH : ${FAILED_SSH_24H} tentatives échouées (brute-force possible)"
  fi
fi

# Dernière connexion réussie
LAST_LOGIN=$(lastlog -u "$ADMIN_USER" 2>/dev/null | tail -1 | awk '{print $4, $5, $6, $7, $9}' | grep -v "Never" || true)
if [[ -n "$LAST_LOGIN" && "$LAST_LOGIN" != *"Never"* ]]; then
  printf "  ${CYAN}Dernière connexion ${ADMIN_USER} : ${LAST_LOGIN}${RESET}\n"
fi

echo ""
printf "${BOLD}${MAGENTA}── Sécurité fichiers ──${RESET}\n"

# World-writable files in /var/www
if $INSTALL_APACHE_PHP; then
  WW_COUNT=$(find /var/www -type f -perm -002 2>/dev/null | wc -l)
  if [[ "$WW_COUNT" -eq 0 ]]; then
    check_ok "Web : pas de fichiers world-writable dans /var/www"
  else
    check_warn "Web : ${WW_COUNT} fichiers world-writable dans /var/www"
  fi

  # Propriétaire /var/www
  WWW_OWNER=$(stat -c %U /var/www/html 2>/dev/null)
  if [[ "$WWW_OWNER" == "www-data" || "$WWW_OWNER" == "root" ]]; then
    check_ok "Web : /var/www/html propriétaire ${WWW_OWNER}"
  else
    check_warn "Web : /var/www/html propriétaire inattendu (${WWW_OWNER})"
  fi
fi

# Fichiers SUID suspects
SUID_COUNT=$(find /usr/local -type f -perm -4000 2>/dev/null | wc -l)
if [[ "$SUID_COUNT" -eq 0 ]]; then
  check_ok "SUID : pas de binaires SUID dans /usr/local"
else
  check_warn "SUID : ${SUID_COUNT} binaires SUID dans /usr/local"
fi

# Permissions /etc/shadow
SHADOW_PERMS=$(stat -c %a /etc/shadow 2>/dev/null)
if [[ "$SHADOW_PERMS" =~ ^(0|640|600)$ ]]; then
  check_ok "Shadow : permissions correctes (${SHADOW_PERMS})"
else
  check_warn "Shadow : permissions = ${SHADOW_PERMS} (devrait être 640 ou 600)"
fi

echo ""
printf "${BOLD}${MAGENTA}── Base de données ──${RESET}\n"

if $INSTALL_MARIADB; then
  # Version MariaDB
  MARIADB_VER=$(mysql --version 2>/dev/null | grep -oP 'Ver \K[0-9.]+' || echo "")
  if [[ -n "$MARIADB_VER" ]]; then
    check_ok "MariaDB : version ${MARIADB_VER}"
  fi

  # MariaDB écoute en local uniquement
  if ss -tlnp 2>/dev/null | grep mysql | grep -q "127.0.0.1:3306"; then
    check_ok "MariaDB : écoute localhost uniquement"
  elif ss -tlnp 2>/dev/null | grep mysql | grep -q "0.0.0.0:3306"; then
    check_warn "MariaDB : écoute toutes interfaces (0.0.0.0)"
  else
    check_ok "MariaDB : socket Unix (pas de port TCP exposé)"
  fi

  # Root sans mot de passe distant
  if mysql -u root -e "SELECT User,Host FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost','127.0.0.1','::1');" 2>/dev/null | grep -q root; then
    check_fail "MariaDB : root accessible à distance"
  else
    check_ok "MariaDB : root localhost uniquement"
  fi

  # Pas d'utilisateur anonyme
  ANON_USERS=$(mysql -u root -e "SELECT COUNT(*) FROM mysql.user WHERE User='';" -sN 2>/dev/null || echo "?")
  if [[ "$ANON_USERS" == "0" ]]; then
    check_ok "MariaDB : pas d'utilisateur anonyme"
  elif [[ "$ANON_USERS" == "?" ]]; then
    check_warn "MariaDB : impossible de vérifier les utilisateurs"
  else
    check_fail "MariaDB : ${ANON_USERS} utilisateur(s) anonyme(s)"
  fi

  # Base de test supprimée
  TEST_DB=$(mysql -u root -e "SHOW DATABASES LIKE 'test';" -sN 2>/dev/null || echo "")
  if [[ -z "$TEST_DB" ]]; then
    check_ok "MariaDB : base 'test' supprimée"
  else
    check_warn "MariaDB : base 'test' existe encore"
  fi

  # Nombre de bases de données
  DB_COUNT=$(mysql -u root -e "SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME NOT IN ('information_schema','mysql','performance_schema','sys');" -sN 2>/dev/null || echo "?")
  if [[ "$DB_COUNT" != "?" ]]; then
    printf "  ${CYAN}MariaDB : ${DB_COUNT} base(s) de données utilisateur${RESET}\n"
  fi
fi

echo ""
printf "${BOLD}${MAGENTA}── Ressources système ──${RESET}\n"

# Espace disque
DISK_USAGE=$(df -h / | awk 'NR==2 {print $5}' | tr -d '%')
DISK_AVAIL=$(df -h / | awk 'NR==2 {print $4}')
if [[ "$DISK_USAGE" -lt 80 ]]; then
  check_ok "Disque / : ${DISK_USAGE}% utilisé (${DISK_AVAIL} libre)"
elif [[ "$DISK_USAGE" -lt 90 ]]; then
  check_warn "Disque / : ${DISK_USAGE}% utilisé (${DISK_AVAIL} libre)"
else
  check_fail "Disque / : ${DISK_USAGE}% utilisé - CRITIQUE"
fi

# Mémoire
MEM_TOTAL=$(free -h | awk '/^Mem:/ {print $2}')
MEM_AVAIL=$(free -h | awk '/^Mem:/ {print $7}')
MEM_USED_PCT=$(free | awk '/^Mem:/ {printf "%.0f", $3/$2*100}')
if [[ "$MEM_USED_PCT" -lt 80 ]]; then
  check_ok "RAM : ${MEM_USED_PCT}% utilisée (${MEM_AVAIL} disponible sur ${MEM_TOTAL})"
else
  check_warn "RAM : ${MEM_USED_PCT}% utilisée (${MEM_AVAIL} disponible)"
fi

# Swap
if swapon --show | grep -q .; then
  SWAP_SIZE=$(free -h | awk '/^Swap:/ {print $2}')
  check_ok "Swap : ${SWAP_SIZE} configuré"
else
  check_warn "Swap : non configuré"
fi

# Load average
LOAD_1=$(cat /proc/loadavg | awk '{print $1}')
CPU_COUNT=$(nproc)
LOAD_PCT=$(echo "$LOAD_1 $CPU_COUNT" | awk '{printf "%.0f", ($1/$2)*100}')
if [[ "$LOAD_PCT" -lt 70 ]]; then
  check_ok "Load : ${LOAD_1} (${LOAD_PCT}% de ${CPU_COUNT} CPU)"
else
  check_warn "Load : ${LOAD_1} (${LOAD_PCT}% de ${CPU_COUNT} CPU) - élevé"
fi

# Uptime
UPTIME=$(uptime -p | sed 's/up //')
printf "  ${CYAN}Uptime : %s${RESET}\n" "$UPTIME"

# Inodes
INODE_USAGE=$(df -i / | awk 'NR==2 {print $5}' | tr -d '%')
INODE_AVAIL=$(df -i / | awk 'NR==2 {print $4}')
if [[ "$INODE_USAGE" -lt 80 ]]; then
  check_ok "Inodes / : ${INODE_USAGE}% utilisés (${INODE_AVAIL} disponibles)"
elif [[ "$INODE_USAGE" -lt 95 ]]; then
  check_warn "Inodes / : ${INODE_USAGE}% utilisés - surveillez"
else
  check_fail "Inodes / : ${INODE_USAGE}% utilisés - CRITIQUE"
fi

# Processus zombies
ZOMBIES=$(ps aux | grep -c ' Z ' 2>/dev/null || echo 0)
# Exclure la ligne du grep elle-même
ZOMBIES=$((ZOMBIES > 0 ? ZOMBIES - 1 : 0))
if [[ "$ZOMBIES" -eq 0 ]]; then
  check_ok "Processus : pas de zombies"
else
  check_warn "Processus : ${ZOMBIES} zombie(s) détecté(s)"
fi

# OOM Killer récent
OOM_EVENTS=0
if dmesg &>/dev/null; then
  OOM_EVENTS=$(dmesg 2>/dev/null | grep -c "Out of memory" || true)
else
  OOM_EVENTS=$(journalctl -k --since "7 days ago" 2>/dev/null | grep -c "Out of memory" || true)
fi
OOM_EVENTS=$(echo "$OOM_EVENTS" | tr -d '[:space:]')
OOM_EVENTS=${OOM_EVENTS:-0}
if [[ "$OOM_EVENTS" -gt 0 ]]; then
  check_warn "Mémoire : ${OOM_EVENTS} événement(s) OOM Killer récent(s)"
fi

echo ""
printf "${BOLD}${MAGENTA}── Ports ouverts (UFW) ──${RESET}\n"

if $INSTALL_UFW && command -v ufw >/dev/null 2>&1; then
  ufw status | grep -E "^\s*[0-9]+" | while read -r line; do
    printf "  ${CYAN}%s${RESET}\n" "$line"
  done
fi

echo ""
printf "${BOLD}${MAGENTA}── Services en écoute ──${RESET}\n"

# Lister les ports en écoute
ss -tlnp 2>/dev/null | grep LISTEN | awk '{print $4}' | sort -u | while read -r addr; do
  PORT=$(echo "$addr" | rev | cut -d: -f1 | rev)
  BIND=$(echo "$addr" | rev | cut -d: -f2- | rev)
  case "$PORT" in
    22|${SSH_PORT}) SVC="SSH" ;;
    80) SVC="HTTP" ;;
    443) SVC="HTTPS" ;;
    3306) SVC="MariaDB" ;;
    25|587) SVC="SMTP" ;;
    8891) SVC="OpenDKIM" ;;
    *) SVC="" ;;
  esac
  if [[ "$BIND" == "127.0.0.1" || "$BIND" == "::1" ]]; then
    printf "  ${GREEN}%s${RESET} → port %s (local)\n" "${SVC:-Service}" "$PORT"
  else
    printf "  ${YELLOW}%s${RESET} → port %s (%s)\n" "${SVC:-Service}" "$PORT" "$BIND"
  fi
done

echo ""
printf "${BOLD}${MAGENTA}── Vérification DNS ──${RESET}\n"

# IP publique du serveur
SERVER_IP=$(curl -s --max-time 5 https://api.ipify.org 2>/dev/null || curl -s --max-time 5 https://ifconfig.me 2>/dev/null || echo "")

if [[ -n "$SERVER_IP" ]]; then
  printf "  ${CYAN}IP publique : %s${RESET}\n" "$SERVER_IP"
fi

# Domaine de base (sans sous-domaine)
# Compte le nombre de points dans le FQDN
DOT_COUNT=$(echo "$HOSTNAME_FQDN" | tr -cd '.' | wc -c)
if [[ "$DOT_COUNT" -le 1 ]]; then
  # Domaine simple (ex: example.com) -> garder tel quel
  BASE_DOMAIN="$HOSTNAME_FQDN"
else
  # Sous-domaine (ex: www.example.com) -> extraire domaine de base
  BASE_DOMAIN="${HOSTNAME_FQDN#*.}"
fi

# Vérification enregistrement A (utilise DNS public pour éviter cache local)
if command -v dig >/dev/null 2>&1; then
  DNS_A=$(dig +short A "$HOSTNAME_FQDN" @8.8.8.8 2>/dev/null | head -1)
  if [[ -n "$DNS_A" ]]; then
    if [[ "$DNS_A" == "$SERVER_IP" ]]; then
      check_ok "DNS A : ${HOSTNAME_FQDN} → ${DNS_A} (correspond à ce serveur)"
    else
      check_warn "DNS A : ${HOSTNAME_FQDN} → ${DNS_A} (ce serveur = ${SERVER_IP})"
    fi
  else
    check_warn "DNS A : ${HOSTNAME_FQDN} non résolu"
  fi

  # Vérification www
  DNS_WWW=$(dig +short A "www.${HOSTNAME_FQDN}" @8.8.8.8 2>/dev/null | head -1)
  if [[ -n "$DNS_WWW" ]]; then
    if [[ "$DNS_WWW" == "$SERVER_IP" || "$DNS_WWW" == "$DNS_A" ]]; then
      check_ok "DNS A : www.${HOSTNAME_FQDN} → ${DNS_WWW}"
    else
      check_warn "DNS A : www.${HOSTNAME_FQDN} → ${DNS_WWW} (différent)"
    fi
  else
    check_warn "DNS A : www.${HOSTNAME_FQDN} non résolu"
  fi

  # MX records
  DNS_MX=$(dig +short MX "$BASE_DOMAIN" @8.8.8.8 2>/dev/null | head -1)
  if [[ -n "$DNS_MX" ]]; then
    check_ok "DNS MX : ${BASE_DOMAIN} → ${DNS_MX}"
  else
    check_warn "DNS MX : ${BASE_DOMAIN} non configuré"
  fi

  # SPF record
  DNS_SPF=$(dig +short TXT "$BASE_DOMAIN" @8.8.8.8 2>/dev/null | grep -i "v=spf1" | head -1 || true)
  if [[ -n "$DNS_SPF" ]]; then
    if echo "$DNS_SPF" | grep -qE "(include:|a |mx |ip4:)"; then
      check_ok "DNS SPF : ${DNS_SPF}"
    else
      check_warn "DNS SPF : présent mais peut-être incomplet"
    fi
  else
    check_fail "DNS SPF : non configuré (emails risquent d'être en spam)"
  fi

  # DKIM record
  if [[ -n "${DKIM_SELECTOR:-}" && -n "${DKIM_DOMAIN:-}" ]]; then
    DNS_DKIM=$(dig +short TXT "${DKIM_SELECTOR}._domainkey.${DKIM_DOMAIN}" @8.8.8.8 2>/dev/null | head -1)
    if [[ -n "$DNS_DKIM" ]]; then
      if echo "$DNS_DKIM" | grep -q "v=DKIM1"; then
        check_ok "DNS DKIM : ${DKIM_SELECTOR}._domainkey.${DKIM_DOMAIN} configuré"
      else
        check_warn "DNS DKIM : présent mais format inattendu"
      fi
    else
      check_warn "DNS DKIM : ${DKIM_SELECTOR}._domainkey.${DKIM_DOMAIN} non trouvé"
    fi
  fi

  # DMARC record
  DNS_DMARC=$(dig +short TXT "_dmarc.${BASE_DOMAIN}" @8.8.8.8 2>/dev/null | grep -i "v=DMARC1" | head -1 || true)
  if [[ -n "$DNS_DMARC" ]]; then
    if echo "$DNS_DMARC" | grep -qE "p=(none|quarantine|reject)"; then
      DMARC_POLICY=$(echo "$DNS_DMARC" | grep -oE "p=(none|quarantine|reject)" | cut -d= -f2)
      if [[ "$DMARC_POLICY" == "none" ]]; then
        check_warn "DNS DMARC : policy=none (trop permissif, passer à quarantine)"
      else
        check_ok "DNS DMARC : politique=${DMARC_POLICY}"
      fi
    else
      check_warn "DNS DMARC : présent mais politique non définie"
    fi
  else
    check_warn "DNS DMARC : _dmarc.${BASE_DOMAIN} non configuré"
  fi

  # PTR (reverse DNS)
  if [[ -n "$SERVER_IP" ]]; then
    DNS_PTR=$(dig +short -x "$SERVER_IP" 2>/dev/null | head -1 | sed 's/\.$//')
    if [[ -n "$DNS_PTR" ]]; then
      if [[ "$DNS_PTR" == "$HOSTNAME_FQDN" || "$DNS_PTR" == *"$BASE_DOMAIN"* ]]; then
        check_ok "DNS PTR : ${SERVER_IP} → ${DNS_PTR}"
      else
        check_warn "DNS PTR : ${SERVER_IP} → ${DNS_PTR} (attendu: ${HOSTNAME_FQDN})"
      fi
    else
      check_warn "DNS PTR : reverse DNS non configuré pour ${SERVER_IP}"
    fi
  fi
else
  check_warn "dig non disponible - installation de dnsutils requise pour les checks DNS"
fi

# Résumé
echo ""
printf "${BOLD}══════════════════════════════════════════════════════════════${RESET}\n"
printf "${BOLD}  Résumé : ${GREEN}%d OK${RESET} | ${YELLOW}%d avertissements${RESET} | ${RED}%d erreurs${RESET}\n" "$CHECKS_OK" "$CHECKS_WARN" "$CHECKS_FAIL"
printf "${BOLD}══════════════════════════════════════════════════════════════${RESET}\n"

if [[ $CHECKS_FAIL -gt 0 ]]; then
  warn "Des erreurs ont été détectées. Vérifiez les points ci-dessus."
elif [[ $CHECKS_WARN -gt 0 ]]; then
  note "Quelques avertissements, mais l'installation semble fonctionnelle."
else
  log "Toutes les vérifications sont passées avec succès !"
fi

# ---------------------------------- 18) Récapitulatif & Notes -------------------------
section "Récapitulatif & Prochaines étapes"

print_title() { printf "${BOLD}${CYAN}▸ %s${RESET}\n" "$1"; }
print_cmd()   { printf "  ${GREEN}%s${RESET}\n" "$1"; }
print_note()  { printf "  ${YELLOW}%s${RESET}\n" "$1"; }

echo ""
print_title "Connexion SSH (clé uniquement)"
print_cmd "ssh -p ${SSH_PORT} ${ADMIN_USER}@${HOSTNAME_FQDN}"
echo ""

print_title "Certificats TLS (Let's Encrypt)"
print_note "Quand le DNS pointe bien ici, exécute :"
print_cmd "certbot --apache -d ${HOSTNAME_FQDN} -d www.${HOSTNAME_FQDN} --email ${EMAIL_FOR_CERTBOT} --agree-tos -n"
print_cmd "systemctl reload apache2"
echo ""

print_title "DKIM (OpenDKIM)"
print_note "Vérification correspondance clé publique/privée :"
print_cmd "opendkim-testkey -d ${DKIM_DOMAIN} -s ${DKIM_SELECTOR} -x /etc/opendkim.conf"
print_note "Si mismatch, mettre à jour le TXT ${DKIM_SELECTOR}._domainkey.${DKIM_DOMAIN}"
print_note "Clé publique : ${DKIM_KEYDIR}/${DKIM_SELECTOR}.txt"
echo ""

print_title "Vérification emails (Postfix)"
print_note "Voir les derniers emails envoyés :"
print_cmd "grep -E 'status=(sent|deferred|bounced)' /var/log/mail.log | tail -20"
print_note "File d'attente (emails en attente/échec) :"
print_cmd "mailq"
print_note "Détails d'un email bloqué (ID visible dans mailq) :"
print_cmd "postcat -q <ID>"
print_note "Forcer le renvoi des emails en attente :"
print_cmd "postqueue -f"
print_note "Envoyer un email de test :"
print_cmd "echo 'Test depuis ${HOSTNAME_FQDN}' | mail -s 'Test Postfix' ${EMAIL_FOR_CERTBOT}"
print_note "Statuts : sent=OK | deferred=réessai auto | bounced=rejeté (vérifier SPF/DKIM)"
echo ""

print_title "Pare-feu (UFW)"
print_cmd "ufw status verbose"
echo ""

print_title "Fail2ban"
print_cmd "fail2ban-client status sshd"
echo ""

if $GEOIP_BLOCK; then
  print_title "Blocage GeoIP (Asie + Afrique)"
  print_note "103 pays bloqués via ipset + UFW"
  print_cmd "ipset list geoip_blocked | wc -l    # Nombre de plages bloquées"
  print_note "Débloquer un pays (ex: Japon 'jp') :"
  print_cmd "nano /usr/local/bin/geoip-update.sh  # Retirer 'jp' de ASIA"
  print_cmd "/usr/local/bin/geoip-update.sh       # Recharger les plages"
  print_cmd "ufw reload"
  print_note "Débloquer une IP spécifique temporairement :"
  print_cmd "ipset del geoip_blocked <IP>"
  print_note "Débloquer une IP définitivement (whitelist UFW) :"
  print_cmd "ufw insert 1 allow from <IP>"
  print_note "Voir les connexions bloquées :"
  print_cmd "dmesg | grep -i 'blocked' | tail -20"
  print_note "Mise à jour auto: /etc/cron.weekly/geoip-update"
  echo ""
fi

print_title "MariaDB"
print_note "Hardening de base effectué (test DB supprimée, comptes vides nettoyés)"
print_note "Crée un utilisateur applicatif dédié pour ta/tes app(s)"
echo ""

if $INSTALL_PHPMYADMIN && [[ -f /root/.phpmyadmin_alias ]]; then
  PMA_ALIAS_RECAP=$(cat /root/.phpmyadmin_alias)
  print_title "phpMyAdmin"
  print_cmd "https://${HOSTNAME_FQDN}/${PMA_ALIAS_RECAP}"
  print_note "URL masquée pour éviter les scans automatiques"
  print_note "Connexion avec un utilisateur MariaDB"
  echo ""
fi

if $INSTALL_CLAMAV; then
  print_title "ClamAV"
  print_note "Scan quotidien à 2h00 : /root/scripts/clamav_scan.sh"
  print_note "Logs : /var/log/clamav/"
  print_note "Mail d'alerte → ${EMAIL_FOR_CERTBOT}"
  print_cmd "crontab -l | grep clamav"
  echo ""
fi

print_title "Mises à jour"
print_note "unattended-upgrades : patchs sécurité auto"
print_note "check-updates.sh : rapport hebdo (lundi 7h00) → ${EMAIL_FOR_CERTBOT}"
print_cmd "crontab -l | grep check-updates"
echo ""

if $INSTALL_PYTHON3; then
  print_title "Python 3"
  print_note "Version : $(python3 --version 2>/dev/null | awk '{print $2}')"
  print_note "pip, venv, pipx installés (PEP 668 compliant)"
  print_note "Créer un environnement virtuel :"
  print_cmd "python3 -m venv mon_projet_venv && source mon_projet_venv/bin/activate"
  print_note "Installer une application Python (recommandé) :"
  print_cmd "pipx install nom_application"
  print_note "Installer un package dans un venv :"
  print_cmd "source mon_venv/bin/activate && pip install nom_package"
  echo ""
fi

if $INSTALL_RKHUNTER; then
  print_title "rkhunter (détection rootkits)"
  print_note "Scan hebdomadaire (dimanche 3h00) → ${EMAIL_FOR_CERTBOT}"
  print_note "Scan manuel :"
  print_cmd "rkhunter --check --skip-keypress"
  print_note "Mettre à jour après install paquets :"
  print_cmd "rkhunter --propupd"
  echo ""
fi

if $INSTALL_LOGWATCH; then
  print_title "Logwatch (résumé des logs)"
  print_note "Rapport quotidien automatique → ${EMAIL_FOR_CERTBOT}"
  print_note "Exécution manuelle :"
  print_cmd "logwatch --output mail --mailto ${EMAIL_FOR_CERTBOT} --detail Med"
  echo ""
fi

if $INSTALL_SSH_ALERT; then
  print_title "Alertes SSH"
  print_note "Email envoyé à chaque connexion SSH → ${EMAIL_FOR_CERTBOT}"
  print_note "Inclut : IP, géolocalisation, date/heure"
  echo ""
fi

if $INSTALL_AIDE; then
  print_title "AIDE (intégrité fichiers)"
  print_note "Vérification quotidienne (4h00) → ${EMAIL_FOR_CERTBOT}"
  print_note "Vérification manuelle :"
  print_cmd "aide --check"
  print_note "Après mises à jour système légitimes :"
  print_cmd "aide --update && mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db"
  echo ""
fi

if $INSTALL_MODSEC_CRS && $INSTALL_APACHE_PHP; then
  print_title "ModSecurity OWASP CRS"
  print_note "Mode actuel : DetectionOnly (logs sans blocage)"
  print_note "Voir les alertes :"
  print_cmd "tail -f /var/log/apache2/modsec_audit.log"
  print_note "Activer le blocage (après validation) :"
  print_cmd "sed -i 's/SecRuleEngine DetectionOnly/SecRuleEngine On/' /etc/modsecurity/modsecurity.conf && systemctl restart apache2"
  echo ""
fi

if $SECURE_TMP; then
  print_title "Sécurisation /tmp"
  print_note "/tmp et /var/tmp montés avec noexec,nosuid,nodev"
  print_note "Empêche l'exécution de scripts malveillants depuis /tmp"
  echo ""
fi

print_title "Audit de sécurité"
print_note "Rapport hebdomadaire (lundi 7h00) → ${EMAIL_FOR_CERTBOT}"
print_note "Exécution manuelle :"
print_cmd "sudo ${0} --audit"
echo ""

print_title "Sécurité noyau & journaux"
print_note "sysctl durci ; journald en stockage persistant"
echo ""

print_title "Remarques DNS (actions requises)"
if [[ -z "${DNS_MX:-}" ]]; then
  print_note "⚠ MX : non configuré - configurer chez le registrar si emails entrants requis"
else
  print_note "MX : ${DNS_MX}"
fi
if [[ -z "${DNS_SPF:-}" ]]; then
  print_note "⚠ SPF : non configuré - ajouter TXT \"v=spf1 a mx ~all\" pour éviter le spam"
else
  print_note "SPF : configuré"
fi
if [[ -z "${DNS_DMARC:-}" ]]; then
  print_note "⚠ DMARC : non configuré - ajouter TXT _dmarc avec p=quarantine"
elif echo "${DNS_DMARC:-}" | grep -q "p=none"; then
  print_note "⚠ DMARC : policy=none (trop permissif, passer à quarantine ou reject)"
else
  print_note "DMARC : configuré"
fi
print_note "Postfix : envoi local uniquement (loopback-only)"
echo ""

printf "${CYAN}Fichier log :${RESET} %s\n\n" "${LOG_FILE}"

# ================================== MODE AUDIT : EMAIL ================================
if $AUDIT_MODE; then
  AUDIT_REPORT="$(mktempfile .html)"

  # Génère le rapport HTML avec charte graphique Since & Co
  # Version email-compatible (tables, inline styles, pas de SVG)
  # Couleurs: #dc5c3b (orange), #142136 (bleu foncé), #f2fafa (fond), #99c454 (vert)
  cat > "$AUDIT_REPORT" <<'HTMLEOF'
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Audit de sécurité</title>
</head>
<body style="margin:0; padding:0; background-color:#f2fafa; font-family:Arial, Helvetica, sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background-color:#f2fafa;">
    <tr>
      <td align="center" style="padding:20px;">
        <table width="600" cellpadding="0" cellspacing="0" style="background-color:#ffffff; border-radius:8px; overflow:hidden; box-shadow:0 2px 8px rgba(0,0,0,0.1);">
          <!-- Header -->
          <tr>
            <td style="background-color:#142136; padding:30px; text-align:center;">
              <img src="data:image/svg+xml;base64,PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz48c3ZnIGlkPSJDYWxxdWVfMiIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIiB2aWV3Qm94PSIwIDAgMTMyLjQzMDggMTQwLjAwNyI+PGcgaWQ9IkNvbXBvbmVudHMiPjxnIGlkPSJfOTZmMTU1MTgtYWUxMy00N2IxLWIyMjAtMTkwNmU3NjUyMWViXzEiPjxwYXRoIGQ9Ik0xMDEuNzUwMiwxLjMzMTZsLTQ4Ljg3NjUsMjcuMzYwM2MtMy4yOTcyLDEuODQ2NS0zLjI4MTcsNi41NDI4LS4wMzEsOC40NzAyLDQ0LjY1NTIsMjYuNDYwMywzMi44MjQxLDYwLjYzMTksMTYuMzA1NCw4My42NjU5LTMuMjA3Nyw0LjQ2OTEsMi4zMTQ2LDkuOTYzOSw2Ljc5NCw2Ljc3MzRDMTExLjE3NTUsMTAyLjUxNzgsMTU4LjcxNDksNTUuMjg2NSwxMTQuNzA2OCwzLjU4OTRjLTMuMTkyMi0zLjc0OTgtOC42NTc4LTQuNjYzNi0xMi45NTY1LTIuMjU3OCIgc3R5bGU9ImZpbGw6I2RjNWMzYjsgc3Ryb2tlLXdpZHRoOjBweDsiLz48cGF0aCBkPSJNMzAuOTQwMyw0My44MTMxTDIuNTg0NSw1OS42ODc1Yy0zLjQyNTQsMS45MTU4LTMuNDMwOCw2Ljc0MTItLjEwNiw4LjgyMjMsMzIuMjY2NSwyMC4xNzY5LDI0LjQzOCw0NS42ODQxLDEyLjE4NjYsNjMuNTMzNy0zLjA5NjUsNC41MTQ1LDIuMjUxOSwxMC4wNjc4LDYuODg2OCw3LjE1NDUsMzIuMTY0LTIwLjIyMTgsNzUuMjYwMi01OC4zNDE2LDIwLjg3Ni05NC44NjItMy40MzA4LTIuMzAyMi03Ljg4MjQtMi41NDEyLTExLjQ4NzUtLjUyMyIgc3R5bGU9ImZpbGw6I2RjNWMzYjsgc3Ryb2tlLXdpZHRoOjBweDsiLz48L2c+PC9nPjwvc3ZnPg==" alt="Since & Co" width="45" height="48" style="display:block; margin:0 auto 15px auto;">
              <h1 style="color:#ffffff; font-size:22px; margin:0; font-weight:600;">Audit de sécurité</h1>
HTMLEOF

  # Ajouter les infos dynamiques dans le header
  cat >> "$AUDIT_REPORT" <<HTMLEOF
              <p style="color:#6bdbdb; font-size:13px; margin:8px 0 0 0;">${HOSTNAME_FQDN} • $(date '+%d/%m/%Y %H:%M') • v${SCRIPT_VERSION}</p>
            </td>
          </tr>
          <!-- Résumé -->
          <tr>
            <td style="padding:20px; background-color:#f8f9fa;">
              <table width="100%" cellpadding="0" cellspacing="0">
                <tr>
                  <td width="33%" style="padding:5px;">
                    <table width="100%" cellpadding="15" cellspacing="0" style="background-color:#e8f5e9; border-radius:8px; border-left:4px solid #99c454;">
                      <tr><td align="center">
                        <div style="font-size:28px; font-weight:bold; color:#2e7d32;">${CHECKS_OK}</div>
                        <div style="font-size:11px; color:#666; text-transform:uppercase;">OK</div>
                      </td></tr>
                    </table>
                  </td>
                  <td width="33%" style="padding:5px;">
                    <table width="100%" cellpadding="15" cellspacing="0" style="background-color:#fff3e0; border-radius:8px; border-left:4px solid #ff9800;">
                      <tr><td align="center">
                        <div style="font-size:28px; font-weight:bold; color:#e65100;">${CHECKS_WARN}</div>
                        <div style="font-size:11px; color:#666; text-transform:uppercase;">Warn</div>
                      </td></tr>
                    </table>
                  </td>
                  <td width="33%" style="padding:5px;">
                    <table width="100%" cellpadding="15" cellspacing="0" style="background-color:#ffebee; border-radius:8px; border-left:4px solid #dc5c3b;">
                      <tr><td align="center">
                        <div style="font-size:28px; font-weight:bold; color:#dc5c3b;">${CHECKS_FAIL}</div>
                        <div style="font-size:11px; color:#666; text-transform:uppercase;">Erreurs</div>
                      </td></tr>
                    </table>
                  </td>
                </tr>
              </table>
            </td>
          </tr>
          <!-- Contenu -->
          <tr>
            <td style="padding:25px;">
HTMLEOF

  # Fonctions pour générer le HTML
  add_html_section() {
    local title="$1"
    local icon=""
    # Icônes par section
    case "$title" in
      *Services*) icon="⚙" ;;
      *SSH*) icon="🔐" ;;
      *Web*) icon="🌐" ;;
      *DNS*) icon="📡" ;;
      *Protection*) icon="🛡" ;;
      *Apache*) icon="📊" ;;
      *menaces*) icon="🦠" ;;
      *Emails*) icon="✉" ;;
      *Ressources*) icon="💻" ;;
      *) icon="📋" ;;
    esac
    cat >> "$AUDIT_REPORT" <<SECTIONHTML
              <table width="100%" cellpadding="0" cellspacing="0" style="margin-top:20px;">
                <tr>
                  <td style="background:linear-gradient(90deg, #142136 0%, #1e3a5f 100%); padding:10px 15px; border-radius:8px 8px 0 0;">
                    <span style="font-size:16px; margin-right:8px;">${icon}</span>
                    <span style="color:#ffffff; font-size:14px; font-weight:600;">${title}</span>
                  </td>
                </tr>
                <tr>
                  <td style="background-color:#f8f9fa; border-radius:0 0 8px 8px; border:1px solid #e8e8e8; border-top:none;">
                    <table width="100%" cellpadding="0" cellspacing="0">
SECTIONHTML
  }

  add_html_check() {
    local status="$1" msg="$2"
    local color="${HTML_COLOR_CYAN}" icon="•" bg="#f8f9fa"
    case "$status" in
      ok) color="#2e7d32"; icon="✓"; bg="#f1f8e9" ;;
      warn) color="#e65100"; icon="⚠"; bg="#fff8e1" ;;
      fail) color="#c62828"; icon="✗"; bg="#ffebee" ;;
      info) color="#1565c0"; icon="ℹ"; bg="#e3f2fd" ;;
    esac
    echo "<tr><td style='padding:8px 15px; font-size:13px; background:${bg}; border-bottom:1px solid #eee;'><span style='color:${color}; font-weight:bold; font-size:14px; margin-right:10px;'>${icon}</span>${msg}</td></tr>" >> "$AUDIT_REPORT"
  }

  # Fonction pour ajouter une barre de progression
  add_progress_bar() {
    local label="$1" value="$2" max="${3:-100}" color="${4:-green}"
    local pct=$((value * 100 / max))
    [[ "$pct" -gt 100 ]] && pct=100
    local bar_color="${HTML_COLOR_GREEN}"
    case "$color" in
      orange) bar_color="#ff9800" ;;
      red) bar_color="${HTML_COLOR_ACCENT}" ;;
      cyan) bar_color="${HTML_COLOR_CYAN}" ;;
    esac
    cat >> "$AUDIT_REPORT" <<PROGHTML
                <tr><td style="padding:8px 12px;">
                  <table width="100%" cellpadding="0" cellspacing="0">
                    <tr>
                      <td style="font-size:12px; color:#333;">${label}</td>
                      <td width="50" align="right" style="font-size:12px; font-weight:bold; color:#333;">${value}%</td>
                    </tr>
                    <tr>
                      <td colspan="2" style="padding-top:4px;">
                        <table width="100%" cellpadding="0" cellspacing="0" style="background-color:#e0e0e0; border-radius:4px; height:8px;">
                          <tr><td width="${pct}%" style="background-color:${bar_color}; border-radius:4px;"></td><td></td></tr>
                        </table>
                      </td>
                    </tr>
                  </table>
                </td></tr>
PROGHTML
  }

  # Fonction pour ajouter une grille de stats (simplifié pour email)
  add_stats_grid_open() {
    echo "<tr><td style='padding:10px 12px;'><table width='100%' cellpadding='0' cellspacing='8'><tr>" >> "$AUDIT_REPORT"
  }

  add_stat_box() {
    local value="$1" label="$2" color="${3:-}"
    local val_color="${HTML_COLOR_DARK}"
    case "$color" in
      accent) val_color="${HTML_COLOR_ACCENT}" ;;
      cyan) val_color="${HTML_COLOR_CYAN}" ;;
      green) val_color="${HTML_COLOR_GREEN}" ;;
    esac
    echo "<td width='50%' style='background:#fff; border-radius:8px; padding:12px; text-align:center; border:1px solid #eee;'><div style='font-size:22px; font-weight:bold; color:${val_color};'>${value}</div><div style='font-size:10px; color:#888; text-transform:uppercase;'>${label}</div></td>" >> "$AUDIT_REPORT"
  }

  add_stats_grid_close() {
    echo "</tr></table></td></tr>" >> "$AUDIT_REPORT"
  }

  close_section() {
    echo "</table></td></tr></table>" >> "$AUDIT_REPORT"
  }

  # Services
  add_html_section "Services"
  check_service_active sshd "SSH" html || check_service_active ssh "SSH" html || true
  ufw status | grep -qiE "(Status|État).*acti" && add_html_check ok "UFW : actif" || add_html_check warn "UFW : inactif"
  check_service_active fail2ban "Fail2ban" html
  $INSTALL_APACHE_PHP && check_service_active apache2 "Apache" html
  $INSTALL_MARIADB && check_service_active mariadb "MariaDB" html
  $INSTALL_POSTFIX_DKIM && check_service_active postfix "Postfix" html
  $INSTALL_POSTFIX_DKIM && check_service_active opendkim "OpenDKIM" html
  $INSTALL_CLAMAV && check_service_active clamav-daemon "ClamAV" html
  close_section

  # Sécurité SSH
  add_html_section "Sécurité SSH"
  grep -qE "^\s*PermitRootLogin\s+no" /etc/ssh/sshd_config && add_html_check ok "Root login désactivé" || add_html_check warn "Root login non désactivé"
  grep -qE "^\s*PasswordAuthentication\s+no" /etc/ssh/sshd_config && add_html_check ok "Auth par mot de passe désactivée" || add_html_check warn "Auth par mot de passe active"
  grep -qE "^\s*Port\s+${SSH_PORT}" /etc/ssh/sshd_config && add_html_check ok "Port SSH : ${SSH_PORT}" || add_html_check warn "Port SSH non configuré"
  # Tentatives échouées
  if [[ -f /var/log/auth.log ]]; then
    FAILED_SSH_HTML=$(grep -c "Failed password" /var/log/auth.log 2>/dev/null || echo 0)
    if [[ "$FAILED_SSH_HTML" -lt 50 ]]; then
      add_html_check ok "${FAILED_SSH_HTML} tentatives SSH échouées"
    else
      add_html_check warn "${FAILED_SSH_HTML} tentatives SSH échouées (brute-force?)"
    fi
  fi
  close_section

  # Sécurité Web
  if $INSTALL_APACHE_PHP; then
    add_html_section "Sécurité Web"
    curl -sI http://localhost/ 2>/dev/null | grep -qi "X-Powered-By:.*PHP" && add_html_check warn "expose_php visible" || add_html_check ok "expose_php masqué"
    a2query -m security2 >/dev/null 2>&1 && add_html_check ok "mod_security activé" || add_html_check warn "mod_security non activé"
    a2query -m headers >/dev/null 2>&1 && add_html_check ok "mod_headers activé" || add_html_check warn "mod_headers non activé"
    # Certificat SSL
    if $INSTALL_CERTBOT && [[ -f "/etc/letsencrypt/live/${HOSTNAME_FQDN}/cert.pem" ]]; then
      CERT_EXP_HTML=$(openssl x509 -enddate -noout -in "/etc/letsencrypt/live/${HOSTNAME_FQDN}/cert.pem" 2>/dev/null | cut -d= -f2)
      CERT_EXP_EPOCH_HTML=$(date -d "$CERT_EXP_HTML" +%s 2>/dev/null || echo 0)
      DAYS_LEFT_HTML=$(( (CERT_EXP_EPOCH_HTML - $(date +%s)) / 86400 ))
      if [[ "$DAYS_LEFT_HTML" -gt "$SSL_WARN_DAYS" ]]; then
        add_html_check ok "SSL : expire dans ${DAYS_LEFT_HTML} jours"
      elif [[ "$DAYS_LEFT_HTML" -gt 10 ]]; then
        add_html_check warn "SSL : expire dans ${DAYS_LEFT_HTML} jours"
      else
        add_html_check fail "SSL : expire dans ${DAYS_LEFT_HTML} jours - RENOUVELER IMMÉDIATEMENT !"
      fi
    fi
    close_section
  fi

  # DNS
  add_html_section "DNS"
  [[ -n "${DNS_A:-}" ]] && add_html_check ok "A : ${HOSTNAME_FQDN} → ${DNS_A}" || add_html_check warn "A : non résolu"
  [[ -n "${DNS_MX:-}" ]] && add_html_check ok "MX : ${DNS_MX}" || add_html_check warn "MX : non configuré"
  [[ -n "${DNS_SPF:-}" ]] && add_html_check ok "SPF : configuré" || add_html_check fail "SPF : non configuré"
  [[ -n "${DNS_DKIM:-}" ]] && add_html_check ok "DKIM : configuré" || add_html_check warn "DKIM : non configuré"
  if [[ -n "${DNS_DMARC:-}" ]]; then
    echo "${DNS_DMARC}" | grep -q "p=none" && add_html_check warn "DMARC : policy=none (trop permissif)" || add_html_check ok "DMARC : configuré"
  else
    add_html_check warn "DMARC : non configuré"
  fi
  [[ -n "${DNS_PTR:-}" ]] && add_html_check ok "PTR : ${DNS_PTR}" || add_html_check warn "PTR : non configuré"
  close_section

  # Protection GeoIP & ModSecurity
  add_html_section "Protection avancée"

  # GeoIP - Pays bloqués
  if $GEOIP_BLOCK; then
    if ipset list geoip_blocked >/dev/null 2>&1; then
      GEOIP_RANGES_HTML=$(ipset list geoip_blocked 2>/dev/null | grep -c '^[0-9]' || echo "0")
      add_html_check ok "GeoIP : ${GEOIP_RANGES_HTML} plages IP bloquées (${GEOIP_COUNTRY_COUNT} pays)"
      add_stats_grid_open
      add_stat_box "${GEOIP_RANGES_HTML}" "Plages bloquées" "accent"
      add_stat_box "${GEOIP_COUNTRY_COUNT}" "Pays bloqués" "cyan"
      add_stats_grid_close
    else
      add_html_check fail "GeoIP : ipset geoip_blocked non trouvé"
    fi
  else
    add_html_check info "GeoIP : non activé"
  fi

  # ModSecurity stats
  if $INSTALL_MODSEC_CRS && $INSTALL_APACHE_PHP; then
    MODSEC_LOG="/var/log/apache2/modsec_audit.log"
    if [[ -f "$MODSEC_LOG" ]]; then
      # Compter les événements des dernières 24h
      YESTERDAY=$(date -d "yesterday" '+%d/%b/%Y')
      TODAY=$(date '+%d/%b/%Y')
      MODSEC_EVENTS_24H=$(grep -cE "\[${TODAY}|\[${YESTERDAY}" "$MODSEC_LOG" 2>/dev/null || echo "0")
      MODSEC_TOTAL=$(wc -l < "$MODSEC_LOG" 2>/dev/null || echo "0")

      # Mode (DetectionOnly ou On)
      if grep -q "SecRuleEngine On" /etc/modsecurity/modsecurity.conf 2>/dev/null; then
        MODSEC_MODE="Blocage actif"
        add_html_check ok "ModSecurity : mode blocage actif"
      else
        MODSEC_MODE="Détection seule"
        add_html_check warn "ModSecurity : mode détection (non bloquant)"
      fi

      add_stats_grid_open
      add_stat_box "${MODSEC_EVENTS_24H}" "Événements 24h" "accent"
      add_stat_box "${MODSEC_TOTAL}" "Total lignes log" ""
      add_stats_grid_close
    else
      add_html_check info "ModSecurity : pas de logs encore"
    fi
  fi

  # Fail2ban bans actifs
  if systemctl is-active --quiet fail2ban; then
    F2B_TOTAL_BANS=$(fail2ban-client status 2>/dev/null | grep -oP 'Number of jail:\s+\K\d+' || echo "0")
    # Compter les IPs actuellement bannies
    F2B_BANNED_IPS=0
    for jail in $(fail2ban-client status 2>/dev/null | grep "Jail list" | sed 's/.*:\s*//' | tr ',' ' '); do
      banned=$(fail2ban-client status "$jail" 2>/dev/null | grep "Currently banned" | awk '{print $NF}')
      F2B_BANNED_IPS=$((F2B_BANNED_IPS + ${banned:-0}))
    done
    add_html_check ok "Fail2ban : ${F2B_TOTAL_BANS} jail(s), ${F2B_BANNED_IPS} IP(s) bannies"
  fi
  close_section

  # Analyse des logs Apache
  if $INSTALL_APACHE_PHP; then
    add_html_section "Analyse Apache (24h)"

    ACCESS_LOG="/var/log/apache2/access.log"
    ERROR_LOG="/var/log/apache2/error.log"
    # Forcer locale C pour avoir Jan/Feb/Mar (format Apache) au lieu de janv./févr./mars
    TODAY_PATTERN=$(LC_TIME=C date '+%d/%b/%Y')
    YESTERDAY_PATTERN=$(LC_TIME=C date -d "yesterday" '+%d/%b/%Y')

    if [[ -f "$ACCESS_LOG" ]]; then
      # Stats générales access.log (head -1 pour éviter les multi-lignes)
      TOTAL_REQUESTS=$(grep -cE "\[${TODAY_PATTERN}|\[${YESTERDAY_PATTERN}" "$ACCESS_LOG" 2>/dev/null | head -1 || echo "0")
      TOTAL_404=$(grep -E "\[${TODAY_PATTERN}|\[${YESTERDAY_PATTERN}" "$ACCESS_LOG" 2>/dev/null | grep -c '" 404 ' | head -1 || echo "0")
      TOTAL_500=$(grep -E "\[${TODAY_PATTERN}|\[${YESTERDAY_PATTERN}" "$ACCESS_LOG" 2>/dev/null | grep -c '" 50[0-9] ' | head -1 || echo "0")
      UNIQUE_IPS=$(grep -E "\[${TODAY_PATTERN}|\[${YESTERDAY_PATTERN}" "$ACCESS_LOG" 2>/dev/null | awk '{print $1}' | sort -u | wc -l | tr -d ' ' || echo "0")
      # Nettoyer les valeurs (supprimer espaces/newlines)
      TOTAL_REQUESTS=${TOTAL_REQUESTS//[^0-9]/}; [[ -z "$TOTAL_REQUESTS" ]] && TOTAL_REQUESTS=0
      TOTAL_404=${TOTAL_404//[^0-9]/}; [[ -z "$TOTAL_404" ]] && TOTAL_404=0
      TOTAL_500=${TOTAL_500//[^0-9]/}; [[ -z "$TOTAL_500" ]] && TOTAL_500=0
      UNIQUE_IPS=${UNIQUE_IPS//[^0-9]/}; [[ -z "$UNIQUE_IPS" ]] && UNIQUE_IPS=0

      add_stats_grid_open
      add_stat_box "${TOTAL_REQUESTS}" "Requêtes" ""
      add_stat_box "${UNIQUE_IPS}" "IPs uniques" "cyan"
      add_stats_grid_close
      add_stats_grid_open
      add_stat_box "${TOTAL_404}" "Erreurs 404" "accent"
      add_stat_box "${TOTAL_500}" "Erreurs 5xx" "accent"
      add_stats_grid_close

      # Détection URLs suspectes (scanners de vulnérabilités)
      SUSPICIOUS_PATTERNS='(wp-login|wp-admin|wp-content|wp-includes|xmlrpc\.php|\.env|\.git|phpinfo|phpmyadmin|pma|adminer|\.sql|\.bak|\.zip|\.tar|\.rar|shell|eval\(|base64|union.*select|concat\(|etc/passwd|\.\.\/|%2e%2e|<script|\.asp|\.aspx|cgi-bin|\.cgi)'
      SUSPICIOUS_HITS=$(grep -iE "\[${TODAY_PATTERN}|\[${YESTERDAY_PATTERN}" "$ACCESS_LOG" 2>/dev/null | grep -icE "$SUSPICIOUS_PATTERNS" | head -1 || echo "0")
      SUSPICIOUS_HITS=${SUSPICIOUS_HITS//[^0-9]/}; [[ -z "$SUSPICIOUS_HITS" ]] && SUSPICIOUS_HITS=0

      if [[ "$SUSPICIOUS_HITS" -gt 100 ]]; then
        add_html_check fail "URLs suspectes : ${SUSPICIOUS_HITS} requêtes (scanners actifs !)"
      elif [[ "$SUSPICIOUS_HITS" -gt 20 ]]; then
        add_html_check warn "URLs suspectes : ${SUSPICIOUS_HITS} requêtes"
      elif [[ "$SUSPICIOUS_HITS" -gt 0 ]]; then
        add_html_check ok "URLs suspectes : ${SUSPICIOUS_HITS} requêtes (normal)"
      else
        add_html_check ok "Aucune URL suspecte détectée"
      fi

      # Top 5 URLs suspectes
      if [[ "$SUSPICIOUS_HITS" -gt 0 ]]; then
        TOP_SUSPICIOUS=$(grep -iE "\[${TODAY_PATTERN}|\[${YESTERDAY_PATTERN}" "$ACCESS_LOG" 2>/dev/null | \
          grep -iE "$SUSPICIOUS_PATTERNS" | \
          awk '{print $7}' | sort | uniq -c | sort -rn | head -3 | \
          awk '{printf "%s (%d), ", $2, $1}' | sed 's/, $//')
        [[ -n "$TOP_SUSPICIOUS" ]] && add_html_check info "Top URLs ciblées : ${TOP_SUSPICIOUS}"
      fi

      # Bots malveillants (User-Agents suspects)
      BAD_BOTS='(nikto|sqlmap|nmap|masscan|zgrab|census|shodan|curl/|wget/|python-requests|go-http|libwww|scanner|exploit|vulnerability|attack)'
      BAD_BOT_HITS=$(grep -iE "\[${TODAY_PATTERN}|\[${YESTERDAY_PATTERN}" "$ACCESS_LOG" 2>/dev/null | grep -icE "$BAD_BOTS" | head -1 || echo "0")
      BAD_BOT_HITS=${BAD_BOT_HITS//[^0-9]/}; [[ -z "$BAD_BOT_HITS" ]] && BAD_BOT_HITS=0

      if [[ "$BAD_BOT_HITS" -gt 50 ]]; then
        add_html_check fail "Bots malveillants : ${BAD_BOT_HITS} requêtes"
      elif [[ "$BAD_BOT_HITS" -gt 10 ]]; then
        add_html_check warn "Bots malveillants : ${BAD_BOT_HITS} requêtes"
      elif [[ "$BAD_BOT_HITS" -gt 0 ]]; then
        add_html_check ok "Bots suspects : ${BAD_BOT_HITS} requêtes"
      fi
    else
      add_html_check info "access.log non disponible"
    fi

    # Erreurs Apache (error.log)
    if [[ -f "$ERROR_LOG" ]]; then
      # Forcer locale C pour avoir Mon Jan 06 au lieu de lun. janv. 06
      TODAY_ERR=$(LC_TIME=C date '+%a %b %d')
      YESTERDAY_ERR=$(LC_TIME=C date -d "yesterday" '+%a %b %d')
      PHP_ERRORS=$(grep -cE "^\[${TODAY_ERR}|^\[${YESTERDAY_ERR}" "$ERROR_LOG" 2>/dev/null | head -1 || echo "0")
      PHP_ERRORS=${PHP_ERRORS//[^0-9]/}; [[ -z "$PHP_ERRORS" ]] && PHP_ERRORS=0
      PHP_FATAL=$(grep -E "^\[${TODAY_ERR}|^\[${YESTERDAY_ERR}" "$ERROR_LOG" 2>/dev/null | grep -ic "fatal\|critical" | head -1 || echo "0")
      PHP_FATAL=${PHP_FATAL//[^0-9]/}; [[ -z "$PHP_FATAL" ]] && PHP_FATAL=0

      if [[ "$PHP_FATAL" -gt 0 ]]; then
        add_html_check fail "Erreurs fatales PHP : ${PHP_FATAL}"
      elif [[ "$PHP_ERRORS" -gt 100 ]]; then
        add_html_check warn "Erreurs Apache/PHP : ${PHP_ERRORS} (élevé)"
      else
        add_html_check ok "Erreurs Apache/PHP : ${PHP_ERRORS}"
      fi
    fi
    close_section
  fi

  # Bases de menaces (fraîcheur)
  add_html_section "Bases de menaces"

  # ClamAV
  $INSTALL_CLAMAV && check_db_freshness /var/lib/clamav "ClamAV" 1 "$DB_FRESH_DAYS" html

  # rkhunter
  $INSTALL_RKHUNTER && check_db_freshness /var/lib/rkhunter/db/rkhunter.dat "rkhunter" "$DB_FRESH_DAYS" "$DB_STALE_DAYS" html

  # AIDE
  $INSTALL_AIDE && check_db_freshness /var/lib/aide/aide.db "AIDE" "$DB_FRESH_DAYS" "$DB_STALE_DAYS" html

  # Fail2ban
  if systemctl is-active --quiet fail2ban; then
    F2B_BANS=$(fail2ban-client status 2>/dev/null | grep "Number of jail" | awk '{print $NF}')
    add_html_check ok "Fail2ban : ${F2B_BANS:-0} jail(s) active(s)"
  fi

  # IPs de confiance
  if [[ -n "${TRUSTED_IPS:-}" ]]; then
    add_html_check ok "IPs de confiance : ${TRUSTED_IPS}"
    if [[ -f /etc/modsecurity/whitelist-trusted-ips.conf ]]; then
      add_html_check ok "ModSecurity whitelist : configurée"
    fi
  fi

  close_section

  # Emails
  if $INSTALL_POSTFIX_DKIM; then
    add_html_section "Emails (Postfix)"
    MAIL_QUEUE_HTML=$(mailq 2>/dev/null | tail -1)
    if echo "$MAIL_QUEUE_HTML" | grep -q "Mail queue is empty"; then
      add_html_check ok "File d'attente vide"
    else
      QUEUED_COUNT_HTML=$(mailq 2>/dev/null | grep -c "^[A-F0-9]" || echo "0")
      add_html_check warn "${QUEUED_COUNT_HTML} email(s) en attente"
    fi
    if [[ -f /var/log/mail.log ]]; then
      BOUNCED_HTML=$(grep -c "status=bounced" /var/log/mail.log 2>/dev/null || echo "0")
      DEFERRED_HTML=$(grep -c "status=deferred" /var/log/mail.log 2>/dev/null || echo "0")
      SENT_HTML=$(grep -c "status=sent" /var/log/mail.log 2>/dev/null || echo "0")
      [[ "$BOUNCED_HTML" -gt 0 ]] && add_html_check fail "${BOUNCED_HTML} email(s) rejeté(s)"
      [[ "$DEFERRED_HTML" -gt 0 ]] && add_html_check warn "${DEFERRED_HTML} email(s) différé(s)"
      [[ "$SENT_HTML" -gt 0 ]] && add_html_check ok "${SENT_HTML} email(s) envoyé(s)"
    fi
    close_section
  fi

  # Ressources système avec graphiques
  add_html_section "Ressources système"
  DISK_USAGE=$(df -h / | awk 'NR==2 {print $5}' | tr -d '%')
  DISK_TOTAL=$(df -h / | awk 'NR==2 {print $2}')
  DISK_USED=$(df -h / | awk 'NR==2 {print $3}')
  MEM_USED_PCT=$(free | awk '/^Mem:/ {printf "%.0f", $3/$2*100}')
  MEM_TOTAL=$(free -h | awk '/^Mem:/ {print $2}')
  MEM_USED=$(free -h | awk '/^Mem:/ {print $3}')
  LOAD_1=$(cat /proc/loadavg | awk '{print $1}')
  CPU_CORES=$(nproc)

  # Barres de progression pour disque et RAM
  DISK_COLOR="green"
  [[ "$DISK_USAGE" -gt 70 ]] && DISK_COLOR="orange"
  [[ "$DISK_USAGE" -gt 90 ]] && DISK_COLOR="red"
  add_progress_bar "Disque (${DISK_USED} / ${DISK_TOTAL})" "$DISK_USAGE" 100 "$DISK_COLOR"

  MEM_COLOR="green"
  [[ "$MEM_USED_PCT" -gt 70 ]] && MEM_COLOR="orange"
  [[ "$MEM_USED_PCT" -gt 90 ]] && MEM_COLOR="red"
  add_progress_bar "RAM (${MEM_USED} / ${MEM_TOTAL})" "$MEM_USED_PCT" 100 "$MEM_COLOR"

  # Stats grid pour load et uptime
  LOAD_PCT=$(echo "$LOAD_1 $CPU_CORES" | awk '{printf "%.0f", ($1/$2)*100}')
  LOAD_COLOR="green"
  [[ "$LOAD_PCT" -gt 70 ]] && LOAD_COLOR="orange"
  [[ "$LOAD_PCT" -gt 100 ]] && LOAD_COLOR="red"
  add_progress_bar "Load (${LOAD_1} sur ${CPU_CORES} cores)" "$LOAD_PCT" 100 "$LOAD_COLOR"

  # Vérifications complémentaires
  [[ "$DISK_USAGE" -lt 80 ]] && add_html_check ok "Disque : ${DISK_USAGE}% utilisé" || add_html_check warn "Disque : ${DISK_USAGE}% utilisé"
  [[ "$MEM_USED_PCT" -lt 80 ]] && add_html_check ok "RAM : ${MEM_USED_PCT}% utilisée" || add_html_check warn "RAM : ${MEM_USED_PCT}% utilisée"
  add_html_check ok "Load : ${LOAD_1} (${CPU_CORES} cores)"

  # Inodes
  INODE_USAGE_HTML=$(df -i / | awk 'NR==2 {print $5}' | tr -d '%')
  [[ "$INODE_USAGE_HTML" -lt 80 ]] && add_html_check ok "Inodes : ${INODE_USAGE_HTML}% utilisés" || add_html_check warn "Inodes : ${INODE_USAGE_HTML}% utilisés"

  # Taille des logs
  LOG_SIZE_MB_HTML=$(du -sm /var/log 2>/dev/null | awk '{print $1}')
  if [[ -n "$LOG_SIZE_MB_HTML" ]]; then
    LOG_SIZE_HTML=$(du -sh /var/log 2>/dev/null | awk '{print $1}')
    [[ "$LOG_SIZE_MB_HTML" -lt "$LOG_SIZE_WARN_MB" ]] && add_html_check ok "Logs : ${LOG_SIZE_HTML}" || add_html_check warn "Logs : ${LOG_SIZE_HTML}"
  fi

  # Zombies
  ZOMBIES_HTML=$(ps aux 2>/dev/null | grep -c ' Z ' || echo 0)
  ZOMBIES_HTML=$((ZOMBIES_HTML > 0 ? ZOMBIES_HTML - 1 : 0))
  [[ "$ZOMBIES_HTML" -eq 0 ]] && add_html_check ok "Processus zombies : 0" || add_html_check warn "Processus zombies : ${ZOMBIES_HTML}"
  add_html_check ok "Uptime : $(uptime -p | sed 's/up //')"
  close_section

  # Ferme le contenu et ajoute le footer Since & Co
  cat >> "$AUDIT_REPORT" <<'HTMLEOF'
            </td>
          </tr>
          <!-- Footer -->
          <tr>
            <td style="background-color:#142136; padding:25px; text-align:center;">
              <img src="data:image/svg+xml;base64,PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz48c3ZnIGlkPSJDYWxxdWVfMiIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIiB2aWV3Qm94PSIwIDAgMTMyLjQzMDggMTQwLjAwNyI+PGcgaWQ9IkNvbXBvbmVudHMiPjxnIGlkPSJfOTZmMTU1MTgtYWUxMy00N2IxLWIyMjAtMTkwNmU3NjUyMWViXzEiPjxwYXRoIGQ9Ik0xMDEuNzUwMiwxLjMzMTZsLTQ4Ljg3NjUsMjcuMzYwM2MtMy4yOTcyLDEuODQ2NS0zLjI4MTcsNi41NDI4LS4wMzEsOC40NzAyLDQ0LjY1NTIsMjYuNDYwMywzMi44MjQxLDYwLjYzMTksMTYuMzA1NCw4My42NjU5LTMuMjA3Nyw0LjQ2OTEsMi4zMTQ2LDkuOTYzOSw2Ljc5NCw2Ljc3MzRDMTExLjE3NTUsMTAyLjUxNzgsMTU4LjcxNDksNTUuMjg2NSwxMTQuNzA2OCwzLjU4OTRjLTMuMTkyMi0zLjc0OTgtOC42NTc4LTQuNjYzNi0xMi45NTY1LTIuMjU3OCIgc3R5bGU9ImZpbGw6I2RjNWMzYjsgc3Ryb2tlLXdpZHRoOjBweDsiLz48cGF0aCBkPSJNMzAuOTQwMyw0My44MTMxTDIuNTg0NSw1OS42ODc1Yy0zLjQyNTQsMS45MTU4LTMuNDMwOCw2Ljc0MTItLjEwNiw4LjgyMjMsMzIuMjY2NSwyMC4xNzY5LDI0LjQzOCw0NS42ODQxLDEyLjE4NjYsNjMuNTMzNy0zLjA5NjUsNC41MTQ1LDIuMjUxOSwxMC4wNjc4LDYuODg2OCw3LjE1NDUsMzIuMTY0LTIwLjIyMTgsNzUuMjYwMi01OC4zNDE2LDIwLjg3Ni05NC44NjItMy40MzA4LTIuMzAyMi03Ljg4MjQtMi41NDEyLTExLjQ4NzUtLjUyMyIgc3R5bGU9ImZpbGw6I2RjNWMzYjsgc3Ryb2tlLXdpZHRoOjBweDsiLz48L2c+PC9nPjwvc3ZnPg==" alt="Since & Co" width="30" height="32" style="display:block; margin:0 auto 10px auto;">
              <p style="color:#a0a0a0; font-size:12px; margin:0 0 5px 0;">Audit généré par <span style="color:#dc5c3b; font-weight:500;">Since & Co</span></p>
              <p style="color:#666; font-size:11px; margin:0;">Prochain audit : lundi à 7h00</p>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>
HTMLEOF

  # Envoie l'email
  SUBJECT="[Audit v${SCRIPT_VERSION}] ${HOSTNAME_FQDN} - ${CHECKS_OK} OK / ${CHECKS_WARN} warn / ${CHECKS_FAIL} err"
  (
    echo "To: ${EMAIL_FOR_CERTBOT}"
    echo "Subject: ${SUBJECT}"
    echo "Content-Type: text/html; charset=UTF-8"
    echo "MIME-Version: 1.0"
    echo ""
    cat "$AUDIT_REPORT"
  ) | sendmail -t

  log "Rapport d'audit envoyé à ${EMAIL_FOR_CERTBOT}"
  rm -f "$AUDIT_REPORT"
  exit 0
fi

# ================================== COPIE SCRIPT & CRON AUDIT =========================
# Copier le script dans /root/scripts pour le cron (emplacement stable)
INSTALL_SCRIPT_DIR="/root/scripts"
INSTALL_SCRIPT_PATH="${INSTALL_SCRIPT_DIR}/${SCRIPT_NAME}.sh"
INSTALL_CONFIG_PATH="${INSTALL_SCRIPT_DIR}/${SCRIPT_NAME}.conf"
mkdir -p "$INSTALL_SCRIPT_DIR"

# Copier le script si exécuté depuis ailleurs
CURRENT_SCRIPT="$(readlink -f "$0")"
if [[ "$CURRENT_SCRIPT" != "$INSTALL_SCRIPT_PATH" ]]; then
  cp -f "$CURRENT_SCRIPT" "$INSTALL_SCRIPT_PATH"
  chmod +x "$INSTALL_SCRIPT_PATH"
  log "Script copié dans ${INSTALL_SCRIPT_PATH}"
fi

# Copier/migrer la configuration
if [[ -f "$CONFIG_FILE" && "$CONFIG_FILE" != "$INSTALL_CONFIG_PATH" ]]; then
  cp -f "$CONFIG_FILE" "$INSTALL_CONFIG_PATH"
  log "Configuration copiée dans ${INSTALL_CONFIG_PATH}"
fi

# Migrer les anciens fichiers de config si présents
for old_conf in "/root/.bootstrap.conf" "${SCRIPT_DIR}/.bootstrap.conf"; do
  if [[ -f "$old_conf" && ! -f "$INSTALL_CONFIG_PATH" ]]; then
    cp -f "$old_conf" "$INSTALL_CONFIG_PATH"
    log "Configuration migrée de ${old_conf} vers ${INSTALL_CONFIG_PATH}"
    break
  fi
done

# Ajoute/met à jour le cron pour l'audit hebdomadaire
add_cron_job "\-\-audit" "${CRON_AUDIT} ${INSTALL_SCRIPT_PATH} --audit >/dev/null 2>&1" "Audit de sécurité hebdomadaire (lundi 7h00)"
log "Cron audit configuré → ${INSTALL_SCRIPT_PATH} --audit"

# Attendre la fin de l'initialisation AIDE si lancée en arrière-plan
if [[ -n "${AIDE_PID:-}" ]]; then
  log "Attente de la fin de l'initialisation AIDE (PID ${AIDE_PID})..."
  if wait "$AIDE_PID" 2>/dev/null; then
    # Renommer la base AIDE si aideinit a réussi
    if [[ -f /var/lib/aide/aide.db.new ]]; then
      mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
      log "Base AIDE initialisée avec succès."
    fi
  else
    warn "L'initialisation AIDE a échoué (exit code $?). Relancez 'aideinit' manuellement."
  fi
fi

log "Terminé. Garde une session SSH ouverte tant que tu n'as pas validé la nouvelle connexion sur le port ${SSH_PORT}."
