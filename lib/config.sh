#!/usr/bin/env bash
# lib/config.sh — Gestion de la configuration (load, save, prompts, questions)
# Sourcé par debian13-server.sh — Dépend de: lib/core.sh, lib/constants.sh

# ---------------------------------- Valeurs par défaut -------------------------------
HOSTNAME_FQDN_DEFAULT="example.com"
SSH_PORT_DEFAULT="65222"
ADMIN_USER_DEFAULT="debian"
DKIM_SELECTOR_DEFAULT="mail"
DKIM_DOMAIN_DEFAULT="example.com"
EMAIL_FOR_CERTBOT_DEFAULT="root@example.com"
TIMEZONE_DEFAULT="Europe/Paris"

# ---------------------------------- Entrées utilisateur -------------------------------
prompt_default() {
  local p="$1" d="${2:-}"
  local ans=""
  read -r -p "$(printf "${BOLD}${p}${RESET} [${d}]: ")" ans || true
  echo "${ans:-$d}"
}

prompt_yes_no() {
  local q="$1" d="${2:-y}" ans=""
  local def="[Y/n]"; [[ "$d" =~ ^[Nn]$ ]] && def="[y/N]"
  read -r -p "$(printf "${BOLD}${q}${RESET} ${def}: ")" ans || true
  ans="${ans:-$d}"
  [[ "$ans" =~ ^[Yy]$ ]] && return 0 || return 1
}

# ---------------------------------- Config file ---------------------------------------
# Liste unique des variables de configuration — source de vérité
CONFIG_VARS=(
  "HOSTNAME_FQDN|str"  "SSH_PORT|str"  "ADMIN_USER|str"
  "DKIM_SELECTOR|str"  "DKIM_DOMAIN|str"  "EMAIL_FOR_CERTBOT|str"  "TIMEZONE|str"
  "INSTALL_LOCALES|bool"  "INSTALL_SSH_HARDEN|bool"  "INSTALL_UFW|bool"
  "GEOIP_BLOCK|bool"  "INSTALL_FAIL2BAN|bool"  "INSTALL_APACHE_PHP|bool"
  "PHP_DISABLE_FUNCTIONS|bool"  "INSTALL_MARIADB|bool"  "INSTALL_PHPMYADMIN|bool"
  "INSTALL_POSTFIX_DKIM|bool"  "INSTALL_CERTBOT|bool"  "CERTBOT_WILDCARD|bool"  "INSTALL_DEVTOOLS|bool"
  "INSTALL_NODE|bool"  "INSTALL_RUST|bool"  "INSTALL_PYTHON3|bool"
  "INSTALL_COMPOSER|bool"  "INSTALL_SYMFONY|bool"  "INSTALL_SHELL_FUN|bool"
  "INSTALL_YTDL|bool"  "INSTALL_CLAMAV|bool"  "INSTALL_RKHUNTER|bool"
  "INSTALL_LOGWATCH|bool"  "INSTALL_SSH_ALERT|bool"  "INSTALL_AIDE|bool"
  "INSTALL_MODSEC_CRS|bool"  "MODSEC_ENFORCE|bool"  "INSTALL_APPARMOR|bool"  "INSTALL_AUDITD|bool"  "EGRESS_FILTER|bool"
  "SECURE_TMP|bool"  "INSTALL_BASHRC_GLOBAL|bool"
  "TRUSTED_IPS|str"
  "SLACK_WEBHOOK|str"  "TELEGRAM_BOT_TOKEN|str"  "TELEGRAM_CHAT_ID|str"  "DISCORD_WEBHOOK|str"
)

# Valeurs par défaut pour les modules (source unique)
declare -A MODULE_DEFAULTS=(
  [INSTALL_LOCALES]=true  [INSTALL_SSH_HARDEN]=true  [INSTALL_UFW]=true
  [GEOIP_BLOCK]=false  [INSTALL_FAIL2BAN]=true  [INSTALL_APACHE_PHP]=true
  [PHP_DISABLE_FUNCTIONS]=true  [INSTALL_MARIADB]=true  [INSTALL_PHPMYADMIN]=true
  [INSTALL_POSTFIX_DKIM]=true  [INSTALL_CERTBOT]=true  [CERTBOT_WILDCARD]=false  [INSTALL_DEVTOOLS]=true
  [INSTALL_NODE]=true  [INSTALL_RUST]=true  [INSTALL_PYTHON3]=true
  [INSTALL_COMPOSER]=true  [INSTALL_SYMFONY]=false  [INSTALL_SHELL_FUN]=true
  [INSTALL_YTDL]=false  [INSTALL_CLAMAV]=true  [INSTALL_RKHUNTER]=true
  [INSTALL_LOGWATCH]=true  [INSTALL_SSH_ALERT]=true  [INSTALL_AIDE]=true
  [INSTALL_MODSEC_CRS]=true  [MODSEC_ENFORCE]=false  [INSTALL_APPARMOR]=true  [INSTALL_AUDITD]=true  [EGRESS_FILTER]=false
  [SECURE_TMP]=true  [INSTALL_BASHRC_GLOBAL]=true
  [TRUSTED_IPS]=""
  [SLACK_WEBHOOK]=""  [TELEGRAM_BOT_TOKEN]=""  [TELEGRAM_CHAT_ID]=""  [DISCORD_WEBHOOK]=""
)

apply_config_defaults() {
  for key in "${!MODULE_DEFAULTS[@]}"; do
    if [[ -z "${!key+x}" ]]; then
      declare -g "$key=${MODULE_DEFAULTS[$key]}"
    fi
  done
}

save_config() {
  {
    echo "# Configuration générée le $(date '+%Y-%m-%d %H:%M:%S')"
    echo "CONFIG_VERSION=${CONFIG_VERSION}"
    for entry in "${CONFIG_VARS[@]}"; do
      local var="${entry%%|*}" type="${entry##*|}"
      local val="${!var:-}"
      if [[ "$type" == "bool" ]]; then
        echo "${var}=${val}"
      else
        echo "${var}=\"${val}\""
      fi
    done
  } > "$CONFIG_FILE" || { err "Impossible d'écrire ${CONFIG_FILE}"; return 1; }
  log "Configuration sauvegardée dans ${CONFIG_FILE}"
}

# Valider une ligne de configuration.
# Accepte: commentaires, lignes vides, VAR=bool, VAR=int, VAR="safe string", VAR=simple
# Rejette: $(), ``, ${}, ;, |, &, <, >, (, ), toute forme d'execution de code
validate_config_line() {
  local line="$1"
  # Commentaires et lignes vides : OK
  [[ "$line" =~ ^[[:space:]]*$ ]] && return 0
  [[ "$line" =~ ^[[:space:]]*# ]] && return 0
  # Rejeter tout caractere dangereux (shell metacharacters)
  # Doit etre fait AVANT le pattern matching pour bloquer les injections dans les quotes
  if [[ "$line" =~ [\$\`\;$'\n'] ]] || [[ "$line" =~ [^a-zA-Z0-9_=\"\ .,:/@+%{}\'-] && "$line" =~ [\|\&\<\>\(\)] ]]; then
    return 1
  fi
  # Pattern strict : UPPER_VAR=value
  # Valeurs autorisees: true, false, entier, "chaine sans $`", mot simple sans $`
  if [[ "$line" =~ ^[A-Z_][A-Z_0-9]*=(true|false|[0-9]+|\"[^\"$\`]*\"|[a-zA-Z0-9_./@:+%-]*)$ ]]; then
    return 0
  fi
  return 1
}

load_config() {
  if [[ -f "$CONFIG_FILE" ]]; then
    # Valider chaque ligne du fichier de configuration
    local line_num=0 bad_lines=""
    while IFS= read -r line || [[ -n "$line" ]]; do
      ((++line_num))
      if ! validate_config_line "$line"; then
        bad_lines+="  L${line_num}: ${line}\n"
      fi
    done < "$CONFIG_FILE"
    if [[ -n "$bad_lines" ]]; then
      warn "Le fichier de config ${CONFIG_FILE} contient des lignes suspectes :"
      printf "%b" "$bad_lines" | head -5
      die "Corrigez le fichier de config ou supprimez-le pour le recréer."
      return 2  # die exits in production; fallback for tests
    fi
    # Extraire la version du fichier avant sourcing (CONFIG_VERSION est readonly)
    local file_version
    file_version="$(grep -m1 '^CONFIG_VERSION=' "$CONFIG_FILE" | cut -d= -f2)" || true
    file_version="${file_version:-1}"
    set +u
    # shellcheck disable=SC1090
    source <(grep -v '^CONFIG_VERSION=' "$CONFIG_FILE")
    set -u
    if (( file_version < CONFIG_VERSION )); then
      warn "Fichier de config version ${file_version}, version courante ${CONFIG_VERSION}. Migration automatique."
    fi
    return 0
  fi
  return 1
}

ask_missing_options() {
  local has_missing=false
  local config_updated=false

  local new_options=(
    "INSTALL_PYTHON3|Installer Python 3 + pip + venv ?|y"
    "INSTALL_RKHUNTER|Installer rkhunter (détection rootkits) ?|y"
    "INSTALL_LOGWATCH|Installer Logwatch (résumé quotidien des logs par email) ?|y"
    "INSTALL_SSH_ALERT|Activer les alertes email à chaque connexion SSH ?|y"
    "INSTALL_AIDE|Installer AIDE (détection modifications fichiers) ?|y"
    "INSTALL_MODSEC_CRS|Installer les règles OWASP CRS pour ModSecurity ?|y"
    "CERTBOT_WILDCARD|Certificat wildcard via DNS OVH (nécessite credentials API) ?|n"
    "MODSEC_ENFORCE|Activer ModSecurity en mode blocage (On) au lieu de DetectionOnly ?|n"
    "SECURE_TMP|Sécuriser /tmp (noexec, nosuid, nodev) ?|y"
    "INSTALL_BASHRC_GLOBAL|Déployer le .bashrc commun pour tous les utilisateurs ?|y"
    "PHP_DISABLE_FUNCTIONS|Désactiver les fonctions PHP dangereuses (exec, system...) ?|y"
  )

  for opt in "${new_options[@]}"; do
    local var_name="${opt%%|*}"
    if [[ -z "${!var_name:-}" ]]; then
      has_missing=true
      break
    fi
  done

  if $has_missing; then
    echo ""
    warn "Nouvelles options détectées (absentes de votre configuration) :"
    echo ""

    for opt in "${new_options[@]}"; do
      local var_name="${opt%%|*}"
      local rest="${opt#*|}"
      local prompt="${rest%%|*}"
      local default="${rest##*|}"

      if [[ -z "${!var_name:-}" ]]; then
        config_updated=true
        declare -g "$var_name=true"
        prompt_yes_no "$prompt" "$default" || declare -g "$var_name=false"
      fi
    done

    if [[ -z "${TRUSTED_IPS:-}" ]]; then
      config_updated=true
      echo ""
      echo "IPs de confiance (whitelist fail2ban + ModSecurity)."
      echo "Exemples: votre IP maison, IP bureau. Séparées par des espaces."
      echo "Laisser vide pour ignorer."
      TRUSTED_IPS="$(prompt_default "IPs de confiance" "")"
    fi

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
  local comps="" var type
  for entry in "${CONFIG_VARS[@]}"; do
    var="${entry%%|*}"; type="${entry##*|}"
    [[ "$type" == "bool" ]] || continue
    if [[ "${!var}" == "true" ]]; then
      local name="${var#INSTALL_}"
      name="${name,,}"
      name="${name//_/-}"
      comps+="${name} "
    fi
  done
  printf "  %-25s %s\n" "Composants:" "$comps"
}

# ---------------------------------- Questions -----------------------------------------
ask_all_questions() {
  section "Paramètres de base"
  HOSTNAME_FQDN="$(prompt_default "Nom d'hôte (FQDN)" "$HOSTNAME_FQDN_DEFAULT")"
  if [[ ! "$HOSTNAME_FQDN" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)+$ ]]; then
    warn "Le hostname '${HOSTNAME_FQDN}' ne semble pas être un FQDN valide (ex: server.example.com)"
  fi
  SSH_PORT="$(prompt_default 'Port SSH' "$SSH_PORT_DEFAULT")"
  if ! [[ "$SSH_PORT" =~ ^[0-9]+$ ]] || (( SSH_PORT < 1 || SSH_PORT > 65535 )); then
    warn "Port SSH invalide '${SSH_PORT}' (doit être 1-65535), utilisation de ${SSH_PORT_DEFAULT}"
    SSH_PORT="$SSH_PORT_DEFAULT"
  fi
  ADMIN_USER="$(prompt_default 'Utilisateur admin (clé SSH déjà en place)' "$ADMIN_USER_DEFAULT")"
  DKIM_SELECTOR="$(prompt_default 'DKIM selector' "$DKIM_SELECTOR_DEFAULT")"
  DKIM_DOMAIN="$(prompt_default 'Domaine DKIM' "$DKIM_DOMAIN_DEFAULT")"
  if [[ ! "$DKIM_DOMAIN" =~ ^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$ ]]; then
    warn "Domaine DKIM '${DKIM_DOMAIN}' semble invalide"
  fi
  EMAIL_FOR_CERTBOT="$(prompt_default "Email Let's Encrypt" "$EMAIL_FOR_CERTBOT_DEFAULT")"
  if [[ ! "$EMAIL_FOR_CERTBOT" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
    warn "Email '${EMAIL_FOR_CERTBOT}' ne semble pas valide"
  fi
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
  prompt_yes_no "Installer Certbot (Let's Encrypt) ?" "y" || INSTALL_CERTBOT=false
  CERTBOT_WILDCARD=false
  if $INSTALL_CERTBOT; then
    if prompt_yes_no "Certificat wildcard (*.${HOSTNAME_FQDN}) via DNS OVH ? (sinon HTTP classique)" "n"; then
      CERTBOT_WILDCARD=true
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
      if [[ -z "$OVH_APP_KEY" || -z "$OVH_APP_SECRET" || -z "$OVH_CONSUMER_KEY" ]]; then
        warn "Credentials OVH incomplets. Le certificat wildcard sera ignoré."
        CERTBOT_WILDCARD=false
      fi
    fi
  fi
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
  MODSEC_ENFORCE=false
  if $INSTALL_MODSEC_CRS; then
    prompt_yes_no "Activer ModSecurity en mode blocage (On) au lieu de DetectionOnly ?" "n" && MODSEC_ENFORCE=true
  fi
  SECURE_TMP=true
  prompt_yes_no "Sécuriser /tmp (noexec, nosuid, nodev) ?" "y" || SECURE_TMP=false
  INSTALL_BASHRC_GLOBAL=true
  prompt_yes_no "Déployer le .bashrc commun pour tous les utilisateurs ?" "y" || INSTALL_BASHRC_GLOBAL=false

  section "IPs de confiance (whitelist)"
  echo "IPs qui seront whitelistées dans fail2ban et ModSecurity."
  echo "Exemples: votre IP maison, IP bureau. Séparées par des espaces."
  echo "Laisser vide pour ignorer."
  TRUSTED_IPS="$(prompt_default "IPs de confiance" "${TRUSTED_IPS:-}")"
  # Validation stricte des IPs
  if [[ -n "$TRUSTED_IPS" ]]; then
    local validated_ips=""
    for ip in $TRUSTED_IPS; do
      if [[ "$ip" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})(/([0-9]{1,2}))?$ ]]; then
        local o1="${BASH_REMATCH[1]}" o2="${BASH_REMATCH[2]}" o3="${BASH_REMATCH[3]}" o4="${BASH_REMATCH[4]}" cidr="${BASH_REMATCH[6]:-}"
        if (( o1 <= 255 && o2 <= 255 && o3 <= 255 && o4 <= 255 )) && [[ -z "$cidr" || "$cidr" -le 32 ]]; then
          validated_ips+="$ip "
        else
          warn "IP '${ip}' : octet ou CIDR hors plage — ignorée"
        fi
      else
        warn "IP/CIDR '${ip}' : format invalide (attendu: x.x.x.x ou x.x.x.x/yy) — ignorée"
      fi
    done
    TRUSTED_IPS="${validated_ips% }"
  fi

  save_config
}
