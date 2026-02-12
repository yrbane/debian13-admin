#!/usr/bin/env bash
# =======================================================================================
#  Bootstrap & Hardening Debian 13 (trixie) — OVH
#  Auteur : Seb
#
#  DESCRIPTION (en français car documentation) :
#    - Script interactif, coloré, auto-documenté (--help) pour configurer et sécuriser
#      un serveur Debian 13 (trixie) chez OVH en partant d'une installation vierge.
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
#    * Postfix (send-only) + OpenDKIM (sélecteur 'mail') pour mails signés
#    * Certbot (Let's Encrypt) pour HTTPS
#    * Outils dev : Git, Curl, build-essential, Node (nvm), Rust (rustup), Composer
#    * Confort shell : neofetch, fortune-mod, cowsay, lolcat, grc, (youtube-dl optionnel), p7zip/rar
#    * ClamAV (freshclam + service)
#    * .bashrc commun (tous utilisateurs) — coloré/fonctions/alias + fortune|cowsay|lolcat
#
#  REMARQUES DNS IMPORTANTES :
#    - Vos MX pointent chez OVH → le serveur N'ACCEPTE PAS d'email entrant (Postfix en loopback).
#      Il n'envoie que des mails sortants (alertes/cron/app) signés DKIM.
#    - Enregistrement wildcard suspect dans votre exemple : "*  IN A  42.44.139.193"
#      → Probablement une faute : "142.44.139.193".
#    - DKIM : sélecteur "mail" déjà publié (TXT long). La clé privée locale DOIT correspondre.
#      Le script NE REMPLACE PAS une clé existante. Si mismatch → régénérer clé & mettre à jour DNS.
#
#  USAGE RAPIDE :
#    sudo /root/bootstrap.sh
#    sudo /root/bootstrap.sh --noninteractive    # passe en mode non interactif (utilise défauts)
#    sudo /root/bootstrap.sh --help              # affiche l'aide détaillée
#
#  NOTE LÉGALE :
#    Exécuter en connaissance de cause. Sauvegardes automatiques des fichiers sensibles *.bak.
#
# =======================================================================================

set -Eeuo pipefail

# ---------------------------------- Répertoire & version ------------------------------
SCRIPT_NAME="debian13-server"
SCRIPT_VERSION="1.2.3"
if [[ -n "${BASH_SOURCE[0]:-}" && "${BASH_SOURCE[0]}" != "bash" ]]; then
  SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
else
  SCRIPT_DIR="/root/scripts"
fi
LIB_DIR="${SCRIPT_DIR}/lib"
CONFIG_FILE="${SCRIPT_DIR}/${SCRIPT_NAME}.conf"

# ---------------------------------- Chargement des bibliothèques ----------------------
# shellcheck source=lib/core.sh
source "${LIB_DIR}/core.sh"
# shellcheck source=lib/constants.sh
source "${LIB_DIR}/constants.sh"
# shellcheck source=lib/helpers.sh
source "${LIB_DIR}/helpers.sh"
# shellcheck source=lib/config.sh
source "${LIB_DIR}/config.sh"

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
  note "Exécution via pipe détectée - utilisation de la configuration existante."
  NONINTERACTIVE=true
fi

# ---------------------------------- Prérequis -----------------------------------------
require_root

if ! grep -qi 'debian' /etc/os-release; then
  warn "Distribution non détectée comme Debian. Le script cible Debian 13 (trixie)."
fi

if [[ "${AUDIT_MODE:-false}" != "true" ]]; then
  preflight_checks
fi

# ---------------------------------- Configuration -------------------------------------
if $AUDIT_MODE; then
  if [[ -f "$CONFIG_FILE" ]]; then
    load_config
    apply_config_defaults
  else
    die "Mode audit : fichier de configuration ${CONFIG_FILE} requis. Exécutez d'abord le script normalement."
  fi
elif ! $NONINTERACTIVE; then
  if [[ -f "$CONFIG_FILE" ]]; then
    section "Configuration existante détectée"
    load_config
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
  if $PIPED_MODE && [[ -f "$CONFIG_FILE" ]]; then
    load_config
    apply_config_defaults
    section "Configuration existante chargée (mode pipe)"
    show_config
  else
    HOSTNAME_FQDN="$HOSTNAME_FQDN_DEFAULT"
    SSH_PORT="$SSH_PORT_DEFAULT"
    ADMIN_USER="$ADMIN_USER_DEFAULT"
    DKIM_SELECTOR="$DKIM_SELECTOR_DEFAULT"
    DKIM_DOMAIN="$DKIM_DOMAIN_DEFAULT"
    EMAIL_FOR_CERTBOT="$EMAIL_FOR_CERTBOT_DEFAULT"
    TIMEZONE="$TIMEZONE_DEFAULT"
    apply_config_defaults
  fi
fi

# Chemins/constantes dérivées (readonly après affectation)
readonly DKIM_KEYDIR="/etc/opendkim/keys/${DKIM_DOMAIN}"
readonly LOG_FILE="/var/log/bootstrap_ovh_debian13.log"
USER_HOME="$(get_user_home)"
DEBIAN_FRONTEND=noninteractive
export DEBIAN_FRONTEND

# ================================== VÉRIFICATIONS (définitions) =======================
# shellcheck source=lib/verify.sh
source "${LIB_DIR}/verify.sh"

# ================================== INSTALLATION ======================================
if ! $AUDIT_MODE; then
  apt_update_upgrade

  # shellcheck source=lib/install-base.sh
  source "${LIB_DIR}/install-base.sh"
  # shellcheck source=lib/install-web.sh
  source "${LIB_DIR}/install-web.sh"
  # shellcheck source=lib/install-devtools.sh
  source "${LIB_DIR}/install-devtools.sh"
  # shellcheck source=lib/install-security.sh
  source "${LIB_DIR}/install-security.sh"
fi

# ================================== VÉRIFICATIONS (exécution CLI) =====================
CHECK_MODE="cli"
verify_services
verify_ssh
verify_web
verify_system
verify_devtools
verify_dkim
verify_sysconfig
verify_users
verify_files
verify_database
verify_resources
verify_ports
verify_listening
verify_dns

# Résumé des vérifications
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
print_cmd "grep -E 'status=(sent|deferred|bounced)' ${MAIL_LOG} | tail -20"
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
  print_note "Scan quotidien à 2h00 : ${SCRIPTS_DIR}/clamav_scan.sh"
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
  print_cmd "tail -f ${MODSEC_AUDIT_LOG}"
  print_note "Activer le blocage (après validation) :"
  print_cmd "sed -i 's/SecRuleEngine DetectionOnly/SecRuleEngine On/' ${MODSEC_CONFIG} && systemctl restart apache2"
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
elif [[ "${DNS_DMARC:-}" == *"p=none"* ]]; then
  print_note "⚠ DMARC : policy=none (trop permissif, passer à quarantine ou reject)"
else
  print_note "DMARC : configuré"
fi
print_note "Postfix : envoi local uniquement (loopback-only)"
echo ""

printf "${CYAN}Fichier log :${RESET} %s\n\n" "${LOG_FILE}"

# ================================== MODE AUDIT : EMAIL ================================
# shellcheck source=lib/audit-html.sh
source "${LIB_DIR}/audit-html.sh"

# ================================== COPIE SCRIPT & CRON AUDIT =========================
INSTALL_SCRIPT_DIR="/root/scripts"
INSTALL_SCRIPT_PATH="${INSTALL_SCRIPT_DIR}/${SCRIPT_NAME}.sh"
INSTALL_CONFIG_PATH="${INSTALL_SCRIPT_DIR}/${SCRIPT_NAME}.conf"
mkdir -p "$INSTALL_SCRIPT_DIR"

# Copier le script et ses bibliothèques si exécuté depuis ailleurs
CURRENT_SCRIPT="$(readlink -f "$0")"
if [[ "$CURRENT_SCRIPT" != "$INSTALL_SCRIPT_PATH" ]]; then
  cp -f "$CURRENT_SCRIPT" "$INSTALL_SCRIPT_PATH"
  chmod +x "$INSTALL_SCRIPT_PATH"
  # Copier les bibliothèques lib/
  if [[ -d "${SCRIPT_DIR}/lib" ]]; then
    mkdir -p "${INSTALL_SCRIPT_DIR}/lib"
    cp -f "${SCRIPT_DIR}/lib/"*.sh "${INSTALL_SCRIPT_DIR}/lib/"
  fi
  # Copier les templates
  if [[ -d "${SCRIPT_DIR}/templates" ]]; then
    mkdir -p "${INSTALL_SCRIPT_DIR}/templates"
    cp -f "${SCRIPT_DIR}/templates/"* "${INSTALL_SCRIPT_DIR}/templates/" 2>/dev/null || true
  fi
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

# MAILTO en tête du crontab
set_cron_mailto "${EMAIL_FOR_CERTBOT}"

# Ajoute/met à jour le cron pour l'audit hebdomadaire
add_cron_job "\-\-audit" "${CRON_AUDIT} ${INSTALL_SCRIPT_PATH} --audit >/dev/null 2>&1" "Audit de sécurité hebdomadaire (lundi 7h00)"
log "Cron audit configuré → ${INSTALL_SCRIPT_PATH} --audit"

# Attendre la fin de l'initialisation AIDE si lancée en arrière-plan
if [[ -n "${AIDE_PID:-}" ]]; then
  log "Attente de la fin de l'initialisation AIDE (PID ${AIDE_PID})..."
  if wait "$AIDE_PID" 2>/dev/null; then
    if [[ -f /var/lib/aide/aide.db.new ]]; then
      mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
      log "Base AIDE initialisée avec succès."
    fi
  else
    warn "L'initialisation AIDE a échoué (exit code $?). Relancez 'aideinit' manuellement."
  fi
fi

log "Terminé. Garde une session SSH ouverte tant que tu n'as pas validé la nouvelle connexion sur le port ${SSH_PORT}."
