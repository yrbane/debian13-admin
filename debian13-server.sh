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
# shellcheck source=lib/ovh-api.sh
source "${LIB_DIR}/ovh-api.sh"
# shellcheck source=lib/domain-manager.sh
source "${LIB_DIR}/domain-manager.sh"
# shellcheck source=lib/backup.sh
source "${LIB_DIR}/backup.sh"
# shellcheck source=lib/hooks.sh
source "${LIB_DIR}/hooks.sh"
# shellcheck source=lib/clone.sh
source "${LIB_DIR}/clone.sh"

# ---------------------------------- Aide / usage --------------------------------------
show_help() {
  printf "\n"
  printf "${BOLD}${CYAN}  Bootstrap & Hardening Debian 13 (OVH)${RESET}\n"
  printf "\n"

  printf "${BOLD}${MAGENTA}USAGE:${RESET}\n"
  printf "  sudo ./${SCRIPT_NAME}.sh [OPTIONS]\n"
  printf "\n"

  printf "${BOLD}${MAGENTA}OPTIONS GÉNÉRALES :${RESET}\n"
  printf "  ${GREEN}--noninteractive${RESET}          N'affiche pas les questions ; utilise les valeurs par défaut.\n"
  printf "  ${GREEN}--audit${RESET}                   Vérifications + rapport email, sans installation.\n"
  printf "  ${GREEN}--check-dns${RESET}               Vérifie uniquement DNS/DKIM/mail (sans installation).\n"
  printf "  ${GREEN}--fix${RESET}                     Avec --check-dns : corrige automatiquement les DNS via API OVH.\n"
  printf "  ${GREEN}--dry-run${RESET}                 Simule les actions sans modifier le système.\n"
  printf "  ${GREEN}--renew-ovh${RESET}               Regénérer les credentials API OVH (certificat wildcard).\n"
  printf "  ${GREEN}--help${RESET}, ${GREEN}-h${RESET}                Affiche cette aide.\n"
  printf "\n"

  printf "${BOLD}${MAGENTA}GESTION MULTI-DOMAINES :${RESET}\n"
  printf "  ${GREEN}--domain-add <dom> [sel]${RESET}  Ajouter un domaine sur le serveur.\n"
  printf "                            Crée automatiquement : clé DKIM, VHosts Apache,\n"
  printf "                            certificat SSL, enregistrements DNS (via OVH API),\n"
  printf "                            page parking WebGL et rotation des logs.\n"
  printf "                            Le sélecteur DKIM est optionnel ${YELLOW}(défaut: mail)${RESET}.\n"
  printf "  ${GREEN}--domain-remove <dom>${RESET}     Retirer un domaine (VHosts + logrotate + OpenDKIM).\n"
  printf "                            Les clés DKIM, certificats SSL et fichiers web\n"
  printf "                            sont conservés (nettoyage manuel si nécessaire).\n"
  printf "                            Le domaine principal ne peut pas être supprimé.\n"
  printf "  ${GREEN}--domain-list${RESET}             Lister tous les domaines gérés avec leur sélecteur DKIM.\n"
  printf "  ${GREEN}--domain-check [dom]${RESET}      Vérifier la configuration d'un domaine (DNS, DKIM,\n"
  printf "                            SPF, DMARC, SSL, VHost). Sans argument : vérifie\n"
  printf "                            tous les domaines enregistrés.\n"
  printf "  ${GREEN}--domain-staging <dom>${RESET}  Déployer un domaine en mode staging (pas de SSL/DNS).\n"
  printf "  ${GREEN}--domain-promote <dom>${RESET}  Promouvoir un domaine staging en production.\n"
  printf "  ${GREEN}--domain-group <d> <g>${RESET}  Assigner un domaine à un groupe.\n"
  printf "  ${GREEN}--group-list${RESET}              Lister les groupes de domaines.\n"
  printf "  ${GREEN}--domain-export <dom>${RESET}    Exporter un domaine vers une archive tar.gz.\n"
  printf "                            Contient : DKIM, VHosts, logrotate, fichiers web.\n"
  printf "  ${GREEN}--domain-import <arch>${RESET}   Importer un domaine depuis une archive tar.gz.\n"
  printf "  ${GREEN}--audit-html <path>${RESET}      Générer un rapport d'audit en HTML.\n"
  printf "  ${GREEN}--clone-keygen${RESET}            Générer une clé SSH pour le clonage serveur.\n"
  printf "  ${GREEN}--clone <ip> [port]${RESET}      Cloner la configuration vers un serveur cible.\n"
  printf "  ${GREEN}--backup${RESET}                  Sauvegarde complète (configs, DKIM, MariaDB, cron).\n"
  printf "  ${GREEN}--backup-list${RESET}             Lister les sauvegardes disponibles.\n"
  printf "\n"

  printf "${BOLD}${MAGENTA}PARAMÈTRES${RESET} (mode interactif, sinon valeurs par défaut) :\n"
  printf "  - HOSTNAME_FQDN     ${YELLOW}(défaut: %s)${RESET}\n" "${HOSTNAME_FQDN_DEFAULT}"
  printf "  - SSH_PORT          ${YELLOW}(défaut: %s)${RESET}\n" "${SSH_PORT_DEFAULT}"
  printf "  - ADMIN_USER        ${YELLOW}(défaut: %s)${RESET}\n" "${ADMIN_USER_DEFAULT}"
  printf "  - DKIM_SELECTOR     ${YELLOW}(défaut: %s)${RESET}\n" "${DKIM_SELECTOR_DEFAULT}"
  printf "  - DKIM_DOMAIN       ${YELLOW}(défaut: %s)${RESET}\n" "${DKIM_DOMAIN_DEFAULT}"
  printf "  - EMAIL_FOR_CERTBOT ${YELLOW}(défaut: %s)${RESET}\n" "${EMAIL_FOR_CERTBOT_DEFAULT}"
  printf "  - TIMEZONE          ${YELLOW}(défaut: %s)${RESET}\n" "${TIMEZONE_DEFAULT}"
  printf "\n"

  printf "${BOLD}${MAGENTA}COMPOSANTS INSTALLABLES${RESET} (question par question) :\n"
  printf "  - Locales fr_FR complètes\n"
  printf "  - Durcissement SSH + port personnalisé\n"
  printf "  - UFW (deny in, allow out) + Fail2ban\n"
  printf "  - Apache + PHP + durcissements\n"
  printf "  - MariaDB (hardening basique)\n"
  printf "  - phpMyAdmin (URL sécurisée aléatoire)\n"
  printf "  - Postfix send-only + OpenDKIM (signature DKIM multi-domaines)\n"
  printf "  - Certbot (Let's Encrypt) + intégration Apache\n"
  printf "  - Outils dev (Git, Curl, build-essential)\n"
  printf "  - Node.js via nvm (LTS)\n"
  printf "  - Rust via rustup (stable)\n"
  printf "  - Composer (global)\n"
  printf "  - Confort shell (neofetch, fortune-mod, cowsay, lolcat, grc, p7zip, unrar)\n"
  printf "  - ClamAV (freshclam + daemon)\n"
  printf "  - .bashrc commun pour tous les utilisateurs\n"
  printf "\n"

  printf "${BOLD}${MAGENTA}NOTES DNS & SÉCURITÉ :${RESET}\n"
  printf "  - MX chez OVH : le serveur n'écoute pas SMTP entrant (relay local désactivé).\n"
  printf "  - DKIM : une clé par domaine, sélecteur configurable (défaut ${YELLOW}\"mail\"${RESET}).\n"
  printf "    OpenDKIM signe automatiquement selon le From: via signingtable.\n"
  printf "  - SPF/DMARC : configurés par domaine = emails non-spam.\n"
  printf "  - Multi-domaines : chaque domaine ajouté via --domain-add obtient ses propres\n"
  printf "    enregistrements DNS (A, AAAA, SPF, DKIM, DMARC, CAA), VHosts et certificat.\n"
  printf "\n"

  printf "${BOLD}${MAGENTA}FICHIER DE CONFIGURATION :${RESET}\n"
  printf "  Après les questions, un fichier ${YELLOW}.conf${RESET} est créé à côté du script.\n"
  printf "  Les exécutions suivantes proposent de réutiliser cette configuration.\n"
  printf "  Le registre des domaines est stocké dans ${YELLOW}domains.conf${RESET}.\n"
  printf "\n"

  printf "${BOLD}${MAGENTA}EXEMPLES :${RESET}\n"
  printf "\n"
  printf "  ${BOLD}Installation & audit :${RESET}\n"
  printf "  ${GREEN}sudo ./${SCRIPT_NAME}.sh${RESET}                       # Exécution standard (interactif)\n"
  printf "  ${GREEN}sudo ./${SCRIPT_NAME}.sh --noninteractive${RESET}       # Valeurs par défaut\n"
  printf "  ${GREEN}sudo ./${SCRIPT_NAME}.sh --audit${RESET}                # Audit uniquement (rapport email)\n"
  printf "\n"
  printf "  ${BOLD}DNS & certificats :${RESET}\n"
  printf "  ${GREEN}sudo ./${SCRIPT_NAME}.sh --check-dns${RESET}            # Vérification DNS/DKIM/SPF/DMARC\n"
  printf "  ${GREEN}sudo ./${SCRIPT_NAME}.sh --check-dns --fix${RESET}      # Vérification + correction auto DNS OVH\n"
  printf "  ${GREEN}sudo ./${SCRIPT_NAME}.sh --renew-ovh${RESET}            # Regénérer credentials API OVH\n"
  printf "\n"
  printf "  ${BOLD}Multi-domaines :${RESET}\n"
  printf "  ${GREEN}sudo ./${SCRIPT_NAME}.sh --domain-add example.com${RESET}          # Ajouter (sélecteur: mail)\n"
  printf "  ${GREEN}sudo ./${SCRIPT_NAME}.sh --domain-add example.com dkim2025${RESET} # Ajouter (sélecteur custom)\n"
  printf "  ${GREEN}sudo ./${SCRIPT_NAME}.sh --domain-list${RESET}                     # Lister les domaines\n"
  printf "  ${GREEN}sudo ./${SCRIPT_NAME}.sh --domain-check example.com${RESET}        # Vérifier un domaine\n"
  printf "  ${GREEN}sudo ./${SCRIPT_NAME}.sh --domain-check${RESET}                    # Vérifier tous les domaines\n"
  printf "  ${GREEN}sudo ./${SCRIPT_NAME}.sh --domain-remove example.com${RESET}       # Retirer un domaine\n"
  printf "\n"
}

# ---------------------------------- Arguments -----------------------------------------
NONINTERACTIVE=false
AUDIT_MODE=false
CHECK_DNS_MODE=false
RENEW_OVH_MODE=false
FIX_DNS=false
PIPED_MODE=false
DOMAIN_ADD=""
DOMAIN_ADD_SELECTOR=""
DOMAIN_REMOVE=""
DOMAIN_LIST_MODE=false
DOMAIN_CHECK=""
DOMAIN_CHECK_ALL=false
DOMAIN_EXPORT=""
DOMAIN_IMPORT=""
BACKUP_MODE=false
BACKUP_LIST_MODE=false
DRY_RUN=false
DOMAIN_STAGING=""
DOMAIN_PROMOTE=""
DOMAIN_SET_GROUP=""
DOMAIN_SET_GROUP_NAME=""
GROUP_LIST_MODE=false
AUDIT_HTML=""
CLONE_KEYGEN=false
CLONE_TARGET=""
CLONE_PORT="22"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --noninteractive) NONINTERACTIVE=true ;;
    --audit) AUDIT_MODE=true ;;
    --check-dns) CHECK_DNS_MODE=true ;;
    --fix) FIX_DNS=true ;;
    --renew-ovh) RENEW_OVH_MODE=true ;;
    --domain-add)
      shift; DOMAIN_ADD="${1:-}"
      [[ -z "$DOMAIN_ADD" ]] && die "--domain-add nécessite un nom de domaine."
      # Sélecteur optionnel en argument suivant (s'il ne commence pas par --)
      if [[ -n "${2:-}" && "${2:-}" != --* ]]; then
        shift; DOMAIN_ADD_SELECTOR="$1"
      fi
      ;;
    --domain-remove)
      shift; DOMAIN_REMOVE="${1:-}"
      [[ -z "$DOMAIN_REMOVE" ]] && die "--domain-remove nécessite un nom de domaine."
      ;;
    --domain-list) DOMAIN_LIST_MODE=true ;;
    --domain-export)
      shift; DOMAIN_EXPORT="${1:-}"
      [[ -z "$DOMAIN_EXPORT" ]] && die "--domain-export nécessite un nom de domaine."
      ;;
    --domain-import)
      shift; DOMAIN_IMPORT="${1:-}"
      [[ -z "$DOMAIN_IMPORT" ]] && die "--domain-import nécessite un chemin vers l'archive."
      ;;
    --dry-run) DRY_RUN=true ;;
    --backup) BACKUP_MODE=true ;;
    --backup-list) BACKUP_LIST_MODE=true ;;
    --domain-check)
      if [[ -n "${2:-}" && "${2:-}" != --* ]]; then
        shift; DOMAIN_CHECK="$1"
      else
        DOMAIN_CHECK_ALL=true
      fi
      ;;
    --domain-staging)
      shift; DOMAIN_STAGING="${1:-}"
      [[ -z "$DOMAIN_STAGING" ]] && die "--domain-staging nécessite un nom de domaine."
      ;;
    --domain-promote)
      shift; DOMAIN_PROMOTE="${1:-}"
      [[ -z "$DOMAIN_PROMOTE" ]] && die "--domain-promote nécessite un nom de domaine."
      ;;
    --domain-group)
      shift; DOMAIN_SET_GROUP="${1:-}"
      [[ -z "$DOMAIN_SET_GROUP" ]] && die "--domain-group nécessite un domaine."
      shift; DOMAIN_SET_GROUP_NAME="${1:-}"
      [[ -z "$DOMAIN_SET_GROUP_NAME" ]] && die "--domain-group nécessite un nom de groupe."
      ;;
    --group-list) GROUP_LIST_MODE=true ;;
    --audit-html)
      shift; AUDIT_HTML="${1:-}"
      [[ -z "$AUDIT_HTML" ]] && die "--audit-html nécessite un chemin de sortie."
      ;;
    --clone-keygen) CLONE_KEYGEN=true ;;
    --clone)
      shift; CLONE_TARGET="${1:-}"
      [[ -z "$CLONE_TARGET" ]] && die "--clone nécessite une adresse IP cible."
      if [[ -n "${2:-}" && "${2:-}" != --* ]]; then
        shift; CLONE_PORT="$1"
      fi
      ;;
    --help|-h) show_help; exit 0 ;;
    *) err "Option inconnue: $1"; show_help; exit 1 ;;
  esac
  shift
done

# Validation : --fix nécessite --check-dns
if $FIX_DNS && ! $CHECK_DNS_MODE; then
  die "--fix nécessite --check-dns. Usage : sudo $0 --check-dns --fix"
fi

# Détection mode domain-*
DOMAIN_MODE=false
if [[ -n "$DOMAIN_ADD" || -n "$DOMAIN_REMOVE" || "$DOMAIN_LIST_MODE" == "true" || -n "$DOMAIN_CHECK" || "$DOMAIN_CHECK_ALL" == "true" || -n "$DOMAIN_EXPORT" || -n "$DOMAIN_IMPORT" || -n "$DOMAIN_STAGING" || -n "$DOMAIN_PROMOTE" || -n "$DOMAIN_SET_GROUP" || "$GROUP_LIST_MODE" == "true" ]]; then
  DOMAIN_MODE=true
fi

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

if [[ "${AUDIT_MODE:-false}" != "true" && "${CHECK_DNS_MODE:-false}" != "true" && "${RENEW_OVH_MODE:-false}" != "true" && "${DOMAIN_MODE:-false}" != "true" ]]; then
  preflight_checks
fi

# ---------------------------------- Configuration -------------------------------------
if $AUDIT_MODE || $CHECK_DNS_MODE || $RENEW_OVH_MODE || $DOMAIN_MODE; then
  if [[ -f "$CONFIG_FILE" ]]; then
    load_config
    apply_config_defaults
  else
    die "Fichier de configuration ${CONFIG_FILE} requis. Exécutez d'abord le script normalement."
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
DKIM_KEYDIR="${DKIM_KEYDIR_BASE:-/etc/opendkim/keys}"
readonly LOG_FILE="/var/log/bootstrap_ovh_debian13.log"
STRUCTURED_LOG="/var/log/bootstrap_structured.jsonl"
[[ -n "$AUDIT_HTML" ]] && HTML_REPORT="$AUDIT_HTML"
USER_HOME="$(get_user_home)"
DEBIAN_FRONTEND=noninteractive
export DEBIAN_FRONTEND

# ================================== VÉRIFICATIONS (définitions) =======================
# shellcheck source=lib/verify.sh
source "${LIB_DIR}/verify.sh"

# ---------------------------------- Fonction checklist DNS ----------------------------
print_dns_actions() {
  print_title "Actions DNS requises chez le registrar"
  if [[ -n "${SERVER_IP:-}" ]]; then
    print_note "IP publique IPv4 : ${SERVER_IP}"
  fi
  if [[ -n "${SERVER_IP6:-}" ]]; then
    print_note "IP publique IPv6 : ${SERVER_IP6}"
  fi
  echo ""

  # A record
  if [[ -n "${DNS_A:-}" && "${DNS_A:-}" == "${SERVER_IP:-}" ]]; then
    log "A ${HOSTNAME_FQDN} → ${DNS_A}"
  else
    warn "A : ajouter/corriger chez le registrar :"
    print_cmd "${HOSTNAME_FQDN}.   IN A   ${SERVER_IP}"
  fi

  # www A
  if [[ -n "${DNS_WWW:-}" ]] && [[ "${DNS_WWW:-}" == "${SERVER_IP:-}" || "${DNS_WWW:-}" == "${DNS_A:-}" ]]; then
    log "A www.${HOSTNAME_FQDN} → ${DNS_WWW}"
  else
    warn "www A : ajouter chez le registrar :"
    print_cmd "www.${HOSTNAME_FQDN}.   IN A   ${SERVER_IP}"
  fi

  # AAAA record (IPv6)
  if [[ -n "${SERVER_IP6:-}" ]]; then
    if [[ -n "${DNS_AAAA:-}" && "${DNS_AAAA:-}" == "${SERVER_IP6}" ]]; then
      log "AAAA ${HOSTNAME_FQDN} → ${DNS_AAAA}"
    else
      warn "AAAA : ajouter/corriger chez le registrar :"
      print_cmd "${HOSTNAME_FQDN}.   IN AAAA   ${SERVER_IP6}"
    fi

    # www AAAA
    if [[ -n "${DNS_WWW6:-}" && "${DNS_WWW6:-}" == "${SERVER_IP6}" ]]; then
      log "AAAA www.${HOSTNAME_FQDN} → ${DNS_WWW6}"
    else
      warn "www AAAA : ajouter chez le registrar :"
      print_cmd "www.${HOSTNAME_FQDN}.   IN AAAA   ${SERVER_IP6}"
    fi
  fi

  # MX
  if [[ -n "${DNS_MX:-}" ]]; then
    log "MX ${BASE_DOMAIN} → ${DNS_MX}"
  else
    warn "MX : non configuré (requis pour recevoir des emails) :"
    print_cmd "${BASE_DOMAIN}.   IN MX 10   ${HOSTNAME_FQDN}."
  fi

  # SPF
  if [[ -n "${DNS_SPF:-}" ]]; then
    log "SPF ${BASE_DOMAIN} → configuré"
  else
    warn "SPF : ajouter un enregistrement TXT :"
    print_cmd "${BASE_DOMAIN}.   IN TXT   \"v=spf1 a mx ip4:${SERVER_IP} ~all\""
  fi

  # DKIM
  if [[ -n "${DNS_DKIM:-}" ]] && [[ "${DNS_DKIM:-}" == *"v=DKIM1"* ]]; then
    log "DKIM ${DKIM_SELECTOR}._domainkey.${DKIM_DOMAIN} → configuré"
  else
    warn "DKIM : ajouter l'enregistrement TXT suivant :"
    if [[ -f "${DKIM_KEYDIR}/${DKIM_DOMAIN}/${DKIM_SELECTOR}.txt" ]]; then
      print_note "Contenu de ${DKIM_KEYDIR}/${DKIM_DOMAIN}/${DKIM_SELECTOR}.txt :"
      print_cmd "$(cat "${DKIM_KEYDIR}/${DKIM_DOMAIN}/${DKIM_SELECTOR}.txt" 2>/dev/null || echo '(fichier introuvable)')"
    else
      print_cmd "${DKIM_SELECTOR}._domainkey.${DKIM_DOMAIN}.   IN TXT   \"v=DKIM1; k=rsa; p=...\""
      print_note "Générer la clé : opendkim-genkey -s ${DKIM_SELECTOR} -d ${DKIM_DOMAIN}"
    fi
  fi

  # DMARC
  if [[ -n "${DNS_DMARC:-}" ]] && [[ "${DNS_DMARC:-}" != *"p=none"* ]]; then
    log "DMARC _dmarc.${BASE_DOMAIN} → configuré"
  else
    if [[ "${DNS_DMARC:-}" == *"p=none"* ]]; then
      warn "DMARC : policy=none trop permissif, passer à quarantine :"
    else
      warn "DMARC : ajouter un enregistrement TXT :"
    fi
    print_cmd "_dmarc.${BASE_DOMAIN}.   IN TXT   \"v=DMARC1; p=quarantine; rua=mailto:${EMAIL_FOR_CERTBOT}; fo=1\""
  fi

  # PTR IPv4 (reverse DNS)
  if [[ -n "${DNS_PTR:-}" ]] && [[ "${DNS_PTR:-}" == "$HOSTNAME_FQDN" ]]; then
    log "PTR IPv4 ${SERVER_IP} → ${DNS_PTR}"
  else
    warn "PTR IPv4 (reverse DNS) : non configuré ou incorrect pour ${SERVER_IP}"
    if [[ -n "${DNS_PTR:-}" ]]; then
      print_note "Actuel : ${DNS_PTR} (attendu : ${HOSTNAME_FQDN})"
    fi
    print_note "Configurer dans le panneau OVH :"
    print_note "  Manager OVH → IP → Roue crantée → Modifier le reverse → ${HOSTNAME_FQDN}"
  fi

  # PTR IPv6 (reverse DNS)
  if [[ -n "${SERVER_IP6:-}" ]]; then
    if [[ -n "${DNS_PTR6:-}" ]] && [[ "${DNS_PTR6:-}" == "$HOSTNAME_FQDN" ]]; then
      log "PTR IPv6 ${SERVER_IP6} → ${DNS_PTR6}"
    else
      warn "PTR IPv6 (reverse DNS) : non configuré ou incorrect pour ${SERVER_IP6}"
      if [[ -n "${DNS_PTR6:-}" ]]; then
        print_note "Actuel : ${DNS_PTR6} (attendu : ${HOSTNAME_FQDN})"
      fi
      print_note "Configurer dans le panneau OVH :"
      print_note "  Manager OVH → IP → Sélectionner l'IPv6 → Modifier le reverse → ${HOSTNAME_FQDN}"
    fi
  fi

  # CAA
  if [[ -n "${DNS_CAA:-}" ]]; then
    log "CAA ${BASE_DOMAIN} → configuré"
  else
    warn "CAA : recommandé pour restreindre les autorités de certification :"
    print_cmd "${BASE_DOMAIN}.   IN CAA 0 issue \"letsencrypt.org\""
  fi

  echo ""
  print_note "Postfix : envoi local uniquement (loopback-only)"
  echo ""
  print_note "Vérification rapide (après propagation DNS) :"
  print_cmd "dig +short A ${HOSTNAME_FQDN} @8.8.8.8"
  if [[ -n "${SERVER_IP6:-}" ]]; then
    print_cmd "dig +short AAAA ${HOSTNAME_FQDN} @8.8.8.8"
  fi
  print_cmd "dig +short MX ${BASE_DOMAIN} @8.8.8.8"
  print_cmd "dig +short TXT ${BASE_DOMAIN} @8.8.8.8"
  print_cmd "dig +short TXT ${DKIM_SELECTOR}._domainkey.${DKIM_DOMAIN} @8.8.8.8"
  print_cmd "dig +short TXT _dmarc.${BASE_DOMAIN} @8.8.8.8"
  print_cmd "dig +short -x ${SERVER_IP}"
  if [[ -n "${SERVER_IP6:-}" ]]; then
    print_cmd "dig +short -x ${SERVER_IP6}"
  fi
  print_cmd "dig +short CAA ${BASE_DOMAIN} @8.8.8.8"
  echo ""
}

# ---------------------------------- Correction DNS automatique -------------------------
# Délègue à dm_setup_dns (A, AAAA, SPF, DKIM, DMARC, CAA) + dm_setup_ptr (reverse)
fix_dns() {
  # MX : ne pas toucher (géré par OVH MX Plan)
  if [[ -z "${DNS_MX:-}" ]]; then
    note "DNS fix : MX non configuré — géré par OVH (MX Plan), pas de correction automatique."
  fi

  # Domaine principal : A, AAAA, SPF, DKIM, DMARC, CAA
  dm_setup_dns "$HOSTNAME_FQDN" "$DKIM_SELECTOR"
  local fix_ok=$DM_DNS_OK fix_fail=$DM_DNS_FAIL

  # PTR (reverse DNS) — spécifique au domaine principal
  dm_setup_ptr "$HOSTNAME_FQDN"
  ((fix_ok += DM_PTR_OK))
  ((fix_fail += DM_PTR_FAIL))

  # Domaines additionnels
  local _dm_line _dm_domain _dm_selector
  while IFS= read -r _dm_line; do
    _dm_domain="${_dm_line%%:*}"
    _dm_selector="${_dm_line#*:}"
    [[ "$_dm_domain" == "${DKIM_DOMAIN}" ]] && continue
    log "DNS fix multi-domaines : ${_dm_domain}"
    dm_setup_dns "$_dm_domain" "$_dm_selector"
    ((fix_ok += DM_DNS_OK))
    ((fix_fail += DM_DNS_FAIL))
  done < <(dm_list_domains)

  echo ""
  printf "${BOLD}  Corrections : ${GREEN}%d réussie(s)${RESET} | ${RED}%d échouée(s)${RESET}\n" "$fix_ok" "$fix_fail"
  echo ""
}

# ================================== MODE --check-dns ==================================
if $CHECK_DNS_MODE; then
  CHECK_MODE="cli"
  verify_dkim
  verify_dns
  echo ""
  printf "${BOLD}══════════════════════════════════════════════════════════════${RESET}\n"
  printf "${BOLD}  Résultat : ${GREEN}%d OK${RESET} | ${YELLOW}%d avertissements${RESET} | ${RED}%d erreurs${RESET}\n" "$CHECKS_OK" "$CHECKS_WARN" "$CHECKS_FAIL"
  printf "${BOLD}══════════════════════════════════════════════════════════════${RESET}\n"
  echo ""

  if $FIX_DNS; then
    section "Correction automatique DNS via API OVH"

    # Vérifier les credentials OVH
    note "Vérification des credentials OVH..."
    _OVH_AK="" _OVH_AS="" _OVH_CK=""
    if ! ovh_test_credentials 2>/dev/null; then
      die "Credentials OVH invalides ou absents. Lancez --renew-ovh pour les configurer."
    fi
    log "Credentials OVH valides."
    echo ""

    # Corriger les enregistrements DNS (domaine principal + additionnels)
    fix_dns

    # Pause propagation
    note "Attente de 10 secondes pour la propagation DNS..."
    sleep 10

    # Re-vérification
    section "Vérification post-correction"
    CHECKS_OK=0; CHECKS_WARN=0; CHECKS_FAIL=0
    verify_dns
    echo ""
    printf "${BOLD}══════════════════════════════════════════════════════════════${RESET}\n"
    printf "${BOLD}  Résultat post-fix : ${GREEN}%d OK${RESET} | ${YELLOW}%d avertissements${RESET} | ${RED}%d erreurs${RESET}\n" "$CHECKS_OK" "$CHECKS_WARN" "$CHECKS_FAIL"
    printf "${BOLD}══════════════════════════════════════════════════════════════${RESET}\n"
    echo ""
  fi

  print_dns_actions
  exit 0
fi

# ================================== MODE --renew-ovh ====================================
if $RENEW_OVH_MODE; then
  section "Regénération des credentials API OVH"

  if ! ${CERTBOT_WILDCARD:-false}; then
    warn "CERTBOT_WILDCARD n'est pas activé dans la configuration."
    if ! prompt_yes_no "Voulez-vous quand même configurer des credentials OVH ?" "n"; then
      exit 0
    fi
  fi

  # Afficher les credentials actuels (masqués)
  if [[ -f "${OVH_DNS_CREDENTIALS}" ]]; then
    local_ak=$(grep 'application_key' "${OVH_DNS_CREDENTIALS}" 2>/dev/null | cut -d'=' -f2 | tr -d ' ')
    local_ck=$(grep 'consumer_key' "${OVH_DNS_CREDENTIALS}" 2>/dev/null | cut -d'=' -f2 | tr -d ' ')
    echo ""
    note "Credentials actuels (${OVH_DNS_CREDENTIALS}) :"
    note "  Application Key : ${local_ak:0:4}****${local_ak: -4}"
    note "  Consumer Key    : ${local_ck:0:4}****${local_ck: -4}"
    echo ""

    # Tester la validité des credentials actuels
    note "Test de validité des credentials actuels..."
    _OVH_AK="" _OVH_AS="" _OVH_CK=""  # Forcer le rechargement
    if ovh_test_credentials 2>/dev/null; then
      log "Credentials actuels valides."
      if ! prompt_yes_no "Les credentials fonctionnent. Voulez-vous quand même les remplacer ?" "n"; then
        exit 0
      fi
    else
      warn "Credentials actuels invalides ou expirés."
    fi

    # Backup de l'ancien fichier
    backup_file "${OVH_DNS_CREDENTIALS}"
    log "Ancien fichier sauvegardé."
  else
    note "Aucun fichier de credentials existant (${OVH_DNS_CREDENTIALS})."
  fi

  # Demander les nouveaux credentials
  echo ""
  echo "Créez un nouveau token sur :"
  echo "  ${BOLD}https://eu.api.ovh.com/createToken/${RESET}"
  echo ""
  echo "Droits requis :"
  echo "  GET    /domain/zone/*"
  echo "  POST   /domain/zone/*"
  echo "  DELETE /domain/zone/*"
  echo ""

  NEW_APP_KEY="$(prompt_default "Application Key" "")"
  NEW_APP_SECRET="$(prompt_default "Application Secret" "")"
  NEW_CONSUMER_KEY="$(prompt_default "Consumer Key" "")"

  if [[ -z "$NEW_APP_KEY" || -z "$NEW_APP_SECRET" || -z "$NEW_CONSUMER_KEY" ]]; then
    die "Credentials incomplets. Aucune modification effectuée."
  fi

  # Écrire le nouveau fichier
  cat > "${OVH_DNS_CREDENTIALS}" <<OVHCREDS
dns_ovh_endpoint = ${OVH_API_ENDPOINT}
dns_ovh_application_key = ${NEW_APP_KEY}
dns_ovh_application_secret = ${NEW_APP_SECRET}
dns_ovh_consumer_key = ${NEW_CONSUMER_KEY}
OVHCREDS
  chmod 600 "${OVH_DNS_CREDENTIALS}"
  log "Nouveaux credentials sauvegardés dans ${OVH_DNS_CREDENTIALS} (mode 600)"

  # Tester les nouveaux credentials
  _OVH_AK="" _OVH_AS="" _OVH_CK=""  # Forcer le rechargement
  echo ""
  note "Test des nouveaux credentials..."
  if ovh_test_credentials 2>/dev/null; then
    log "Nouveaux credentials valides !"
  else
    warn "Les nouveaux credentials ne fonctionnent pas."
    warn "Vérifiez vos clés sur https://eu.api.ovh.com/console/"
    warn "Le fichier ${OVH_DNS_CREDENTIALS} a été mis à jour mais les clés semblent invalides."
  fi

  # Proposer le renouvellement du certificat
  if ${CERTBOT_WILDCARD:-false} && [[ -d "/etc/letsencrypt/live/${HOSTNAME_FQDN}" ]]; then
    echo ""
    if prompt_yes_no "Forcer le renouvellement du certificat wildcard avec les nouveaux credentials ?" "y"; then
      log "Renouvellement du certificat wildcard en cours..."
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
        2>&1 | tee -a "${LOG_FILE:-/var/log/bootstrap_ovh_debian13.log}"

      if systemctl is-active --quiet apache2; then
        systemctl reload apache2
        log "Apache rechargé."
      fi
    fi
  fi

  echo ""
  log "Opération terminée."
  exit 0
fi

# ================================== MODE --backup =====================================

if $BACKUP_LIST_MODE; then
  section "Sauvegardes disponibles"
  backup_list
  exit 0
fi

if $BACKUP_MODE; then
  section "Sauvegarde complète"
  run_hooks "pre-backup"
  backup_full
  run_hooks "post-backup" "$BACKUP_DEST"
  exit 0
fi

# ================================== MODES --domain-* ==================================

# --- --domain-list ---
if $DOMAIN_LIST_MODE; then
  section "Domaines gérés"
  if [[ -f "$DOMAINS_CONF" ]] && [[ -s "$DOMAINS_CONF" ]]; then
    local_count=0
    while IFS= read -r line; do
      domain="${line%%:*}"
      selector="${line#*:}"
      printf "  ${GREEN}%s${RESET}  (sélecteur DKIM: ${YELLOW}%s${RESET})\n" "$domain" "$selector"
      ((++local_count))
    done < <(dm_list_domains)
    echo ""
    log "${local_count} domaine(s) enregistré(s)."
  else
    note "Aucun domaine enregistré."
    note "Ajoutez un domaine : sudo $0 --domain-add example.com"
  fi
  exit 0
fi

# --- --domain-add ---
if [[ -n "$DOMAIN_ADD" ]]; then
  section "Ajout du domaine : ${DOMAIN_ADD}"
  local_selector="${DOMAIN_ADD_SELECTOR:-mail}"
  run_hooks "pre-domain-add" "$DOMAIN_ADD" "$local_selector"

  if dm_domain_exists "$DOMAIN_ADD"; then
    warn "Le domaine ${DOMAIN_ADD} est déjà enregistré."
    note "Utilisez --domain-check ${DOMAIN_ADD} pour vérifier sa configuration."
    exit 0
  fi

  # 1. Enregistrer
  log "Enregistrement de ${DOMAIN_ADD} (sélecteur: ${local_selector})..."
  dm_register_domain "$DOMAIN_ADD" "$local_selector"

  # 2. Générer clé DKIM
  log "Génération de la clé DKIM..."
  dm_generate_dkim_key "$DOMAIN_ADD" "$local_selector" || warn "Échec génération DKIM"

  # 3. Reconstruire OpenDKIM
  log "Reconstruction des tables OpenDKIM..."
  dm_rebuild_opendkim

  # 4. Page parking
  log "Déploiement de la page parking..."
  dm_deploy_parking "$DOMAIN_ADD"
  chown -R "${WEB_USER:-www-data}:${WEB_USER:-www-data}" "${WEB_ROOT:-/var/www}/${DOMAIN_ADD}" 2>/dev/null || true

  # 5. DNS OVH (si credentials disponibles)
  if [[ -f "${OVH_DNS_CREDENTIALS}" ]]; then
    log "Configuration DNS via API OVH..."
    _OVH_AK="" _OVH_AS="" _OVH_CK=""
    if ovh_test_credentials 2>/dev/null; then
      dm_setup_dns "$DOMAIN_ADD" "$local_selector"
    else
      warn "Credentials OVH invalides. DNS non configuré automatiquement."
    fi
  else
    note "Pas de credentials OVH — configurez le DNS manuellement."
  fi

  # 6. SSL
  log "Obtention du certificat SSL..."
  dm_obtain_ssl "$DOMAIN_ADD" "${EMAIL_FOR_CERTBOT}" || warn "Échec obtention SSL (configurer le DNS d'abord ?)"

  # 7. VHosts Apache
  log "Déploiement des VHosts Apache..."
  dm_deploy_vhosts "$DOMAIN_ADD"
  # Activer les sites
  if command -v a2ensite >/dev/null 2>&1; then
    a2ensite "000-${DOMAIN_ADD}-redirect.conf" 2>/dev/null || true
    a2ensite "010-${DOMAIN_ADD}.conf" 2>/dev/null || true
    systemctl reload apache2 2>/dev/null || true
  fi

  # 8. Logrotate
  log "Configuration logrotate..."
  dm_deploy_logrotate "$DOMAIN_ADD"

  run_hooks "post-domain-add" "$DOMAIN_ADD" "$local_selector"

  # Récap
  echo ""
  section "Récapitulatif — ${DOMAIN_ADD}"
  print_title "Domaine ajouté"
  print_note "DKIM: ${local_selector}._domainkey.${DOMAIN_ADD}"
  print_note "VHost: https://${DOMAIN_ADD}"
  print_note "Parking: ${WEB_ROOT:-/var/www}/${DOMAIN_ADD}/www/public/"
  print_note "Logs: /var/log/apache2/${DOMAIN_ADD}/"
  echo ""
  print_note "Vérifier le domaine :"
  print_cmd "sudo $0 --domain-check ${DOMAIN_ADD}"
  echo ""
  exit 0
fi

# --- --domain-remove ---
if [[ -n "$DOMAIN_REMOVE" ]]; then
  section "Suppression du domaine : ${DOMAIN_REMOVE}"

  # Interdire la suppression du domaine principal
  if [[ "$DOMAIN_REMOVE" == "${HOSTNAME_FQDN}" || "$DOMAIN_REMOVE" == "${DKIM_DOMAIN:-}" ]]; then
    die "Impossible de supprimer le domaine principal (${DOMAIN_REMOVE})."
  fi

  if ! dm_domain_exists "$DOMAIN_REMOVE"; then
    die "Le domaine ${DOMAIN_REMOVE} n'est pas enregistré."
  fi

  # Confirmation interactive
  warn "Cette action va supprimer les VHosts et la config logrotate pour ${DOMAIN_REMOVE}."
  warn "Les clés DKIM, certificats SSL et fichiers web seront conservés."
  if ! prompt_yes_no "Confirmer la suppression de ${DOMAIN_REMOVE} ?" "n"; then
    log "Suppression annulée."
    exit 0
  fi

  # Suppression
  run_hooks "pre-domain-remove" "$DOMAIN_REMOVE"
  dm_remove_vhosts "$DOMAIN_REMOVE"
  dm_remove_logrotate "$DOMAIN_REMOVE"
  dm_unregister_domain "$DOMAIN_REMOVE"
  dm_rebuild_opendkim

  if command -v a2ensite >/dev/null 2>&1; then
    systemctl reload apache2 2>/dev/null || true
  fi

  run_hooks "post-domain-remove" "$DOMAIN_REMOVE"
  log "Domaine ${DOMAIN_REMOVE} supprimé."
  warn "Fichiers conservés (nettoyage manuel si nécessaire) :"
  print_note "  DKIM: ${DKIM_KEYDIR}/${DOMAIN_REMOVE}/"
  print_note "  SSL:  /etc/letsencrypt/live/${DOMAIN_REMOVE}/"
  print_note "  Web:  ${WEB_ROOT:-/var/www}/${DOMAIN_REMOVE}/"
  echo ""
  exit 0
fi

# --- --domain-export ---
if [[ -n "$DOMAIN_EXPORT" ]]; then
  section "Export du domaine : ${DOMAIN_EXPORT}"
  local_export_dir="${PWD}"
  dm_export_domain "$DOMAIN_EXPORT" "$local_export_dir"
  log "Archive créée : ${local_export_dir}/${DOMAIN_EXPORT}.tar.gz"
  exit 0
fi

# --- --domain-import ---
if [[ -n "$DOMAIN_IMPORT" ]]; then
  section "Import de domaine depuis : ${DOMAIN_IMPORT}"
  dm_import_domain "$DOMAIN_IMPORT"
  # Rebuild OpenDKIM tables
  dm_rebuild_opendkim
  # Enable VHosts if apache available
  local_imported_domain=$(tar xzf "$DOMAIN_IMPORT" -O ./manifest.conf 2>/dev/null | grep "^DOMAIN=" | cut -d= -f2)
  if [[ -n "$local_imported_domain" ]] && command -v a2ensite >/dev/null 2>&1; then
    a2ensite "000-${local_imported_domain}-redirect.conf" 2>/dev/null || true
    a2ensite "010-${local_imported_domain}.conf" 2>/dev/null || true
    systemctl reload apache2 2>/dev/null || true
  fi
  log "Domaine importé. Vérifiez avec : sudo $0 --domain-check ${local_imported_domain:-}"
  exit 0
fi

# --- --clone-keygen ---
if $CLONE_KEYGEN; then
  section "Génération de clé SSH pour clonage"
  clone_generate_key
  echo ""
  log "Copiez cette clé publique sur le serveur cible :"
  log "  ssh-copy-id -i ${CLONE_SSH_KEY}.pub root@<IP_CIBLE>"
  log "Puis lancez le clonage :"
  log "  sudo $0 --clone <IP_CIBLE> [port]"
  exit 0
fi

# --- --clone ---
if [[ -n "$CLONE_TARGET" ]]; then
  section "Clonage vers ${CLONE_TARGET}:${CLONE_PORT}"
  load_config
  clone_preflight "$CLONE_TARGET" || exit 1
  clone_sync "$CLONE_TARGET" "$CLONE_PORT"
  notify_all "Clonage terminé vers ${CLONE_TARGET}"
  exit 0
fi

# --- --domain-staging ---
if [[ -n "$DOMAIN_STAGING" ]]; then
  section "Déploiement staging : ${DOMAIN_STAGING}"
  load_config
  dm_deploy_staging "$DOMAIN_STAGING"
  log "Domaine ${DOMAIN_STAGING} déployé en mode staging."
  log "Promouvoir en production : sudo $0 --domain-promote ${DOMAIN_STAGING}"
  exit 0
fi

# --- --domain-promote ---
if [[ -n "$DOMAIN_PROMOTE" ]]; then
  section "Promotion en production : ${DOMAIN_PROMOTE}"
  load_config
  if ! dm_is_staging "$DOMAIN_PROMOTE"; then
    die "${DOMAIN_PROMOTE} n'est pas en mode staging."
  fi
  dm_promote_staging "$DOMAIN_PROMOTE"
  log "Domaine ${DOMAIN_PROMOTE} promu en production."
  log "Configurer SSL/DNS : sudo $0 --domain-check ${DOMAIN_PROMOTE}"
  exit 0
fi

# --- --domain-group ---
if [[ -n "$DOMAIN_SET_GROUP" ]]; then
  load_config
  dm_set_group "$DOMAIN_SET_GROUP" "$DOMAIN_SET_GROUP_NAME"
  log "Domaine ${DOMAIN_SET_GROUP} assigné au groupe '${DOMAIN_SET_GROUP_NAME}'."
  exit 0
fi

# --- --group-list ---
if $GROUP_LIST_MODE; then
  load_config
  section "Groupes de domaines"
  while IFS= read -r grp; do
    [[ -z "$grp" ]] && continue
    printf "${BOLD}%s${RESET}:\n" "$grp"
    while IFS= read -r dom; do
      printf "  - %s\n" "$dom"
    done < <(dm_list_group "$grp")
  done < <(dm_list_groups)
  exit 0
fi

# --- --domain-check ---
if [[ -n "$DOMAIN_CHECK" ]] || $DOMAIN_CHECK_ALL; then
  CHECK_MODE="cli"
  CHECKS_OK=0; CHECKS_WARN=0; CHECKS_FAIL=0

  if [[ -n "$DOMAIN_CHECK" ]]; then
    dm_check_domain "$DOMAIN_CHECK"
  else
    section "Vérification de tous les domaines"
    while IFS= read -r line; do
      domain="${line%%:*}"
      selector="${line#*:}"
      dm_check_domain "$domain" "$selector"
    done < <(dm_list_domains)
  fi

  echo ""
  printf "${BOLD}══════════════════════════════════════════════════════════════${RESET}\n"
  printf "${BOLD}  Résultat : ${GREEN}%d OK${RESET} | ${YELLOW}%d avertissements${RESET} | ${RED}%d erreurs${RESET}\n" "$CHECKS_OK" "$CHECKS_WARN" "$CHECKS_FAIL"
  printf "${BOLD}══════════════════════════════════════════════════════════════${RESET}\n"
  echo ""
  exit 0
fi

# ================================== INSTALLATION ======================================
if ! $AUDIT_MODE; then
  run_hooks "pre-install"
  apt_update_upgrade

  # shellcheck source=lib/install-base.sh
  source "${LIB_DIR}/install-base.sh"
  # shellcheck source=lib/install-web.sh
  source "${LIB_DIR}/install-web.sh"
  # shellcheck source=lib/install-devtools.sh
  source "${LIB_DIR}/install-devtools.sh"
  # shellcheck source=lib/install-security.sh
  source "${LIB_DIR}/install-security.sh"
  run_hooks "post-install"
fi

# ================================== VÉRIFICATIONS (exécution CLI) =====================
CHECK_MODE="cli"
[[ -n "${HTML_REPORT:-}" ]] && html_report_start "Audit ${HOSTNAME_FQDN} — $(date '+%F %T')"
verify_services
verify_ssh
verify_web
verify_system
verify_devtools
verify_dkim
verify_sysconfig
verify_apparmor
verify_auditd
verify_egress
verify_suid_binaries
verify_tls_version
verify_users
verify_files
verify_database
verify_resources
verify_ports
verify_listening
verify_dns

[[ -n "${HTML_REPORT:-}" ]] && html_report_end && log "Rapport HTML : ${HTML_REPORT}"

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
print_note "Clé publique : ${DKIM_KEYDIR}/${DKIM_DOMAIN}/${DKIM_SELECTOR}.txt"
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

print_title "Rotation des logs (logrotate)"
print_note "Rotation configurée : sudo.log (hebdo), bootstrap (mensuel)"
if $INSTALL_MODSEC_CRS && $INSTALL_APACHE_PHP; then
  print_note "Rotation configurée : modsec_audit.log (quotidien, 14j)"
fi
print_cmd "logrotate --debug /etc/logrotate.d/custom-bootstrap"
echo ""

if $INSTALL_APACHE_PHP; then
  print_title "VirtualHosts HTTPS"
  print_note "Apex      : https://${HOSTNAME_FQDN}  →  /var/www/${HOSTNAME_FQDN}/www/public"
  print_note "Wildcard  : https://*.${HOSTNAME_FQDN} →  /var/www/${HOSTNAME_FQDN}/{sub}/public"
  print_note "www       : https://www.${HOSTNAME_FQDN} → 301 → https://${HOSTNAME_FQDN}"
  print_note "HTTP      : http://${HOSTNAME_FQDN}    → 301 → https://${HOSTNAME_FQDN}"
  echo ""
  print_note "Ajouter un sous-domaine (ex: app) :"
  print_cmd "mkdir -p /var/www/${HOSTNAME_FQDN}/app/public && chown -R www-data:www-data /var/www/${HOSTNAME_FQDN}/app"
  echo ""
  print_note "Pages d'erreur : ${ERROR_PAGES_DIR}/ (WebGL 3D, debug pour IPs de confiance)"
  print_note "Logs VHost     : /var/log/apache2/${HOSTNAME_FQDN}/"
  echo ""
fi

print_title "Gestion multi-domaines"
print_note "Ajouter un domaine :"
print_cmd "sudo ${0} --domain-add example.com"
print_note "Lister les domaines :"
print_cmd "sudo ${0} --domain-list"
print_note "Vérifier un domaine :"
print_cmd "sudo ${0} --domain-check example.com"
print_note "Supprimer un domaine :"
print_cmd "sudo ${0} --domain-remove example.com"
echo ""

print_title "Sauvegarde"
print_note "Sauvegarde complète (configs, DKIM, MariaDB, cron) :"
print_cmd "sudo ${0} --backup"
print_note "Lister les sauvegardes :"
print_cmd "sudo ${0} --backup-list"
echo ""

print_title "Hooks / Plugins"
print_note "Répertoire : ${HOOKS_DIR}"
print_note "Événements : pre-install, post-install, pre-backup, post-backup,"
print_note "  pre-domain-add, post-domain-add, pre-domain-remove, post-domain-remove"
print_note "Nommer les scripts : <événement>-<description>.sh (chmod +x)"
echo ""

print_dns_actions

print_title "Clonage serveur"
print_note "Générer une clé SSH :"
print_cmd "sudo ${0} --clone-keygen"
print_note "Copier la clé sur le serveur cible :"
print_cmd "ssh-copy-id -i /root/.ssh/clone_rsa.pub root@<IP_CIBLE>"
print_note "Lancer le clonage :"
print_cmd "sudo ${0} --clone <IP_CIBLE> [port]"
echo ""

print_title "Notifications"
print_note "Configurer les webhooks dans le fichier .conf :"
print_note "  SLACK_WEBHOOK, TELEGRAM_BOT_TOKEN + TELEGRAM_CHAT_ID, DISCORD_WEBHOOK"
echo ""

printf "${CYAN}Fichier log :${RESET} %s\n\n" "${LOG_FILE}"

# Notification de fin d'installation
notify_all "Installation terminée sur ${HOSTNAME_FQDN} — ${CHECKS_OK} OK, ${CHECKS_WARN} avertissements, ${CHECKS_FAIL} erreurs"

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
