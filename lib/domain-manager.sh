#!/usr/bin/env bash
# lib/domain-manager.sh — Gestion multi-domaines
# Sourcé par debian13-server.sh — Dépend de: lib/core.sh, lib/constants.sh, lib/ovh-api.sh
#
# Architecturé autour d'un registre central (domains.conf) et d'un ensemble
# de fonctions préfixées dm_* qui opèrent sur ce registre. Chaque domaine
# est une ligne "domaine:sélecteur_dkim" dans le fichier.
#
# Principes de conception :
#
#   1. CHEMINS INJECTABLES — Tous les chemins système sont définis via des
#      variables avec valeur par défaut (syntaxe : "${VAR:=default}").
#      Les tests bats surchargent ces variables vers des répertoires temp
#      (via override_paths dans test_helper.sh), ce qui isole totalement
#      les tests du système réel.
#
#   2. IDEMPOTENCE — Les fonctions de création (register, deploy_*) sont
#      idempotentes : les appeler deux fois produit le même résultat.
#      Implémenté via des guards (vérification d'existence avant écriture).
#
#   3. REBUILD TOTAL — OpenDKIM est régénéré entièrement à partir du
#      registre (pas de modification incrémentale). Plus simple, plus sûr,
#      et l'opération est quasi instantanée (<100 domaines).
#
#   4. TEMPLATE RENDERING — Les VHosts et pages parking sont générés
#      depuis des templates avec substitution de __HOSTNAME_FQDN__.
#      Centralise le HTML/config et facilite la personnalisation.

# --- Chemins (overridable pour les tests) ---
# Syntaxe bash : "${VAR:=default}" affecte la valeur par défaut seulement
# si la variable est vide ou non définie. Transparent en production,
# indispensable pour l'injection de chemins en test.
: "${DOMAINS_CONF:=${SCRIPTS_DIR:-/root/scripts}/domains.conf}"
: "${DKIM_KEYDIR:=/etc/opendkim/keys}"
: "${OPENDKIM_DIR:=/etc/opendkim}"
: "${WEB_ROOT:=/var/www}"
: "${APACHE_SITES_DIR:=/etc/apache2/sites-available}"
: "${LOGROTATE_DIR:=/etc/logrotate.d}"
: "${TEMPLATES_DIR:=${SCRIPT_DIR:-/root/scripts}/templates}"
: "${LOG_DIR:=/var/log/apache2}"
: "${DOMAINS_CONF_DIR:=${SCRIPTS_DIR:-/root/scripts}/domains.d}"
: "${GIT_REPOS_DIR:=/var/git}"

# ==============================================================================
# Helpers internes (DRY)
# Fonctions privées (convention : appelées uniquement par ce fichier).
# Extraites pour éviter la duplication dans les fonctions publiques.
# ==============================================================================

# Rendre un template : remplacer __HOSTNAME_FQDN__ par $domain et écrire $dest.
# Le domaine est échappé pour sed (les . / & \ sont des métacaractères).
dm_render_template() {
  local template="${TEMPLATES_DIR}/$1"
  local domain="$2"
  local dest="$3"
  if [[ ! -f "$template" ]]; then
    warn "Template introuvable: ${template}"
    return 1
  fi
  # Echapper les metacaracteres sed dans le domaine (& / \ .)
  local safe_domain
  safe_domain=$(printf '%s' "$domain" | sed 's/[&/\]/\\&/g')
  sed "s/__HOSTNAME_FQDN__/${safe_domain}/g" "$template" > "$dest"
}

# Upsert DNS OVH : cherche un enregistrement existant (par zone/sub/type),
# le met à jour s'il existe, le crée sinon. Pattern classique create-or-update
# qui rend les opérations DNS idempotentes.
dm_dns_upsert() {
  local zone="$1" sub="$2" rtype="$3" value="$4"
  local rid
  rid=$(ovh_dns_find "$zone" "$sub" "$rtype" 2>/dev/null) || rid=""
  if [[ -n "$rid" ]]; then
    ovh_dns_update "$zone" "$rid" "$value" 2>/dev/null
  else
    ovh_dns_create "$zone" "$sub" "$rtype" "$value" 2>/dev/null
  fi
}

# Chemin de la cle publique DKIM (.txt) d'un domaine
# $1=domain $2=selector
dm_dkim_txt_path() {
  echo "${DKIM_KEYDIR}/${1}/${2}.txt"
}

# Chemin de la cle privee DKIM d'un domaine
# $1=domain $2=selector
dm_dkim_key_path() {
  echo "${DKIM_KEYDIR}/${1}/${2}.private"
}

# Extraire le sous-domaine relatif a la zone de base
# $1=fqdn $2=base_domain  →  stdout (vide si apex)
_dm_subdomain() {
  local fqdn="$1" base="$2"
  if [[ "$fqdn" != "$base" ]]; then
    echo "${fqdn%%."$base"}"
  fi
}

# ==============================================================================
# Registre de domaines (domains.conf)
# ==============================================================================
# Format texte simple : une ligne par domaine, "domaine:sélecteur_dkim".
# Les commentaires (#) et lignes vides sont ignorés.
# Ce format a été choisi pour sa lisibilité et sa facilité d'édition manuelle.
# Pour les métadonnées riches par domaine, voir la section "Per-domain config"
# qui utilise un fichier .conf séparé par domaine dans domains.d/.

# Extraire le domaine de base (TLD+1) d'un FQDN.
# Utilisé pour déterminer la zone DNS OVH à manipuler.
# Limitation : ne gère pas les TLD composés (.co.uk, .com.br).
# Ex: srv.example.com → example.com, example.com → example.com
dm_extract_base_domain() {
  local fqdn="$1"
  echo "$fqdn" | awk -F. '{print $(NF-1)"."$NF}'
}

# Lister les domaines enregistres (domain:selector par ligne)
dm_list_domains() {
  [[ -f "$DOMAINS_CONF" ]] || return 0
  grep -v '^\s*#' "$DOMAINS_CONF" | grep -v '^\s*$' || true
}

# Verifier si un domaine est enregistre
dm_domain_exists() {
  local domain="$1"
  [[ -f "$DOMAINS_CONF" ]] || return 1
  grep -q "^${domain}:" "$DOMAINS_CONF" 2>/dev/null
}

# Enregistrer un domaine (idempotent)
# $1 = domain, $2 = selector (defaut: mail)
dm_register_domain() {
  local domain="$1" selector="${2:-mail}"
  dm_domain_exists "$domain" && return 0
  echo "${domain}:${selector}" >> "$DOMAINS_CONF"
}

# Desenregistrer un domaine
dm_unregister_domain() {
  local domain="$1"
  [[ -f "$DOMAINS_CONF" ]] || return 0
  local tmpfile="${DOMAINS_CONF}.tmp"
  grep -v "^${domain}:" "$DOMAINS_CONF" > "$tmpfile" || true
  mv "$tmpfile" "$DOMAINS_CONF"
}

# Obtenir le selecteur DKIM d'un domaine
dm_get_selector() {
  local domain="$1"
  [[ -f "$DOMAINS_CONF" ]] || return 0
  local line
  line=$(grep "^${domain}:" "$DOMAINS_CONF" 2>/dev/null) || true
  if [[ -n "$line" ]]; then
    echo "${line#*:}"
  fi
}

# ==============================================================================
# OpenDKIM — régénération des tables depuis domains.conf
# ==============================================================================
# OpenDKIM signe les emails sortants selon le champ From:.
# Trois fichiers de config sont régénérés à chaque modification :
#
#   keytable     : associe "sélecteur._domainkey.domaine" → clé privée
#   signingtable : associe "*@domaine" → entrée keytable correspondante
#   trustedhosts : IPs autorisées à signer (localhost uniquement)
#
# Stratégie REBUILD TOTAL : on écrase les fichiers à chaque appel plutôt
# que de les modifier incrémentalement. Avantages :
#   - Pas de désynchronisation possible entre le registre et les tables
#   - Code plus simple (pas de gestion d'ajout/suppression de lignes)
#   - Performance acceptable (< 100 domaines = instantané)

dm_rebuild_opendkim() {
  local do_restart=true
  [[ "${1:-}" == "--no-restart" ]] && do_restart=false

  local keytable="${OPENDKIM_DIR}/keytable"
  local signingtable="${OPENDKIM_DIR}/signingtable"
  local trustedhosts="${OPENDKIM_DIR}/trustedhosts"

  : > "$keytable"
  : > "$signingtable"
  cat > "$trustedhosts" <<'EOF'
127.0.0.1
localhost
::1
EOF

  local line domain selector keyfile
  while IFS= read -r line; do
    domain="${line%%:*}"
    selector="${line#*:}"
    keyfile=$(dm_dkim_key_path "$domain" "$selector")
    [[ -f "$keyfile" ]] || continue
    echo "${selector}._domainkey.${domain} ${domain}:${selector}:${keyfile}" >> "$keytable"
    echo "*@${domain} ${selector}._domainkey.${domain}" >> "$signingtable"
  done < <(dm_list_domains)

  if $do_restart; then
    systemctl restart opendkim 2>/dev/null || true
  fi
}

# Generer une cle DKIM pour un domaine (si absente)
# $1 = domain, $2 = selector (defaut: mail)
dm_generate_dkim_key() {
  local domain="$1" selector="${2:-mail}"
  local keydir="${DKIM_KEYDIR}/${domain}"
  local keyfile
  keyfile=$(dm_dkim_key_path "$domain" "$selector")

  [[ -f "$keyfile" ]] && { log "DKIM: cle existante pour ${domain} (${selector})"; return 0; }

  mkdir -p "$keydir"
  chmod 755 "$keydir"

  if opendkim-genkey -s "$selector" -d "$domain" -b "${DKIM_KEY_BITS:-2048}" -r -D "$keydir"; then
    chown opendkim:opendkim "$keyfile"
    chmod 600 "$keyfile"
    chmod 644 "$(dm_dkim_txt_path "$domain" "$selector")"
    log "DKIM: cle generee pour ${domain} (${selector})"
  else
    warn "DKIM: echec generation cle pour ${domain}"
    return 1
  fi

  chmod 750 "$keydir"
  chown -R opendkim:opendkim "$keydir"
}

# Rotation de clé DKIM : génère un nouveau sélecteur horodaté (mail20260214),
# met à jour le registre, mais conserve l'ancien sélecteur sur disque.
# Procédure recommandée : publier le nouveau DNS, attendre 48h de propagation,
# puis supprimer manuellement l'ancienne clé et l'ancien enregistrement DNS.
dm_rotate_dkim() {
  local domain="$1"
  if ! dm_domain_exists "$domain"; then
    err "Domaine non enregistré : ${domain}"
    return 1
  fi

  local old_sel
  old_sel=$(dm_get_selector "$domain")
  local new_sel="mail$(date +%Y%m%d)"

  # Avoid collision with existing key
  if [[ -f "${DKIM_KEYDIR}/${domain}/${new_sel}.private" ]]; then
    new_sel="${new_sel}r${RANDOM}"
  fi

  log "DKIM rotation: ${domain} ${old_sel} → ${new_sel}"
  dm_generate_dkim_key "$domain" "$new_sel"

  # Update selector in domains.conf
  dm_unregister_domain "$domain"
  dm_register_domain "$domain" "$new_sel"

  log "DKIM rotation terminée. Ancien sélecteur '${old_sel}' conservé."
  log "Publiez le nouveau DNS, puis supprimez l'ancien après 48h."
}

# ==============================================================================
# Déploiement : parking page, VHosts, logrotate
# ==============================================================================
# Chaque domaine obtient une arborescence web, des VHosts Apache et une
# config logrotate. Les VHosts sont numérotés pour contrôler l'ordre de
# chargement Apache (000- redirect, 010- HTTPS, 015- proxy/mTLS, 020- wildcard).

# Page parking WebGL : page d'attente esthétique déployée immédiatement.
# Le template parking-page.html contient un canvas Three.js animé.
dm_deploy_parking() {
  local domain="$1"
  local docroot="${WEB_ROOT}/${domain}/www/public"

  mkdir -p "${docroot}/css"
  dm_render_template "parking-page.html" "$domain" "${docroot}/index.html" || return 1
  cp "${TEMPLATES_DIR}/parking-style.css" "${docroot}/css/style.css"

  cat > "${docroot}/robots.txt" <<'EOF'
User-agent: *
Disallow: /
EOF
  log "Parking page deployee pour ${domain}"
}

# Deployer les VHosts Apache pour un domaine
dm_deploy_vhosts() {
  local domain="$1"

  mkdir -p "${LOG_DIR}/${domain}" 2>/dev/null || true
  dm_render_template "vhost-http-redirect.conf.template" "$domain" \
    "${APACHE_SITES_DIR}/000-${domain}-redirect.conf" || return 1
  dm_render_template "vhost-https.conf.template" "$domain" \
    "${APACHE_SITES_DIR}/010-${domain}.conf" || return 1
  log "VHosts deployes pour ${domain}"
}

# Deployer le VHost wildcard pour un domaine
dm_deploy_vhost_wildcard() {
  local domain="$1"
  dm_render_template "vhost-wildcard.conf.template" "$domain" \
    "${APACHE_SITES_DIR}/020-${domain}-wildcard.conf" || return 1
  log "VHost wildcard deploye pour ${domain}"
}

# Supprimer les VHosts Apache d'un domaine
dm_remove_vhosts() {
  local domain="$1"
  rm -f "${APACHE_SITES_DIR}/000-${domain}-redirect.conf"
  rm -f "${APACHE_SITES_DIR}/010-${domain}.conf"
  rm -f "${APACHE_SITES_DIR}/020-${domain}-wildcard.conf"
  local enabled_dir
  enabled_dir="$(dirname "$APACHE_SITES_DIR")/sites-enabled"
  rm -f "${enabled_dir}/000-${domain}-redirect.conf" 2>/dev/null || true
  rm -f "${enabled_dir}/010-${domain}.conf" 2>/dev/null || true
  rm -f "${enabled_dir}/020-${domain}-wildcard.conf" 2>/dev/null || true
  log "VHosts supprimes pour ${domain}"
}

# Deployer la config logrotate pour un domaine
dm_deploy_logrotate() {
  local domain="$1"
  cat > "${LOGROTATE_DIR}/apache-vhost-${domain}" <<EOF
${LOG_DIR}/${domain}/*.log {
    daily
    missingok
    rotate ${LOGROTATE_KEEP_DAYS:-14}
    compress
    delaycompress
    notifempty
    create 0640 root adm
    sharedscripts
    postrotate
        if invoke-rc.d apache2 status > /dev/null 2>&1; then
            invoke-rc.d apache2 reload > /dev/null
        fi
    endscript
}
EOF
  log "Logrotate configure pour ${domain}"
}

# Supprimer la config logrotate d'un domaine
dm_remove_logrotate() {
  local domain="$1"
  rm -f "${LOGROTATE_DIR}/apache-vhost-${domain}"
  log "Logrotate supprime pour ${domain}"
}

# ==============================================================================
# SSL — obtention de certificat via certbot
# ==============================================================================
# Deux stratégies de validation Let's Encrypt selon la disponibilité
# des credentials API OVH :
#   - DNS-01 (OVH) : certificat wildcard *.domaine — nécessite l'API OVH
#   - HTTP-01 (fallback) : certificat apex + www — fonctionne sans API
# Le choix est automatique : si le fichier .ovh-dns.ini existe → DNS-01.

dm_obtain_ssl() {
  local domain="$1" email="${2:-${EMAIL_FOR_CERTBOT:-}}"

  if [[ -f "${OVH_DNS_CREDENTIALS:-/root/.ovh-dns.ini}" ]]; then
    log "SSL: obtention certificat wildcard pour ${domain} (DNS-01 OVH)"
    certbot certonly \
      --dns-ovh \
      --dns-ovh-credentials "${OVH_DNS_CREDENTIALS:-/root/.ovh-dns.ini}" \
      --dns-ovh-propagation-seconds "${CERTBOT_DNS_PROPAGATION:-60}" \
      -d "${domain}" -d "*.${domain}" \
      --email "$email" --agree-tos --non-interactive 2>&1
  else
    log "SSL: obtention certificat pour ${domain} (HTTP-01)"
    certbot certonly \
      --apache --preferred-challenges http \
      -d "${domain}" -d "www.${domain}" \
      --email "$email" --agree-tos --non-interactive 2>&1
  fi
}

# ==============================================================================
# DANE/TLSA — sécurisation TLS pour SMTP
# ==============================================================================
# DANE (DNS-based Authentication of Named Entities, RFC 6698) publie le hash
# du certificat TLS dans le DNS. Les serveurs SMTP supportant DANE peuvent
# vérifier que le certificat présenté correspond à celui publié, empêchant
# les attaques MITM même avec une CA compromise.
# Format TLSA : "3 1 1 <sha256>" = DANE-EE, SubjectPublicKeyInfo, SHA-256.

dm_generate_tlsa_record() {
  local cert="$1"
  [[ -f "$cert" ]] || { warn "TLSA: certificat introuvable: ${cert}"; return 1; }

  local hash
  hash=$(openssl x509 -in "$cert" -noout -pubkey 2>/dev/null \
    | openssl pkey -pubin -outform DER 2>/dev/null \
    | openssl dgst -sha256 -hex 2>/dev/null \
    | awk '{print $NF}')

  [[ -n "$hash" && "${#hash}" -eq 64 ]] || { warn "TLSA: impossible de calculer le hash"; return 1; }

  echo "3 1 1 ${hash}"
}

# Publier un enregistrement TLSA pour SMTP (port 25) via OVH API
# $1 = domain
dm_setup_tlsa() {
  local domain="$1"
  local cert_path="${LETSENCRYPT_LIVE:-/etc/letsencrypt/live}/${domain}/cert.pem"

  if [[ ! -f "$cert_path" ]]; then
    log "TLSA: pas de certificat pour ${domain}, ignoré"
    return 0
  fi

  local tlsa_record
  tlsa_record=$(dm_generate_tlsa_record "$cert_path") || return 0

  local base_domain
  base_domain=$(dm_extract_base_domain "$domain")
  local subdomain
  subdomain=$(_dm_subdomain "$domain" "$base_domain")

  local tlsa_sub="_25._tcp"
  [[ -n "$subdomain" ]] && tlsa_sub="_25._tcp.${subdomain}"

  dm_dns_upsert "$base_domain" "$tlsa_sub" "TLSA" "\"${tlsa_record}\"" || {
    warn "TLSA: échec publication pour ${domain}"
    return 1
  }

  log "TLSA: enregistrement publié pour ${domain} (_25._tcp)"
}

# ==============================================================================
# DNS — configuration via API OVH
# ==============================================================================
# Séquence complète de configuration DNS pour un domaine :
# A → AAAA → SPF → DKIM → DMARC → CAA → TLSA → refresh zone.
# Les compteurs DM_DNS_OK / DM_DNS_FAIL permettent un résumé en fin d'opération.
# Chaque enregistrement utilise dm_dns_upsert() (create-or-update idempotent).

dm_setup_dns() {
  local domain="$1" selector="${2:-mail}"
  local base_domain
  base_domain=$(dm_extract_base_domain "$domain")
  local subdomain
  subdomain=$(_dm_subdomain "$domain" "$base_domain")

  DM_DNS_OK=0; DM_DNS_FAIL=0

  # --- A + www A ---
  if [[ -n "${SERVER_IP:-}" ]]; then
    dm_dns_upsert "$base_domain" "$subdomain" "A" "\"${SERVER_IP}\"" && ((++DM_DNS_OK)) || ((++DM_DNS_FAIL))
    local www_sub="www"
    [[ -n "$subdomain" ]] && www_sub="www.${subdomain}"
    dm_dns_upsert "$base_domain" "$www_sub" "A" "\"${SERVER_IP}\"" && ((++DM_DNS_OK)) || ((++DM_DNS_FAIL))
  fi

  # --- AAAA ---
  if [[ -n "${SERVER_IP6:-}" ]]; then
    dm_dns_upsert "$base_domain" "$subdomain" "AAAA" "\"${SERVER_IP6}\"" && ((++DM_DNS_OK)) || ((++DM_DNS_FAIL))
  fi

  # --- SPF ---
  ovh_setup_spf "$base_domain" "${SERVER_IP:-}" 2>/dev/null && ((++DM_DNS_OK)) || ((++DM_DNS_FAIL))

  # --- DKIM ---
  local dkim_txt
  dkim_txt=$(dm_dkim_txt_path "$domain" "$selector")
  if [[ -f "$dkim_txt" ]]; then
    ovh_setup_dkim "$base_domain" "$selector" "$dkim_txt" 2>/dev/null && ((++DM_DNS_OK)) || ((++DM_DNS_FAIL))
  else
    warn "DNS: fichier DKIM ${dkim_txt} introuvable, DKIM ignore"
  fi

  # --- DMARC ---
  ovh_setup_dmarc "$base_domain" "${EMAIL_FOR_CERTBOT:-}" 2>/dev/null && ((++DM_DNS_OK)) || ((++DM_DNS_FAIL))

  # --- CAA ---
  local caa_rid
  caa_rid=$(ovh_dns_find "$base_domain" "" "CAA" 2>/dev/null) || caa_rid=""
  if [[ -z "$caa_rid" ]]; then
    ovh_dns_create "$base_domain" "" "CAA" "\"0 issue \\\"${CAA_ISSUER:-letsencrypt.org}\\\"\"" 2>/dev/null && ((++DM_DNS_OK)) || ((++DM_DNS_FAIL))
  fi

  # --- TLSA (DANE pour SMTP) ---
  dm_setup_tlsa "$domain" && ((++DM_DNS_OK)) || ((++DM_DNS_FAIL))

  # --- Refresh zone ---
  ovh_dns_refresh "$base_domain" 2>/dev/null || true

  log "DNS: ${domain} — ${DM_DNS_OK} OK, ${DM_DNS_FAIL} echec(s)"
}

# Configurer PTR (reverse DNS) — specifique au domaine principal
# $1=hostname_fqdn
dm_setup_ptr() {
  local fqdn="$1"
  DM_PTR_OK=0; DM_PTR_FAIL=0

  if [[ -n "${SERVER_IP:-}" && "${DNS_PTR:-}" != "$fqdn" ]]; then
    log "DNS fix : PTR IPv4 ${SERVER_IP} -> ${fqdn}"
    if ovh_ip_reverse_set "$SERVER_IP" "$fqdn" 2>/dev/null; then
      ((++DM_PTR_OK))
    else
      ((++DM_PTR_FAIL))
    fi
  fi

  if [[ -n "${SERVER_IP6:-}" && "${DNS_PTR6:-}" != "$fqdn" ]]; then
    log "DNS fix : PTR IPv6 ${SERVER_IP6} -> ${fqdn}"
    if ovh_ip_reverse_set "$SERVER_IP6" "$fqdn" 2>/dev/null; then
      ((++DM_PTR_OK))
    else
      ((++DM_PTR_FAIL))
    fi
  fi
}

# ==============================================================================
# Vérification d'un domaine
# ==============================================================================
# Audit en lecture seule : interroge les DNS publics (8.8.8.8) et vérifie
# la présence de chaque enregistrement. Utilise emit_check() (lib/verify.sh)
# pour un affichage ok/warn/fail cohérent avec le reste de l'audit.

dm_check_domain() {
  local domain="$1" selector="${2:-}"

  if [[ -z "$selector" ]]; then
    selector=$(dm_get_selector "$domain")
    [[ -z "$selector" ]] && selector="mail"
  fi

  local base_domain
  base_domain=$(dm_extract_base_domain "$domain")

  emit_section "Domaine: ${domain}"

  # DNS A
  local dns_a
  dns_a=$(dig +short A "$domain" @8.8.8.8 2>/dev/null | head -1) || dns_a=""
  if [[ -n "$dns_a" ]]; then
    emit_check "ok" "DNS A ${domain} -> ${dns_a}"
  else
    emit_check "fail" "DNS A ${domain} non resolu"
  fi

  # DNS AAAA
  local dns_aaaa
  dns_aaaa=$(dig +short AAAA "$domain" @8.8.8.8 2>/dev/null | head -1) || dns_aaaa=""
  if [[ -n "$dns_aaaa" ]]; then
    emit_check "ok" "DNS AAAA ${domain} -> ${dns_aaaa}"
  else
    emit_check "warn" "DNS AAAA ${domain} non configure"
  fi

  # SPF
  local dns_spf
  dns_spf=$(dig +short TXT "$base_domain" @8.8.8.8 2>/dev/null | grep "v=spf1" | head -1) || dns_spf=""
  if [[ -n "$dns_spf" ]]; then
    emit_check "ok" "SPF ${base_domain} configure"
  else
    emit_check "fail" "SPF ${base_domain} manquant"
  fi

  # DKIM
  local dns_dkim
  dns_dkim=$(dig +short TXT "${selector}._domainkey.${domain}" @8.8.8.8 2>/dev/null | head -1) || dns_dkim=""
  if [[ -n "$dns_dkim" ]] && [[ "$dns_dkim" == *"v=DKIM1"* ]]; then
    emit_check "ok" "DKIM ${selector}._domainkey.${domain} configure"
  else
    emit_check "fail" "DKIM ${selector}._domainkey.${domain} manquant"
  fi

  # DMARC
  local dns_dmarc
  dns_dmarc=$(dig +short TXT "_dmarc.${base_domain}" @8.8.8.8 2>/dev/null | head -1) || dns_dmarc=""
  if [[ -n "$dns_dmarc" ]]; then
    emit_check "ok" "DMARC _dmarc.${base_domain} configure"
  else
    emit_check "fail" "DMARC _dmarc.${base_domain} manquant"
  fi

  # SSL certificate
  if [[ -d "/etc/letsencrypt/live/${domain}" ]]; then
    local expiry
    expiry=$(openssl x509 -enddate -noout -in "/etc/letsencrypt/live/${domain}/fullchain.pem" 2>/dev/null | cut -d= -f2) || expiry=""
    if [[ -n "$expiry" ]]; then
      emit_check "ok" "SSL ${domain} valide jusqu'au ${expiry}"
    else
      emit_check "warn" "SSL ${domain} certificat present mais illisible"
    fi
  else
    emit_check "warn" "SSL ${domain} pas de certificat"
  fi

  # VHost
  if [[ -f "${APACHE_SITES_DIR}/010-${domain}.conf" ]]; then
    emit_check "ok" "VHost HTTPS ${domain} present"
  else
    emit_check "warn" "VHost HTTPS ${domain} absent"
  fi

  emit_section_close
}

# ==============================================================================
# Export / Import de domaines
# ==============================================================================
# Migration de domaine entre serveurs : export vers archive tar.gz autonome
# contenant un manifest (métadonnées) + tous les fichiers de config.
# Le manifest permet de restaurer sans connaître les chemins d'origine.
# Complémentaire au clonage complet (lib/clone.sh) : ici on exporte un
# seul domaine, pas tout le serveur.

dm_export_domain() {
  local domain="$1" dest_dir="${2:-.}"
  local selector

  if ! dm_domain_exists "$domain"; then
    warn "Export: le domaine ${domain} n'est pas enregistré"
    return 1
  fi

  selector=$(dm_get_selector "$domain")

  local staging
  staging=$(mktemp -d)
  local archive="${dest_dir}/${domain}.tar.gz"
  mkdir -p "$dest_dir"

  # Manifest
  cat > "${staging}/manifest.conf" <<EOF
DOMAIN=${domain}
SELECTOR=${selector}
EXPORT_DATE=$(date +%Y-%m-%d_%H%M%S)
EOF

  # DKIM keys
  if [[ -d "${DKIM_KEYDIR}/${domain}" ]]; then
    mkdir -p "${staging}/dkim"
    cp -a "${DKIM_KEYDIR}/${domain}"/. "${staging}/dkim/"
  fi

  # VHosts Apache
  local found_vhosts=false
  for pattern in "000-${domain}-redirect.conf" "010-${domain}.conf" "020-${domain}-wildcard.conf"; do
    if [[ -f "${APACHE_SITES_DIR}/${pattern}" ]]; then
      found_vhosts=true
      mkdir -p "${staging}/apache"
      cp "${APACHE_SITES_DIR}/${pattern}" "${staging}/apache/"
    fi
  done

  # Logrotate
  if [[ -f "${LOGROTATE_DIR}/apache-vhost-${domain}" ]]; then
    mkdir -p "${staging}/logrotate"
    cp "${LOGROTATE_DIR}/apache-vhost-${domain}" "${staging}/logrotate/"
  fi

  # Web root
  if [[ -d "${WEB_ROOT}/${domain}" ]]; then
    cp -a "${WEB_ROOT}/${domain}" "${staging}/www-root"
    # Rename to relative: www-root contains the domain's web tree
    mv "${staging}/www-root" "${staging}/www"
  fi

  tar czf "$archive" -C "$staging" .
  rm -rf "$staging"

  log "Export: ${domain} -> ${archive}"
}

# Importer un domaine depuis une archive tar.gz
# $1 = path to archive
dm_import_domain() {
  local archive="$1"

  if [[ ! -f "$archive" ]]; then
    warn "Import: archive introuvable: ${archive}"
    return 1
  fi

  # Extract to temporary directory
  local staging
  staging=$(mktemp -d)
  tar xzf "$archive" -C "$staging" 2>/dev/null || { warn "Import: archive corrompue"; rm -rf "$staging"; return 1; }

  # Read manifest
  if [[ ! -f "${staging}/manifest.conf" ]]; then
    warn "Import: manifest.conf manquant dans l'archive"
    rm -rf "$staging"
    return 1
  fi

  local domain selector
  domain=$(grep "^DOMAIN=" "${staging}/manifest.conf" | cut -d= -f2)
  selector=$(grep "^SELECTOR=" "${staging}/manifest.conf" | cut -d= -f2)

  if [[ -z "$domain" ]]; then
    warn "Import: DOMAIN manquant dans manifest.conf"
    rm -rf "$staging"
    return 1
  fi

  if dm_domain_exists "$domain"; then
    warn "Import: le domaine ${domain} est déjà enregistré (désinscrire d'abord)"
    rm -rf "$staging"
    return 1
  fi

  # Register domain
  dm_register_domain "$domain" "${selector:-mail}"

  # Restore DKIM keys
  if [[ -d "${staging}/dkim" ]]; then
    mkdir -p "${DKIM_KEYDIR}/${domain}"
    cp -a "${staging}/dkim"/. "${DKIM_KEYDIR}/${domain}/"
  fi

  # Restore VHosts
  if [[ -d "${staging}/apache" ]]; then
    cp "${staging}/apache"/*.conf "${APACHE_SITES_DIR}/" 2>/dev/null || true
  fi

  # Restore logrotate
  if [[ -d "${staging}/logrotate" ]]; then
    cp "${staging}/logrotate"/* "${LOGROTATE_DIR}/" 2>/dev/null || true
  fi

  # Restore web root
  if [[ -d "${staging}/www" ]]; then
    mkdir -p "${WEB_ROOT}/${domain}"
    cp -a "${staging}/www"/. "${WEB_ROOT}/${domain}/"
  fi

  rm -rf "$staging"
  log "Import: ${domain} restauré depuis ${archive}"
}

# ==============================================================================
# Configuration par domaine (domains.d/)
# ==============================================================================
# Alors que domains.conf stocke uniquement domaine:sélecteur, le répertoire
# domains.d/ contient un fichier .conf par domaine avec des paires clé=valeur
# arbitraires (STAGING, GROUP, DB_NAME, CONTAINER_IMAGE, WAF_RATE_LIMIT...).
# Format INI simplifié : une clé par ligne, pas de sections.

dm_set_domain_config() {
  local domain="$1" key="$2" value="$3"
  mkdir -p "$DOMAINS_CONF_DIR"
  local conf="${DOMAINS_CONF_DIR}/${domain}.conf"
  # Remove existing key if present, then append
  if [[ -f "$conf" ]]; then
    local tmp
    tmp=$(grep -v "^${key}=" "$conf" 2>/dev/null || true)
    printf '%s\n' "$tmp" > "$conf"
  fi
  echo "${key}=${value}" >> "$conf"
  # Clean empty lines at top
  sed -i '/^$/d' "$conf"
}

# Get a config key for a domain
# $1 = domain, $2 = key, $3 = default (optional)
dm_get_domain_config() {
  local domain="$1" key="$2" default="${3:-}"
  local conf="${DOMAINS_CONF_DIR}/${domain}.conf"
  if [[ -f "$conf" ]]; then
    local val
    val=$(grep "^${key}=" "$conf" 2>/dev/null | tail -1 | cut -d= -f2-)
    if [[ -n "$val" ]]; then
      echo "$val"
      return 0
    fi
  fi
  [[ -n "$default" ]] && echo "$default"
  return 0
}

# List all config keys for a domain
# $1 = domain
dm_list_domain_config() {
  local domain="$1"
  local conf="${DOMAINS_CONF_DIR}/${domain}.conf"
  [[ -f "$conf" ]] && grep -v '^#' "$conf" | grep -v '^$' || true
}

# ==============================================================================
# Staging mode
# ==============================================================================
# Déployer un domaine sans toucher au DNS ni demander de certificat SSL.
# Utile pour préparer la config avant le basculement DNS, ou pour tester
# en local. La promotion vers production efface le flag STAGING.

dm_deploy_staging() {
  local domain="$1" selector="${2:-mail}"
  dm_register_domain "$domain" "$selector"
  dm_set_domain_config "$domain" "STAGING" "true"
  dm_deploy_parking "$domain"
  dm_deploy_vhosts "$domain"
  dm_deploy_logrotate "$domain"
  log "Staging: ${domain} déployé en mode staging (pas de SSL/DNS)"
}

# Check if a domain is in staging mode
# $1 = domain — returns 0 if staging, 1 otherwise
dm_is_staging() {
  local domain="$1"
  local val
  val=$(dm_get_domain_config "$domain" "STAGING")
  [[ "$val" == "true" ]]
}

# Promote a staging domain to production (clear staging flag)
# $1 = domain
dm_promote_staging() {
  local domain="$1"
  dm_set_domain_config "$domain" "STAGING" "false"
  log "Staging: ${domain} promu en production"
}

# ==============================================================================
# Groupes de domaines
# ==============================================================================
# Organiser les domaines par usage (production, staging, client-X, etc.).
# Le groupe est stocké comme clé "GROUP" dans la config par domaine.
# Permet d'appliquer des opérations en batch sur un sous-ensemble.

dm_set_group() {
  local domain="$1" group="$2"
  dm_set_domain_config "$domain" "GROUP" "$group"
}

# Get the group for a domain (empty if none)
dm_get_group() {
  local domain="$1"
  dm_get_domain_config "$domain" "GROUP"
}

# List all domains in a given group
dm_list_group() {
  local group="$1"
  local entry domain
  while IFS= read -r entry; do
    [[ -z "$entry" ]] && continue
    domain="${entry%%:*}"
    local g
    g=$(dm_get_domain_config "$domain" "GROUP")
    [[ "$g" == "$group" ]] && echo "$domain"
  done < <(dm_list_domains)
}

# List all distinct group names
dm_list_groups() {
  local entry domain seen=""
  while IFS= read -r entry; do
    [[ -z "$entry" ]] && continue
    domain="${entry%%:*}"
    local g
    g=$(dm_get_domain_config "$domain" "GROUP")
    if [[ -n "$g" && "$seen" != *"|${g}|"* ]]; then
      echo "$g"
      seen="${seen}|${g}|"
    fi
  done < <(dm_list_domains)
}

# ==============================================================================
# Reverse proxy
# ==============================================================================
# VHost Apache en mode reverse proxy : forward vers un backend applicatif
# (Node, Python, Go...) avec support WebSocket (RewriteCond Upgrade) et
# headers de sécurité standards. Le proxy écoute sur :443 et forward en HTTP
# vers le backend local (pas de TLS interne — le backend est sur loopback).

dm_deploy_proxy() {
  local domain="$1" backend="$2"
  local conf="${APACHE_SITES_DIR}/015-${domain}-proxy.conf"

  cat > "$conf" <<PROXY
<VirtualHost *:443>
    ServerName ${domain}
    ServerAlias www.${domain}

    ProxyPreserveHost On
    ProxyPass / ${backend}/
    ProxyPassReverse / ${backend}/

    # WebSocket support
    RewriteEngine On
    RewriteCond %{HTTP:Upgrade} =websocket [NC]
    RewriteRule /(.*) ws://${backend#http://}\$1 [P,L]

    # Security headers
    Header always set X-Frame-Options "SAMEORIGIN"
    Header always set X-Content-Type-Options "nosniff"
    Header always set X-XSS-Protection "1; mode=block"
    Header always set Referrer-Policy "strict-origin-when-cross-origin"

    ErrorLog \${APACHE_LOG_DIR}/${domain}/error.log
    CustomLog \${APACHE_LOG_DIR}/${domain}/access.log combined
</VirtualHost>
PROXY
  log "Reverse proxy déployé : ${domain} → ${backend}"
}

# Supprimer le VHost reverse proxy
# $1 = domain
dm_remove_proxy() {
  local domain="$1"
  rm -f "${APACHE_SITES_DIR}/015-${domain}-proxy.conf"
}

# ==============================================================================
# Git push-to-deploy
# ==============================================================================
# Crée un dépôt git bare sur le serveur avec un hook post-receive qui
# checkout automatiquement dans le DocumentRoot du domaine.
# Workflow développeur : git remote add prod ssh://root@server/var/git/dom.git
#                        git push prod main
# Le hook fait un simple "git checkout -f" — pas de build, pas de restart.
# Pour des workflows plus complexes, utiliser le système de hooks (lib/hooks.sh).

dm_setup_git_deploy() {
  local domain="$1"
  local repo_dir="${GIT_REPOS_DIR}/${domain}.git"
  local docroot="${WEB_ROOT}/${domain}/www/public"
  local hook="${repo_dir}/hooks/post-receive"

  mkdir -p "${repo_dir}"
  git init --bare "$repo_dir" 2>/dev/null || true

  mkdir -p "${repo_dir}/hooks"
  cat > "$hook" <<HOOK
#!/bin/bash
GIT_WORK_TREE="${docroot}" git checkout -f
echo "Deployed ${domain} to ${docroot}"
HOOK
  chmod +x "$hook"
  log "Git deploy configuré : ${domain} → ${docroot}"
}

# Retourner l'URL du remote git pour un domaine
# $1 = domain
dm_get_git_remote() {
  local domain="$1"
  echo "ssh://root@${HOSTNAME_FQDN:-localhost}${GIT_REPOS_DIR}/${domain}.git"
}

# ==============================================================================
# Gestion de bases de données par domaine
# ==============================================================================
# Un domaine = une base MariaDB + un utilisateur dédié. Le mot de passe est
# généré aléatoirement et stocké dans la config par domaine (domains.d/).
# Convention de nommage : les points et tirets du domaine sont remplacés
# par des underscores (ex: app.example.com → app_example_com).

dm_create_database() {
  local domain="$1"
  # Derive DB name from domain: dots → underscores
  local db_name
  db_name=$(echo "$domain" | tr '.' '_' | tr '-' '_')
  local db_user="${db_name}"
  local db_pass
  db_pass=$(openssl rand -base64 18 2>/dev/null | tr -d '/+=' | head -c 16)
  [[ -z "$db_pass" ]] && db_pass="pass$(date +%s)"

  # Check if already configured
  local existing
  existing=$(dm_get_domain_config "$domain" "DB_NAME")
  [[ -n "$existing" ]] && { log "DB: base déjà configurée pour ${domain}"; return 0; }

  mysql -e "CREATE DATABASE IF NOT EXISTS \`${db_name}\`;" 2>/dev/null
  mysql -e "CREATE USER IF NOT EXISTS '${db_user}'@'localhost' IDENTIFIED BY '${db_pass}';" 2>/dev/null
  mysql -e "GRANT ALL PRIVILEGES ON \`${db_name}\`.* TO '${db_user}'@'localhost';" 2>/dev/null
  mysql -e "FLUSH PRIVILEGES;" 2>/dev/null

  dm_set_domain_config "$domain" "DB_NAME" "$db_name"
  dm_set_domain_config "$domain" "DB_USER" "$db_user"
  dm_set_domain_config "$domain" "DB_PASSWORD" "$db_pass"

  log "DB: base ${db_name} créée pour ${domain} (user: ${db_user})"
}

# Supprimer la base de données et l'utilisateur d'un domaine
# $1 = domain
dm_drop_database() {
  local domain="$1"
  local db_name
  db_name=$(dm_get_domain_config "$domain" "DB_NAME")
  local db_user
  db_user=$(dm_get_domain_config "$domain" "DB_USER")

  [[ -z "$db_name" ]] && db_name=$(echo "$domain" | tr '.' '_' | tr '-' '_')
  [[ -z "$db_user" ]] && db_user="$db_name"

  mysql -e "DROP DATABASE IF EXISTS \`${db_name}\`;" 2>/dev/null
  mysql -e "DROP USER IF EXISTS '${db_user}'@'localhost';" 2>/dev/null

  log "DB: base ${db_name} supprimée pour ${domain}"
}

# Lister les domaines avec une base de données configurée
dm_list_databases() {
  local entry domain
  while IFS= read -r entry; do
    [[ -z "$entry" ]] && continue
    domain="${entry%%:*}"
    local db
    db=$(dm_get_domain_config "$domain" "DB_NAME")
    [[ -n "$db" ]] && echo "${domain}:${db}"
  done < <(dm_list_domains)
}

# ==============================================================================
# Conteneurisation (Docker/Podman)
# ==============================================================================
# Déployer une application containerisée pour un domaine :
# 1. Lancer le conteneur sur un port local aléatoire (8000-8999)
# 2. Configurer un reverse proxy Apache vers ce port
# 3. Stocker les métadonnées (image, port, nom) dans la config par domaine
#
# Le conteneur est bindé sur 127.0.0.1 uniquement — pas d'exposition directe.
# Le nom du conteneur est dérivé du domaine (points → tirets).

dm_deploy_container() {
  local domain="$1" image="$2" port="${3:-80}"
  local container_name
  container_name=$(echo "$domain" | tr '.' '-')
  local host_port
  host_port=$((8000 + RANDOM % 1000))

  # Run container
  docker run -d --name "$container_name" \
    --restart unless-stopped \
    -p "127.0.0.1:${host_port}:${port}" \
    "$image"

  # Store config
  if declare -f dm_set_domain_config >/dev/null 2>&1; then
    dm_set_domain_config "$domain" "CONTAINER_IMAGE" "$image"
    dm_set_domain_config "$domain" "CONTAINER_NAME" "$container_name"
    dm_set_domain_config "$domain" "CONTAINER_PORT" "$host_port"
  fi

  # Setup reverse proxy
  dm_deploy_proxy "$domain" "http://127.0.0.1:${host_port}"

  log "Container: ${container_name} (${image}) → port ${host_port}"
}

# Arrêter le conteneur d'un domaine
# $1 = domain
dm_stop_container() {
  local domain="$1"
  local container_name
  container_name=$(echo "$domain" | tr '.' '-')
  docker stop "$container_name"
  log "Container: ${container_name} arrêté"
}

# Statut du conteneur d'un domaine
# $1 = domain
dm_container_status() {
  local domain="$1"
  local container_name
  container_name=$(echo "$domain" | tr '.' '-')
  docker ps --filter "name=${container_name}"
}

# Logs du conteneur d'un domaine
# $1 = domain
dm_container_logs() {
  local domain="$1"
  local container_name
  container_name=$(echo "$domain" | tr '.' '-')
  docker logs "$container_name"
}
