#!/usr/bin/env bash
# lib/domain-manager.sh — Gestion multi-domaines (DKIM, VHost, SSL, DNS, parking)
# Source par debian13-server.sh — Depend de: lib/core.sh, lib/constants.sh, lib/ovh-api.sh

# Chemins (overridable pour les tests)
: "${DOMAINS_CONF:=${SCRIPTS_DIR:-/root/scripts}/domains.conf}"
: "${DKIM_KEYDIR:=/etc/opendkim/keys}"
: "${OPENDKIM_DIR:=/etc/opendkim}"
: "${WEB_ROOT:=/var/www}"
: "${APACHE_SITES_DIR:=/etc/apache2/sites-available}"
: "${LOGROTATE_DIR:=/etc/logrotate.d}"
: "${TEMPLATES_DIR:=${SCRIPT_DIR:-/root/scripts}/templates}"
: "${LOG_DIR:=/var/log/apache2}"
: "${DOMAINS_CONF_DIR:=${SCRIPTS_DIR:-/root/scripts}/domains.d}"

# ==============================================================================
# Helpers internes (DRY)
# ==============================================================================

# Rendre un template : remplacer __HOSTNAME_FQDN__ par $domain et ecrire $dest
# $1 = template (chemin relatif dans TEMPLATES_DIR), $2 = domain, $3 = dest
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

# Upsert un enregistrement DNS OVH (find → update ou create)
# $1=zone $2=subdomain $3=type $4=value  —  retourne 0=ok 1=fail
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
# Format: domain:selector (un par ligne, commentaires #, lignes vides ignorees)
# ==============================================================================

# Extraire le domaine de base (TLD+1) d'un FQDN
# Ex: srv.example.com -> example.com, example.com -> example.com
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
# OpenDKIM — regeneration des tables depuis domains.conf
# ==============================================================================

# Regenerer keytable, signingtable et trustedhosts
# --no-restart : ne pas redemarrer opendkim (pour les tests)
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

# ==============================================================================
# Deploiement : parking page, VHosts, logrotate
# ==============================================================================

# Deployer la page parking WebGL pour un domaine
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

# Obtenir un certificat SSL pour un domaine
# DNS-01 wildcard si credentials OVH disponibles, sinon HTTP-01
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

# Générer un enregistrement TLSA (3 1 1) depuis un certificat
# $1 = chemin vers le fichier cert.pem
# Stdout: "3 1 1 <sha256hex>"
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

# Configurer tous les enregistrements DNS pour un domaine via OVH API
# $1=domain $2=selector(defaut:mail)
# Retourne le nombre de succes dans $DM_DNS_OK et echecs dans $DM_DNS_FAIL
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
# Verification d'un domaine
# ==============================================================================

# Verification complete d'un domaine
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

# Exporter un domaine vers une archive tar.gz
# $1 = domain, $2 = destination directory
# Crée $dest/$domain.tar.gz contenant : manifest, dkim/, apache/, logrotate/, www/
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
# Per-domain configuration
# ==============================================================================

# Set a config key for a domain
# $1 = domain, $2 = key, $3 = value
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

# Deploy a domain in staging mode (no SSL via certbot, no DNS)
# $1 = domain, $2 = selector (default: mail)
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
# Domain groups
# ==============================================================================

# Assign a domain to a group
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
