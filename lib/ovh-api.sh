#!/usr/bin/env bash
# lib/ovh-api.sh — Helper pour l'API OVH (requêtes signées)
# Usage: source ovh-api.sh ; ovh_api GET /domain/zone/ ; ovh_api POST /path '{"body":"json"}'
# Dépend de: OVH_DNS_CREDENTIALS (fichier .ini avec les credentials)

# Charger les credentials OVH depuis le fichier .ini
_ovh_load_creds() {
  local creds="${OVH_DNS_CREDENTIALS:-/root/.ovh-dns.ini}"
  [[ -f "$creds" ]] || { echo "ERROR: $creds not found" >&2; return 1; }
  _OVH_AK=$(grep 'application_key' "$creds" | cut -d'=' -f2 | tr -d ' ')
  _OVH_AS=$(grep 'application_secret' "$creds" | cut -d'=' -f2 | tr -d ' ')
  _OVH_CK=$(grep 'consumer_key' "$creds" | cut -d'=' -f2 | tr -d ' ')
  _OVH_EP="https://eu.api.ovh.com/1.0"
}

# Appel API OVH signé
# $1 = METHOD (GET|POST|PUT|DELETE)
# $2 = path (e.g. /domain/zone/)
# $3 = body (optionnel, JSON)
# Retourne 0 si succès, 1 si erreur API
ovh_api() {
  local method="$1" path="$2" body="${3:-}"
  [[ -z "${_OVH_AK:-}" ]] && _ovh_load_creds
  local url="${_OVH_EP}${path}"
  local tstamp
  tstamp=$(curl -s "${_OVH_EP}/auth/time")
  local raw="${_OVH_AS}+${_OVH_CK}+${method}+${url}+${body}+${tstamp}"
  local sig
  sig="\$1\$$(echo -n "$raw" | sha1sum | cut -d' ' -f1)"

  local response
  if [[ -n "$body" ]]; then
    response=$(curl -s -H "Content-Type: application/json" \
      -H "X-Ovh-Application: ${_OVH_AK}" \
      -H "X-Ovh-Consumer: ${_OVH_CK}" \
      -H "X-Ovh-Timestamp: ${tstamp}" \
      -H "X-Ovh-Signature: ${sig}" \
      -X "$method" -d "$body" "$url")
  else
    response=$(curl -s -H "Content-Type: application/json" \
      -H "X-Ovh-Application: ${_OVH_AK}" \
      -H "X-Ovh-Consumer: ${_OVH_CK}" \
      -H "X-Ovh-Timestamp: ${tstamp}" \
      -H "X-Ovh-Signature: ${sig}" \
      -X "$method" "$url")
  fi

  # Détecter les erreurs API OVH (réponse contient "class" et "message")
  if echo "$response" | grep -q '"class"'; then
    echo "OVH_API_ERROR: $response" >&2
    return 1
  fi
  echo "$response"
}

# Trouver un enregistrement DNS par subdomain + type
# $1 = zone (ex: example.com)
# $2 = subdomain (ex: mail._domainkey, _dmarc, ou "" pour apex)
# $3 = fieldType (TXT, A, MX, etc.)
# Retourne l'ID de l'enregistrement, ou vide si non trouvé
ovh_dns_find() {
  local zone="$1" sub="$2" ftype="$3"
  local path="/domain/zone/${zone}/record?fieldType=${ftype}"
  [[ -n "$sub" ]] && path="${path}&subDomain=${sub}"
  local ids
  ids=$(ovh_api GET "$path") || return 1
  # ids est un JSON array [123,456,...] — retourner le premier
  echo "$ids" | tr -d '[]' | tr ',' '\n' | head -1
}

# Lire un enregistrement DNS
# $1 = zone, $2 = record ID
ovh_dns_get() {
  ovh_api GET "/domain/zone/$1/record/$2"
}

# Créer un enregistrement DNS
# $1 = zone, $2 = subdomain, $3 = fieldType, $4 = target (valeur)
# $5 = ttl (optionnel, défaut 3600)
ovh_dns_create() {
  local zone="$1" sub="$2" ftype="$3" target="$4" ttl="${5:-3600}"
  local body="{\"fieldType\":\"${ftype}\",\"subDomain\":\"${sub}\",\"target\":${target},\"ttl\":${ttl}}"
  ovh_api POST "/domain/zone/${zone}/record" "$body" || return 1
}

# Mettre à jour un enregistrement DNS
# $1 = zone, $2 = record ID, $3 = target (valeur)
# $4 = ttl (optionnel)
ovh_dns_update() {
  local zone="$1" rid="$2" target="$3" ttl="${4:-}"
  local body
  if [[ -n "$ttl" ]]; then
    body="{\"target\":${target},\"ttl\":${ttl}}"
  else
    body="{\"target\":${target}}"
  fi
  ovh_api PUT "/domain/zone/${zone}/record/${rid}" "$body" || return 1
}

# Supprimer un enregistrement DNS
# $1 = zone, $2 = record ID
ovh_dns_delete() {
  ovh_api DELETE "/domain/zone/$1/record/$2" || return 1
}

# Appliquer les changements DNS (refresh zone)
# $1 = zone
ovh_dns_refresh() {
  ovh_api POST "/domain/zone/$1/refresh" || return 1
}

# Vérifier que les credentials OVH fonctionnent
# Retourne 0 si OK, 1 si erreur
ovh_test_credentials() {
  local result
  result=$(ovh_api GET "/auth/currentCredential") || return 1
  return 0
}

# ---- Fonctions haut niveau pour la configuration email ----

# Configurer SPF
# $1 = zone, $2 = server IP
ovh_setup_spf() {
  local zone="$1" server_ip="$2"
  local spf_value="\"v=spf1 a mx ip4:${server_ip} include:mx.ovh.com ~all\""
  local existing_id
  existing_id=$(ovh_dns_find "$zone" "" "TXT") || { echo "SPF : erreur API" >&2; return 1; }

  # Vérifier si un SPF existe déjà parmi les TXT du apex
  if [[ -n "$existing_id" ]]; then
    local ids
    ids=$(ovh_api GET "/domain/zone/${zone}/record?fieldType=TXT&subDomain=") || { echo "SPF : erreur API" >&2; return 1; }
    for rid in $(echo "$ids" | tr -d '[]' | tr ',' ' '); do
      local rec
      rec=$(ovh_dns_get "$zone" "$rid") || continue
      if echo "$rec" | grep -q "v=spf1"; then
        log "SPF : enregistrement existant (ID ${rid}), mise à jour..."
        ovh_dns_update "$zone" "$rid" "\"${spf_value}\"" || return 1
        ovh_dns_refresh "$zone" || true
        return 0
      fi
    done
  fi

  log "SPF : création de l'enregistrement..."
  ovh_dns_create "$zone" "" "TXT" "\"${spf_value}\"" || return 1
  ovh_dns_refresh "$zone" || true
}

# Configurer DKIM
# $1 = zone, $2 = selector, $3 = chemin du fichier .txt DKIM
ovh_setup_dkim() {
  local zone="$1" selector="$2" dkim_file="$3"
  local subdomain="${selector}._domainkey"

  # Extraire la clé publique du fichier DKIM (format opendkim-genkey)
  local dkim_value
  dkim_value=$(sed -n '/^[[:space:]]*"/s/^[[:space:]]*"//;s/"[[:space:]]*$//;s/"$//p' "$dkim_file" | tr -d '\n')

  if [[ -z "$dkim_value" ]]; then
    echo "DKIM : impossible d'extraire la clé de ${dkim_file}" >&2
    return 1
  fi

  local existing_id
  existing_id=$(ovh_dns_find "$zone" "$subdomain" "TXT") || { echo "DKIM : erreur API" >&2; return 1; }

  if [[ -n "$existing_id" ]]; then
    log "DKIM : enregistrement existant (ID ${existing_id}), mise à jour..."
    ovh_dns_update "$zone" "$existing_id" "\"${dkim_value}\"" || return 1
  else
    log "DKIM : création de l'enregistrement ${subdomain}.${zone}..."
    ovh_dns_create "$zone" "$subdomain" "TXT" "\"${dkim_value}\"" || return 1
  fi
  ovh_dns_refresh "$zone" || true
}

# Configurer DMARC
# $1 = zone, $2 = email admin (pour les rapports)
ovh_setup_dmarc() {
  local zone="$1" admin_email="$2"
  local dmarc_value="\"v=DMARC1; p=quarantine; rua=mailto:${admin_email}; sp=quarantine; aspf=r;\""

  local existing_id
  existing_id=$(ovh_dns_find "$zone" "_dmarc" "TXT") || { echo "DMARC : erreur API" >&2; return 1; }

  if [[ -n "$existing_id" ]]; then
    log "DMARC : enregistrement existant (ID ${existing_id}), mise à jour..."
    ovh_dns_update "$zone" "$existing_id" "\"${dmarc_value}\"" || return 1
  else
    log "DMARC : création de l'enregistrement _dmarc.${zone}..."
    ovh_dns_create "$zone" "_dmarc" "TXT" "\"${dmarc_value}\"" || return 1
  fi
  ovh_dns_refresh "$zone" || true
}

# ---- Fonctions reverse DNS (PTR) ----

# Obtenir le reverse DNS actuel d'une IP
# $1 = IP (IPv4 ou IPv6)
# Retourne le reverse FQDN ou vide
ovh_ip_reverse_get() {
  local ip="$1"
  # URL-encode IPv6 (remplacer : par %3A)
  local ip_encoded="${ip//:/%3A}"
  local result
  result=$(ovh_api GET "/ip/${ip_encoded}/reverse") || return 1
  # Retourne le premier reverse trouvé
  echo "$result" | tr -d '[]"' | head -1
}

# Configurer le reverse DNS d'une IP
# $1 = IP (IPv4 ou IPv6)
# $2 = reverse FQDN (ex: srv.example.com)
ovh_ip_reverse_set() {
  local ip="$1" reverse_fqdn="$2"
  # URL-encode IPv6 (remplacer : par %3A)
  local ip_encoded="${ip//:/%3A}"

  # Vérifier si un reverse existe déjà
  local existing
  existing=$(ovh_api GET "/ip/${ip_encoded}/reverse" 2>/dev/null) || true

  # Si un reverse existe, le supprimer d'abord
  if [[ -n "$existing" && "$existing" != "[]" ]]; then
    ovh_api DELETE "/ip/${ip_encoded}/reverse/${ip_encoded}" 2>/dev/null || true
  fi

  # Créer le nouveau reverse
  local body="{\"ipReverse\":\"${ip}\",\"reverse\":\"${reverse_fqdn}.\"}"
  ovh_api POST "/ip/${ip_encoded}/reverse" "$body" || return 1
}

# Tester la délivrabilité email via Postfix
# $1 = adresse destinataire, $2 = hostname
ovh_test_mail() {
  local recipient="$1" hostname="$2"
  local test_id
  test_id=$(date +%s)

  log "Envoi d'un email de test a ${recipient}..."
  echo "Deliverability test from ${hostname} - ID: ${test_id}
Date: $(date)
Server: ${hostname}
This message was sent automatically to verify:
- Postfix configuration (send-only)
- DKIM signature (selector: mail)
- SPF record
- DMARC policy

If you receive this message, the email configuration is functional." \
    | mail -s "[Test] Deliverability ${hostname} - ${test_id}" "$recipient"

  # Attendre que Postfix traite et envoie
  sleep 10

  # Vérifier le statut dans les logs (mail.log ou journalctl)
  local status
  if [[ -f /var/log/mail.log ]]; then
    status=$(grep "${test_id}" /var/log/mail.log 2>/dev/null | tail -3)
  else
    status=$(journalctl -u postfix --since "30 seconds ago" --no-pager 2>/dev/null | tail -5)
  fi

  if echo "$status" | grep -q "status=sent"; then
    log "Email de test envoye avec succes (status=sent)"
    return 0
  elif echo "$status" | grep -q "status=deferred"; then
    warn "Email de test differe (status=deferred)"
    return 1
  elif echo "$status" | grep -q "status=bounced"; then
    echo "Email de test rejete (status=bounced) -- verifiez SPF/DKIM/DMARC" >&2
    return 1
  else
    note "Statut non encore disponible dans les logs (traitement en cours)"
    note "Verifiez : journalctl -u postfix -n 10"
    return 0
  fi
}
