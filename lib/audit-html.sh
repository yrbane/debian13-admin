#!/usr/bin/env bash
# lib/audit-html.sh — Génération rapport HTML audit + envoi email
# Sourcé par debian13-server.sh — Dépend de: lib/core.sh, lib/constants.sh, lib/helpers.sh, lib/config.sh, lib/verify.sh

# ================================== MODE AUDIT : EMAIL ================================
if $AUDIT_MODE; then
  AUDIT_REPORT="$(mktempfile .html)"

  # Date patterns Apache/modsec (locale C, calculés une seule fois)
  AUDIT_TODAY=$(LC_TIME=C date '+%d/%b/%Y')
  AUDIT_YESTERDAY=$(LC_TIME=C date -d "yesterday" '+%d/%b/%Y')
  AUDIT_TODAY_ERR=$(LC_TIME=C date '+%a %b %d')
  AUDIT_YESTERDAY_ERR=$(LC_TIME=C date -d "yesterday" '+%a %b %d')

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

  # Bascule en mode HTML pour que emit_check/emit_section dispatche vers add_html_check/add_html_section
  CHECK_MODE="html"

  # Services
  add_html_section "Services"
  check_service_active sshd "SSH" || check_service_active ssh "SSH" || true
  ufw status | grep -qiE "(Status|État).*acti" && add_html_check ok "UFW : actif" || add_html_check warn "UFW : inactif"
  check_service_active fail2ban "Fail2ban"
  $INSTALL_APACHE_PHP && check_service_active apache2 "Apache"
  $INSTALL_MARIADB && check_service_active mariadb "MariaDB"
  $INSTALL_POSTFIX_DKIM && check_service_active postfix "Postfix"
  $INSTALL_POSTFIX_DKIM && check_service_active opendkim "OpenDKIM"
  $INSTALL_CLAMAV && check_service_active clamav-daemon "ClamAV"
  close_section

  # Sécurité SSH
  add_html_section "Sécurité SSH"
  check_config_grep ${SSHD_CONFIG} "^\s*PermitRootLogin\s+no" "Root login désactivé" "Root login non désactivé"
  check_config_grep ${SSHD_CONFIG} "^\s*PasswordAuthentication\s+no" "Auth par mot de passe désactivée" "Auth par mot de passe active"
  check_config_grep ${SSHD_CONFIG} "^\s*Port\s+${SSH_PORT}" "Port SSH : ${SSH_PORT}" "Port SSH non configuré"
  # Tentatives échouées
  if [[ -f ${AUTH_LOG} ]]; then
    FAILED_SSH_HTML=$(safe_count "Failed password" ${AUTH_LOG})
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
      DAYS_LEFT_HTML=$(days_until "$CERT_EXP_EPOCH_HTML")
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
    [[ "${DNS_DMARC}" == *"p=none"* ]] && add_html_check warn "DMARC : policy=none (trop permissif)" || add_html_check ok "DMARC : configuré"
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
      GEOIP_RANGES_HTML=$(ipset list geoip_blocked 2>/dev/null | grep -c '^[0-9]') || GEOIP_RANGES_HTML=0
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
    MODSEC_LOG="${MODSEC_AUDIT_LOG}"
    if [[ -f "$MODSEC_LOG" ]]; then
      # Compter les événements des dernières 24h (réutilise AUDIT_TODAY/AUDIT_YESTERDAY)
      MODSEC_EVENTS_24H=$(grep -cE "\[${AUDIT_TODAY}|\[${AUDIT_YESTERDAY}" "$MODSEC_LOG" 2>/dev/null) || MODSEC_EVENTS_24H=0
      MODSEC_TOTAL=$(wc -l < "$MODSEC_LOG" 2>/dev/null) || MODSEC_TOTAL=0

      # Mode (DetectionOnly ou On)
      if grep -q "SecRuleEngine On" ${MODSEC_CONFIG} 2>/dev/null; then
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

    ACCESS_LOG="${APACHE_ACCESS_LOG}"
    ERROR_LOG="${APACHE_ERROR_LOG}"
    # Les date patterns AUDIT_TODAY/AUDIT_YESTERDAY sont calculés une seule fois en début de section audit

    if [[ -f "$ACCESS_LOG" ]]; then
      # Cache : extraire les lignes des 24h une seule fois (évite 7+ grep sur access.log)
      local ACCESS_24H
      ACCESS_24H=$(mktemp)
      grep -E "\[${AUDIT_TODAY}|\[${AUDIT_YESTERDAY}" "$ACCESS_LOG" > "$ACCESS_24H" 2>/dev/null || true

      # Stats générales depuis le cache
      TOTAL_REQUESTS=$(sanitize_int "$(wc -l < "$ACCESS_24H")")
      TOTAL_404=$(sanitize_int "$(grep -c '" 404 ' "$ACCESS_24H" 2>/dev/null || echo 0)")
      TOTAL_500=$(sanitize_int "$(grep -c '" 50[0-9] ' "$ACCESS_24H" 2>/dev/null || echo 0)")
      UNIQUE_IPS=$(sanitize_int "$(awk '{print $1}' "$ACCESS_24H" | sort -u | wc -l)")

      add_stats_grid_open
      add_stat_box "${TOTAL_REQUESTS}" "Requêtes" ""
      add_stat_box "${UNIQUE_IPS}" "IPs uniques" "cyan"
      add_stats_grid_close
      add_stats_grid_open
      add_stat_box "${TOTAL_404}" "Erreurs 404" "accent"
      add_stat_box "${TOTAL_500}" "Erreurs 5xx" "accent"
      add_stats_grid_close

      # Détection URLs suspectes (scanners de vulnérabilités)
      SUSPICIOUS_PATTERNS="$SUSPICIOUS_URL_PATTERNS"
      SUSPICIOUS_HITS=$(sanitize_int "$(grep -icE "$SUSPICIOUS_PATTERNS" "$ACCESS_24H" 2>/dev/null || echo 0)")

      if [[ "$SUSPICIOUS_HITS" -gt 100 ]]; then
        add_html_check fail "URLs suspectes : ${SUSPICIOUS_HITS} requêtes (scanners actifs !)"
      elif [[ "$SUSPICIOUS_HITS" -gt 20 ]]; then
        add_html_check warn "URLs suspectes : ${SUSPICIOUS_HITS} requêtes"
      elif [[ "$SUSPICIOUS_HITS" -gt 0 ]]; then
        add_html_check ok "URLs suspectes : ${SUSPICIOUS_HITS} requêtes (normal)"
      else
        add_html_check ok "Aucune URL suspecte détectée"
      fi

      # Top 3 URLs suspectes
      if [[ "$SUSPICIOUS_HITS" -gt 0 ]]; then
        TOP_SUSPICIOUS=$(grep -iE "$SUSPICIOUS_PATTERNS" "$ACCESS_24H" 2>/dev/null | \
          awk '{print $7}' | sort | uniq -c | sort -rn | head -3 | \
          awk '{printf "%s (%d), ", $2, $1}' | sed 's/, $//')
        [[ -n "$TOP_SUSPICIOUS" ]] && add_html_check info "Top URLs ciblées : ${TOP_SUSPICIOUS}"
      fi

      # Bots malveillants (User-Agents suspects)
      BAD_BOTS="$BAD_BOT_AGENTS"
      BAD_BOT_HITS=$(sanitize_int "$(grep -icE "$BAD_BOTS" "$ACCESS_24H" 2>/dev/null || echo 0)")

      if [[ "$BAD_BOT_HITS" -gt 50 ]]; then
        add_html_check fail "Bots malveillants : ${BAD_BOT_HITS} requêtes"
      elif [[ "$BAD_BOT_HITS" -gt 10 ]]; then
        add_html_check warn "Bots malveillants : ${BAD_BOT_HITS} requêtes"
      elif [[ "$BAD_BOT_HITS" -gt 0 ]]; then
        add_html_check ok "Bots suspects : ${BAD_BOT_HITS} requêtes"
      fi
      rm -f "$ACCESS_24H"
    else
      add_html_check info "access.log non disponible"
    fi

    # Erreurs Apache (error.log)
    if [[ -f "$ERROR_LOG" ]]; then
      PHP_ERRORS=$(grep -cE "^\[${AUDIT_TODAY_ERR}|^\[${AUDIT_YESTERDAY_ERR}" "$ERROR_LOG" 2>/dev/null | head -1 || echo "0")
      PHP_ERRORS=$(sanitize_int "$PHP_ERRORS")
      PHP_FATAL=$(grep -E "^\[${AUDIT_TODAY_ERR}|^\[${AUDIT_YESTERDAY_ERR}" "$ERROR_LOG" 2>/dev/null | grep -ic "fatal\|critical" | head -1 || echo "0")
      PHP_FATAL=$(sanitize_int "$PHP_FATAL")

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
  $INSTALL_CLAMAV && check_db_freshness /var/lib/clamav "ClamAV" 1 "$DB_FRESH_DAYS"

  # rkhunter
  $INSTALL_RKHUNTER && check_db_freshness /var/lib/rkhunter/db/rkhunter.dat "rkhunter" "$DB_FRESH_DAYS" "$DB_STALE_DAYS"

  # AIDE
  $INSTALL_AIDE && check_db_freshness /var/lib/aide/aide.db "AIDE" "$DB_FRESH_DAYS" "$DB_STALE_DAYS"

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
    if [[ "$MAIL_QUEUE_HTML" == *"Mail queue is empty"* ]]; then
      add_html_check ok "File d'attente vide"
    else
      QUEUED_COUNT_HTML=$(mailq 2>/dev/null | grep -c "^[A-F0-9]") || QUEUED_COUNT_HTML=0
      add_html_check warn "${QUEUED_COUNT_HTML} email(s) en attente"
    fi
    if [[ -f ${MAIL_LOG} ]]; then
      BOUNCED_HTML=$(safe_count "status=bounced" ${MAIL_LOG})
      DEFERRED_HTML=$(safe_count "status=deferred" ${MAIL_LOG})
      SENT_HTML=$(safe_count "status=sent" ${MAIL_LOG})
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
  LOAD_1=$(awk '{print $1}' /proc/loadavg)
  CPU_CORES=$(nproc)

  # Barres de progression pour disque, RAM et load
  add_progress_bar "Disque (${DISK_USED} / ${DISK_TOTAL})" "$DISK_USAGE" 100 "$(threshold_color "$DISK_USAGE" 70 90)"
  add_progress_bar "RAM (${MEM_USED} / ${MEM_TOTAL})" "$MEM_USED_PCT" 100 "$(threshold_color "$MEM_USED_PCT" 70 90)"

  LOAD_PCT=$(echo "$LOAD_1 $CPU_CORES" | awk '{printf "%.0f", ($1/$2)*100}')
  add_progress_bar "Load (${LOAD_1} sur ${CPU_CORES} cores)" "$LOAD_PCT" 100 "$(threshold_color "$LOAD_PCT" 70 100)"

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
  ZOMBIES_HTML=$(ps aux 2>/dev/null | grep -c ' Z ') || ZOMBIES_HTML=0
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
