# lib/optimize.sh — Optimisations de performance du serveur, reproductibles et
# RÉVERSIBLES. Chaque optimisation est matérialisée par un fichier de conf dédié
# (drop-in) préfixé « debian13 » : l'appliquer = déposer le fichier, l'annuler =
# le retirer et recharger le service (retour au comportement par défaut). Le
# basculement MPM (non-drop-in) est tracé par un marqueur pour un rollback exact.
#
# Optimisations :
#   1. Réseau      : BBR (congestion control) + fq qdisc + TCP Fast Open
#   2. Compression : mod_deflate/brotli Apache (HTML/CSS/JS/JSON/SVG)
#   3. PHP         : OPcache JIT + tuning OPcache
#   4. MariaDB     : innodb_buffer_pool_size + log + O_DIRECT
#   5. Apache MPM  : prefork+mod_php → event+PHP-FPM (concurrence, mémoire)
#
# Entrées : optimize_apply / optimize_rollback / optimize_status
# Gardées par OPTIMIZE_* (config.sh). Idempotent.

OPT_MARKER_DIR="${OPT_MARKER_DIR:-/var/lib/debian13-optimize}"
OPT_SYSCTL="/etc/sysctl.d/99-debian13-perf.conf"
OPT_MODLOAD="/etc/modules-load.d/debian13-bbr.conf"
OPT_APACHE_COMP="/etc/apache2/conf-available/debian13-compression.conf"
OPT_MARIADB="/etc/mysql/mariadb.conf.d/99-debian13-tuning.cnf"
OPT_PHP_INI="debian13-perf"   # nom du mod PHP (mods-available/<nom>.ini)

_opt_phpver() { php -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;' 2>/dev/null; }

# ============================================================================
# 1) RÉSEAU — BBR + fq + TCP Fast Open
# ============================================================================
optimize_net_apply() {
  echo 'tcp_bbr' > "$OPT_MODLOAD"
  modprobe tcp_bbr 2>/dev/null || true
  cat > "$OPT_SYSCTL" <<'EOF'
# Optimisations réseau — debian13-server.sh (retirer ce fichier pour annuler)
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_fastopen = 3
net.core.somaxconn = 4096
net.ipv4.tcp_slow_start_after_idle = 0
EOF
  sysctl --system >/dev/null 2>&1 || true
  local cc; cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)
  log "Réseau : congestion control = ${cc}, TCP Fast Open = 3, qdisc = fq"
}
optimize_net_rollback() {
  rm -f "$OPT_SYSCTL" "$OPT_MODLOAD"
  sysctl -w net.ipv4.tcp_congestion_control=cubic >/dev/null 2>&1 || true
  sysctl -w net.core.default_qdisc=fq_codel >/dev/null 2>&1 || true
  sysctl --system >/dev/null 2>&1 || true
  log "Réseau : réglages retirés (retour aux valeurs par défaut)"
}

# ============================================================================
# 2) COMPRESSION — mod_deflate (+ brotli si dispo)
# ============================================================================
optimize_compression_apply() {
  command -v a2enmod >/dev/null 2>&1 || { warn "Compression : Apache absent, ignoré"; return 0; }
  a2enmod deflate >/dev/null 2>&1 || true
  local has_brotli=false
  a2enmod brotli >/dev/null 2>&1 && has_brotli=true
  {
    echo "# Compression — debian13-server.sh (a2disconf debian13-compression pour annuler)"
    echo '<IfModule mod_deflate.c>'
    echo '  AddOutputFilterByType DEFLATE text/html text/plain text/xml text/css \'
    echo '    application/javascript application/json application/xml image/svg+xml \'
    echo '    application/rss+xml application/atom+xml application/x-font-ttf font/woff font/woff2'
    echo '  DeflateCompressionLevel 6'
    echo '  SetEnvIfNoCase Request_URI \.(?:gif|jpe?g|png|webp|avif|ico|zip|gz|bz2|br|rar|7z|woff2?|mp[34]|webm|ogg)$ no-gzip dont-vary'
    echo '  Header append Vary Accept-Encoding'
    echo '</IfModule>'
    if $has_brotli; then
      echo '<IfModule mod_brotli.c>'
      echo '  AddOutputFilterByType BROTLI_COMPRESS text/html text/plain text/css \'
      echo '    application/javascript application/json image/svg+xml application/xml'
      echo '  BrotliCompressionQuality 5'
      echo '</IfModule>'
    fi
  } > "$OPT_APACHE_COMP"
  a2enconf debian13-compression >/dev/null 2>&1 || true
  apachectl configtest 2>/dev/null && systemctl reload apache2 2>/dev/null || true
  log "Compression : mod_deflate$($has_brotli && echo ' + brotli') activé (HTML/CSS/JS/JSON/SVG)"
}
optimize_compression_rollback() {
  a2disconf debian13-compression >/dev/null 2>&1 || true
  rm -f "$OPT_APACHE_COMP"
  apachectl configtest 2>/dev/null && systemctl reload apache2 2>/dev/null || true
  log "Compression : configuration retirée"
}

# ============================================================================
# 3) PHP — OPcache JIT + tuning
# ============================================================================
optimize_php_apply() {
  local v; v=$(_opt_phpver)
  [[ -z "$v" ]] && { warn "PHP : introuvable, ignoré"; return 0; }
  local dir="/etc/php/${v}/mods-available"
  [[ -d "$dir" ]] || { warn "PHP ${v} : ${dir} absent, ignoré"; return 0; }
  cat > "${dir}/${OPT_PHP_INI}.ini" <<'EOF'
; OPcache JIT + tuning — debian13-server.sh (phpdismod debian13-perf pour annuler)
opcache.enable=1
opcache.memory_consumption=192
opcache.interned_strings_buffer=16
opcache.max_accelerated_files=20000
opcache.jit=tracing
opcache.jit_buffer_size=64M
opcache.validate_timestamps=1
opcache.revalidate_freq=2
realpath_cache_size=4096K
realpath_cache_ttl=600
EOF
  phpenmod -v "$v" "$OPT_PHP_INI" >/dev/null 2>&1 || true
  systemctl reload "php${v}-fpm" 2>/dev/null || true
  systemctl reload apache2 2>/dev/null || true
  log "PHP ${v} : OPcache JIT (tracing, 64M) + tuning activés"
}
optimize_php_rollback() {
  local v; v=$(_opt_phpver)
  [[ -z "$v" ]] && return 0
  phpdismod -v "$v" "$OPT_PHP_INI" >/dev/null 2>&1 || true
  rm -f "/etc/php/${v}/mods-available/${OPT_PHP_INI}.ini"
  systemctl reload "php${v}-fpm" 2>/dev/null || true
  systemctl reload apache2 2>/dev/null || true
  log "PHP ${v} : OPcache JIT retiré"
}

# ============================================================================
# 4) MARIADB — buffer pool + logs + O_DIRECT
# ============================================================================
optimize_mariadb_apply() {
  command -v mariadbd >/dev/null 2>&1 || command -v mysqld >/dev/null 2>&1 || { warn "MariaDB : absente, ignoré"; return 0; }
  local dir="/etc/mysql/mariadb.conf.d"
  [[ -d "$dir" ]] || { warn "MariaDB : ${dir} absent, ignoré"; return 0; }
  # Dimensionner le buffer pool : ~1/4 de la RAM, plafonné à 4 Go, plancher 256 Mo.
  local ram_mb pool_mb
  ram_mb=$(free -m 2>/dev/null | awk '/^Mem:/{print $2}')
  pool_mb=$(( ram_mb / 4 )); (( pool_mb > 4096 )) && pool_mb=4096; (( pool_mb < 256 )) && pool_mb=256
  cat > "$OPT_MARIADB" <<EOF
# Tuning MariaDB — debian13-server.sh (retirer ce fichier pour annuler)
[mysqld]
innodb_buffer_pool_size = ${pool_mb}M
innodb_log_file_size    = 256M
innodb_flush_method     = O_DIRECT
innodb_flush_log_at_trx_commit = 2
skip_name_resolve       = 1
EOF
  systemctl restart mariadb 2>/dev/null || systemctl restart mysql 2>/dev/null || true
  log "MariaDB : innodb_buffer_pool_size = ${pool_mb}M, O_DIRECT, skip_name_resolve"
}
optimize_mariadb_rollback() {
  rm -f "$OPT_MARIADB"
  systemctl restart mariadb 2>/dev/null || systemctl restart mysql 2>/dev/null || true
  log "MariaDB : tuning retiré (retour aux valeurs par défaut)"
}

# ============================================================================
# 5) APACHE MPM — prefork+mod_php → event+PHP-FPM
# ============================================================================
_opt_fpm_handler() { echo "proxy:unix:/run/php/php$(_opt_phpver)-fpm.sock|fcgi://localhost"; }

# Teste que PHP s'exécute réellement en servant les error pages (aliasées
# globalement) via le backend Apache. Retourne 0 si OK, 1 si PHP servi en clair.
# Si le test est impossible (pas d'error pages), ne bloque pas (retourne 0).
_opt_php_executes() {
  local port=443
  systemctl is-active --quiet websec 2>/dev/null && port=8443
  local body
  body=$(curl -sS -k --max-time 6 -A "Mozilla/5.0" "http://127.0.0.1:${port}/errorpages/error.php?code=200" 2>/dev/null)
  [[ -z "$body" ]] && body=$(curl -sS -k --max-time 6 -A "Mozilla/5.0" "https://127.0.0.1:${port}/errorpages/error.php?code=200" 2>/dev/null)
  [[ -z "$body" ]] && return 0            # impossible de tester → ne bloque pas
  [[ "$body" != *"<?php"* ]]             # échec si le code PHP est renvoyé en clair
}

optimize_mpm_apply() {
  command -v a2enmod >/dev/null 2>&1 || { warn "MPM : Apache absent, ignoré"; return 0; }
  local v; v=$(_opt_phpver)
  [[ -z "$v" ]] && { warn "MPM : PHP introuvable, ignoré"; return 0; }
  if apache2ctl -M 2>/dev/null | grep -q 'mpm_event_module'; then
    log "MPM : déjà en event, rien à faire"; return 0
  fi
  apt_install "php${v}-fpm" 2>/dev/null || DEBIAN_FRONTEND=noninteractive apt-get install -y "php${v}-fpm" >/dev/null 2>&1 || {
    warn "MPM : échec installation php${v}-fpm, basculement annulé"; return 1; }
  mkdir -p "$OPT_MARKER_DIR"; echo "prefork+mod_php" > "${OPT_MARKER_DIR}/mpm-previous"

  # Convertir les handlers mod_php explicites (application/x-httpd-php) vers FPM :
  # sinon Apache sert le PHP en clair là où ces handlers sont posés (ex. les
  # pages d'erreur). Les fichiers modifiés sont tracés pour un rollback exact.
  local fpmh; fpmh=$(_opt_fpm_handler)
  : > "${OPT_MARKER_DIR}/php-handler-files"
  while IFS= read -r f; do
    [[ -f "$f" ]] || continue
    backup_file "$f"
    sed -i "s#SetHandler application/x-httpd-php#SetHandler \"${fpmh}\"#g" "$f"
    echo "$f" >> "${OPT_MARKER_DIR}/php-handler-files"
  done < <(grep -rlF 'SetHandler application/x-httpd-php' /etc/apache2/ 2>/dev/null)

  a2dismod "php${v}" >/dev/null 2>&1 || true
  a2dismod mpm_prefork >/dev/null 2>&1 || true
  a2enmod mpm_event proxy_fcgi setenvif >/dev/null 2>&1 || true
  a2enconf "php${v}-fpm" >/dev/null 2>&1 || true
  systemctl enable --now "php${v}-fpm" >/dev/null 2>&1 || true

  if apachectl configtest 2>/dev/null && _opt_php_executes; then
    systemctl restart apache2 2>/dev/null || true
    log "MPM : basculé en event + PHP-FPM (php${v}-fpm), handlers PHP convertis"
  else
    warn "MPM : configtest ou exécution PHP KO — rollback automatique"; optimize_mpm_rollback
  fi
}
optimize_mpm_rollback() {
  local v; v=$(_opt_phpver)
  [[ -z "$v" ]] && return 0
  a2disconf "php${v}-fpm" >/dev/null 2>&1 || true
  a2dismod mpm_event proxy_fcgi >/dev/null 2>&1 || true
  a2enmod mpm_prefork "php${v}" >/dev/null 2>&1 || true
  # Restaurer les handlers mod_php explicites convertis à l'apply.
  local fpmh; fpmh=$(_opt_fpm_handler)
  if [[ -f "${OPT_MARKER_DIR}/php-handler-files" ]]; then
    while IFS= read -r f; do
      [[ -f "$f" ]] && sed -i "s#SetHandler \"${fpmh}\"#SetHandler application/x-httpd-php#g" "$f"
    done < "${OPT_MARKER_DIR}/php-handler-files"
    rm -f "${OPT_MARKER_DIR}/php-handler-files"
  fi
  apachectl configtest 2>/dev/null && systemctl restart apache2 2>/dev/null || true
  rm -f "${OPT_MARKER_DIR}/mpm-previous"
  log "MPM : rétabli en prefork + mod_php (handlers restaurés)"
}

# ============================================================================
# Orchestration
# ============================================================================
optimize_apply() {
  section "Optimisations de performance (reproductibles, réversibles via --optimize-rollback)"
  ${OPTIMIZE_NET:-true}         && optimize_net_apply
  ${OPTIMIZE_COMPRESSION:-true} && optimize_compression_apply
  ${OPTIMIZE_PHP_JIT:-true}     && optimize_php_apply
  ${OPTIMIZE_MARIADB:-true}     && optimize_mariadb_apply
  ${OPTIMIZE_MPM_EVENT:-true}   && optimize_mpm_apply
  log "Optimisations appliquées. Annulation : sudo ${0##*/} --optimize-rollback"
}
optimize_rollback() {
  section "Annulation des optimisations de performance"
  optimize_mpm_rollback
  optimize_mariadb_rollback
  optimize_php_rollback
  optimize_compression_rollback
  optimize_net_rollback
  log "Optimisations annulées."
}

# État (pour l'audit)
optimize_status() {
  emit_section "Optimisations de performance"
  local cc; cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)
  [[ "$cc" == "bbr" ]] && emit_check ok "Réseau : BBR actif" || emit_check info "Réseau : congestion control = ${cc:-?}"
  [[ -f "$OPT_APACHE_COMP" ]] && emit_check ok "Compression Apache : active" || emit_check info "Compression : non activée"
  local v; v=$(_opt_phpver)
  [[ -n "$v" && -f "/etc/php/${v}/mods-available/${OPT_PHP_INI}.ini" ]] && emit_check ok "PHP OPcache JIT : actif" || emit_check info "PHP OPcache JIT : non activé"
  [[ -f "$OPT_MARIADB" ]] && emit_check ok "MariaDB tuning : actif" || emit_check info "MariaDB tuning : non activé"
  apache2ctl -M 2>/dev/null | grep -q mpm_event_module && emit_check ok "Apache MPM : event (+PHP-FPM)" || emit_check info "Apache MPM : prefork"
  emit_section_close
}
