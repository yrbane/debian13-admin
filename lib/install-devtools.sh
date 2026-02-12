#!/usr/bin/env bash
# lib/install-devtools.sh — Dev tools, Node, Rust, Python, Composer, Symfony, Shell fun
# Sourcé par debian13-server.sh — Dépend de: lib/core.sh, lib/constants.sh, lib/helpers.sh, lib/config.sh

# ---------------------------------- 9) Dev tools --------------------------------------
if $INSTALL_DEVTOOLS; then
  section "Outils dev (Git/Curl/build-essential/grc)"
  apt_install git curl build-essential pkg-config dnsutils grc
fi

# ---------------------------------- 10) Node (nvm) ------------------------------------
if $INSTALL_NODE; then
  section "Node.js via nvm (LTS) pour ${ADMIN_USER}"


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


  # Crée le répertoire bin local si nécessaire
  run_as_user "mkdir -p ${USER_HOME}/.local/bin"

  # Télécharge et installe Composer pour l'utilisateur (download then execute)
  COMPOSER_INSTALLER="$(mktempfile .php)"
  curl -fsSL https://getcomposer.org/installer -o "$COMPOSER_INSTALLER"
  # Vérification du hash (obligatoire — sécurité supply chain)
  EXPECTED_SIG="$(curl -fsSL https://composer.github.io/installer.sig 2>/dev/null || true)"
  if [[ -z "$EXPECTED_SIG" ]]; then
    warn "Impossible de récupérer la signature Composer. Installation annulée."
    rm -f "$COMPOSER_INSTALLER"
  else
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
