#!/usr/bin/env bash
# lib/tui.sh — Abstraction TUI (whiptail/dialog avec fallback texte)
# Sourcé par debian13-server.sh
#
# Couche d'abstraction pour les interfaces texte interactives.
# Cascade de priorité : whiptail (installé par défaut sur Debian) → dialog → texte pur.
# Chaque fonction a le même comportement quel que soit le backend :
#   - Retourne le choix de l'utilisateur sur stdout
#   - Affiche l'interface sur stderr (convention ncurses)
#   - Code retour 0 = OK, 1 = annulation
#
# Le fallback texte pur garantit le fonctionnement même dans un conteneur
# Docker sans terminal ncurses ou via SSH sans allocation de PTY.
#
# Astuce file descriptors : whiptail/dialog écrivent leur résultat sur stderr.
# Le swap "3>&1 1>&2 2>&3" redirige stderr→stdout pour capturer le résultat
# dans une variable tout en affichant l'interface sur le terminal.

: "${TUI_BACKEND:=$(command -v whiptail >/dev/null 2>&1 && echo whiptail || (command -v dialog >/dev/null 2>&1 && echo dialog || echo none))}"
TUI_HEIGHT=12
TUI_WIDTH=70

# Vérifie si un backend TUI est disponible
tui_available() {
  [[ "$TUI_BACKEND" != "none" ]] && command -v "$TUI_BACKEND" >/dev/null 2>&1
}

# Question oui/non
# $1 = message, $2 = titre
tui_yesno() {
  local msg="$1" title="${2:-Question}"
  if tui_available; then
    "$TUI_BACKEND" --yesno "$msg" $TUI_HEIGHT $TUI_WIDTH --title "$title" 3>&1 1>&2 2>&3
  else
    printf "${BOLD:-}%s${RESET:-} [O/n] " "$msg"
    local reply
    read -r reply
    [[ "$reply" =~ ^[OoYy]?$ ]]
  fi
}

# Saisie texte
# $1 = message, $2 = titre, $3 = valeur par défaut
tui_input() {
  local msg="$1" title="${2:-Saisie}" default="${3:-}"
  if tui_available; then
    "$TUI_BACKEND" --inputbox "$msg" $TUI_HEIGHT $TUI_WIDTH "$default" --title "$title" 3>&1 1>&2 2>&3
  else
    printf "%s [%s] : " "$msg" "$default"
    local reply
    read -r reply
    echo "${reply:-$default}"
  fi
}

# Menu à choix unique
# $1 = message, $2 = titre, puis paires tag/description
tui_menu() {
  local msg="$1" title="${2:-Menu}"; shift 2
  if tui_available; then
    "$TUI_BACKEND" --menu "$msg" $TUI_HEIGHT $TUI_WIDTH 5 "$@" --title "$title" 3>&1 1>&2 2>&3
  else
    echo "$msg" >&2
    local i=1
    while [[ $# -ge 2 ]]; do
      echo "  ${i}) $1 — $2" >&2
      shift 2
      ((i++))
    done
    printf "Choix : " >&2
    local reply
    read -r reply
    echo "$reply"
  fi
}

# Checklist (multi-select)
# $1 = message, $2 = titre, puis triplets tag/description/état
tui_checklist() {
  local msg="$1" title="${2:-Sélection}"; shift 2
  if tui_available; then
    "$TUI_BACKEND" --checklist "$msg" $TUI_HEIGHT $TUI_WIDTH 8 "$@" --title "$title" 3>&1 1>&2 2>&3
  else
    echo "$msg" >&2
    local i=1
    while [[ $# -ge 3 ]]; do
      local mark=" "
      [[ "$3" == "on" ]] && mark="x"
      echo "  [${mark}] ${i}) $1 — $2" >&2
      shift 3
      ((i++))
    done
    printf "Choix (séparés par espace) : " >&2
    local reply
    read -r reply
    echo "$reply"
  fi
}

# Boîte de message
# $1 = message, $2 = titre
tui_msg() {
  local msg="$1" title="${2:-Info}"
  if tui_available; then
    "$TUI_BACKEND" --msgbox "$msg" $TUI_HEIGHT $TUI_WIDTH --title "$title" 3>&1 1>&2 2>&3
  else
    echo "=== $title ===" >&2
    echo "$msg" >&2
  fi
}
