#!/usr/bin/env bash
# lib/core.sh — Couleurs, logging, fonctions d'affichage de base
# Sourcé par debian13-server.sh
#
# Premier fichier sourcé : ne dépend d'aucune autre bibliothèque.
# Fournit la couche d'abstraction pour toutes les sorties console.
# Chaque niveau de log a un préfixe visuel distinct pour un repérage rapide
# dans un terminal scrollant (typique d'une installation longue).
#
# Convention : les fonctions log/warn/err utilisent %b (pas %s) pour
# interpréter les séquences d'échappement ANSI passées en argument.

# Détection automatique : les couleurs sont désactivées si stdout est
# redirigé vers un fichier ou un pipe (évite les séquences ANSI parasites).
if [[ -t 1 ]]; then
  RED="\e[31m"; GREEN="\e[32m"; YELLOW="\e[33m"; BLUE="\e[34m"; MAGENTA="\e[35m"; CYAN="\e[36m"; BOLD="\e[1m"; RESET="\e[0m"
else
  RED=""; GREEN=""; YELLOW=""; BLUE=""; MAGENTA=""; CYAN=""; BOLD=""; RESET=""
fi

# Niveaux de log — chaque préfixe est visuellement distinct :
#   [+] vert   = action réussie / progression normale
#   [!] jaune  = avertissement (non bloquant)
#   [✗] rouge  = erreur (redirigé vers stderr)
#   [-] cyan   = note informative
#   ==> violet = titre de section (séparateur visuel)
log()     { printf "${GREEN}[+]${RESET} %b\n" "$*"; }
warn()    { printf "${YELLOW}[!]${RESET} %b\n" "$*"; }
err()     { printf "${RED}[✗]${RESET} %b\n" "$*" >&2; }
note()    { printf "${CYAN}[-]${RESET} %b\n" "$*"; }
section() { printf "\n${BOLD}${MAGENTA}==> %b${RESET}\n" "$*"; }
die()     { err "$1"; exit 1; }
print_title() { printf "${BOLD}${CYAN}▸ %s${RESET}\n" "$1"; }
print_cmd()   { printf "  ${GREEN}%s${RESET}\n" "$1"; }
print_note()  { printf "  ${YELLOW}%s${RESET}\n" "$1"; }
