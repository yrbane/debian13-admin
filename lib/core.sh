#!/usr/bin/env bash
# lib/core.sh — Couleurs, logging, fonctions d'affichage de base
# Sourcé par debian13-server.sh

# Couleurs (désactivées si stdout n'est pas un terminal)
if [[ -t 1 ]]; then
  RED="\e[31m"; GREEN="\e[32m"; YELLOW="\e[33m"; BLUE="\e[34m"; MAGENTA="\e[35m"; CYAN="\e[36m"; BOLD="\e[1m"; RESET="\e[0m"
else
  RED=""; GREEN=""; YELLOW=""; BLUE=""; MAGENTA=""; CYAN=""; BOLD=""; RESET=""
fi

log()     { printf "${GREEN}[+]${RESET} %b\n" "$*"; }
warn()    { printf "${YELLOW}[!]${RESET} %b\n" "$*"; }
err()     { printf "${RED}[✗]${RESET} %b\n" "$*" >&2; }
note()    { printf "${CYAN}[-]${RESET} %b\n" "$*"; }
section() { printf "\n${BOLD}${MAGENTA}==> %b${RESET}\n" "$*"; }
die()     { err "$1"; exit 1; }
print_title() { printf "${BOLD}${CYAN}▸ %s${RESET}\n" "$1"; }
print_cmd()   { printf "  ${GREEN}%s${RESET}\n" "$1"; }
print_note()  { printf "  ${YELLOW}%s${RESET}\n" "$1"; }
