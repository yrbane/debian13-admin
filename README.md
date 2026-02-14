# debian13-server

Bootstrap, hardening et gestion multi-domaines pour **Debian 13 (Trixie)** chez OVH.

Point d'entree unique : `debian13-server.sh` — 17 bibliotheques, 465 tests, zero dependance externe.

## Philosophie

- **Un seul script** : pas de playbook Ansible, pas de Terraform. Un `sudo ./debian13-server.sh` suffit.
- **Idempotent** : relancer le script ne casse rien. Chaque operation verifie l'etat avant d'agir.
- **Testable** : tous les chemins systeme sont injectables via variables d'environnement. Les tests bats tournent dans des repertoires temporaires sans toucher au systeme.
- **Modulaire** : chaque `lib/*.sh` est autonome et documente ses dependances.

## Fonctionnalites

### Installation & Hardening

| Categorie | Details |
|-----------|---------|
| **Systeme** | Locales fr_FR, fuseau Europe/Paris, hostname/FQDN, mises a jour auto |
| **SSH** | Cle uniquement, port configurable, algorithmes post-quantiques (sntrup761) |
| **Pare-feu** | UFW (deny in/out + whitelist) + Fail2ban etendu (POST flood, auth stuffing, recidive) |
| **Web** | Apache + PHP + mod_security + mod_evasive + headers securite |
| **Base de donnees** | MariaDB (hardening) + phpMyAdmin (URL aleatoire) |
| **Email** | Postfix send-only + OpenDKIM multi-domaines + DANE/TLSA |
| **SSL** | Certbot : wildcard DNS-01 (OVH) ou HTTP-01 (fallback) |
| **DNS** | Config auto SPF / DKIM / DMARC / CAA / TLSA via API OVH |
| **Securite avancee** | AppArmor, auditd, egress filtering, GeoIP blocking, SUID audit |
| **Dev** | Git, Node.js (nvm), Rust (rustup), Composer, Python 3, pipx |

### Gestion multi-domaines

Chaque domaine ajoute obtient automatiquement :
- Enregistrements DNS (A, AAAA, SPF, DKIM, DMARC, CAA, TLSA)
- Cle DKIM dediee + tables OpenDKIM
- VHosts Apache (HTTP redirect + HTTPS + wildcard)
- Certificat Let's Encrypt (wildcard si OVH, HTTP-01 sinon)
- Page parking WebGL + robots.txt
- Rotation des logs (logrotate)
- Base de donnees MariaDB optionnelle
- Configuration par domaine (domains.d/)

### Operations

| Fonctionnalite | Description |
|----------------|-------------|
| **Dashboard** | Interface web temps reel (HTML/CGI), refresh 10s, URL secrete + restriction IP |
| **Monitoring** | Checks proactifs (services, disque, SSL, Postfix) + alertes multi-canal |
| **Notifications** | Slack, Telegram, Discord — configurables independamment |
| **Snapshots** | Sauvegarde incrementale des configs, auto-snapshot avant ajout/suppression domaine |
| **Rollback** | Restauration d'un snapshot en une commande |
| **Backup distant** | Chiffrement GPG + rsync over SSH vers un serveur de backup |
| **Clonage** | Duplication complete de la config vers un autre serveur |
| **Fleet** | Orchestration multi-serveurs (exec, status, sync) |

### Domaines avances

| Fonctionnalite | Description |
|----------------|-------------|
| **Reverse proxy** | VHost proxy avec WebSocket, headers securite |
| **Git push-to-deploy** | Depot bare + hook post-receive → deploiement auto |
| **Conteneurs** | Docker/Podman : run + proxy auto + config par domaine |
| **WAF par domaine** | Regles ModSecurity avec rate-limiting et whitelist IP |
| **mTLS** | CA interne + certificats clients + VHost avec SSLVerifyClient |
| **Staging** | Deploiement sans SSL/DNS pour preparation avant bascule |
| **Groupes** | Organisation des domaines par usage (production, staging, client-X) |
| **DKIM rotation** | Nouveau selecteur horodate, conservation de l'ancien pendant 48h |
| **Export/Import** | Archive tar.gz autonome pour migration inter-serveurs |

### Observabilite

| Fonctionnalite | Description |
|----------------|-------------|
| **Audit HTML** | Rapport HTML auto-contenu genere pendant la verification |
| **Structured logging** | Logs JSON (NDJSON) pour ingestion Loki/Elasticsearch |
| **Healthz** | Endpoint CGI retournant du JSON (uptime, load, disk, memory) |
| **Dry-run** | Simulation des actions sans modification du systeme |
| **TUI** | Interface whiptail/dialog avec fallback texte pur |
| **Hooks** | Systeme de plugins : scripts dans hooks.d/ executes sur evenements |

## Demarrage rapide

```bash
# Premiere installation (interactif)
sudo ./debian13-server.sh

# Mode non-interactif (valeurs par defaut)
sudo ./debian13-server.sh --noninteractive

# Audit seul (pas d'installation, rapport email)
sudo ./debian13-server.sh --audit

# Simulation sans modification
sudo ./debian13-server.sh --dry-run
```

## Multi-domaines

```bash
# Ajouter un domaine (DKIM + VHost + SSL + DNS + parking)
sudo ./debian13-server.sh --domain-add example.com

# Selecteur DKIM custom
sudo ./debian13-server.sh --domain-add example.com dkim2025

# Lister / verifier / supprimer
sudo ./debian13-server.sh --domain-list
sudo ./debian13-server.sh --domain-check example.com
sudo ./debian13-server.sh --domain-check                  # tous
sudo ./debian13-server.sh --domain-remove example.com

# Staging → production
sudo ./debian13-server.sh --domain-staging example.com
sudo ./debian13-server.sh --domain-promote example.com

# Groupes
sudo ./debian13-server.sh --domain-group example.com production
sudo ./debian13-server.sh --group-list

# Export / Import
sudo ./debian13-server.sh --domain-export example.com
sudo ./debian13-server.sh --domain-import example.com.tar.gz

# Rotation DKIM
sudo ./debian13-server.sh --dkim-rotate example.com
```

> Detail de l'architecture multi-domaines : [docs/multi-domain.md](docs/multi-domain.md)

## DNS & certificats

```bash
# Verification DNS/DKIM/SPF/DMARC
sudo ./debian13-server.sh --check-dns

# Verification + correction auto via API OVH
sudo ./debian13-server.sh --check-dns --fix

# Regenerer les credentials API OVH
sudo ./debian13-server.sh --renew-ovh
```

## Operations

```bash
# Dashboard web
sudo ./debian13-server.sh --dashboard example.com

# Snapshots
sudo ./debian13-server.sh --snapshot-list
sudo ./debian13-server.sh --rollback <snapshot-id>

# Backup
sudo ./debian13-server.sh --backup
sudo ./debian13-server.sh --backup-list

# Clonage serveur
sudo ./debian13-server.sh --clone-keygen
sudo ./debian13-server.sh --clone 10.0.0.2
sudo ./debian13-server.sh --clone 10.0.0.2 2222    # port SSH custom

# Fleet
sudo ./debian13-server.sh --fleet-add web1 10.0.0.2
sudo ./debian13-server.sh --fleet-list
sudo ./debian13-server.sh --fleet-status
sudo ./debian13-server.sh --fleet-exec "apt-get update -y"
sudo ./debian13-server.sh --fleet-sync

# Audit HTML
sudo ./debian13-server.sh --audit-html /tmp/rapport.html
```

> Guide complet des operations : [docs/operations.md](docs/operations.md)

## Architecture

```
debian13-server.sh              Point d'entree unique (flags, orchestration)
lib/
  core.sh                       Couleurs, logging (log/warn/err/section/die)
  constants.sh                  Constantes readonly (seuils, chemins, patterns)
  helpers.sh                    Utilitaires + securite + monitoring + notifications
  config.sh                     Gestion du fichier .conf (load/save/prompts)
  ovh-api.sh                    API OVH (requetes signees HMAC, DNS CRUD)
  domain-manager.sh             Gestion multi-domaines (30+ fonctions dm_*)
  install-base.sh               Locales, hostname, SSH, UFW, Fail2ban
  install-web.sh                Apache, PHP, MariaDB, Postfix, OpenDKIM, Certbot
  install-devtools.sh           Node.js, Rust, Python, Composer
  install-security.sh           ClamAV, rkhunter, AIDE, GeoIP, ModSecurity
  verify.sh                     Verifications post-install (emit_check ok/warn/fail)
  audit-html.sh                 Generation de rapport HTML + envoi email
  backup.sh                     Backup automatise (configs, DKIM, MariaDB, cron)
  clone.sh                      Clonage serveur (SSH + rsync)
  fleet.sh                      Orchestration multi-serveurs
  tui.sh                        TUI whiptail/dialog + fallback texte
  hooks.sh                      Systeme de plugins (hooks.d/*.sh)
templates/
  vhost-*.conf.template         Templates Apache VHost (redirect, HTTPS, wildcard)
  parking-page.html             Page parking WebGL (Three.js)
  parking-style.css             Style de la page parking
  error-page-webgl.php          Pages d'erreur 4xx/5xx WebGL
  error-notify.php              Notification 5xx (email)
  *.sh.template                 Scripts cron (ClamAV, rkhunter, AIDE, updates)
  bashrc.template               .bashrc commun (couleurs, alias, fortune)
tests/
  test_helper.sh                Stubs, mocks, setup/teardown pour tous les tests
  *.bats                        43 fichiers de tests (465 tests)
hooks.d/                        Repertoire pour les scripts hook (optionnel)
domains.conf                    Registre des domaines (genere)
domains.d/                      Configuration par domaine (genere)
debian13-server.conf            Configuration sauvegardee (genere)
fleet.conf                      Inventaire fleet (genere)
Makefile                        test, lint, check-syntax, docker-test
Dockerfile.test                 Environnement de test Docker
```

## Tests

465 tests unitaires avec [bats-core](https://github.com/bats-core/bats-core) repartis en 43 fichiers.

```bash
# Installer bats
sudo apt install bats

# Lancer tous les tests
make test

# Linter (shellcheck)
make lint

# Verification syntaxe bash
make check-syntax

# Tests dans Docker (isolation complete)
make docker-test
```

### Couverture

| Domaine | Fichiers | Tests |
|---------|----------|-------|
| Registre domaines | domain_registry, domain_config, domain_staging, domain_groups | ~40 |
| Deploiement | domain_deploy, domain_dns, domain_ssl, opendkim_rebuild, domain_export | ~35 |
| Securite | apparmor, auditd, egress, fail2ban_ext, waf_domain, mtls | ~45 |
| Infrastructure | helpers, constants, config_validation, verify, verify_extended | ~55 |
| Operations | backup, backup_remote, clone, fleet, rollback, monitoring | ~60 |
| Fonctionnalites | dashboard, healthz, dkim_rotate, reverse_proxy, git_deploy | ~50 |
| Avance | containers, domain_db, tui, dryrun, notifications, hooks | ~55 |
| Observabilite | structured_log, html_report, integration | ~30 |
| Conventions | return_conventions, dane_tlsa, ovh_api | ~25 |

### Ecrire un test

```bash
#!/usr/bin/env bats

load test_helper

setup() {
  setup_test_env       # Cree $TEST_DIR avec sous-repertoires temp
  override_paths       # Redirige DOMAINS_CONF, DKIM_KEYDIR, etc. vers $TEST_DIR
  source "${BATS_TEST_DIRNAME}/../lib/domain-manager.sh"
}

teardown() { teardown_test_env; }

@test "ma_fonctionnalite: description du cas" {
  dm_register_domain "test.com" "mail"
  run dm_get_selector "test.com"
  [ "$output" = "mail" ]
}
```

## Configuration

Le script genere `debian13-server.conf` apres la premiere execution.
Les executions suivantes proposent de reutiliser cette configuration.

| Variable | Defaut | Description |
|----------|--------|-------------|
| `HOSTNAME_FQDN` | *(interactif)* | FQDN du serveur |
| `SSH_PORT` | `65222` | Port SSH personnalise |
| `ADMIN_USER` | `debian` | Utilisateur admin (sudo) |
| `DKIM_SELECTOR` | `mail` | Selecteur DKIM du domaine principal |
| `EMAIL_FOR_CERTBOT` | *(interactif)* | Email pour Let's Encrypt et alertes |
| `TIMEZONE` | `Europe/Paris` | Fuseau horaire |
| `SLACK_WEBHOOK` | *(vide)* | URL webhook Slack pour notifications |
| `TELEGRAM_BOT_TOKEN` | *(vide)* | Token bot Telegram |
| `TELEGRAM_CHAT_ID` | *(vide)* | Chat ID Telegram |
| `DISCORD_WEBHOOK` | *(vide)* | URL webhook Discord |

## Prerequis

- Debian 13 (Trixie) — installation vierge
- Acces root (ou sudo)
- Connexion internet
- *(Optionnel)* Credentials API OVH pour DNS automatique et certificats wildcard

## Licence

Usage prive.
