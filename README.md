<div align="center">

<br>

# `debian13-server`

**Bootstrap, hardening et gestion multi-domaines**<br>
**Debian 13 (Trixie) — OVH**

<br>

<table>
<tr>
<td align="center"><strong>17</strong><br><sub>bibliotheques</sub></td>
<td align="center"><strong>465</strong><br><sub>tests</sub></td>
<td align="center"><strong>47</strong><br><sub>fonctions dm_*</sub></td>
<td align="center"><strong>19</strong><br><sub>verifications</sub></td>
<td align="center"><strong>0</strong><br><sub>dependance externe</sub></td>
</tr>
</table>

<br>

```
sudo ./debian13-server.sh
```

<sub>Un seul script. Idempotent. Testable. Modulaire.</sub>

<br>

</div>

---

## Demarrage rapide

```bash
# Premiere installation (interactif — pose les questions de configuration)
sudo ./debian13-server.sh

# Mode non-interactif (valeurs par defaut)
sudo ./debian13-server.sh --noninteractive

# Audit seul (verification + rapport email, aucune installation)
sudo ./debian13-server.sh --audit

# Simulation sans modification
sudo ./debian13-server.sh --dry-run
```

---

## Fonctionnalites

<details open>
<summary><h3>Installation & Hardening</h3></summary>

| | Composant | Details |
|:--:|-----------|---------|
| **OS** | Systeme | Locales `fr_FR.UTF-8`, fuseau `Europe/Paris`, hostname FQDN, mises a jour auto |
| **SSH** | Acces | Cle uniquement, port custom, algorithmes post-quantiques (`sntrup761x25519`) |
| **FW** | Pare-feu | UFW deny-all + whitelist, Fail2ban 3 niveaux (standard, custom, progressif) |
| **WEB** | Apache | PHP-FPM, mod_security OWASP CRS, mod_evasive, headers defensifs, `ServerTokens Prod` |
| **DB** | MariaDB | Hardening auto (`mysql_secure_installation`), phpMyAdmin URL aleatoire |
| **MAIL** | Postfix | Send-only (loopback), OpenDKIM multi-domaines, DANE/TLSA |
| **SSL** | Certbot | Wildcard DNS-01 via API OVH, fallback HTTP-01, renouvellement auto |
| **DNS** | OVH API | SPF, DKIM, DMARC, CAA, TLSA — upsert automatique via requetes signees HMAC |
| **SEC** | Avance | AppArmor, auditd, egress filtering, GeoIP (103 pays), `/tmp noexec`, sysctl hardening |
| **DEV** | Outils | Git, Node.js (nvm), Rust (rustup), Composer, Python 3, pipx |

</details>

<details open>
<summary><h3>Gestion multi-domaines</h3></summary>

Chaque domaine ajoute via `--domain-add` obtient **automatiquement** :

| Composant | Detail |
|-----------|--------|
| **DNS** | Enregistrements A, AAAA, SPF, DKIM, DMARC, CAA, TLSA via API OVH |
| **DKIM** | Cle RSA 2048 bits dediee + tables OpenDKIM (keytable, signingtable) |
| **VHosts** | HTTP→HTTPS redirect, HTTPS apex+www, wildcard subdomains |
| **SSL** | Certificat Let's Encrypt wildcard (DNS-01) ou standard (HTTP-01) |
| **Parking** | Page WebGL Three.js avec nom de domaine 3D anime + `robots.txt` |
| **Logs** | Repertoire `/var/log/apache2/{domaine}/` + logrotate 14j |
| **BDD** | Base MariaDB optionnelle (`dm_create_database`) |
| **Config** | Configuration par domaine dans `domains.d/` |

```bash
# Ajouter un domaine (sequence complete en 8 etapes)
sudo ./debian13-server.sh --domain-add example.com

# Selecteur DKIM custom
sudo ./debian13-server.sh --domain-add example.com dkim2025

# Lister / verifier / supprimer
sudo ./debian13-server.sh --domain-list
sudo ./debian13-server.sh --domain-check example.com
sudo ./debian13-server.sh --domain-check                  # tous
sudo ./debian13-server.sh --domain-remove example.com
```

</details>

<details>
<summary><h3>Operations avancees sur les domaines</h3></summary>

| Fonctionnalite | Commande | Description |
|----------------|----------|-------------|
| **Staging** | `--domain-staging` | Deploiement sans SSL/DNS pour preparation |
| **Promotion** | `--domain-promote` | Bascule staging → production (SSL + DNS) |
| **Groupes** | `--domain-group` | Organisation par usage (production, staging, client-X) |
| **Export** | `--domain-export` | Archive `tar.gz` autonome (DKIM + VHost + config) |
| **Import** | `--domain-import` | Restauration depuis archive (migration inter-serveurs) |
| **DKIM rotation** | `--dkim-rotate` | Nouveau selecteur horodate, ancien conserve 48h |
| **Reverse proxy** | `dm_deploy_proxy` | VHost proxy avec WebSocket et headers securite |
| **Git deploy** | `dm_setup_git_deploy` | Depot bare + hook `post-receive` → deploiement auto |
| **Conteneurs** | `dm_deploy_container` | Docker/Podman : run + reverse proxy auto |
| **WAF** | `deploy_waf_domain_rules` | Regles ModSecurity par domaine + rate-limiting |
| **mTLS** | `mtls_*` | CA interne + certificats clients + `SSLVerifyClient` |

```bash
# Staging → production
sudo ./debian13-server.sh --domain-staging example.com
sudo ./debian13-server.sh --domain-promote example.com

# Groupes
sudo ./debian13-server.sh --domain-group example.com production
sudo ./debian13-server.sh --group-list

# Export / Import (migration)
sudo ./debian13-server.sh --domain-export example.com
sudo ./debian13-server.sh --domain-import example.com.tar.gz

# Rotation DKIM
sudo ./debian13-server.sh --dkim-rotate example.com
```

</details>

<details>
<summary><h3>Operations systeme</h3></summary>

| Fonctionnalite | Description |
|----------------|-------------|
| **Dashboard** | Interface web temps reel (HTML/CGI), refresh 10s, URL secrete + restriction IP |
| **Monitoring** | Checks proactifs (services, disque, SSL, Postfix) + alertes multi-canal |
| **Notifications** | Slack, Telegram, Discord — configurables independamment |
| **Snapshots** | Auto-snapshot avant chaque operation destructive |
| **Rollback** | Restauration d'un snapshot en une commande |
| **Backup** | Configs + DKIM + MariaDB + crontab, retention configurable, purge auto |
| **Backup distant** | Chiffrement GPG + rsync over SSH vers un serveur de backup |
| **Clonage** | Duplication complete de la config vers un autre serveur |
| **Fleet** | Orchestration multi-serveurs (exec, status, sync) |

```bash
# DNS : verification + correction automatique
sudo ./debian13-server.sh --check-dns
sudo ./debian13-server.sh --check-dns --fix

# Dashboard web
sudo ./debian13-server.sh --dashboard example.com

# Snapshots & rollback
sudo ./debian13-server.sh --snapshot-list
sudo ./debian13-server.sh --rollback <snapshot-id>

# Backup
sudo ./debian13-server.sh --backup
sudo ./debian13-server.sh --backup-list

# Clonage serveur
sudo ./debian13-server.sh --clone-keygen
sudo ./debian13-server.sh --clone 10.0.0.2

# Fleet management
sudo ./debian13-server.sh --fleet-add web1 10.0.0.2
sudo ./debian13-server.sh --fleet-list
sudo ./debian13-server.sh --fleet-status
sudo ./debian13-server.sh --fleet-exec "apt-get update -y"
sudo ./debian13-server.sh --fleet-sync

# Audit HTML
sudo ./debian13-server.sh --audit-html /tmp/rapport.html

# Regenerer credentials API OVH
sudo ./debian13-server.sh --renew-ovh
```

</details>

<details>
<summary><h3>Observabilite</h3></summary>

| Fonctionnalite | Description |
|----------------|-------------|
| **Audit HTML** | Rapport HTML auto-contenu avec 19 categories de verifications |
| **Structured logging** | Logs JSON (NDJSON) pour ingestion Loki/Elasticsearch |
| **Healthz** | Endpoint CGI retournant du JSON (uptime, load, disk, memory) |
| **Dry-run** | Simulation des actions sans modification du systeme |
| **TUI** | Interface whiptail/dialog avec fallback texte pur |
| **Hooks** | Systeme de plugins : scripts dans `hooks.d/` executes sur evenements |

</details>

---

## Architecture

### Flux d'execution

```
sudo ./debian13-server.sh [flags]
  │
  ├── Chargement des 11 bibliotheques (source lib/*.sh)
  │     Couche 0 : core → constants → helpers → config
  │     Couche 1 : ovh-api → domain-manager
  │     Couche 2 : backup, hooks, clone, tui, fleet
  │
  ├── Parsing des arguments (~30 flags mutuellement exclusifs)
  │
  ├── Mode operationnel ? (--domain-add, --check-dns, --backup, etc.)
  │     OUI → action ciblee + exit 0 (pas de fall-through)
  │     NON → mode installation complet ↓
  │
  ├── Configuration (load .conf existant ou prompts interactifs)
  │
  ├── Installation sequentielle :
  │     install-base.sh      SSH, UFW, GeoIP, Fail2ban
  │     install-web.sh       Apache, PHP, MariaDB, Postfix, Certbot, VHosts
  │     install-devtools.sh  Node, Rust, Python, Composer
  │     install-security.sh  ClamAV, AIDE, ModSec, AppArmor, sysctl
  │
  ├── Verification (verify.sh) → rapport CLI ou HTML
  └── Recapitulatif + sauvegarde config
```

### Defense en profondeur

```
Internet
  │
  ├─ GeoIP (ipset)         blocage geographique au niveau kernel (103 pays)
  ├─ UFW (iptables)         deny-all + whitelist : SSH, 80, 443
  ├─ Fail2ban               ban IP apres N echecs (3 niveaux de filtres)
  │   ├─ Standard           sshd, apache-auth, apache-badbots
  │   ├─ Custom             vulnscan (wp-admin, .env), badagent (nikto, sqlmap)
  │   └─ Progressif         recidive : 1h → 24h → 7j
  ├─ ModSecurity (WAF)      OWASP CRS : SQLi, XSS, LFI, RCE
  ├─ Apache headers          HSTS, CSP, X-Frame-Options, Permissions-Policy
  ├─ PHP hardening           disable_functions, opcache, expose_php=Off
  ├─ AppArmor (MAC)          confinement Apache, MariaDB, Postfix
  ├─ auditd                  journalisation syscalls sensibles
  ├─ /tmp noexec             pas d'execution depuis les repertoires temporaires
  └─ sysctl                  ASLR, syncookies, rp_filter, kptr_restrict
```

### Stack email (delivrabilite)

```
Application/Cron → mail() → Postfix (loopback) → OpenDKIM → Internet
                                                      │
                                            Verification destinataire :
                                            ✔ SPF   IP du serveur autorisee ?
                                            ✔ DKIM  signature = cle DNS ?
                                            ✔ DMARC action si echec ?
                                            ✔ DANE  certificat TLS dans le DNS ?
```

### Pipeline `--domain-add`

```
--domain-add example.com [selecteur]
  │
  1. dm_register_domain     domains.conf (domaine:selecteur)
  2. dm_generate_dkim_key    /etc/opendkim/keys/example.com/{sel}.private
  3. dm_rebuild_opendkim     keytable + signingtable + trustedhosts
  4. dm_deploy_parking       /var/www/example.com/www/public/ (WebGL)
  5. dm_setup_dns            API OVH : A, AAAA, www, SPF, DKIM, DMARC, CAA
  6. dm_obtain_ssl           certbot DNS-01 (wildcard) ou HTTP-01
  7. dm_deploy_vhosts        000-redirect + 010-https + 020-wildcard
  8. dm_deploy_logrotate     /etc/logrotate.d/apache-vhost-example.com
```

> Chaque etape est tolerante aux erreurs. Si le DNS echoue (pas de credentials OVH), le VHost est quand meme deploye. Corriger ensuite : `--check-dns --fix`.

### Arborescence

```
debian13-server.sh                Point d'entree unique (flags, orchestration)
│
├── lib/
│   ├── core.sh                   Couleurs, logging (log/warn/err/section/die)
│   ├── constants.sh              Constantes readonly (seuils, chemins, patterns)
│   ├── helpers.sh                Utilitaires, securite, monitoring, notifications
│   ├── config.sh                 Gestion du fichier .conf (load/save/prompts)
│   ├── ovh-api.sh                API OVH (requetes signees HMAC-SHA1, DNS CRUD)
│   ├── domain-manager.sh         Multi-domaines (47 fonctions dm_*)
│   ├── install-base.sh           Locales, hostname, SSH, UFW, GeoIP, Fail2ban
│   ├── install-web.sh            Apache, PHP, MariaDB, Postfix, OpenDKIM, Certbot
│   ├── install-devtools.sh       Node.js, Rust, Python, Composer
│   ├── install-security.sh       ClamAV, rkhunter, AIDE, ModSec, AppArmor, sysctl
│   ├── verify.sh                 19 fonctions verify_* (emit_check ok/warn/fail)
│   ├── audit-html.sh             Rapport HTML auto-contenu + envoi email
│   ├── backup.sh                 Backup (configs, DKIM, MariaDB, crontab)
│   ├── clone.sh                  Clonage serveur (SSH + rsync)
│   ├── fleet.sh                  Orchestration multi-serveurs
│   ├── tui.sh                    TUI whiptail/dialog + fallback texte
│   └── hooks.sh                  Plugins (hooks.d/*.sh sur evenements)
│
├── templates/
│   ├── vhost-*.conf.template     Apache VHost (redirect, HTTPS, wildcard)
│   ├── parking-page.html         Page parking WebGL (Three.js)
│   ├── parking-style.css         Styles parking
│   ├── error-page-webgl.php      Pages d'erreur 4xx/5xx WebGL
│   ├── error-notify.php          Notification email 5xx (throttle)
│   ├── error-style.css           Styles erreurs
│   ├── *.sh.template             Scripts cron (ClamAV, rkhunter, AIDE, updates)
│   └── bashrc.template           .bashrc (couleurs, alias, fortune|cowsay|lolcat)
│
├── tests/
│   ├── test_helper.sh            Stubs, mocks, setup/teardown
│   └── *.bats                    43 fichiers — 465 tests
│
├── hooks.d/                      Scripts hook (optionnel, executes sur evenements)
├── domains.conf                  Registre des domaines (genere, domaine:selecteur)
├── domains.d/                    Configuration par domaine (genere)
├── debian13-server.conf          Configuration sauvegardee (genere)
├── fleet.conf                    Inventaire fleet (genere)
├── Makefile                      test, lint, check-syntax, docker-test
└── Dockerfile.test               Environnement de test isole
```

---

## Tests

<table>
<tr>
<td>

**465 tests** unitaires avec [bats-core](https://github.com/bats-core/bats-core), repartis en **43 fichiers**.

```bash
sudo apt install bats    # installer bats

make test                # lancer tous les tests
make lint                # shellcheck
make check-syntax        # bash -n sur tous les fichiers
make docker-test         # tests dans Docker (isolation)
```

</td>
<td>

| Domaine | Tests |
|---------|:-----:|
| Registre domaines | ~40 |
| Deploiement | ~35 |
| Securite | ~45 |
| Infrastructure | ~55 |
| Operations | ~60 |
| Fonctionnalites | ~50 |
| Avance | ~55 |
| Observabilite | ~30 |
| Conventions | ~25 |

</td>
</tr>
</table>

<details>
<summary><strong>Ecrire un test</strong></summary>

```bash
#!/usr/bin/env bats

load test_helper

setup() {
  setup_test_env       # Cree $TEST_DIR avec sous-repertoires temp
  override_paths       # Redirige DOMAINS_CONF, DKIM_KEYDIR, etc. vers $TEST_DIR
  source "${BATS_TEST_DIRNAME}/../lib/domain-manager.sh"
}

teardown() { teardown_test_env; }

@test "get_selector: retourne le selecteur enregistre" {
  dm_register_domain "test.com" "mail"
  run dm_get_selector "test.com"
  [ "$output" = "mail" ]
}
```

**Principe** : `setup_test_env` cree un repertoire temporaire, `override_paths` redirige toutes les constantes systeme (`DOMAINS_CONF`, `DKIM_KEYDIR`, `APACHE_SITES_DIR`, etc.) vers ce repertoire. Les tests n'ont aucun effet de bord sur le systeme reel.

</details>

---

## Conventions de code

| Convention | Detail |
|------------|--------|
| **Nommage** | `dm_*` (domain-manager), `ovh_*` (API OVH), `verify_*` (checks), `backup_*` (backups) |
| **Chemins injectables** | `: "${VAR:=default}"` — permet aux tests de rediriger vers des repertoires temporaires |
| **Idempotence** | Chaque fonction verifie l'etat avant d'agir (pas de duplication, pas de crash sur relance) |
| **Hooks** | Evenements `pre-*` / `post-*` pour chaque operation destructive |
| **Logging** | `log()` info, `warn()` avertissement, `err()` erreur, `die()` fatal + exit 1 |
| **Snapshots** | Auto-snapshot avant `--domain-add`, `--domain-remove`, `--rollback` |
| **Templates** | Placeholders `__VAR__` remplaces par `sed` au deploiement |

---

## Configuration

Le script genere `debian13-server.conf` apres la premiere execution. Les executions suivantes proposent de reutiliser cette configuration.

| Variable | Defaut | Description |
|----------|:------:|-------------|
| `HOSTNAME_FQDN` | *(interactif)* | FQDN du serveur |
| `SSH_PORT` | `65222` | Port SSH personnalise |
| `ADMIN_USER` | `debian` | Utilisateur admin (sudo) |
| `DKIM_SELECTOR` | `mail` | Selecteur DKIM du domaine principal |
| `EMAIL_FOR_CERTBOT` | *(interactif)* | Email pour Let's Encrypt et alertes |
| `TIMEZONE` | `Europe/Paris` | Fuseau horaire |
| `CERTBOT_WILDCARD` | `true` | Certificat wildcard via DNS-01 OVH |
| `MODSEC_ENFORCE` | `true` | ModSecurity en mode blocage (vs DetectionOnly) |
| `TRUSTED_IPS` | *(vide)* | IPs whitelistees (ModSec, Fail2ban, debug pages erreur) |
| `SLACK_WEBHOOK` | *(vide)* | URL webhook Slack |
| `TELEGRAM_BOT_TOKEN` | *(vide)* | Token bot Telegram |
| `TELEGRAM_CHAT_ID` | *(vide)* | Chat ID Telegram |
| `DISCORD_WEBHOOK` | *(vide)* | URL webhook Discord |

---

## Prerequis

- **Debian 13** (Trixie) — installation vierge
- **Acces root** (ou sudo)
- **Connexion internet**
- *(Optionnel)* Credentials API OVH pour DNS automatique et certificats wildcard

<details>
<summary><strong>Creer les credentials API OVH</strong></summary>

1. Aller sur [eu.api.ovh.com/createToken/](https://eu.api.ovh.com/createToken/)
2. Configurer les droits :

```
GET    /domain/zone/*
POST   /domain/zone/*
DELETE /domain/zone/*
GET    /ip/*
POST   /ip/*
DELETE /ip/*
```

3. Sauvegarder les 3 cles (Application Key, Application Secret, Consumer Key)
4. Le script les demandera lors de la premiere execution avec `CERTBOT_WILDCARD=true`
5. Ou les configurer manuellement dans `/root/.ovh-dns.ini` (mode 600)

</details>

---

<div align="center">
<sub>Usage prive — Auteur : Seb</sub>
</div>
