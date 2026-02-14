# debian13-server

Bootstrap, hardening et gestion multi-domaines pour un serveur **Debian 13 (Trixie)** chez OVH.

Un seul point d'entree : `debian13-server.sh`.

## Fonctionnalites

| Categorie | Details |
|-----------|---------|
| **Systeme** | Locales fr_FR, fuseau Europe/Paris, hostname/FQDN, mises a jour auto |
| **SSH** | Cle uniquement, port configurable (defaut 65222), algorithmes durcis |
| **Pare-feu** | UFW (deny in / allow out) + Fail2ban (SSH + filtres Apache) |
| **Web** | Apache + PHP + durcissements (headers, mod_security, mod_evasive) |
| **Base de donnees** | MariaDB (hardening de base) + phpMyAdmin (URL aleatoire) |
| **Email** | Postfix send-only + OpenDKIM (signature DKIM multi-domaines) |
| **SSL** | Certbot (Let's Encrypt) — wildcard DNS-01 OVH ou HTTP-01 |
| **DNS** | Configuration auto SPF / DKIM / DMARC / CAA via API OVH |
| **Multi-domaines** | Ajout/suppression de domaines avec DKIM, VHosts, SSL, DNS, parking |
| **Securite** | ClamAV, rkhunter, AIDE, GeoIP blocking, alertes SSH |
| **Dev** | Git, Node.js (nvm), Rust (rustup), Composer, Python 3, pipx |
| **Monitoring** | Logwatch, audit HTML, notifications 5xx, pages d'erreur WebGL |

## Demarrage rapide

```bash
# Premiere installation (interactif)
sudo ./debian13-server.sh

# Mode non-interactif (valeurs par defaut)
sudo ./debian13-server.sh --noninteractive

# Audit seul (pas d'installation, rapport email)
sudo ./debian13-server.sh --audit
```

## Gestion multi-domaines

Chaque domaine ajoute obtient automatiquement :
- Enregistrements DNS (A, AAAA, SPF, DKIM, DMARC, CAA) via API OVH
- Cle DKIM dediee + tables OpenDKIM
- VHosts Apache (HTTP redirect + HTTPS + wildcard)
- Certificat Let's Encrypt (wildcard si OVH, HTTP-01 sinon)
- Page parking WebGL + robots.txt
- Rotation des logs (logrotate)

```bash
# Ajouter un domaine
sudo ./debian13-server.sh --domain-add example.com

# Ajouter avec un selecteur DKIM custom
sudo ./debian13-server.sh --domain-add example.com dkim2025

# Lister les domaines geres
sudo ./debian13-server.sh --domain-list

# Verifier un domaine (DNS, DKIM, SPF, DMARC, SSL, VHost)
sudo ./debian13-server.sh --domain-check example.com

# Verifier tous les domaines
sudo ./debian13-server.sh --domain-check

# Retirer un domaine
sudo ./debian13-server.sh --domain-remove example.com
```

> Voir [docs/multi-domain.md](docs/multi-domain.md) pour les details d'architecture.

## DNS & certificats

```bash
# Verification DNS/DKIM/SPF/DMARC
sudo ./debian13-server.sh --check-dns

# Verification + correction automatique via API OVH
sudo ./debian13-server.sh --check-dns --fix

# Regenerer les credentials API OVH
sudo ./debian13-server.sh --renew-ovh
```

## Architecture

```
debian13-server.sh          Point d'entree unique
lib/
  core.sh                   Fonctions de base (log, couleurs, die)
  constants.sh              Constantes (seuils, chemins, patterns)
  helpers.sh                Utilitaires (backup, prompt, preflight)
  config.sh                 Gestion du fichier .conf
  ovh-api.sh                API OVH (requetes signees, DNS)
  domain-manager.sh         Gestion multi-domaines (20 fonctions dm_*)
  install-base.sh           Installation systeme de base
  install-web.sh            Apache/PHP, MariaDB, Postfix, Certbot, VHosts
  install-devtools.sh       Outils de developpement
  install-security.sh       ClamAV, rkhunter, AIDE, GeoIP
  verify.sh                 Verifications post-install (emit_check)
  audit-html.sh             Generation de rapport HTML
templates/
  vhost-*.conf.template     Templates Apache VHost
  parking-page.html         Page parking WebGL
  parking-style.css         Style de la page parking
  error-page-webgl.php      Pages d'erreur WebGL
  *.sh.template             Scripts cron (clamav, rkhunter, etc.)
tests/
  test_helper.sh            Stubs/mocks pour les tests
  domain_registry.bats      Tests registre de domaines (17 tests)
  domain_deploy.bats        Tests deploiement parking/VHost/logrotate (12 tests)
  domain_dns.bats           Tests configuration DNS OVH (6 tests)
  domain_ssl.bats           Tests obtention SSL certbot (5 tests)
  opendkim_rebuild.bats     Tests regeneration OpenDKIM (6 tests)
Makefile                    test, lint, check-syntax
domains.conf                Registre des domaines (genere)
debian13-server.conf        Configuration sauvegardee (genere)
```

## Tests

Les tests unitaires utilisent [bats-core](https://github.com/bats-core/bats-core) (46 tests).

```bash
# Installer bats
sudo apt install bats

# Lancer tous les tests
make test

# Linter (shellcheck)
make lint

# Verification syntaxe bash
make check-syntax
```

## Configuration

Le script genere un fichier `debian13-server.conf` apres la premiere execution.
Les executions suivantes proposent de reutiliser cette configuration.

Parametres principaux :

| Variable | Defaut | Description |
|----------|--------|-------------|
| `HOSTNAME_FQDN` | *(interactif)* | FQDN du serveur |
| `SSH_PORT` | `65222` | Port SSH personnalise |
| `ADMIN_USER` | `debian` | Utilisateur admin (sudo) |
| `DKIM_SELECTOR` | `mail` | Selecteur DKIM |
| `EMAIL_FOR_CERTBOT` | *(interactif)* | Email pour Let's Encrypt et alertes |
| `TIMEZONE` | `Europe/Paris` | Fuseau horaire |

## Prerequis

- Debian 13 (Trixie) — installation vierge
- Acces root (ou sudo)
- Connexion internet
- *(Optionnel)* Credentials API OVH pour DNS automatique et certificats wildcard

## Licence

Usage prive.
