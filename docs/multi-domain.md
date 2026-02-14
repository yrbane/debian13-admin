# Gestion multi-domaines

Documentation technique du systeme multi-domaines de `debian13-server.sh`.

## Vue d'ensemble

Le serveur peut heberger plusieurs domaines. Chaque domaine est enregistre dans
`domains.conf` et obtient sa propre configuration : DKIM, VHosts, SSL, DNS, parking,
base de donnees, conteneur, regles WAF, etc.

Tout passe par le point d'entree unique `debian13-server.sh` avec les flags `--domain-*`.

## Registre : `domains.conf`

Fichier texte simple, un domaine par ligne, format `domaine:selecteur_dkim`.

```
# Commentaires ignores
example.com:mail
example.com:dkim2025
```

Chemin par defaut : `/root/scripts/domains.conf` (variable `DOMAINS_CONF`).

Le domaine principal (`HOSTNAME_FQDN`) est enregistre automatiquement lors de
l'installation de Postfix/OpenDKIM.

## Configuration par domaine : `domains.d/`

En complement de `domains.conf` (une seule paire domaine:selecteur), chaque domaine
peut avoir des metadonnees riches dans `domains.d/<domaine>.conf` :

```ini
STAGING=false
GROUP=production
DB_NAME=example_com
DB_USER=example_com
DB_PASSWORD=xxxxxxxx
CONTAINER_IMAGE=nginx:latest
CONTAINER_NAME=example-com
CONTAINER_PORT=8142
WAF_RATE_LIMIT=200
```

Les fonctions `dm_set_domain_config` / `dm_get_domain_config` gerent ce fichier.

## Bibliotheque : `lib/domain-manager.sh`

Toutes les fonctions sont prefixees `dm_`. Les chemins sont injectables via
variables d'environnement (pour les tests).

### Variables injectables

| Variable | Defaut | Usage |
|----------|--------|-------|
| `DOMAINS_CONF` | `/root/scripts/domains.conf` | Registre des domaines |
| `DOMAINS_CONF_DIR` | `/root/scripts/domains.d` | Configuration par domaine |
| `DKIM_KEYDIR` | `/etc/opendkim/keys` | Repertoire racine des cles DKIM |
| `OPENDKIM_DIR` | `/etc/opendkim` | Configuration OpenDKIM |
| `WEB_ROOT` | `/var/www` | Racine des sites web |
| `APACHE_SITES_DIR` | `/etc/apache2/sites-available` | VHosts Apache |
| `LOGROTATE_DIR` | `/etc/logrotate.d` | Configurations logrotate |
| `TEMPLATES_DIR` | `/root/scripts/templates` | Templates HTML/VHost |
| `LOG_DIR` | `/var/log/apache2` | Logs Apache |
| `GIT_REPOS_DIR` | `/var/git` | Depots git bare (push-to-deploy) |

### Helpers internes (DRY)

```
dm_render_template $template $domain $dest   Rend un template (__HOSTNAME_FQDN__ -> domain)
dm_dns_upsert $zone $sub $type $value        Upsert DNS (find -> update ou create)
dm_dkim_txt_path $domain $selector           Chemin cle publique DKIM
dm_dkim_key_path $domain $selector           Chemin cle privee DKIM
_dm_subdomain $fqdn $base                    Sous-domaine relatif a la zone
```

### Fonctions publiques

#### Registre

| Fonction | Description |
|----------|-------------|
| `dm_extract_base_domain $fqdn` | Extrait le TLD+1 (`srv.example.com` → `example.com`) |
| `dm_list_domains` | Liste les domaines (stdout, `domain:selector` par ligne) |
| `dm_domain_exists $domain` | Retourne 0 si enregistre, 1 sinon |
| `dm_register_domain $domain [$selector]` | Enregistre un domaine (idempotent, defaut: `mail`) |
| `dm_unregister_domain $domain` | Supprime un domaine du registre |
| `dm_get_selector $domain` | Retourne le selecteur DKIM |

#### OpenDKIM

| Fonction | Description |
|----------|-------------|
| `dm_rebuild_opendkim [--no-restart]` | Regenere keytable/signingtable/trustedhosts depuis `domains.conf` |
| `dm_generate_dkim_key $domain [$selector]` | Genere une cle DKIM si absente |
| `dm_rotate_dkim $domain` | Rotation : nouveau selecteur horodate, conserve l'ancien |

Layout des cles DKIM :
```
/etc/opendkim/keys/
  example.com/
    mail.private            Cle privee
    mail.txt                Cle publique (pour le DNS)
  example.com/
    dkim2025.private
    dkim2025.txt
    mail20260214.private    Nouvelle cle apres rotation
    mail20260214.txt
```

Fichiers generes dans `/etc/opendkim/` :
```
keytable        Associe selecteur -> cle privee
signingtable    Associe *@domaine -> selecteur._domainkey.domaine
trustedhosts    127.0.0.1, localhost, ::1
```

Strategie de regeneration : les trois fichiers sont **ecrases entierement** a chaque
appel de `dm_rebuild_opendkim()` depuis le contenu de `domains.conf`. Pas de modification
incrementale — plus simple et sans risque de desynchronisation.

#### Deploiement

| Fonction | Description |
|----------|-------------|
| `dm_deploy_parking $domain` | Page parking HTML + CSS + robots.txt |
| `dm_deploy_vhosts $domain` | VHosts HTTP redirect + HTTPS |
| `dm_deploy_vhost_wildcard $domain` | VHost wildcard `*.domain` |
| `dm_remove_vhosts $domain` | Supprime les VHosts (available + enabled) |
| `dm_deploy_logrotate $domain` | Config logrotate pour le domaine |
| `dm_remove_logrotate $domain` | Supprime la config logrotate |

Structure web par domaine :
```
/var/www/example.com/
  www/public/
    index.html          Page parking WebGL
    robots.txt          Disallow all
    css/style.css       Style parking
```

VHosts generes (numerotation = ordre de chargement Apache) :
```
/etc/apache2/sites-available/
  000-example.com-redirect.conf     HTTP -> HTTPS (priorite max)
  010-example.com.conf              HTTPS apex + www
  015-example.com-proxy.conf        Reverse proxy (si configure)
  015-example.com-mtls.conf         mTLS (si configure)
  020-example.com-wildcard.conf     *.example.com (si wildcard cert)
```

#### SSL

| Fonction | Description |
|----------|-------------|
| `dm_obtain_ssl $domain [$email]` | DNS-01 wildcard (OVH) ou HTTP-01 fallback |

Logique de choix automatique :
- Si `/root/.ovh-dns.ini` existe → `certbot --dns-ovh` avec wildcard `*.domain`
- Sinon → `certbot --apache --preferred-challenges http` (apex + www)

#### DNS

| Fonction | Description |
|----------|-------------|
| `dm_setup_dns $domain [$selector]` | Configure A, AAAA, SPF, DKIM, DMARC, CAA, TLSA via OVH API |
| `dm_setup_ptr $hostname_fqdn` | Configure PTR (reverse DNS) IPv4/IPv6 |
| `dm_generate_tlsa_record $cert` | Genere un enregistrement DANE/TLSA (3 1 1 SHA-256) |
| `dm_setup_tlsa $domain` | Publie TLSA pour SMTP (port 25) |

Apres execution, `$DM_DNS_OK` et `$DM_DNS_FAIL` contiennent les compteurs.

Enregistrements crees/mis a jour :
- `A` : domaine → `$SERVER_IP`
- `A` : www.domaine → `$SERVER_IP`
- `AAAA` : domaine → `$SERVER_IP6` (si disponible)
- `TXT` : SPF (`v=spf1 ip4:... -all`)
- `TXT` : DKIM (`selecteur._domainkey.domaine`)
- `TXT` : DMARC (`_dmarc.domaine`)
- `CAA` : `0 issue "letsencrypt.org"` (si absent)
- `TLSA` : `_25._tcp.domaine` (DANE pour SMTP)

#### Reverse proxy

| Fonction | Description |
|----------|-------------|
| `dm_deploy_proxy $domain $backend_url` | VHost proxy :443 → backend local (WebSocket inclus) |
| `dm_remove_proxy $domain` | Supprime le VHost proxy |

Le VHost proxy genere inclut :
- ProxyPreserveHost On
- Support WebSocket (RewriteCond Upgrade)
- Headers securite (X-Frame-Options, CSP, HSTS, Referrer-Policy)

#### Git push-to-deploy

| Fonction | Description |
|----------|-------------|
| `dm_setup_git_deploy $domain` | Cree un depot bare + hook post-receive |
| `dm_get_git_remote $domain` | Retourne l'URL du remote (`ssh://root@host/var/git/dom.git`) |

#### Bases de donnees

| Fonction | Description |
|----------|-------------|
| `dm_create_database $domain` | Cree une base + utilisateur MariaDB (password auto) |
| `dm_drop_database $domain` | Supprime base + utilisateur |
| `dm_list_databases` | Liste les domaines avec base configuree |

Les credentials sont stockes dans `domains.d/<domaine>.conf` (DB_NAME, DB_USER, DB_PASSWORD).

#### Conteneurisation

| Fonction | Description |
|----------|-------------|
| `dm_deploy_container $domain $image [$port]` | Run conteneur + reverse proxy auto |
| `dm_stop_container $domain` | Arrete le conteneur |
| `dm_container_status $domain` | Affiche le statut (docker ps) |
| `dm_container_logs $domain` | Affiche les logs (docker logs) |

Le conteneur est binde sur `127.0.0.1:PORT_ALEATOIRE` et un reverse proxy Apache
est automatiquement configure pour le domaine.

#### Staging & groupes

| Fonction | Description |
|----------|-------------|
| `dm_deploy_staging $domain [$selector]` | Deploie sans SSL/DNS (flag STAGING=true) |
| `dm_is_staging $domain` | Retourne 0 si staging |
| `dm_promote_staging $domain` | Efface le flag STAGING |
| `dm_set_group $domain $group` | Assigne un groupe |
| `dm_get_group $domain` | Retourne le groupe |
| `dm_list_group $group` | Liste les domaines du groupe |
| `dm_list_groups` | Liste tous les groupes |

#### Export / Import

| Fonction | Description |
|----------|-------------|
| `dm_export_domain $domain [$dest_dir]` | Archive tar.gz (DKIM, VHosts, web, logrotate, manifest) |
| `dm_import_domain $archive` | Restaure un domaine depuis archive (refuse si deja enregistre) |

#### Verification

| Fonction | Description |
|----------|-------------|
| `dm_check_domain $domain [$selector]` | Verifie DNS A/AAAA, SPF, DKIM, DMARC, SSL, VHost |

Utilise le systeme `emit_check` (ok/warn/fail) de `lib/verify.sh`.

#### Configuration par domaine

| Fonction | Description |
|----------|-------------|
| `dm_set_domain_config $domain $key $value` | Ecrire une cle dans `domains.d/<dom>.conf` |
| `dm_get_domain_config $domain $key [$default]` | Lire une cle (retourne default si absente) |
| `dm_list_domain_config $domain` | Liste toutes les cles du domaine |

## Sequence `--domain-add`

```
1. snapshot_create              Snapshot automatique (rollback possible)
2. dm_register_domain           Ajouter au registre
3. dm_generate_dkim_key         Generer la cle DKIM
4. dm_rebuild_opendkim          Regenerer keytable/signingtable
5. dm_deploy_parking            Page parking WebGL
6. dm_setup_dns                 DNS OVH (si credentials)
7. dm_obtain_ssl                Certificat Let's Encrypt
8. dm_deploy_vhosts             VHosts Apache + a2ensite
9. dm_deploy_logrotate          Rotation des logs
```

## Sequence `--domain-remove`

```
1. snapshot_create              Snapshot automatique
2. dm_remove_vhosts             Supprimer les VHosts
3. dm_remove_logrotate          Supprimer logrotate
4. dm_unregister_domain         Retirer du registre
5. dm_rebuild_opendkim          Regenerer les tables (sans ce domaine)
```

> Les cles DKIM, certificats SSL et fichiers web sont **conserves** (nettoyage manuel).

## Integration avec `fix_dns()`

La fonction `fix_dns()` dans `debian13-server.sh` (appelee par `--check-dns --fix`)
delegue a `dm_setup_dns()` + `dm_setup_ptr()` pour le domaine principal, puis itere
automatiquement sur tous les domaines additionnels de `domains.conf`.

## Tests

~150 tests multi-domaines repartis sur 15 fichiers bats.

```bash
make test
```

Les tests utilisent des repertoires temporaires et des mocks pour isoler
les fonctions de tout effet de bord systeme :

| Fichier | Couverture |
|---------|-----------|
| `domain_registry.bats` | Registre, extract_base_domain, list/register/unregister/exists/get_selector |
| `domain_deploy.bats` | Parking, VHosts, logrotate, suppression, idempotence |
| `domain_dns.bats` | DNS OVH (mock API) : SPF, DKIM, DMARC, A, refresh, fallback |
| `domain_ssl.bats` | Certbot DNS-01 vs HTTP-01, wildcard, email |
| `opendkim_rebuild.bats` | Keytable, signingtable, trustedhosts, cles manquantes |
| `domain_config.bats` | Configuration par domaine (set/get/list/default) |
| `domain_staging.bats` | Staging, promotion, flag STAGING |
| `domain_groups.bats` | Groupes, affectation, listage |
| `domain_export.bats` | Export/import, manifest, idempotence |
| `dkim_rotate.bats` | Rotation DKIM, collision de selecteurs |
| `reverse_proxy.bats` | Deploiement/suppression proxy, WebSocket, headers |
| `git_deploy.bats` | Depot bare, hook post-receive, URL remote |
| `domain_db.bats` | Creation/suppression base, credentials stockes |
| `containers.bats` | Deploy/stop/status/logs, reverse proxy auto |
| `dane_tlsa.bats` | Generation TLSA, publication DNS |

### Ecrire un nouveau test

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

### Points d'attention pour les tests

- **Chemins injectables** : toujours utiliser les variables (`$DOMAINS_CONF`, `$DKIM_KEYDIR`, etc.)
  au lieu de chemins absolus dans le code.
- **Mocking de commandes systeme** : redefinir la commande comme fonction bash et
  l'exporter (`export -f commande`). Attention : `export -f openssl` peut provoquer
  des bugs subtils avec bats — preferer un vrai appel si possible.
- **noexec /tmp** : utiliser `stat -c %a` au lieu de `[[ -x ]]` pour tester les permissions,
  et `bash "$script"` au lieu de `./$script` pour l'execution.
- **Subshell bats** : `run` execute dans un subshell — les modifications d'array ou de
  variable ne sont pas visibles apres `run`. Utiliser un fichier pour persister l'etat.
- **chown en non-root** : mocker `chown() { return 0; }; export -f chown` dans le setup.
