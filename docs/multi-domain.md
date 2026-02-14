# Gestion multi-domaines

Documentation technique du systeme multi-domaines de `debian13-server.sh`.

## Vue d'ensemble

Le serveur peut heberger plusieurs domaines. Chaque domaine est enregistre dans
`domains.conf` et obtient sa propre configuration : DKIM, VHosts, SSL, DNS, parking.

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

## Bibliotheque : `lib/domain-manager.sh`

Toutes les fonctions sont prefixees `dm_`. Les chemins sont injectables via
variables d'environnement (pour les tests).

### Variables injectables

| Variable | Defaut | Usage |
|----------|--------|-------|
| `DOMAINS_CONF` | `/root/scripts/domains.conf` | Registre des domaines |
| `DKIM_KEYDIR` | `/etc/opendkim/keys` | Repertoire racine des cles DKIM |
| `OPENDKIM_DIR` | `/etc/opendkim` | Configuration OpenDKIM |
| `WEB_ROOT` | `/var/www` | Racine des sites web |
| `APACHE_SITES_DIR` | `/etc/apache2/sites-available` | VHosts Apache |
| `LOGROTATE_DIR` | `/etc/logrotate.d` | Configurations logrotate |
| `TEMPLATES_DIR` | `/root/scripts/templates` | Templates HTML/VHost |
| `LOG_DIR` | `/var/log/apache2` | Logs Apache |

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
| `dm_extract_base_domain $fqdn` | Extrait le TLD+1 (`srv.example.com` -> `example.com`) |
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

Layout des cles DKIM :
```
/etc/opendkim/keys/
  example.com/
    mail.private        Cle privee
    mail.txt            Cle publique (pour le DNS)
  example.com/
    dkim2025.private
    dkim2025.txt
```

Fichiers generes dans `/etc/opendkim/` :
```
keytable        Associe selecteur -> cle privee
signingtable    Associe *@domaine -> selecteur._domainkey.domaine
trustedhosts    127.0.0.1, localhost, ::1
```

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

VHosts generes :
```
/etc/apache2/sites-available/
  000-example.com-redirect.conf     HTTP -> HTTPS
  010-example.com.conf              HTTPS apex + www
  020-example.com-wildcard.conf     *.example.com (si wildcard cert)
```

#### SSL

| Fonction | Description |
|----------|-------------|
| `dm_obtain_ssl $domain [$email]` | DNS-01 wildcard (OVH) ou HTTP-01 fallback |

Logique :
- Si `/root/.ovh-dns.ini` existe : `certbot --dns-ovh` avec wildcard `*.domain`
- Sinon : `certbot --apache --preferred-challenges http` (apex + www)

#### DNS

| Fonction | Description |
|----------|-------------|
| `dm_setup_dns $domain [$selector]` | Configure A, AAAA, SPF, DKIM, DMARC, CAA via OVH API |
| `dm_setup_ptr $hostname_fqdn` | Configure PTR (reverse DNS) IPv4/IPv6 |

Apres execution, `$DM_DNS_OK` et `$DM_DNS_FAIL` contiennent les compteurs.

Enregistrements crees/mis a jour :
- `A` : domaine -> `$SERVER_IP`
- `A` : www.domaine -> `$SERVER_IP`
- `AAAA` : domaine -> `$SERVER_IP6` (si disponible)
- `TXT` : SPF (`v=spf1 ip4:... -all`)
- `TXT` : DKIM (`selecteur._domainkey.domaine`)
- `TXT` : DMARC (`_dmarc.domaine`)
- `CAA` : `0 issue "letsencrypt.org"` (si absent)

#### Verification

| Fonction | Description |
|----------|-------------|
| `dm_check_domain $domain [$selector]` | Verifie DNS A/AAAA, SPF, DKIM, DMARC, SSL, VHost |

Utilise le systeme `emit_check` (ok/warn/fail) de `lib/verify.sh`.

## Sequence `--domain-add`

```
1. dm_register_domain          Ajouter au registre
2. dm_generate_dkim_key        Generer la cle DKIM
3. dm_rebuild_opendkim         Regenerer keytable/signingtable
4. dm_deploy_parking           Page parking WebGL
5. dm_setup_dns                DNS OVH (si credentials)
6. dm_obtain_ssl               Certificat Let's Encrypt
7. dm_deploy_vhosts            VHosts Apache + a2ensite
8. dm_deploy_logrotate         Rotation des logs
```

## Sequence `--domain-remove`

```
1. dm_remove_vhosts            Supprimer les VHosts
2. dm_remove_logrotate         Supprimer logrotate
3. dm_unregister_domain        Retirer du registre
4. dm_rebuild_opendkim         Regenerer les tables (sans ce domaine)
```

> Les cles DKIM, certificats SSL et fichiers web sont **conserves** (nettoyage manuel).

## Integration avec `fix_dns()`

La fonction `fix_dns()` dans `debian13-server.sh` (appelee par `--check-dns --fix`)
delegue a `dm_setup_dns()` + `dm_setup_ptr()` pour le domaine principal, puis itere
automatiquement sur tous les domaines additionnels de `domains.conf`.

## Tests

46 tests unitaires avec [bats-core](https://github.com/bats-core/bats-core).

```bash
make test
```

Les tests utilisent des repertoires temporaires et des mocks pour isoler
les fonctions de tout effet de bord systeme :

| Fichier | Tests | Couverture |
|---------|-------|-----------|
| `domain_registry.bats` | 17 | Registre, extract_base_domain, list/register/unregister/exists/get_selector |
| `domain_deploy.bats` | 12 | Parking, VHosts, logrotate, suppression, idempotence |
| `domain_dns.bats` | 6 | DNS OVH (mock API) : SPF, DKIM, DMARC, A, refresh, fallback |
| `domain_ssl.bats` | 5 | Certbot DNS-01 vs HTTP-01, wildcard, email |
| `opendkim_rebuild.bats` | 6 | Keytable, signingtable, trustedhosts, cles manquantes, domaines vides |

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
