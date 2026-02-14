# Guide des operations

Operations courantes pour `debian13-server.sh` : monitoring, backup, clonage,
fleet, rollback, dashboard, notifications.

## Dashboard temps reel

Le dashboard est une page HTML avec auto-refresh (10s) qui interroge un
endpoint CGI bash retournant du JSON. Aucune dependance externe.

```bash
sudo ./debian13-server.sh --dashboard example.com
```

Securite :
- URL secrete : `https://example.com/dashboard-<hash>/`
- Restriction IP via `.htaccess` (variable `TRUSTED_IPS`)
- Le hash est derive du nom de domaine (MD5) ou configurable via `DASHBOARD_SECRET`

Metriques affichees :
- Systeme : hostname, load, CPU, uptime
- Memoire : utilisee/totale avec barre de progression
- Disque : utilisation avec seuils colores (vert/orange/rouge)
- Services : statut de chaque daemon (apache2, postfix, mariadb, fail2ban...)
- SSL : jours restants avant expiration
- Fail2ban : nombre d'IPs bannies (SSH + recidive)
- Postfix : taille de la file d'attente

## Monitoring proactif

Quatre checks independants, executables par cron :

| Check | Seuil par defaut | Description |
|-------|-----------------|-------------|
| `monitor_check_services` | — | Verifie que les services critiques tournent |
| `monitor_check_disk` | 85% | Alerte si le disque depasse le seuil |
| `monitor_check_ssl` | 14 jours | Alerte si un certificat expire bientot |
| `monitor_check_postfix` | 50 messages | Alerte si la file Postfix est saturee |

Deploiement du cron :
```bash
# Le script deploie automatiquement un cron de monitoring
# Personnaliser la liste des services :
MONITOR_SERVICES="apache2 postfix fail2ban ufw mariadb"
```

Quand un check echoue, `monitor_run_all()` envoie une notification
via tous les canaux configures (Slack, Telegram, Discord).

## Notifications

Trois canaux independants. Chaque canal est optionnel : si la variable
n'est pas definie, la notification est silencieusement ignoree.

### Slack

```bash
# Dans debian13-server.conf :
SLACK_WEBHOOK="https://hooks.slack.com/services/T.../B.../xxx"
```

### Telegram

```bash
TELEGRAM_BOT_TOKEN="123456:ABC-DEF..."
TELEGRAM_CHAT_ID="-100123456789"
```

### Discord

```bash
DISCORD_WEBHOOK="https://discord.com/api/webhooks/123/xxx"
```

### Utilisation dans le code

```bash
# Un seul canal
notify_slack "Deploiement termine pour example.com"

# Tous les canaux configures
notify_all "ALERTE : disque plein sur $(hostname -f)"
```

## Snapshots & Rollback

### Fonctionnement

Un snapshot capture l'etat des fichiers de configuration :
- `domains.conf` (registre des domaines)
- VHosts Apache (`/etc/apache2/sites-available/*.conf`)
- Logrotate (`/etc/logrotate.d/apache-vhost-*`)
- Configuration par domaine (`domains.d/`)

Les donnees web, bases de donnees et certificats ne sont **pas** inclus
(trop volumineux — utiliser le backup complet pour ca).

### Snapshot automatique

Un snapshot est cree automatiquement avant `--domain-add` et `--domain-remove`.
Le label contient l'operation et le domaine concerne.

### Commandes

```bash
# Lister les snapshots
sudo ./debian13-server.sh --snapshot-list

# Restaurer un snapshot
sudo ./debian13-server.sh --rollback 20260214-153000-before-domain-add
```

Les snapshots sont stockes dans `/var/lib/debian13-snapshots/`.

## Backup

### Backup local

```bash
sudo ./debian13-server.sh --backup
```

Sauvegarde dans `/root/backups/` :
- Fichiers de configuration (/etc/apache2, /etc/postfix, etc.)
- Cles DKIM
- Dump MariaDB (toutes les bases)
- Crontab

### Backup distant

Configuration :
```bash
backup_remote_config "backup.example.com" "/data/backups" "22"
```

Chiffrement + envoi :
```bash
GPG_RECIPIENT="admin@example.com"
backup_remote_encrypt "/root/backups/archive.tar.gz"
backup_remote_rsync "/root/backups"
```

Pipeline typique : `backup local → chiffrement GPG → rsync SSH → serveur distant`.

## Clonage serveur

Dupliquer la configuration complete vers un nouveau serveur.

### Etape 1 : Generer la cle SSH

```bash
sudo ./debian13-server.sh --clone-keygen
# Affiche la cle publique a copier sur le serveur cible
```

### Etape 2 : Copier la cle sur la cible

```bash
ssh-copy-id -i /root/.ssh/clone_rsa.pub root@10.0.0.2
```

### Etape 3 : Synchroniser

```bash
sudo ./debian13-server.sh --clone 10.0.0.2
# Ou avec un port SSH custom :
sudo ./debian13-server.sh --clone 10.0.0.2 2222
```

Ce qui est synchronise :
- Scripts et configuration (`/root/scripts/`)
- Cles DKIM et tables OpenDKIM
- VHosts Apache
- Fichiers web (`/var/www/`)
- Certificats Let's Encrypt
- Logrotate
- Configuration par domaine (`domains.d/`)

Ce qui n'est **pas** synchronise :
- Bases MariaDB (utiliser `mysqldump` separement)
- Hostname et IP (a reconfigurer sur la cible)
- Cles SSH du serveur (`/etc/ssh/ssh_host_*`)

### Etape 4 : Verifier la cible

```bash
ssh root@10.0.0.2 '/root/scripts/debian13-server.sh --audit'
```

## Fleet (multi-serveurs)

Gerer plusieurs serveurs depuis un point central.

### Inventaire

```bash
# Ajouter des serveurs
sudo ./debian13-server.sh --fleet-add web1 10.0.0.2
sudo ./debian13-server.sh --fleet-add web2 10.0.0.3 2222   # port custom

# Lister
sudo ./debian13-server.sh --fleet-list

# Retirer
sudo ./debian13-server.sh --fleet-remove web1
```

Format du fichier `fleet.conf` :
```
web1:10.0.0.2:22
web2:10.0.0.3:2222
```

### Operations

```bash
# Statut de tous les serveurs (uptime)
sudo ./debian13-server.sh --fleet-status

# Executer une commande sur tous les serveurs
sudo ./debian13-server.sh --fleet-exec "apt-get update -y && apt-get upgrade -y"

# Synchroniser la config (clone vers tous les serveurs)
sudo ./debian13-server.sh --fleet-sync
```

L'execution est sequentielle (pas de parallelisme) pour simplifier
la lecture des logs. Un serveur injoignable (ConnectTimeout=5s) ne
bloque pas les suivants.

## Audit HTML

Generer un rapport d'audit au format HTML (auto-contenu, CSS inline).

```bash
sudo ./debian13-server.sh --audit-html /tmp/rapport.html
```

Le rapport contient les memes checks que `--audit` mais dans un format
visuellement structure : sections, icones ok/warn/fail, resume final.

## Structured logging

Activer les logs JSON (NDJSON) en plus des logs console :

```bash
STRUCTURED_LOG="/var/log/debian13-server.json"
```

Format de sortie :
```json
{"ts":"2026-02-14T15:30:00+01:00","level":"info","msg":"Domaine ajouté","domain":"example.com"}
```

Compatible avec `jq`, Loki, Elasticsearch, ou tout pipeline JSON.

## Dry-run

Simuler les actions sans modifier le systeme :

```bash
sudo ./debian13-server.sh --dry-run --domain-add example.com
```

Les commandes enrobees par `dry_run_wrap()` affichent `[DRY-RUN] commande`
au lieu d'etre executees.

## Hooks

Etendre le comportement sans modifier le code source.

### Creation d'un hook

```bash
mkdir -p /root/scripts/hooks.d

cat > /root/scripts/hooks.d/post-domain-add-notify.sh <<'EOF'
#!/bin/bash
# Notifier apres ajout d'un domaine
curl -s -X POST https://hooks.slack.com/services/T.../B.../xxx \
  -d "{\"text\":\"Nouveau domaine: $1\"}"
EOF

chmod +x /root/scripts/hooks.d/post-domain-add-notify.sh
```

### Evenements disponibles

| Evenement | Declencheur | Arguments |
|-----------|-------------|-----------|
| `pre-install` | Avant l'installation | — |
| `post-install` | Apres l'installation | — |
| `pre-domain-add` | Avant `--domain-add` | domaine |
| `post-domain-add` | Apres `--domain-add` | domaine |
| `pre-domain-remove` | Avant `--domain-remove` | domaine |
| `post-domain-remove` | Apres `--domain-remove` | domaine |
| `pre-backup` | Avant `--backup` | — |
| `post-backup` | Apres `--backup` | — |

### Convention de nommage

```
hooks.d/<evenement>-<nom>.sh
```

Exemples :
- `post-install-slack.sh`
- `pre-backup-db-dump.sh`
- `post-domain-add-cloudflare.sh`

Les hooks sont executes dans l'ordre alphabetique. Un hook qui echoue
(code retour != 0) affiche un warning mais ne bloque pas le script principal.

## TUI (interface texte)

Le systeme detecte automatiquement le backend disponible :
1. **whiptail** (installe par defaut sur Debian) — boites de dialogue ncurses
2. **dialog** — alternative si whiptail absent
3. **Texte pur** — fallback universel (read/echo)

Les fonctions TUI disponibles :

| Fonction | Description |
|----------|-------------|
| `tui_yesno "Question ?"` | Oui/Non |
| `tui_input "Prompt" "Titre" "defaut"` | Saisie texte |
| `tui_menu "Choix" "Titre" tag1 desc1 tag2 desc2` | Menu selection unique |
| `tui_checklist "Choix" "Titre" tag1 desc1 on tag2 desc2 off` | Multi-selection |
| `tui_msg "Message" "Titre"` | Boite de message |
