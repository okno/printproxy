# Deploy, aggiornamento e rimozione tramite Git

Questa procedura mantiene separati tre elementi:

- il clone Git in `/srv/printproxy-src`, contenente soltanto sorgenti versionati;
- la configurazione e la chiave HMAC in `/etc/printproxy`, fuori da Git;
- archivi e spool in `/var/lib/printproxy`, fuori da Git.

Eseguire i comandi Git come utente amministrativo normale. Usare `sudo` soltanto
per installazione, servizi, configurazione e backup. Non clonare come `root` e
non inserire token, password, chiavi HMAC o copie di `/etc/printproxy` nel
repository.

## 1. Prerequisiti e clone

Installare Git e i certificati CA sul server Debian:

```bash
sudo apt-get update
sudo apt-get install --no-install-recommends -y git ca-certificates
```

Il repository ufficiale è pubblico e non richiede token per clone o pull. Per
eventuali fork privati usare una deploy key SSH read-only o il credential helper
dell'organizzazione; non inserire mai token nell'URL.

```bash
REPOSITORY_URL='https://github.com/okno/printproxy.git'
sudo install -d -m 0755 -o "$(id -un)" -g "$(id -gn)" /srv/printproxy-src
git clone --origin origin "$REPOSITORY_URL" /srv/printproxy-src
cd /srv/printproxy-src
git remote -v
git status --short
```

`git status --short` deve essere vuoto. Il clone SSH equivalente, utile soltanto
se la macchina possiede già una chiave GitHub configurata, è
`git@github.com:okno/printproxy.git`.

## 2. Selezione e verifica della release

Per una macchina di produzione è preferibile installare un tag immutabile o uno
specifico commit, non una revisione non registrata della branch corrente:

```bash
cd /srv/printproxy-src
git fetch --tags --prune origin
git tag --list
RELEASE_REF='v1.0.2'
git switch --detach "$RELEASE_REF"
git show --no-patch --decorate --oneline HEAD
git rev-parse HEAD
```

Sostituire `v1.0.0` con il tag pubblicato. Se il tag è firmato e la chiave del
maintainer è stata verificata tramite un canale indipendente, controllarlo anche
con:

```bash
git verify-tag "$RELEASE_REF"
```

Se non esiste una firma, confrontare almeno il commit restituito da
`git rev-parse HEAD` con lo SHA-1/SHA-256 della release ricevuto attraverso un
canale indipendente. Non ignorare una firma non valida.

## 3. Prima configurazione, senza secret in Git

La configurazione attiva deve essere `/etc/printproxy/printproxy.conf`. Prepararla
prima dell'installazione permette all'installer di conservarla e validarla senza
modificare il file versionato `config/printproxy.conf`:

```bash
cd /srv/printproxy-src
getent group printproxy >/dev/null || sudo groupadd --system printproxy
sudo install -d -m 0750 -o root -g printproxy /etc/printproxy
sudo install -m 0640 -o root -g printproxy \
  config/printproxy.conf /etc/printproxy/printproxy.conf
sudoedit /etc/printproxy/printproxy.conf
```

Verificare almeno:

- `LISTEN_IP=10.1.2.220` e `VIRTUAL_PREFIX=24`;
- `PRINTER_IP=10.1.2.200` e `PRINTER_PORT=9100`;
- `ALLOWED_CLIENTS` con gli IP esatti dei gestionali, quando noti;
- `ALLOWED_NETWORKS` limitato alla sola rete necessaria;
- `DATA_DIR`, `SPOOL_DIR` e `LOG_DIR` sui percorsi previsti;
- `JOB_END_MODE` e `IDLE_TIMEOUT` coerenti con il pilot;
- `ENABLE_FIREWALL=yes` soltanto dopo avere letto la sezione firewall del
  `README.md` e verificato l'assenza di UFW/firewalld attivi.

`SPLIT_ON_ESCPOS_CUT` deve restare `no`. Archivio e spool devono risiedere su un
filesystem Linux locale supportato: ext3/ext4, XFS, Btrfs o ZFS.

Il valore `HMAC_KEY_FILE` indica soltanto un percorso. La chiave segreta vera è
generata dall'installer in `/etc/printproxy/integrity.key` con permessi
`root:root 0600`; non crearla nel clone, non copiarla nel repository e non
committarla. Anche credenziali Git, backup della configurazione e dump di stampa
devono restare fuori dal clone.

Se Python 3.11 o successivo è già disponibile, si può validare prima del deploy:

```bash
sudo /usr/bin/python3 -I /srv/printproxy-src/printproxy.py \
  --config /etc/printproxy/printproxy.conf --check-config
```

L'installer ripete comunque la validazione e si arresta prima delle modifiche di
rete se la configurazione non è valida.

## 4. Installazione

Confermare prima che `10.1.2.220` sia libero e riservato e che il gestionale stia
ancora stampando direttamente su `10.1.2.200:9100 RAW`. Quindi:

```bash
cd /srv/printproxy-src
chmod +x install.sh uninstall.sh
sudo ./install.sh
```

Lo script installa soltanto le dipendenze mancanti, crea l'utente di servizio,
genera la chiave HMAC, installa il codice sotto `/opt/printproxy`, configura la
VIP e le unit systemd e avvia il servizio. Se `/etc/printproxy/printproxy.conf`
esiste già, lo preserva; eventuali nuovi default vengono salvati come
`/etc/printproxy/printproxy.conf.dist`.

## 5. Verifica e primo pilot

I controlli seguenti non inviano byte di stampa:

```bash
sudo printproxyctl self-test
sudo printproxyctl test-printer
systemctl is-active printproxy.service printproxy-vip.service
systemctl --no-pager --full status printproxy.service
ss -lntp | grep '10.1.2.220:9100'
ip -o -4 addr show | grep '10.1.2.220/24'
ip route get 10.1.2.200
timedatectl status
```

Eseguire anche una verifica completa con uno snapshot stabile:

```bash
sudo systemctl stop printproxy.service
sudo printproxyctl verify
sudo systemctl start printproxy.service
sudo printproxyctl self-test
```

Soltanto dopo il superamento dei controlli modificare il gestionale:

```text
Prima:  10.1.2.200:9100 RAW
Dopo:  10.1.2.220:9100 RAW
```

Non cambiare contemporaneamente driver, code page o formato ESC/POS. La stampa
fisica di prova è deliberatamente separata e richiede conferma esplicita:

```bash
sudo printproxyctl test-print --confirm --text "TEST CORTESIA"
```

Verificare poi archivi, coda e log:

```bash
sudo printproxyctl queue --all
sudo printproxyctl status
journalctl -u printproxy.service --since today --no-pager
```

## 6. Aggiornamento con `git pull` in finestra di manutenzione

Questa modalità è adatta solo se il deploy segue intenzionalmente una branch
stabile, ad esempio `main`. Per release riproducibili usare invece la procedura a
tag descritta nella sezione successiva.

1. Bloccare la creazione di nuovi job oppure riportare temporaneamente il
   gestionale a `10.1.2.200:9100 RAW`.
2. Controllare la coda. Risolvere manualmente eventuali
   `UNKNOWN_PRINT_STATE`; non forzare un retry senza verifica fisica.
3. Fermare il servizio, verificare l'integrità e creare un backup root-only.
4. Aggiornare Git con fast-forward obbligatorio, eseguire i test e rilanciare
   l'installer.

```bash
cd /srv/printproxy-src
sudo printproxyctl queue --all
sudo systemctl stop printproxy.service
sudo printproxyctl verify

DEPLOY_BACKUP="/var/backups/printproxy/git-update-$(date -u +%Y%m%dT%H%M%SZ)"
sudo install -d -m 0700 -o root -g root "$DEPLOY_BACKUP"
sudo cp -a -- /etc/printproxy "$DEPLOY_BACKUP/etc-printproxy"
sudo cp -a -- /var/lib/printproxy "$DEPLOY_BACKUP/var-lib-printproxy"
if [ -d /var/log/printproxy ]; then
  sudo cp -a -- /var/log/printproxy "$DEPLOY_BACKUP/var-log-printproxy"
fi
git rev-parse HEAD | sudo tee "$DEPLOY_BACKUP/source.commit" >/dev/null

git status --short
git switch main
git pull --ff-only origin main
git show --no-patch --decorate --oneline HEAD
python3 -m unittest discover -s tests -v
python3 -m py_compile printproxy.py printproxy_core.py printproxyctl.py
sudo ./install.sh
sudo printproxyctl self-test
```

Prima di `git switch` e `git pull`, `git status --short` deve essere vuoto. Se
mostra file modificati o non tracciati, interrompere e identificarli: non usare
`git reset --hard` e non sovrascrivere dati locali. L'opzione `--ff-only` evita
merge impliciti sul server.

L'installer conserva configurazione e chiave HMAC, deposita eventuali nuovi
default in `.dist` e crea inoltre il proprio backup dei file installati sotto
`/var/backups/printproxy/`. Il backup manuale sopra viene eseguito a servizio
fermo e include anche ledger e spool; proteggerlo come materiale sensibile.

Dopo il deploy rieseguire i controlli della sezione 5. Solo allora rimettere il
gestionale su `10.1.2.220:9100 RAW`.

## 7. Aggiornamento a un nuovo tag

Con il servizio già fermato e il backup già creato come nella sezione precedente:

```bash
cd /srv/printproxy-src
git status --short
git fetch --tags --prune origin
NEW_RELEASE_REF='v1.1.0'
git switch --detach "$NEW_RELEASE_REF"
git show --no-patch --decorate --oneline HEAD
python3 -m unittest discover -s tests -v
sudo ./install.sh
sudo printproxyctl self-test
```

Usare `git verify-tag` solo per release dichiarate firmate; in caso contrario
confrontare il commit con quello pubblicato attraverso un canale indipendente.
Per una release firmata, eseguire il controllo prima dei test e dell'installer:

```bash
git verify-tag "$NEW_RELEASE_REF"
```

## 8. Rollback del codice a tag o commit

Il rollback applicativo della stampa è sempre il primo passo: riportare il
gestionale a `10.1.2.200:9100 RAW`. Poi bloccare nuovi job, fermare il servizio e
conservare un nuovo backup dello stato corrente, anche se l'aggiornamento non è
riuscito.

Per tornare a una release nota e compatibile:

```bash
cd /srv/printproxy-src
sudo systemctl stop printproxy.service

ROLLBACK_BACKUP="/var/backups/printproxy/pre-rollback-$(date -u +%Y%m%dT%H%M%SZ)"
sudo install -d -m 0700 -o root -g root "$ROLLBACK_BACKUP"
sudo cp -a -- /etc/printproxy "$ROLLBACK_BACKUP/etc-printproxy"
sudo cp -a -- /var/lib/printproxy "$ROLLBACK_BACKUP/var-lib-printproxy"
git rev-parse HEAD | sudo tee "$ROLLBACK_BACKUP/source.commit" >/dev/null

git status --short
git fetch --tags --prune origin
GOOD_REF='v1.0.2'
git switch --detach "$GOOD_REF"
git show --no-patch --decorate --oneline HEAD
sudo ./install.sh
sudo printproxyctl self-test
```

`GOOD_REF` può essere un tag o l'hash completo di un commit approvato. Non usare
`git reset --hard`: il cambio detached conserva la cronologia e fallisce in modo
visibile se modifiche locali impediscono il checkout.

L'installer preserva `/etc/printproxy`, la chiave e `/var/lib/printproxy`. Non
mescolare una chiave o un manifest provenienti da backup diversi. Se una vecchia
release non riconosce lo schema corrente, lasciare il servizio fermo e seguire
`docs/RECOVERY.md`; non cancellare spool o ledger per farlo partire. Il ripristino
di una snapshot di dati è un'operazione distinta dal rollback del codice e deve
preservare prima lo stato più recente come evidenza.

Dopo la verifica completa e il pilot, reindirizzare nuovamente il gestionale alla
VIP.

## 9. Disinstallazione conservativa

Prima di disinstallare, ripristinare nel gestionale la destinazione diretta
`10.1.2.200:9100 RAW` e confermare che non arrivino nuovi job. Quindi, dal clone
della stessa release installata:

```bash
cd /srv/printproxy-src
sudo printproxyctl queue --all
sudo systemctl stop printproxy.service
sudo printproxyctl verify
sudo ./uninstall.sh
```

Questa è la modalità predefinita e consigliata: rimuove codice installato, unit,
VIP posseduta e tabella firewall posseduta, ma conserva archivi, spool,
configurazione e chiave HMAC. L'uninstaller crea inoltre una copia root-only della
configurazione sotto `/var/backups/printproxy/`.

Controlli finali:

```bash
systemctl is-active printproxy.service || true
ss -lntp | grep '10.1.2.220:9100' || true
ip -o -4 addr show | grep '10.1.2.220/24' || true
```

## 10. Purge esplicito e irreversibile

Scegliere le opzioni di purge nella **prima** esecuzione dell'uninstaller. Non
eseguire prima la disinstallazione conservativa e poi una seconda disinstallazione:
gli helper autenticati possono essere già stati rimossi e lo script può rifiutare
la seconda operazione in safe mode.

Eliminare la sola configurazione e chiave, conservando archivi e spool:

```bash
sudo ./uninstall.sh --purge-config
```

Eliminare i dati nei soli percorsi predefiniti, conservando configurazione e
chiave:

```bash
sudo ./uninstall.sh --purge-data --i-understand-data-loss
```

Eliminare entrambi:

```bash
sudo ./uninstall.sh --purge-config --purge-data --i-understand-data-loss
```

`--purge-data` non crea un backup degli archivi e ignora per sicurezza percorsi
dati personalizzati. Creare e verificare prima un backup esterno. Senza la chiave
HMAC non sarà più possibile autenticare la storia conservata; per archivi con
valore operativo o probatorio non usare `--purge-config`.

## 11. Rimozione del clone Git

Il clone non è il runtime: il codice attivo viene copiato in `/opt/printproxy`.
Conviene però conservarlo finché aggiornamento, rollback o uninstall non sono
conclusi. Prima della rimozione verificare che non contenga modifiche o commit
locali da conservare:

```bash
git -C /srv/printproxy-src status --short
git -C /srv/printproxy-src log -1 --oneline
```

Se serve una copia recuperabile della storia:

```bash
sudo install -d -m 0700 -o root -g root /var/backups/printproxy
git -C /srv/printproxy-src bundle create /tmp/printproxy-source.bundle --all
sudo install -m 0600 -o root -g root /tmp/printproxy-source.bundle \
  /var/backups/printproxy/printproxy-source.bundle
rm -f -- /tmp/printproxy-source.bundle
```

Dopo avere confermato che il percorso è esattamente quello usato in questa guida,
rimuovere il solo clone:

```bash
cd /
test "$(git -C /srv/printproxy-src rev-parse --show-toplevel)" = "/srv/printproxy-src"
sudo rm -rf -- /srv/printproxy-src
```

Non sostituire il percorso finale con `/srv`, `/opt`, una variabile vuota o una
directory generica. La rimozione del clone non elimina automaticamente
`/etc/printproxy`, `/var/lib/printproxy`, `/var/log/printproxy` o i backup: questi
seguono esclusivamente le scelte fatte con `uninstall.sh`.

## Sequenza breve raccomandata

```text
clone come utente normale
  -> checkout e verifica tag/commit
  -> configurazione in /etc, secret fuori da Git
  -> sudo ./install.sh
  -> self-test + verify a servizio fermo
  -> pilot
  -> cambio gestionale da .200 a .220

update
  -> gestionale temporaneamente su .200 / stop nuovi job
  -> stop + verify + backup
  -> git pull --ff-only oppure checkout nuovo tag
  -> test + sudo ./install.sh + self-test
  -> gestionale nuovamente su .220

remove
  -> gestionale su .200
  -> stop + verify
  -> uninstall conservativo oppure purge esplicitamente confermato
  -> rimozione del clone
```
