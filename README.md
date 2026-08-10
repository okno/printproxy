# Printproxy RAW/JetDirect per stampe di cortesia

Printproxy è un proxy TCP **store-and-forward** per stampe non fiscali RAW/ESC-POS. Riceve ogni segmento configurato, lo rende durevole su disco, calcola SHA-256, aggiorna un registro append-only con hash chain e HMAC, poi lo inoltra senza modificarne un solo byte attraverso un’unica coda seriale.

Il progetto è destinato a Debian 12/13 con Python 3.11 o successivo e dipendenze runtime limitate alla standard library.

> Limite fondamentale: RAW TCP/9100 non offre un identificatore di job né una conferma di stampa fisica. Il software garantisce identità e durabilità digitale del flusso ricevuto, serializzazione e gestione conservativa dell’incertezza; non può garantire “exactly once” sulla carta.

## Architettura

Prima:

```text
Gestionale ──────────────> 10.1.2.200:9100 ──> POS80BL
```

Dopo:

```text
Gestionale
    │ RAW TCP, invariato
    ▼
10.1.2.220:9100
    │
    ▼
Debian Printproxy (IP principale 10.1.2.235)
    ├── .tmp + fsync + rename atomico
    ├── RAW / TXT / JSON / SHA-256
    ├── manifest JSONL + hash chain + HMAC
    └── spool persistente ──> worker singolo ──> 10.1.2.200:9100
                                                  │
                                                  ▼
                                                POS80BL
```

L’IP virtuale dedicato `10.1.2.220` è preferibile a `10.1.2.235`: separa l’identità del servizio dall’amministrazione del server, permette bind e regole ACL precise e rende il rollback immediato. Il servizio oneshot aggiunge solo quell’indirizzo; non modifica IP primario, gateway, route globali, subnet o forwarding.

Non viene usato ARP spoofing/MITM. Poiché il gestionale può essere configurato verso il proxy, un listener applicativo è più semplice da controllare, auditare e rimuovere, senza alterare il piano L2 della LAN.

## Analisi tecnica sintetica

1. La porta più probabile è TCP/9100 RAW/JetDirect con byte ESC/POS. L’installer prova esclusivamente 9100, 515 e 631 con `connect()` e senza inviare payload.
2. L’architettura scelta è ricezione completa, commit durevole e solo dopo inoltro serializzato.
3. Nessun ARP MITM è necessario: il gestionale cambia destinazione da `.200` a `.220`.
4. La fine job è una policy configurabile: chiusura, inattività o il primo dei due. Il default `hybrid` deve essere calibrato sul traffico reale.
5. Un solo worker apre una sola connessione per volta alla stampante; due stream non possono interleavarsi.
6. Il RAW è scritto con chiamate binarie, chunk limitati, `fsync`, nome temporaneo e pubblicazione atomica. Parser e sidecar operano soltanto sul RAW sigillato.
7. Se la stampante è offline, il job rimane archiviato in `FAILED_BEFORE_SEND` con backoff; nessuna riuscita viene simulata.
8. Dopo il marker durevole `SENDING`, ogni errore/crash diventa `UNKNOWN_PRINT_STATE` e non è ritentato automaticamente.
9. SHA-256 protegge il contenuto; hash chain e HMAC proteggono ordine e autenticità dei record locali; una head autenticata rileva il troncamento accidentale del manifest.
10. I failure mode gestiti includono RST client, timeout, job eccessivo, ENOSPC, crash durante ricezione/invio, stampante offline, spool incoerente, concorrenza, shutdown e riavvio.

## Protocollo supportato e discovery

Questa release supporta in sicurezza `PROXY_PROTOCOL=raw` su 9100. LPR/515 e IPP/631 sono protocolli interattivi con framing e risposte applicative: inoltrarli come se fossero RAW produrrebbe archivi e semantica errati. Se 515/631 risultano aperte ma 9100 no, l’installer si arresta senza modificare la rete e richiede un’architettura protocol-aware (normalmente CUPS/IPP/LPR, con un diverso modello di audit).

Una porta aperta non prova da sola il protocollo. Prima del go-live verificare dalla configurazione del gestionale o con una cattura autorizzata e limitata che:

- la destinazione corrente sia RAW TCP/9100;
- il client non attenda risposte bidirezionali `DLE EOT`/status;
- i gap intra-job siano inferiori al timeout scelto;
- sia noto se una connessione contiene uno o più scontrini.

Se il gestionale richiede dialogo bidirezionale con la stampante, **non usare questo proxy**: lo store-and-forward unidirezionale cambierebbe la semantica richiesta/risposta.

## Installazione

Repository pubblico: `https://github.com/okno/printproxy`.

Sul server Debian, clonare una release e lanciare:

```bash
sudo apt-get update
sudo apt-get install --no-install-recommends -y git ca-certificates
git clone https://github.com/okno/printproxy.git /srv/printproxy-src
cd /srv/printproxy-src
git switch --detach v1.0.0
chmod +x install.sh uninstall.sh
sudo ./install.sh
```

La procedura Git completa per prima installazione, aggiornamenti `--ff-only`,
checkout dei tag, rollback, uninstall e rimozione del clone è in
[GIT_DEPLOYMENT.md](docs/GIT_DEPLOYMENT.md).

L’installer:

- verifica root, Debian, systemd e Python;
- installa soltanto i pacchetti mancanti;
- valida la configurazione con parser rigoroso, senza eseguirla come shell;
- rileva l’interfaccia della route verso `10.1.2.200` e i manager di rete attivi;
- esegue duplicate-address detection con ARP prima di aggiungere `.220`;
- non riavvia né porta down l’interfaccia primaria;
- crea utente non privilegiato, directory e chiave HMAC root-only;
- rifiuta per archivio e spool filesystem di rete, FUSE/DrvFS, overlay o volatili; sono ammessi storage locali ext3/ext4, XFS, Btrfs e ZFS;
- installa unit systemd hardenizzate, logrotate e CLI;
- valida le unit, avvia il servizio e mostra lo stato finale.

La persistenza dell’IP usa un’unit oneshot additiva e backend-neutral, affiancata da un timer watchdog che ripristina soltanto la VIP registrata se un reconnect di rete la rimuove. L’installer rileva NetworkManager, systemd-networkd e ifupdown, ma non riscrive profili o file esistenti: al boot ricalcola la route, ripete il DAD, verifica l’interfaccia registrata e aggiunge esclusivamente `10.1.2.220/24`. Questo evita modifiche distruttive e conflitti con configurazioni generate.

Verifiche post-installazione:

```bash
sudo printproxyctl self-test
systemctl status printproxy
ss -lntp | grep 9100
ip addr show
journalctl -u printproxy -f
```

`self-test` non invia alcuna stampa. Solo dopo tutti i controlli, modificare nel gestionale:

```text
IP stampante: 10.1.2.200  ->  10.1.2.220
Porta:        9100        ->  9100
Protocollo:   RAW         ->  RAW
```

La prima prova fisica è deliberatamente esplicita:

```bash
sudo printproxyctl test-print --confirm --text "TEST CORTESIA"
```

## Configurazione

File: `/etc/printproxy/printproxy.conf` (`root:printproxy`, `0640`). Dopo modifiche:

```bash
sudo systemctl stop printproxy
sudo /usr/bin/python3 -I /opt/printproxy/printproxy.py \
  --config /etc/printproxy/printproxy.conf --check-config
sudo systemctl start printproxy
```

Eseguire questa procedura in una finestra senza nuovi job. Lo stop è conservativo: una ricezione interrotta resta `PARTIAL` e un tentativo già entrato in `SENDING` resta `UNKNOWN_PRINT_STATE`, mai ritentato automaticamente.

Parametri principali:

| Parametro | Default | Significato |
|---|---:|---|
| `LISTEN_IP` | `10.1.2.220` | bind dedicato; `0.0.0.0` è rifiutato |
| `PRINTER_IP` | `10.1.2.200` | stampante reale |
| `JOB_END_MODE` | `hybrid` | `connection_close`, `idle_timeout`, `hybrid` |
| `IDLE_TIMEOUT` | `3` | gap in secondi; va calibrato |
| `SESSION_IDLE_TIMEOUT` | `300` | attesa massima del job successivo su sessione persistente |
| `MAX_JOB_BYTES` | `67108864` | limite anti-abuso, RAM sempre chunked |
| `MAX_CONCURRENT_CLIENTS` | `32` | hard cap di socket/client attivi |
| `MAX_READABLE_DUMP_BYTES` | `1048576` | input massimo del renderer `.txt` best-effort |
| `MAX_CONCURRENT_SIDECARS` | `2` | parallelismo limitato dei renderer |
| `FSYNC_INTERVAL_BYTES` | `262144` | frequenza commit durante ricezione |
| `ALLOWED_NETWORKS` | `10.1.2.0/24` | ACL applicativa LAN |
| `ALLOWED_CLIENTS` | vuoto | preferire IP esatti quando noti |
| `PRESERVE_QUEUE_ORDER` | `yes` | un job offline blocca quelli successivi fino al retry |
| `BLOCK_QUEUE_ON_UNKNOWN` | `no` | se `yes`, un incerto sospende tutta la coda |
| `ENABLE_RETENTION` | `no` | nessuna cancellazione automatica di default |
| `ENABLE_FIREWALL` | `no` | tabella nftables dedicata e scoped |

### Confini dei job

| Modalità | Comportamento | Uso consigliato |
|---|---|---|
| `connection_close` | una connessione diventa un archivio | quando il pilot conferma una connessione per stampa |
| `idle_timeout` | ogni gap sigilla un segmento non vuoto; la sessione resta aperta | connessioni persistenti con gap nettamente separati |
| `hybrid` | primo tra FIN e gap | default prudente, da calibrare |

`SPLIT_ON_ESCPOS_CUT` deve restare `no`; questa release rifiuta esplicitamente `yes`. Il CUT può mancare, ripetersi o apparire dentro raster/barcode, quindi non è un delimitatore sicuro senza un parser binario stateful e length-aware.

## File prodotti per job

Esempio base `2026-08-10T17-25-31.123456Z_<UUID>`:

- `.raw`: fonte originale byte-per-byte;
- `.txt`: rendering best-effort ESC/POS con comandi e byte di controllo annotati;
- `.hex`: opzionale, diagnostica reversibile;
- `.json`: metadata correnti e stato operativo.

Il registro globale `/var/lib/printproxy/jobs/manifest.jsonl` è append-only. `manifest.head.json` contiene contatore e head autenticata. Gli stati durevoli sono in `/var/lib/printproxy/spool/states/`.

Archivio e spool devono risiedere su un filesystem Linux locale supportato dall’installer. Il percorso rapido del daemon autentica head e record di coda e usa anche identità, dimensione e timestamp inode per rilevare modifiche esterne; la verifica offline rilegge invece ogni byte e ogni collegamento della chain. NTFS/DrvFS, NFS/CIFS, FUSE, overlay e `tmpfs` non rientrano nel modello di durabilità o rilevamento live.

## Stati, spool e retry

```text
RECEIVING -> SEALED --[evento ARCHIVED]--> QUEUED -> SEND_ARMED -> SENDING -> SENT_UNCONFIRMED
    |              |                              |             |
    |              +------------------------------+             +-> UNKNOWN_PRINT_STATE
    +---------------------> PARTIAL                       errore/crash dopo il marker
                                      connect pre-send -> FAILED_BEFORE_SEND
incoerente -> QUARANTINED
```

- `FAILED_BEFORE_SEND`: nessuna syscall di invio è possibile dopo il marker osservato; retry automatico sicuro con backoff.
- `SENDING`: marker sincronizzato prima della prima `writer.write()`.
- `UNKNOWN_PRINT_STATE`: la stampante potrebbe aver ricevuto un prefisso o tutto; nessun retry automatico.
- `SENT_UNCONFIRMED`: tutti i byte sono stati drenati dallo stack TCP locale e la sessione è stata chiusa; non prova carta, taglio o stampa fisica.
- `PARTIAL`: ricezione interrotta/limite/crash; conservato ma mai inoltrato.

Un retry incerto richiede accettazione esplicita del rischio duplicato:

```bash
sudo printproxyctl retry <JOB_UUID> --confirm-unknown \
  --reason "verifica operatore: nessuna stampa uscita"
```

La CLI crea una richiesta durevole; **non** apre direttamente una seconda connessione alla stampante.

## Comandi di gestione

```bash
sudo printproxyctl status
sudo printproxyctl queue
sudo printproxyctl queue --all --json
sudo printproxyctl test-printer
sudo printproxyctl self-test
sudo printproxyctl retry <JOB_UUID>
sudo printproxyctl retry --all-safe
journalctl -u printproxy --since today
```

`test-printer` esegue solo una connessione TCP vuota verso la stampante. `self-test` verifica configurazione, bind/listener, permessi di scrittura, spazio, SHA-256, head/HMAC, NTP e reachability; non stampa. La verifica completa richiede uno snapshot stabile e viene deliberatamente rifiutata mentre il daemon è attivo:

```bash
sudo systemctl stop printproxy
sudo printproxyctl verify
sudo systemctl start printproxy
```

## Integrità e timestamp

- **SHA-256** rileva una modifica del RAW rispetto al digest registrato; da solo non autentica chi ha creato il digest.
- **Hash chain** collega ogni evento al precedente con JSON canonico e lunghezza esplicita; rileva modifica, eliminazione o riordino interno.
- **HMAC-SHA-256** autentica record e head con un segreto locale. La sorgente resta `/etc/printproxy/integrity.key`, `root:root 0600`; systemd la consegna al daemon non-root tramite `LoadCredential=`.
- **Timestamp locale UTC/NTP** è un dato di audit del server. Non è una marca temporale certificata e può essere influenzato da un amministratore.
- **Timestamp certificato** richiede un’autorità esterna/TSA o ancoraggio WORM/remoto, non incluso.

Una chain/HMAC interamente locale non può dimostrare da sola che un attaccante privilegiato non abbia ripristinato insieme manifest, head e archivi a una vecchia snapshot. Per valore probatorio forte esportare periodicamente head e manifest su storage remoto append-only/WORM o usare una TSA qualificata.

Durante il funzionamento l’append non rilegge l’intera storia a ogni evento: verifica head, tail autenticata e firma del file sul filesystem locale supportato. `printproxyctl verify`, eseguito a servizio fermo, è il controllo completo contro modifiche anche nel prefisso storico. Un amministratore/root capace di alterare anche metadati del filesystem resta fuori dal perimetro della sola protezione locale.

## Test del progetto

```bash
cd printproxy
python3 -m unittest discover -s tests -v
python3 -m py_compile printproxy.py printproxy_core.py printproxyctl.py
```

I 42 test includono payload con tutti i byte `00..FF`, frammentazione, concorrenza, sessioni persistenti, stampante simulata/offline, recovery/outbox, parser, atomicità, retry idempotente, retention autorizzata e tamper detection. La validazione finale su POS80BL deve includere testo accentato, euro, raster, barcode, taglio e almeno 30 stampe rappresentative.

## Troubleshooting rapido

```bash
systemctl status printproxy printproxy-vip printproxy-firewall
journalctl -u printproxy -n 200 --no-pager
ip -4 addr show
ip route get 10.1.2.200
ss -lntp | grep 9100
sudo printproxyctl status
sudo systemctl stop printproxy
sudo printproxyctl verify
sudo systemctl start printproxy
sudo printproxyctl queue
```

- `FAILED_BEFORE_SEND`: verificare alimentazione, rete e porta della stampante; il retry sicuro è automatico.
- `UNKNOWN_PRINT_STATE`: verificare fisicamente prima di qualsiasi retry.
- `PARTIAL`: controllare RST client, timeout e limiti; il file non viene inoltrato.
- `DISK_SPACE_LOW`: liberare spazio fuori dall’archivio oppure espandere il filesystem; non abbassare la soglia senza valutazione.
- NTP warning: abilitare `systemd-timesyncd` o il servizio NTP già adottato.

Dettagli in [TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) e [RECOVERY.md](docs/RECOVERY.md).

## Rollback e disinstallazione

Il rollback funzionale non richiede toccare Debian:

```text
Gestionale: 10.1.2.220 -> 10.1.2.200, porta 9100 RAW
```

La stampa torna diretta anche se il proxy è fermo. Per rimuovere il software, dopo aver ripristinato il gestionale:

```bash
sudo ./uninstall.sh
```

Per default l’uninstaller conserva archivi, spool, configurazione e chiave HMAC. Rimuove soltanto unit/file propri, IP virtuale se creato dal progetto e tabella nftables se posseduta. Opzioni distruttive, esplicite:

```bash
sudo ./uninstall.sh --purge-config
sudo ./uninstall.sh --purge-data --i-understand-data-loss
```

Prima di eliminare la configurazione viene sempre creata una copia root-only in `/var/backups/printproxy/`.

## Security review sintetica

- daemon `User=printproxy`, nessuna capability, filesystem systemd read-only salvo directory dichiarate;
- bind solo sul VIP, ACL IPv4 prima della lettura, nftables opzionale e senza `flush ruleset`;
- nomi file derivati da UUID/timestamp interni, creazione esclusiva e `O_NOFOLLOW`;
- write completi, file e directory sincronizzati, replace atomici, limite dimensione/durata/client;
- contenuto stampa mai scritto nel journal;
- chiave HMAC non leggibile a riposo dal service user;
- nessun IP forwarding, NAT, ARP poisoning o modifica a gateway/subnet;
- retention disabilitata e comunque limitata a `SENT_UNCONFIRMED` vecchi;
- RAW e metadata validati prima dell’inoltro e durante `verify`.

La checklist di produzione e le assunzioni residue sono in [SECURITY.md](docs/SECURITY.md).

## Struttura

```text
printproxy/
├── install.sh
├── uninstall.sh
├── README.md
├── printproxy.py
├── printproxy_core.py
├── printproxyctl.py
├── config/printproxy.conf
├── network/
├── systemd/
├── logrotate/
├── tests/
└── docs/
```
